#ifndef AES_CUH
#define AES_CUH

#include "../../include/aes/aes_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../linearalgebra/addition.cuh"

static constexpr uint32_t AES_LINEAR_THREADS = 256;

/**
 * Evaluates one GF(2) linear map from an index table: out[b, i] is the sum
 * of the inputs the table names for bit b. Bitsliced layout everywhere:
 * bit b of AES input i lives at block b * num_aes_inputs + i.
 */
template <typename Torus>
__global__ void
device_aes_linear_combination(Torus *out, const Torus *in, const uint32_t *idx,
                              uint32_t terms, uint32_t num_aes_inputs,
                              uint32_t chunks_per_ct, uint32_t lwe_size) {
  uint32_t chunk = blockIdx.x % chunks_per_ct;
  uint32_t out_block = blockIdx.x / chunks_per_ct;
  uint32_t coeff = chunk * blockDim.x + threadIdx.x;
  if (coeff >= lwe_size)
    return;

  uint32_t input = out_block % num_aes_inputs;
  uint32_t bit = out_block / num_aes_inputs;

  Torus acc = 0;
  for (uint32_t k = 0; k < terms; ++k) {
    uint32_t src = idx[bit * terms + k];
    if (src != AES_LINEAR_NO_TERM)
      acc += in[((size_t)src * num_aes_inputs + input) * lwe_size + coeff];
  }
  out[(size_t)out_block * lwe_size + coeff] = acc;
}

/**
 * Seeds every AES input with the IV, directly in bitsliced order, so the
 * CTR loop needs no separate transpose pass.
 */
template <typename Torus>
__global__ void
device_aes_broadcast_bits(Torus *out, const Torus *src, uint32_t num_aes_inputs,
                          uint32_t chunks_per_ct, uint32_t lwe_size) {
  uint32_t chunk = blockIdx.x % chunks_per_ct;
  uint32_t out_block = blockIdx.x / chunks_per_ct;
  uint32_t coeff = chunk * blockDim.x + threadIdx.x;
  if (coeff >= lwe_size)
    return;

  uint32_t bit = out_block / num_aes_inputs;
  out[(size_t)out_block * lwe_size + coeff] =
      src[(size_t)bit * lwe_size + coeff];
}

/**
 * AddRoundKey kernel: adds the shared round key, read in place from the
 * expanded key, to every input's state.
 */
template <typename Torus>
__global__ void device_aes_add_broadcast_bits(Torus *out, const Torus *src,
                                              uint32_t num_aes_inputs,
                                              uint32_t chunks_per_ct,
                                              uint32_t lwe_size) {
  uint32_t chunk = blockIdx.x % chunks_per_ct;
  uint32_t out_block = blockIdx.x / chunks_per_ct;
  uint32_t coeff = chunk * blockDim.x + threadIdx.x;
  if (coeff >= lwe_size)
    return;

  uint32_t bit = out_block / num_aes_inputs;
  out[(size_t)out_block * lwe_size + coeff] +=
      src[(size_t)bit * lwe_size + coeff];
}

/**
 * Hands the finished states back in the block order callers expect.
 */
template <typename Torus>
__global__ void
device_aes_bitsliced_to_blocks(Torus *out, const Torus *in, uint32_t num_bits,
                               uint32_t num_aes_inputs, uint32_t chunks_per_ct,
                               uint32_t lwe_size) {
  uint32_t chunk = blockIdx.x % chunks_per_ct;
  uint32_t src_block = blockIdx.x / chunks_per_ct;
  uint32_t coeff = chunk * blockDim.x + threadIdx.x;
  if (coeff >= lwe_size)
    return;

  uint32_t input = src_block % num_aes_inputs;
  uint32_t bit = src_block / num_aes_inputs;
  out[((size_t)input * num_bits + bit) * lwe_size + coeff] =
      in[(size_t)src_block * lwe_size + coeff];
}

/**
 * Thread blocks per ciphertext, keeping the launch grid one-dimensional.
 */
static inline uint32_t aes_linear_chunks_per_ct(uint32_t lwe_size) {
  return CEIL_DIV(lwe_size, AES_LINEAR_THREADS);
}

/**
 * The raw kernels above touch whole block ranges concurrently, so operand
 * ranges must be disjoint, and base pointers are not enough since slices
 * of one buffer can overlap. Also rejects mismatched lwe dimensions and
 * unallocated dry-run ciphertexts, which the kernels cannot survive.
 */
template <typename Torus>
static inline void aes_check_disjoint_ranges(const CudaRadixCiphertextFFI *out,
                                             uint32_t num_out_blocks,
                                             const CudaRadixCiphertextFFI *in,
                                             uint32_t num_in_blocks,
                                             const char *op_name) {
  PANIC_IF_FALSE(out->ptr != nullptr && in->ptr != nullptr,
                 "Cuda error: %s cannot run on unallocated (dry-run) "
                 "ciphertexts",
                 op_name);
  PANIC_IF_FALSE(out->lwe_dimension == in->lwe_dimension,
                 "Cuda error: %s operands must have the same lwe dimension",
                 op_name);
  const size_t lwe_bytes = ((size_t)out->lwe_dimension + 1) * sizeof(Torus);
  const uintptr_t out_start = (uintptr_t)out->ptr;
  const uintptr_t out_end = out_start + num_out_blocks * lwe_bytes;
  const uintptr_t in_start = (uintptr_t)in->ptr;
  const uintptr_t in_end = in_start + num_in_blocks * lwe_bytes;
  PANIC_IF_FALSE(out_end <= in_start || in_end <= out_start,
                 "Cuda error: %s operand ranges overlap", op_name);
}

/**
 * Launches one index-table linear map and mirrors degree and noise
 * host-side exactly as the chain of additions it replaces would.
 */
template <typename Torus>
__host__ void host_aes_linear_combination(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *out,
    const CudaRadixCiphertextFFI *in, const uint32_t *d_idx,
    const uint32_t *h_idx, uint32_t terms, uint32_t num_out_bits,
    uint32_t num_aes_inputs, uint32_t message_modulus, uint32_t carry_modulus) {

  if (out->num_radix_blocks < num_out_bits * num_aes_inputs)
    PANIC("Cuda error: AES linear combination output has too few blocks")

  uint32_t max_src = 0;
  for (uint32_t k = 0; k < num_out_bits * terms; ++k)
    if (h_idx[k] != AES_LINEAR_NO_TERM && h_idx[k] > max_src)
      max_src = h_idx[k];
  if (in->num_radix_blocks < (max_src + 1) * num_aes_inputs)
    PANIC("Cuda error: AES linear combination input has too few blocks for the "
          "index table it is addressed with")
  aes_check_disjoint_ranges<Torus>(out, num_out_bits * num_aes_inputs, in,
                                   (max_src + 1) * num_aes_inputs,
                                   "AES linear combination");

  cuda_set_device(gpu_index);
  uint32_t lwe_size = out->lwe_dimension + 1;
  uint32_t chunks = aes_linear_chunks_per_ct(lwe_size);
  uint32_t num_out_blocks = num_out_bits * num_aes_inputs;

  device_aes_linear_combination<Torus>
      <<<num_out_blocks * chunks, AES_LINEAR_THREADS, 0, stream>>>(
          (Torus *)out->ptr, (const Torus *)in->ptr, d_idx, terms,
          num_aes_inputs, chunks, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t bit = 0; bit < num_out_bits; ++bit) {
    for (uint32_t input = 0; input < num_aes_inputs; ++input) {
      uint64_t degree = 0, noise = 0;
      for (uint32_t k = 0; k < terms; ++k) {
        uint32_t src = h_idx[bit * terms + k];
        if (src == AES_LINEAR_NO_TERM)
          continue;
        degree += in->degrees[src * num_aes_inputs + input];
        noise += in->noise_levels[src * num_aes_inputs + input];
      }
      uint32_t o = bit * num_aes_inputs + input;
      out->degrees[o] = degree;
      out->noise_levels[o] = noise;
      CHECK_NOISE_LEVEL(noise, message_modulus, carry_modulus);
    }
  }
}

/**
 * IV broadcast entry point. Degree and noise carry over unchanged.
 */
template <typename Torus>
__host__ void host_aes_broadcast_bits(cudaStream_t stream, uint32_t gpu_index,
                                      CudaRadixCiphertextFFI *out,
                                      const CudaRadixCiphertextFFI *src,
                                      uint32_t num_bits,
                                      uint32_t num_aes_inputs) {

  if (out->num_radix_blocks < num_bits * num_aes_inputs ||
      src->num_radix_blocks < num_bits)
    PANIC("Cuda error: AES broadcast operands have too few blocks")
  aes_check_disjoint_ranges<Torus>(out, num_bits * num_aes_inputs, src,
                                   num_bits, "AES bit broadcast");

  cuda_set_device(gpu_index);
  uint32_t lwe_size = out->lwe_dimension + 1;
  uint32_t chunks = aes_linear_chunks_per_ct(lwe_size);
  uint32_t num_out_blocks = num_bits * num_aes_inputs;

  device_aes_broadcast_bits<Torus>
      <<<num_out_blocks * chunks, AES_LINEAR_THREADS, 0, stream>>>(
          (Torus *)out->ptr, (const Torus *)src->ptr, num_aes_inputs, chunks,
          lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t bit = 0; bit < num_bits; ++bit)
    for (uint32_t input = 0; input < num_aes_inputs; ++input) {
      out->degrees[bit * num_aes_inputs + input] = src->degrees[bit];
      out->noise_levels[bit * num_aes_inputs + input] = src->noise_levels[bit];
    }
}

/**
 * AddRoundKey entry point, the only place the round keys are read.
 */
template <typename Torus>
__host__ void host_aes_add_round_key(cudaStream_t stream, uint32_t gpu_index,
                                     CudaRadixCiphertextFFI *state,
                                     const CudaRadixCiphertextFFI *round_key,
                                     uint32_t num_bits, uint32_t num_aes_inputs,
                                     uint32_t message_modulus,
                                     uint32_t carry_modulus) {

  if (state->num_radix_blocks < num_bits * num_aes_inputs ||
      round_key->num_radix_blocks < num_bits)
    PANIC("Cuda error: AddRoundKey operands have too few blocks")
  aes_check_disjoint_ranges<Torus>(state, num_bits * num_aes_inputs, round_key,
                                   num_bits, "AddRoundKey");

  cuda_set_device(gpu_index);
  uint32_t lwe_size = state->lwe_dimension + 1;
  uint32_t chunks = aes_linear_chunks_per_ct(lwe_size);
  uint32_t num_out_blocks = num_bits * num_aes_inputs;

  device_aes_add_broadcast_bits<Torus>
      <<<num_out_blocks * chunks, AES_LINEAR_THREADS, 0, stream>>>(
          (Torus *)state->ptr, (const Torus *)round_key->ptr, num_aes_inputs,
          chunks, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t bit = 0; bit < num_bits; ++bit)
    for (uint32_t input = 0; input < num_aes_inputs; ++input) {
      uint32_t o = bit * num_aes_inputs + input;
      state->degrees[o] += round_key->degrees[bit];
      state->noise_levels[o] += round_key->noise_levels[bit];
      CHECK_NOISE_LEVEL(state->noise_levels[o], message_modulus, carry_modulus);
    }
}

/**
 * Final transposition entry point. It is a pure permutation, so the
 * metadata moves with the blocks.
 */
template <typename Torus>
__host__ void
host_aes_bitsliced_to_blocks(cudaStream_t stream, uint32_t gpu_index,
                             CudaRadixCiphertextFFI *out,
                             const CudaRadixCiphertextFFI *in,
                             uint32_t num_bits, uint32_t num_aes_inputs) {

  if (out->num_radix_blocks < num_bits * num_aes_inputs ||
      in->num_radix_blocks < num_bits * num_aes_inputs)
    PANIC("Cuda error: AES transpose operands have too few blocks")
  aes_check_disjoint_ranges<Torus>(out, num_bits * num_aes_inputs, in,
                                   num_bits * num_aes_inputs, "AES transpose");

  cuda_set_device(gpu_index);
  uint32_t lwe_size = out->lwe_dimension + 1;
  uint32_t chunks = aes_linear_chunks_per_ct(lwe_size);
  uint32_t num_blocks = num_bits * num_aes_inputs;

  device_aes_bitsliced_to_blocks<Torus>
      <<<num_blocks * chunks, AES_LINEAR_THREADS, 0, stream>>>(
          (Torus *)out->ptr, (const Torus *)in->ptr, num_bits, num_aes_inputs,
          chunks, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t bit = 0; bit < num_bits; ++bit)
    for (uint32_t input = 0; input < num_aes_inputs; ++input) {
      uint32_t src = bit * num_aes_inputs + input;
      uint32_t dst = input * num_bits + bit;
      out->degrees[dst] = in->degrees[src];
      out->noise_levels[dst] = in->noise_levels[src];
    }
}

/**
 * Allocates everything one AES-CTR encryption needs and reports the
 * footprint, so the caller can lower the S-box parallelism until it fits.
 */
template <typename Torus>
uint64_t scratch_cuda_integer_aes_encrypt(
    CudaStreams streams, int_aes_encrypt_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_aes_encrypt_buffer<Torus>(
      streams, params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism,
      size_tracker);
  return size_tracker;
}

/**
 * Levelled XOR: no bootstrap, the noise adds up until the next flush.
 */
template <typename Torus>
__host__ __forceinline__ void
aes_xor(CudaStreams streams, int_aes_encrypt_buffer<Torus> *mem,
        CudaRadixCiphertextFFI *out, const CudaRadixCiphertextFFI *lhs,
        const CudaRadixCiphertextFFI *rhs) {

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), out, lhs, rhs,
                       out->num_radix_blocks, mem->params.message_modulus,
                       mem->params.carry_modulus);
}

/**
 * Bootstraps a vector back to clean bits, the expensive step the whole
 * file is arranged to call as rarely and as widely as possible.
 */
template <typename Torus, typename KSTorus>
__host__ __forceinline__ void
aes_flush_inplace(CudaStreams streams, CudaRadixCiphertextFFI *data,
                  int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
                  KSTorus *const *ksks) {

  integer_radix_apply_univariate_lookup_table<Torus>(streams, data, data, bsks,
                                                     ksks, mem->luts->state_lut,
                                                     data->num_radix_blocks);
}

/**
 * Gathers scattered wire vectors, flushes them in one bootstrap batch
 * through the given LUT slot, and scatters the results back. The resting
 * slot is restored, so shared LUTs are left as found.
 */
template <typename Torus, typename KSTorus>
__host__ void
batch_vec_flush_on_lut(CudaStreams streams, CudaRadixCiphertextFFI **targets,
                       size_t count, int_aes_encrypt_buffer<Torus> *mem,
                       int_radix_lut<Torus> *lut, uint32_t flush_slot,
                       uint32_t resting_slot, void *const *bsks,
                       KSTorus *const *ksks) {

  PANIC_IF_FALSE(count > 0, "flush batch needs at least one target");
  uint32_t num_radix_blocks = targets[0]->num_radix_blocks;
  for (size_t i = 1; i < count; ++i)
    PANIC_IF_FALSE(targets[i]->num_radix_blocks == num_radix_blocks,
                   "flush batch targets must all span the same block count");
  PANIC_IF_FALSE(count * num_radix_blocks <= lut->num_blocks,
                 "flush batch exceeds the LUT capacity");
  PANIC_IF_FALSE(
      2 * count * num_radix_blocks <=
          mem->main_workspaces->batch_processing_buffer->num_radix_blocks,
      "flush batch exceeds the staging buffer capacity");

  CudaRadixCiphertextFFI batch_in, batch_out;
  as_radix_ciphertext_slice<Torus>(
      &batch_in, mem->main_workspaces->batch_processing_buffer, 0,
      count * num_radix_blocks);
  as_radix_ciphertext_slice<Torus>(
      &batch_out, mem->main_workspaces->batch_processing_buffer,
      count * num_radix_blocks, (2 * count) * num_radix_blocks);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI dest_slice;
    as_radix_ciphertext_slice<Torus>(&dest_slice, &batch_in,
                                     i * num_radix_blocks,
                                     (i + 1) * num_radix_blocks);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_slice, targets[i]);
  }

  const bool switch_slot = (flush_slot != resting_slot);
  auto lut_streams =
      streams.active_gpu_subset(lut->num_blocks, mem->params.pbs_type);
  if (switch_slot)
    lut->set_lut_indexes_and_broadcast_constant(lut_streams, flush_slot);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &batch_out, &batch_in, bsks, ksks, lut,
      batch_out.num_radix_blocks);
  if (switch_slot)
    lut->set_lut_indexes_and_broadcast_constant(lut_streams, resting_slot);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI src_slice;
    as_radix_ciphertext_slice<Torus>(&src_slice, &batch_out,
                                     i * num_radix_blocks,
                                     (i + 1) * num_radix_blocks);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       targets[i], &src_slice);
  }
}

/**
 * Ordinary flush batch, on state_lut which already rests on the flush.
 */
template <typename Torus, typename KSTorus>
__host__ __forceinline__ void
batch_vec_flush_inplace(CudaStreams streams, CudaRadixCiphertextFFI **targets,
                        size_t count, int_aes_encrypt_buffer<Torus> *mem,
                        void *const *bsks, KSTorus *const *ksks) {

  batch_vec_flush_on_lut<Torus>(streams, targets, count, mem,
                                mem->luts->state_lut, AES_LUT_FLUSH,
                                AES_LUT_FLUSH, bsks, ksks);
}

/**
 * Flush batches wider than the 128-block state_lut, riding and_lut and
 * its 18 * parallelism capacity.
 */
template <typename Torus, typename KSTorus>
__host__ __forceinline__ void
batch_vec_flush_wide_inplace(CudaStreams streams,
                             CudaRadixCiphertextFFI **targets, size_t count,
                             int_aes_encrypt_buffer<Torus> *mem,
                             void *const *bsks, KSTorus *const *ksks) {

  batch_vec_flush_on_lut<Torus>(streams, targets, count, mem,
                                mem->luts->and_lut, AES_ANDLUT_FLUSH,
                                AES_ANDLUT_AND, bsks, ksks);
}

/**
 * All AND gates of one S-box layer in a single bootstrap batch. Each
 * AND is a univariate LUT on the levelled sum of two bit operands and
 * enters the PBS at noise 2. Array-reference parameters make the three
 * batch lengths match at compile time.
 */
template <typename Torus, typename KSTorus, size_t COUNT>
__host__ void batch_vec_and_inplace(CudaStreams streams,
                                    CudaRadixCiphertextFFI *(&outs)[COUNT],
                                    CudaRadixCiphertextFFI *(&lhs)[COUNT],
                                    CudaRadixCiphertextFFI *(&rhs)[COUNT],
                                    int_aes_encrypt_buffer<Torus> *mem,
                                    void *const *bsks, KSTorus *const *ksks) {

  constexpr size_t count = COUNT;
  uint32_t num_aes_inputs = outs[0]->num_radix_blocks;

  for (size_t i = 0; i < count; ++i)
    PANIC_IF_FALSE(outs[i]->num_radix_blocks == num_aes_inputs &&
                       lhs[i]->num_radix_blocks == num_aes_inputs &&
                       rhs[i]->num_radix_blocks == num_aes_inputs,
                   "AND batch operands must all span the same block count");
  PANIC_IF_FALSE(
      3 * count * num_aes_inputs <=
          mem->main_workspaces->batch_processing_buffer->num_radix_blocks,
      "AND batch exceeds the staging buffer capacity");

  for (size_t i = 0; i < count; ++i)
    for (uint32_t j = 0; j < lhs[i]->num_radix_blocks; ++j)
      PANIC_IF_FALSE(lhs[i]->degrees[j] <= 1 && rhs[i]->degrees[j] <= 1,
                     "AND operands must be bits (degree <= 1); flush the "
                     "wires feeding this gate first");

  CudaRadixCiphertextFFI batch_lhs, batch_rhs, batch_out;
  as_radix_ciphertext_slice<Torus>(
      &batch_lhs, mem->main_workspaces->batch_processing_buffer, 0,
      count * num_aes_inputs);
  as_radix_ciphertext_slice<Torus>(
      &batch_rhs, mem->main_workspaces->batch_processing_buffer,
      count * num_aes_inputs, (2 * count) * num_aes_inputs);
  as_radix_ciphertext_slice<Torus>(
      &batch_out, mem->main_workspaces->batch_processing_buffer,
      (2 * count) * num_aes_inputs, (3 * count) * num_aes_inputs);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI dest_lhs_slice, dest_rhs_slice;
    as_radix_ciphertext_slice<Torus>(&dest_lhs_slice, &batch_lhs,
                                     i * num_aes_inputs,
                                     (i + 1) * num_aes_inputs);
    as_radix_ciphertext_slice<Torus>(&dest_rhs_slice, &batch_rhs,
                                     i * num_aes_inputs,
                                     (i + 1) * num_aes_inputs);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_lhs_slice, lhs[i]);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_rhs_slice, rhs[i]);
  }

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &batch_out,
                       &batch_lhs, &batch_rhs, batch_out.num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &batch_out, &batch_out, bsks, ksks, mem->luts->and_lut,
      batch_out.num_radix_blocks);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI src_slice;
    as_radix_ciphertext_slice<Torus>(&src_slice, &batch_out, i * num_aes_inputs,
                                     (i + 1) * num_aes_inputs);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       outs[i], &src_slice);
  }
}

/**
 * SubBytes over num_bytes_parallel bytes at once, the critical path:
 * 15 bootstrap layers, flushing only where the noise budget forces it.
 * GPU tests check equivalence against plain AES end to end.
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_sbox_n_bytes(CudaStreams streams,
                                      CudaRadixCiphertextFFI *sbox_io_bytes,
                                      uint32_t num_bytes_parallel,
                                      uint32_t num_aes_inputs,
                                      int_aes_encrypt_buffer<Torus> *mem,
                                      void *const *bsks, KSTorus *const *ksks) {

  uint32_t num_sbox_blocks = num_bytes_parallel * num_aes_inputs;
  auto *tables = mem->linear_tables;
  PANIC_IF_FALSE(num_bytes_parallel * AES_BITS_PER_BYTE ==
                     tables->sbox_reorder_len,
                 "S-box called with a parallelism the index tables were not "
                 "built for");

  constexpr uint32_t INPUT_BITS_LEN = 8;
  constexpr uint32_t OUTPUT_BITS_LEN = 8;
  constexpr uint32_t WIRES_A_LEN = 22;
  constexpr uint32_t WIRES_B_LEN = 68;
  constexpr uint32_t WIRES_C_LEN = 18;

  static_assert(WIRES_A_LEN + WIRES_B_LEN + WIRES_C_LEN == AES_SBOX_WIRE_SLOTS,
                "S-box wire count must match the workspace sizing constant");
  static_assert(WIRES_C_LEN == AES_SBOX_AND_GATES,
                "the and_lut and the batch staging buffer are sized on the "
                "circuit's AND gate count");

  // Wire indices keep the published circuit's numbering. This schedule
  // absorbs wires_b[1] into its consumers, leaving that slot unused.
  // output_bits[0..7] below alias wires_a[0..7]: every wires_a read is
  // scheduled before the first output write (the last ones sit in the final
  // AND batch), so a wires_a read inserted after that batch would silently
  // observe output bits instead.
  CudaRadixCiphertextFFI wires_a[WIRES_A_LEN], wires_b[WIRES_B_LEN],
      wires_c[WIRES_C_LEN];

  for (uint32_t i = 0; i < WIRES_A_LEN; ++i)
    as_radix_ciphertext_slice<Torus>(
        &wires_a[i], mem->main_workspaces->sbox_internal_workspace,
        i * num_sbox_blocks, (i + 1) * num_sbox_blocks);
  for (uint32_t i = 0; i < WIRES_B_LEN; ++i)
    as_radix_ciphertext_slice<Torus>(
        &wires_b[i], mem->main_workspaces->sbox_internal_workspace,
        (WIRES_A_LEN + i) * num_sbox_blocks,
        (WIRES_A_LEN + i + 1) * num_sbox_blocks);
  for (uint32_t i = 0; i < WIRES_C_LEN; ++i)
    as_radix_ciphertext_slice<Torus>(
        &wires_c[i], mem->main_workspaces->sbox_internal_workspace,
        (WIRES_A_LEN + WIRES_B_LEN + i) * num_sbox_blocks,
        (WIRES_A_LEN + WIRES_B_LEN + i + 1) * num_sbox_blocks);

  CudaRadixCiphertextFFI *reordered_input_buffer =
      mem->main_workspaces->sbox_input_buffer;
  host_aes_linear_combination<Torus>(
      streams.stream(0), streams.gpu_index(0), reordered_input_buffer,
      sbox_io_bytes, tables->d_sbox_gather, tables->h_sbox_gather, 1,
      tables->sbox_reorder_len, num_aes_inputs, mem->params.message_modulus,
      mem->params.carry_modulus);

  CudaRadixCiphertextFFI input_bits[INPUT_BITS_LEN];
  for (uint32_t bit = 0; bit < INPUT_BITS_LEN; ++bit)
    as_radix_ciphertext_slice<Torus>(&input_bits[bit], reordered_input_buffer,
                                     bit * num_sbox_blocks,
                                     (bit + 1) * num_sbox_blocks);

#define XOR(out, a, b)                                                         \
  do {                                                                         \
    aes_xor<Torus>(streams, mem, out, a, b);                                   \
  } while (0)

#define FLUSH(...)                                                             \
  do {                                                                         \
    CudaRadixCiphertextFFI *targets[] = {__VA_ARGS__};                         \
    batch_vec_flush_inplace(streams, targets,                                  \
                            sizeof(targets) / sizeof(targets[0]), mem, bsks,   \
                            ksks);                                             \
  } while (0)

#define FLUSH_WIDE(...)                                                        \
  do {                                                                         \
    CudaRadixCiphertextFFI *targets[] = {__VA_ARGS__};                         \
    batch_vec_flush_wide_inplace(streams, targets,                             \
                                 sizeof(targets) / sizeof(targets[0]), mem,    \
                                 bsks, ksks);                                  \
  } while (0)

#define AND(outs, lhs, rhs)                                                    \
  do {                                                                         \
    batch_vec_and_inplace(streams, outs, lhs, rhs, mem, bsks, ksks);           \
  } while (0)

#define ADD_ONE(target)                                                        \
  do {                                                                         \
    host_add_scalar_one_inplace<Torus>(streams, target,                        \
                                       mem->params.message_modulus,            \
                                       mem->params.carry_modulus);             \
  } while (0)

  CudaRadixCiphertextFFI *tmp_i46 = &wires_b[46], *tmp_i25 = &wires_b[47],
                         *tmp_i15 = &wires_b[49], *tmp_i02 = &wires_b[50],
                         *tmp_i45 = &wires_b[51], *tmp_i13 = &wires_b[52];
  XOR(&wires_b[0], &input_bits[1], &input_bits[2]);
  XOR(tmp_i46, &input_bits[4], &input_bits[6]);
  XOR(tmp_i25, &input_bits[2], &input_bits[5]);
  XOR(tmp_i15, &input_bits[1], &input_bits[5]);
  XOR(tmp_i02, &input_bits[0], &input_bits[2]);
  XOR(tmp_i45, &input_bits[4], &input_bits[5]);
  XOR(&wires_a[14], &input_bits[3], &input_bits[5]);
  XOR(&wires_a[13], &input_bits[0], &input_bits[6]);
  XOR(&wires_a[9], &input_bits[0], &input_bits[3]);
  XOR(&wires_a[8], &input_bits[0], &input_bits[5]);
  XOR(&wires_a[1], &wires_b[0], &input_bits[7]);
  XOR(&wires_a[12], &wires_a[13], &wires_a[14]);
  XOR(&wires_a[4], &wires_a[1], &input_bits[3]);
  XOR(&wires_a[2], &wires_a[1], &input_bits[0]);
  XOR(&wires_a[5], &wires_a[1], &input_bits[6]);
  XOR(&wires_a[15], &wires_a[9], tmp_i46);
  XOR(&wires_a[6], &wires_a[15], &input_bits[7]);
  XOR(&wires_a[16], tmp_i46, tmp_i25);
  XOR(&wires_a[11], tmp_i46, tmp_i15);
  XOR(&wires_a[7], &wires_a[11], &input_bits[7]);
  XOR(&wires_a[17], &wires_a[9], tmp_i25);
  XOR(&wires_a[18], &wires_a[16], &input_bits[0]);
  XOR(&wires_a[21], tmp_i02, tmp_i45);
  FLUSH_WIDE(&wires_a[14], &wires_a[13], &wires_a[9], &wires_a[8], &wires_a[1],
             &wires_a[12], &wires_a[4], &wires_a[5], &wires_a[2], &wires_a[15],
             &wires_a[6], &wires_a[16], &wires_a[11], &wires_a[7], &wires_a[17],
             &wires_a[18], &wires_a[21]);
  XOR(&wires_a[3], &wires_a[5], &wires_a[8]);
  XOR(&wires_a[10], &wires_a[15], &wires_b[0]);
  XOR(tmp_i13, &input_bits[1], &input_bits[3]);
  XOR(&wires_a[19], &wires_a[16], tmp_i13);
  XOR(&wires_a[20], &wires_a[11], &wires_a[9]);
  FLUSH(&wires_a[3], &wires_a[10], &wires_a[19], &wires_a[20]);
  CudaRadixCiphertextFFI *and_outs_1[] = {
      &wires_b[2],  &wires_b[3],  &wires_b[5],  &wires_b[7], &wires_b[8],
      &wires_b[10], &wires_b[12], &wires_b[13], &wires_b[15]};
  CudaRadixCiphertextFFI *and_lhs_1[] = {
      &wires_a[15], &wires_a[3], &input_bits[7], &wires_a[13], &wires_a[1],
      &wires_a[2],  &wires_a[9], &wires_a[14],   &wires_a[8]};
  CudaRadixCiphertextFFI *and_rhs_1[] = {
      &wires_a[12], &wires_a[6],  &wires_a[4],  &wires_a[16], &wires_a[5],
      &wires_a[7],  &wires_a[11], &wires_a[17], &wires_a[10]};
  AND(and_outs_1, and_lhs_1, and_rhs_1);
  XOR(&wires_b[4], &wires_b[3], &wires_b[2]);
  XOR(&wires_b[6], &wires_b[5], &wires_b[2]);
  XOR(&wires_b[9], &wires_b[8], &wires_b[7]);
  XOR(&wires_b[11], &wires_b[10], &wires_b[7]);
  XOR(&wires_b[14], &wires_b[13], &wires_b[12]);
  XOR(&wires_b[16], &wires_b[15], &wires_b[12]);
  XOR(&wires_b[17], &wires_b[4], &wires_b[14]);
  XOR(&wires_b[18], &wires_b[6], &wires_b[16]);
  XOR(&wires_b[19], &wires_b[9], &wires_b[14]);
  XOR(&wires_b[20], &wires_b[11], &wires_b[16]);
  XOR(&wires_b[21], &wires_b[17], &wires_a[20]);
  XOR(&wires_b[22], &wires_b[18], &wires_a[19]);
  XOR(&wires_b[23], &wires_b[19], &wires_a[21]);
  XOR(&wires_b[24], &wires_b[20], &wires_a[18]);
  FLUSH(&wires_b[21], &wires_b[22], &wires_b[23], &wires_b[24]);
  XOR(&wires_b[25], &wires_b[21], &wires_b[22]);
  CudaRadixCiphertextFFI *and_outs_2[] = {&wires_b[26]};
  CudaRadixCiphertextFFI *and_lhs_2[] = {&wires_b[21]};
  CudaRadixCiphertextFFI *and_rhs_2[] = {&wires_b[23]};
  AND(and_outs_2, and_lhs_2, and_rhs_2);
  XOR(&wires_b[27], &wires_b[24], &wires_b[26]);
  XOR(&wires_b[30], &wires_b[23], &wires_b[24]);
  XOR(&wires_b[31], &wires_b[22], &wires_b[26]);
  FLUSH(&wires_b[25], &wires_b[27], &wires_b[30], &wires_b[31]);

  CudaRadixCiphertextFFI *and_outs_3[] = {&wires_b[28], &wires_b[32]};
  CudaRadixCiphertextFFI *and_lhs_3[] = {&wires_b[25], &wires_b[30]};
  CudaRadixCiphertextFFI *and_rhs_3[] = {&wires_b[27], &wires_b[31]};
  AND(and_outs_3, and_lhs_3, and_rhs_3);
  XOR(&wires_b[29], &wires_b[28], &wires_b[22]);
  XOR(&wires_b[33], &wires_b[32], &wires_b[24]);
  XOR(&wires_b[42], &wires_b[29], &wires_b[33]);
  XOR(&wires_b[34], &wires_b[23], &wires_b[33]);
  XOR(&wires_b[35], &wires_b[27], &wires_b[33]);
  FLUSH(&wires_b[35], &wires_b[29], &wires_b[42], &wires_b[33]);
  CudaRadixCiphertextFFI *and_outs_5[] = {&wires_b[36]};
  CudaRadixCiphertextFFI *and_lhs_5[] = {&wires_b[24]};
  CudaRadixCiphertextFFI *and_rhs_5[] = {&wires_b[35]};
  AND(and_outs_5, and_lhs_5, and_rhs_5);
  XOR(&wires_b[37], &wires_b[36], &wires_b[34]);
  XOR(&wires_b[38], &wires_b[27], &wires_b[36]);

  XOR(&wires_b[44], &wires_b[36], &wires_b[23]);
  FLUSH(&wires_b[37], &wires_b[38], &wires_b[44]);
  CudaRadixCiphertextFFI *and_outs_6[] = {&wires_b[39]};
  CudaRadixCiphertextFFI *and_lhs_6[] = {&wires_b[38]};
  CudaRadixCiphertextFFI *and_rhs_6[] = {&wires_b[29]};
  AND(and_outs_6, and_lhs_6, and_rhs_6);
  XOR(&wires_b[40], &wires_b[25], &wires_b[39]);
  XOR(&wires_b[41], &wires_b[40], &wires_b[37]);
  XOR(&wires_b[43], &wires_b[29], &wires_b[40]);
  XOR(&wires_b[45], &wires_b[42], &wires_b[41]);
  FLUSH(&wires_b[40], &wires_b[41], &wires_b[43], &wires_b[45]);
  CudaRadixCiphertextFFI *and_outs_7[] = {
      &wires_c[0],  &wires_c[1],  &wires_c[2],  &wires_c[3],  &wires_c[4],
      &wires_c[5],  &wires_c[6],  &wires_c[7],  &wires_c[8],  &wires_c[9],
      &wires_c[10], &wires_c[11], &wires_c[12], &wires_c[13], &wires_c[14],
      &wires_c[15], &wires_c[16], &wires_c[17]};
  CudaRadixCiphertextFFI *and_lhs_7[] = {
      &wires_a[15], &wires_a[6],  &wires_b[33], &wires_a[16], &wires_a[1],
      &wires_b[29], &wires_b[42], &wires_a[17], &wires_a[10], &wires_a[12],
      &wires_a[3],  &wires_b[33], &wires_a[13], &wires_a[5],  &wires_b[29],
      &wires_b[42], &wires_b[45], &wires_b[41]};
  CudaRadixCiphertextFFI *and_rhs_7[] = {
      &wires_b[44], &wires_b[37], &input_bits[7], &wires_b[43], &wires_b[40],
      &wires_a[7],  &wires_a[11], &wires_b[45],   &wires_b[41], &wires_b[44],
      &wires_b[37], &wires_a[4],  &wires_b[43],   &wires_b[40], &wires_a[2],
      &wires_a[9],  &wires_a[14], &wires_a[8]};
  AND(and_outs_7, and_lhs_7, and_rhs_7);

  XOR(&wires_b[46], &wires_c[15], &wires_c[16]);
  XOR(&wires_b[47], &wires_c[10], &wires_c[11]);
  XOR(&wires_b[48], &wires_c[5], &wires_c[13]);
  XOR(&wires_b[49], &wires_c[9], &wires_c[10]);
  XOR(&wires_b[50], &wires_c[2], &wires_c[12]);
  XOR(&wires_b[51], &wires_c[2], &wires_c[5]);
  XOR(&wires_b[52], &wires_c[7], &wires_c[8]);
  XOR(&wires_b[53], &wires_c[0], &wires_c[3]);
  XOR(&wires_b[54], &wires_c[6], &wires_c[7]);
  XOR(&wires_b[55], &wires_c[16], &wires_c[17]);
  XOR(&wires_b[57], &wires_b[50], &wires_b[53]);
  XOR(&wires_b[58], &wires_c[4], &wires_b[46]);
  XOR(&wires_b[59], &wires_c[3], &wires_b[54]);
  XOR(&wires_b[61], &wires_c[14], &wires_b[57]);
  XOR(&wires_b[62], &wires_b[52], &wires_b[58]);
  XOR(&wires_b[63], &wires_b[49], &wires_b[58]);
  XOR(&wires_b[64], &wires_c[4], &wires_b[59]);
  FLUSH(&wires_b[57], &wires_b[61], &wires_b[62], &wires_b[63], &wires_b[64],
        &wires_b[46], &wires_b[48]);
  XOR(&wires_b[56], &wires_c[12], &wires_b[48]);
  XOR(&wires_b[60], &wires_b[48], &wires_b[46]);
  XOR(&wires_b[65], &wires_b[61], &wires_b[62]);
  XOR(&wires_b[66], &wires_c[1], &wires_b[63]);

  CudaRadixCiphertextFFI output_bits[OUTPUT_BITS_LEN];
  for (uint32_t i = 0; i < OUTPUT_BITS_LEN; i++)
    as_radix_ciphertext_slice<Torus>(
        &output_bits[i], mem->main_workspaces->sbox_internal_workspace,
        i * num_sbox_blocks, (i + 1) * num_sbox_blocks);

  XOR(&output_bits[0], &wires_b[59], &wires_b[63]);
  XOR(&wires_b[67], &wires_b[64], &wires_b[65]);
  XOR(&output_bits[3], &wires_b[53], &wires_b[66]);
  XOR(&output_bits[4], &wires_b[51], &wires_b[66]);
  XOR(&output_bits[5], &wires_b[47], &wires_b[65]);
  XOR(&output_bits[6], &wires_b[56], &wires_b[62]);
  ADD_ONE(&output_bits[6]);
  XOR(&output_bits[7], &wires_b[60], &wires_b[57]);
  ADD_ONE(&output_bits[7]);
  XOR(&output_bits[1], &wires_b[64], &output_bits[3]);
  ADD_ONE(&output_bits[1]);
  XOR(&output_bits[2], &wires_b[55], &wires_b[67]);
  ADD_ONE(&output_bits[2]);
  FLUSH(&output_bits[0], &output_bits[3], &output_bits[4], &output_bits[5],
        &output_bits[6], &output_bits[7], &output_bits[1], &output_bits[2]);

  CudaRadixCiphertextFFI sbox_output_region;
  as_radix_ciphertext_slice<Torus>(
      &sbox_output_region, mem->main_workspaces->sbox_internal_workspace, 0,
      OUTPUT_BITS_LEN * num_sbox_blocks);
  host_aes_linear_combination<Torus>(
      streams.stream(0), streams.gpu_index(0), sbox_io_bytes,
      &sbox_output_region, tables->d_sbox_scatter, tables->h_sbox_scatter, 1,
      tables->sbox_reorder_len, num_aes_inputs, mem->params.message_modulus,
      mem->params.carry_modulus);

#undef XOR
#undef FLUSH
#undef FLUSH_WIDE
#undef AND
#undef ADD_ONE
}

/**
 * ShiftRows, written straight into the MixColumns workspace, its only
 * consumer.
 */
template <typename Torus>
__host__ void vectorized_shift_rows(CudaStreams streams,
                                    CudaRadixCiphertextFFI *dest,
                                    const CudaRadixCiphertextFFI *state,
                                    uint32_t num_aes_inputs,
                                    int_aes_encrypt_buffer<Torus> *mem) {

  auto *tables = mem->linear_tables;
  host_aes_linear_combination<Torus>(
      streams.stream(0), streams.gpu_index(0), dest, state,
      tables->d_shift_rows, tables->h_shift_rows, 1, AES_STATE_BITS,
      num_aes_inputs, mem->params.message_modulus, mem->params.carry_modulus);
}

/**
 * MixColumns over the whole state in one pass: reads [shifted | xtime of
 * shifted] from its workspace and costs a single bootstrap per round.
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_mix_columns(CudaStreams streams,
                                     CudaRadixCiphertextFFI *state,
                                     const CudaRadixCiphertextFFI *shifted,
                                     uint32_t num_aes_inputs,
                                     int_aes_encrypt_buffer<Torus> *mem,
                                     void *const *bsks, KSTorus *const *ksks) {

  constexpr uint32_t STATE_BITS = AES_STATE_BITS;
  const uint32_t half = STATE_BITS * num_aes_inputs;
  auto *tables = mem->linear_tables;
  CudaRadixCiphertextFFI *workspace =
      mem->round_workspaces->mix_columns_workspace;

  PANIC_IF_FALSE(shifted->ptr == workspace->ptr &&
                     shifted->num_radix_blocks == half,
                 "MixColumns reads its input from the first half of "
                 "mix_columns_workspace: pass the slice ShiftRows wrote");

  CudaRadixCiphertextFFI xtime;
  as_radix_ciphertext_slice<Torus>(&xtime, workspace, half, 2 * half);

  host_aes_linear_combination<Torus>(
      streams.stream(0), streams.gpu_index(0), &xtime, shifted, tables->d_xtime,
      tables->h_xtime, int_aes_linear_tables::XTIME_TERMS, STATE_BITS,
      num_aes_inputs, mem->params.message_modulus, mem->params.carry_modulus);

  aes_flush_inplace<Torus>(streams, &xtime, mem, bsks, ksks);

  host_aes_linear_combination<Torus>(
      streams.stream(0), streams.gpu_index(0), state, workspace,
      tables->d_mix_columns, tables->h_mix_columns,
      int_aes_linear_tables::MIX_COLUMNS_TERMS, STATE_BITS, num_aes_inputs,
      mem->params.message_modulus, mem->params.carry_modulus);
}

/**
 * The round function shared by AES-128 and AES-256, which differ only in
 * round count and in how their round keys were derived.
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_aes_rounds_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *all_states_bitsliced,
    CudaRadixCiphertextFFI const *round_keys, uint32_t num_rounds,
    uint32_t num_aes_inputs, int_aes_encrypt_buffer<Torus> *mem,
    void *const *bsks, KSTorus *const *ksks) {

  constexpr uint32_t BITS_PER_BYTE = AES_BITS_PER_BYTE;
  constexpr uint32_t STATE_BYTES = AES_STATE_BYTES;
  constexpr uint32_t STATE_BITS = AES_STATE_BITS;

  const uint32_t sbox_parallelism = mem->sbox_parallel_instances;
  PANIC_IF_FALSE(sbox_parallelism > 0 && STATE_BYTES % sbox_parallelism == 0,
                 "S-Box parallelism must divide the 16 bytes of the state");

  PANIC_IF_FALSE(round_keys->num_radix_blocks >= (num_rounds + 1) * STATE_BITS,
                 "AES rounds need num_rounds + 1 round keys of 128 bits");

  auto add_round_key = [&](uint32_t round) {
    CudaRadixCiphertextFFI key;
    as_radix_ciphertext_slice<Torus>(&key, (CudaRadixCiphertextFFI *)round_keys,
                                     round * STATE_BITS,
                                     (round + 1) * STATE_BITS);
    host_aes_add_round_key<Torus>(streams.stream(0), streams.gpu_index(0),
                                  all_states_bitsliced, &key, STATE_BITS,
                                  num_aes_inputs, mem->params.message_modulus,
                                  mem->params.carry_modulus);
  };

  add_round_key(0);
  aes_flush_inplace<Torus>(streams, all_states_bitsliced, mem, bsks, ksks);

  CudaRadixCiphertextFFI shifted;
  as_radix_ciphertext_slice<Torus>(&shifted,
                                   mem->round_workspaces->mix_columns_workspace,
                                   0, STATE_BITS * num_aes_inputs);

  for (uint32_t round = 1; round <= num_rounds; ++round) {
    for (uint32_t byte = 0; byte < STATE_BYTES; byte += sbox_parallelism) {
      CudaRadixCiphertextFFI chunk;
      as_radix_ciphertext_slice<Torus>(
          &chunk, all_states_bitsliced, byte * BITS_PER_BYTE * num_aes_inputs,
          (byte + sbox_parallelism) * BITS_PER_BYTE * num_aes_inputs);
      vectorized_sbox_n_bytes<Torus>(streams, &chunk, sbox_parallelism,
                                     num_aes_inputs, mem, bsks, ksks);
    }

    vectorized_shift_rows<Torus>(streams, &shifted, all_states_bitsliced,
                                 num_aes_inputs, mem);

    if (round != num_rounds) {
      vectorized_mix_columns<Torus>(streams, all_states_bitsliced, &shifted,
                                    num_aes_inputs, mem, bsks, ksks);
      aes_flush_inplace<Torus>(streams, all_states_bitsliced, mem, bsks, ksks);
    } else {
      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0),
                                         all_states_bitsliced, &shifted);
    }

    add_round_key(round);
    aes_flush_inplace<Torus>(streams, all_states_bitsliced, mem, bsks, ksks);
  }
}

/**
 * Adds the plaintext counter to the encrypted IV: a Kogge-Stone prefix
 * over a 3-valued kill/generate/propagate symbol, 9 bootstrap launches on
 * the full state instead of 128 dependent ripple-carry steps.
 */
template <typename Torus, typename KSTorus>
__host__ void vectorized_aes_add_counter_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *transposed_states,
    const Torus *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {

  constexpr uint32_t NUM_BITS = AES_STATE_BITS;
  const uint32_t num_blocks = NUM_BITS * num_aes_inputs;

  Torus *h_bits = mem->counter_workspaces->h_counter_bits_buffer;
  for (uint32_t j = 0; j < NUM_BITS; ++j) {
    const uint32_t bit = NUM_BITS - 1 - j;
    for (uint32_t block = 0; block < num_aes_inputs; ++block) {
      h_bits[j * num_aes_inputs + block] =
          counter_bits_le_all_blocks[block * NUM_BITS + bit];
    }
  }

  CudaRadixCiphertextFFI symbols_0, symbols, staging;
  as_radix_ciphertext_slice<Torus>(
      &symbols_0, mem->main_workspaces->ctr_adder_workspace, 0, num_blocks);
  as_radix_ciphertext_slice<Torus>(
      &symbols, mem->main_workspaces->sbox_input_buffer, 0, num_blocks);
  as_radix_ciphertext_slice<Torus>(
      &staging, mem->main_workspaces->sbox_internal_workspace, 0, num_blocks);

  int_radix_lut<Torus> *lut = mem->luts->state_lut;
  auto lut_streams =
      streams.active_gpu_subset(lut->num_blocks, mem->params.pbs_type);

  cuda_memcpy_async_to_gpu(mem->counter_workspaces->d_counter_bits_buffer,
                           h_bits, safe_mul_sizeof<Torus>(num_blocks),
                           streams.stream(0), streams.gpu_index(0));
  set_trivial_radix_ciphertext_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &staging,
      mem->counter_workspaces->d_counter_bits_buffer, h_bits, num_blocks,
      mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &staging,
                       transposed_states, &staging, num_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  lut->set_lut_indexes_and_broadcast_constant(lut_streams, AES_LUT_CTR_KGP);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &symbols_0, &staging, bsks, ksks, lut, num_blocks);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &symbols, &symbols_0);
  lut->set_lut_indexes_and_broadcast_constant(lut_streams, AES_LUT_CTR_SELECT);
  for (uint32_t d = 1; d < NUM_BITS; d <<= 1) {
    const uint32_t active = (NUM_BITS - d) * num_aes_inputs;
    CudaRadixCiphertextFFI higher, lower;
    as_radix_ciphertext_slice<Torus>(&higher, &symbols, 0, active);
    as_radix_ciphertext_slice<Torus>(&lower, &symbols, d * num_aes_inputs,
                                     num_blocks);
    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &higher, &higher, &lower, bsks, ksks, lut, active,
        mem->params.message_modulus);
  }

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &staging, 0,
      (NUM_BITS - 1) * num_aes_inputs, &symbols, num_aes_inputs, num_blocks);
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &staging,
      (NUM_BITS - 1) * num_aes_inputs, num_blocks);
  lut->set_lut_indexes_and_broadcast_constant(lut_streams, AES_LUT_CTR_SUM);
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, transposed_states, &symbols_0, &staging, bsks, ksks, lut,
      num_blocks, mem->params.message_modulus);

  lut->set_lut_indexes_and_broadcast_constant(lut_streams, AES_LUT_FLUSH);
}

/**
 * AES-128-CTR entry point: broadcast the IV, add the counter, run 10
 * rounds, hand the keystream back in block order.
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_aes_ctr_encrypt(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const Torus *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {

  constexpr uint32_t NUM_BITS = AES_STATE_BITS;
  constexpr uint32_t ROUNDS = 10;

  PANIC_IF_FALSE(mem->main_workspaces->main_bitsliced_states_buffer != nullptr,
                 "AES CTR encryption requires a buffer allocated with the "
                 "FULL_ENCRYPTION scope, got a SBOX_ONLY one");

  CudaRadixCiphertextFFI *transposed_states =
      mem->main_workspaces->main_bitsliced_states_buffer;

  host_aes_broadcast_bits<Torus>(streams.stream(0), streams.gpu_index(0),
                                 transposed_states, iv, NUM_BITS,
                                 num_aes_inputs);

  vectorized_aes_add_counter_inplace<Torus>(streams, transposed_states,
                                            counter_bits_le_all_blocks,
                                            num_aes_inputs, mem, bsks, ksks);

  vectorized_aes_rounds_inplace<Torus>(streams, transposed_states, round_keys,
                                       ROUNDS, num_aes_inputs, mem, bsks, ksks);

  host_aes_bitsliced_to_blocks<Torus>(streams.stream(0), streams.gpu_index(0),
                                      output, transposed_states, NUM_BITS,
                                      num_aes_inputs);
}

/**
 * Allocates the key schedule state, including its embedded S-box-only
 * encrypt buffer.
 */
template <typename Torus>
uint64_t scratch_cuda_integer_key_expansion(
    CudaStreams streams, int_key_expansion_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_key_expansion_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/**
 * Expands the encrypted key into round keys, 44 words from 4 for AES-128
 * and 60 from 8 for AES-256. Each word depends on the previous one, so
 * the schedule is inherently serial. The rcon add stays levelled and is
 * absorbed by the end-of-word flush.
 */
template <typename Torus, typename KSTorus, uint32_t TOTAL_WORDS,
          uint32_t KEY_WORDS>
__host__ void host_integer_key_expansion_generic(
    CudaStreams streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key,
    int_key_expansion_generic_buffer<Torus, TOTAL_WORDS, KEY_WORDS> *mem,
    void *const *bsks, KSTorus *const *ksks) {

  constexpr uint32_t BITS_PER_WORD = 32;
  constexpr uint32_t BITS_PER_BYTE = 8;
  constexpr uint32_t BYTES_PER_WORD = 4;

  const Torus rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10,
                        0x20, 0x40, 0x80, 0x1b, 0x36};

  CudaRadixCiphertextFFI *words = mem->words_buffer;

  CudaRadixCiphertextFFI initial_key_dest_slice;
  as_radix_ciphertext_slice<Torus>(&initial_key_dest_slice, words, 0,
                                   KEY_WORDS * BITS_PER_WORD);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &initial_key_dest_slice, key);

  // The embedded state_lut spans 128 blocks, so the initial key bits are
  // flushed by chunks of that width: one chunk for AES-128, two for AES-256.
  constexpr uint32_t KEY_FLUSH_CHUNK = 128;
  static_assert((KEY_WORDS * BITS_PER_WORD) % KEY_FLUSH_CHUNK == 0,
                "the initial key must split into whole flush chunks");
  for (uint32_t start = 0; start < KEY_WORDS * BITS_PER_WORD;
       start += KEY_FLUSH_CHUNK) {
    CudaRadixCiphertextFFI key_chunk;
    as_radix_ciphertext_slice<Torus>(&key_chunk, words, start,
                                     start + KEY_FLUSH_CHUNK);
    aes_flush_inplace(streams, &key_chunk, mem->aes_encrypt_buffer, bsks, ksks);
  }

  for (uint32_t w = KEY_WORDS; w < TOTAL_WORDS; ++w) {
    CudaRadixCiphertextFFI tmp_word_buffer, tmp_far, tmp_near;

    as_radix_ciphertext_slice<Torus>(&tmp_word_buffer, mem->tmp_word_buffer, 0,
                                     BITS_PER_WORD);
    as_radix_ciphertext_slice<Torus>(&tmp_far, words,
                                     (w - KEY_WORDS) * BITS_PER_WORD,
                                     (w - KEY_WORDS + 1) * BITS_PER_WORD);
    as_radix_ciphertext_slice<Torus>(&tmp_near, words, (w - 1) * BITS_PER_WORD,
                                     w * BITS_PER_WORD);

    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &tmp_word_buffer, &tmp_near);

    if (w % KEY_WORDS == 0) {
      CudaRadixCiphertextFFI rotated_word_buffer;
      as_radix_ciphertext_slice<Torus>(
          &rotated_word_buffer, mem->tmp_rotated_word_buffer, 0, BITS_PER_WORD);

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &rotated_word_buffer, 0,
          BITS_PER_WORD - BITS_PER_BYTE, &tmp_word_buffer, BITS_PER_BYTE,
          BITS_PER_WORD);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &rotated_word_buffer,
          BITS_PER_WORD - BITS_PER_BYTE, BITS_PER_WORD, &tmp_word_buffer, 0,
          BITS_PER_BYTE);

      vectorized_sbox_n_bytes<Torus>(streams, &rotated_word_buffer,
                                     BYTES_PER_WORD, 1, mem->aes_encrypt_buffer,
                                     bsks, ksks);

      Torus rcon_val = rcon[w / KEY_WORDS - 1];
      for (uint32_t bit = 0; bit < BITS_PER_BYTE; ++bit) {
        if ((rcon_val >> (7 - bit)) & 1) {
          CudaRadixCiphertextFFI first_byte_bit_slice;
          as_radix_ciphertext_slice<Torus>(&first_byte_bit_slice,
                                           &rotated_word_buffer, bit, bit + 1);
          host_add_scalar_one_inplace<Torus>(streams, &first_byte_bit_slice,
                                             mem->params.message_modulus,
                                             mem->params.carry_modulus);
        }
      }

      copy_radix_ciphertext_async<Torus>(streams.stream(0),
                                         streams.gpu_index(0), &tmp_word_buffer,
                                         &rotated_word_buffer);
    } else if (KEY_WORDS == 8 && w % KEY_WORDS == 4) {
      vectorized_sbox_n_bytes<Torus>(streams, &tmp_word_buffer, BYTES_PER_WORD,
                                     1, mem->aes_encrypt_buffer, bsks, ksks);
    }

    aes_xor(streams, mem->aes_encrypt_buffer, &tmp_word_buffer, &tmp_far,
            &tmp_word_buffer);
    aes_flush_inplace(streams, &tmp_word_buffer, mem->aes_encrypt_buffer, bsks,
                      ksks);

    CudaRadixCiphertextFFI dest_word;
    as_radix_ciphertext_slice<Torus>(&dest_word, words, w * BITS_PER_WORD,
                                     (w + 1) * BITS_PER_WORD);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       &dest_word, &tmp_word_buffer);
  }

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     expanded_keys, words);
}

/**
 * AES-128 key expansion entry point: 11 round keys from a 128-bit key.
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_key_expansion(CudaStreams streams,
                                         CudaRadixCiphertextFFI *expanded_keys,
                                         CudaRadixCiphertextFFI const *key,
                                         int_key_expansion_buffer<Torus> *mem,
                                         void *const *bsks,
                                         KSTorus *const *ksks) {
  host_integer_key_expansion_generic(streams, expanded_keys, key, mem, bsks,
                                     ksks);
}

#endif
