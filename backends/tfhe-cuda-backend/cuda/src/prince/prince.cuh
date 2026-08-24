#ifndef PRINCE_CUH
#define PRINCE_CUH

#include "../../include/prince/prince_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"

/* Homomorphic PRINCEv2, nibble-radix design (GPU port of apps/princev2):
 * one PBS launch per LUT layer over the whole batch, one levelled kernel
 * launch per permutation / bit recombination. */

// out[o] = sum_{t < num_terms} in[indexes[o * num_terms + t]]
template <typename Torus>
__global__ void device_prince_gather_sum(Torus *out, const Torus *in,
                                         const uint32_t *indexes,
                                         uint32_t num_terms, uint32_t lwe_size,
                                         uint32_t num_out_blocks) {
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_out_blocks * lwe_size) {
    uint32_t block = tid / lwe_size;
    uint32_t coeff = tid % lwe_size;
    Torus acc = 0;
    for (uint32_t t = 0; t < num_terms; ++t)
      acc += in[(size_t)indexes[block * num_terms + t] * lwe_size + coeff];
    out[(size_t)block * lwe_size + coeff] = acc;
  }
}

// Every permutation and bit recombination of the circuit, without PBS.
// `out` must not alias `in`.
template <typename Torus>
__host__ void host_prince_gather_sum(CudaStreams streams,
                                     const int_radix_params &params,
                                     CudaRadixCiphertextFFI *out,
                                     CudaRadixCiphertextFFI const *in,
                                     const prince_gather_map &map) {
  PANIC_IF_FALSE(out->ptr != in->ptr,
                 "prince gather_sum does not support in-place operation");
  PANIC_IF_FALSE(out->lwe_dimension == in->lwe_dimension,
                 "prince gather_sum: input and output radix ciphertexts "
                 "should have the same lwe dimension");
  PANIC_IF_FALSE(out->num_radix_blocks >= map.num_out_blocks,
                 "prince gather_sum: output has too few radix blocks");

  cuda_set_device(streams.gpu_index(0));
  uint32_t lwe_size = out->lwe_dimension + 1;
  uint64_t num_entries_u64 = (uint64_t)map.num_out_blocks * lwe_size;
  PANIC_IF_FALSE(num_entries_u64 <= (uint64_t)INT32_MAX,
                 "prince gather_sum: batch too large for a single launch");
  int num_blocks = 0, num_threads = 0;
  int num_entries = (int)num_entries_u64;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  device_prince_gather_sum<Torus>
      <<<num_blocks, num_threads, 0, streams.stream(0)>>>(
          static_cast<Torus *>(out->ptr), static_cast<const Torus *>(in->ptr),
          map.d, map.num_terms, lwe_size, map.num_out_blocks);
  check_cuda_error(cudaGetLastError());

  for (uint32_t o = 0; o < map.num_out_blocks; ++o) {
    uint64_t degree = 0, noise = 0;
    for (uint32_t t = 0; t < map.num_terms; ++t) {
      uint32_t src = map.h[o * map.num_terms + t];
      degree += in->degrees[src];
      noise += in->noise_levels[src];
    }
    out->degrees[o] = degree;
    out->noise_levels[o] = noise;
    CHECK_NOISE_LEVEL(out->noise_levels[o], params.message_modulus,
                      params.carry_modulus);
  }
}

// Switches a multi-slot LUT to the next layer's index pattern
template <typename Torus>
__host__ void prince_use_pattern(CudaStreams streams,
                                 const int_radix_params &params,
                                 int_radix_lut<Torus> *lut,
                                 const prince_lut_pattern<Torus> &pat) {
  memcpy(lut->h_lut_indexes, pat.h,
         safe_mul_sizeof<Torus>((size_t)lut->num_blocks));
  auto active_streams =
      streams.active_gpu_subset(lut->num_blocks, params.pbs_type);
  lut->set_lut_indexes_and_broadcast_from_gpu(active_streams, pat.d,
                                              lut->num_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_prince_key_prep(
    CudaStreams streams, int_prince_key_prep_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_prince_key_prep_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

// Once per key pair and direction: the key bits and 3-bit key parities
// (kappa) the fused e-xor layers absorb levelled. Lane-free. Synchronous.
template <typename Torus>
__host__ void host_integer_prince_key_prep(
    CudaStreams streams, CudaRadixCiphertextFFI *key_bits_first,
    CudaRadixCiphertextFFI *key_bits_second,
    CudaRadixCiphertextFFI *kap_bw_first, CudaRadixCiphertextFFI *kap_bw_second,
    CudaRadixCiphertextFFI *kap_mid_first, CudaRadixCiphertextFFI const *k0,
    CudaRadixCiphertextFFI const *k1, bool is_decrypt,
    int_prince_key_prep_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks) {
  using namespace prince_v2;
  PANIC_IF_FALSE(k0->num_radix_blocks == NUM_U2 &&
                     k1->num_radix_blocks == NUM_U2,
                 "PRINCE keys should have 32 blocks");
  for (auto *out : {key_bits_first, key_bits_second, kap_bw_first,
                    kap_bw_second, kap_mid_first})
    PANIC_IF_FALSE(out->num_radix_blocks == NUM_BITS,
                   "PRINCE prepared key buffers should have 64 blocks");

  CudaRadixCiphertextFFI const *first = is_decrypt ? k1 : k0;
  CudaRadixCiphertextFFI const *second = is_decrypt ? k0 : k1;
  auto active_streams =
      streams.active_gpu_subset(NUM_BITS, mem->params.pbs_type);

  auto extract_bits = [&](CudaRadixCiphertextFFI const *key,
                          CudaRadixCiphertextFFI *bits) {
    host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_a, key,
                                  mem->map_dup);
    prince_use_pattern<Torus>(streams, mem->params, mem->lut, mem->pat_keybit);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, bits, mem->buf_a, bsks, ksks, mem->lut, NUM_BITS);
  };
  auto parity_of_bits = [&](CudaRadixCiphertextFFI const *bits,
                            const prince_gather_map &sum3,
                            CudaRadixCiphertextFFI *kap) {
    mem->lut->set_lut_indexes_and_broadcast_constant(active_streams, 0);
    host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_b, bits, sum3);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, kap, mem->buf_b, bsks, ksks, mem->lut, NUM_BITS);
  };

  extract_bits(first, key_bits_first);
  parity_of_bits(key_bits_first, mem->map_bw_sum3, kap_bw_first);
  parity_of_bits(key_bits_first, mem->map_mid_sum3, kap_mid_first);
  extract_bits(second, key_bits_second);
  parity_of_bits(key_bits_second, mem->map_bw_sum3, kap_bw_second);
  cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
}

// buf_u2q ^ key -> buf_u4 (pv2_xor_to_u4), on lut_flat32's generated
// high/low pattern
template <typename Torus>
__host__ void host_prince_xor_key_to_u4(CudaStreams streams,
                                        int_prince_buffer<Torus> *mem,
                                        CudaRadixCiphertextFFI const *key_buf,
                                        void *const *bsks, Torus *const *ksks) {
  uint32_t num_u2_blocks = prince_v2::NUM_U2 * mem->num_inputs;
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), mem->buf_sum,
                       mem->buf_u2q, key_buf, num_u2_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_sum, mem->buf_sum, bsks, ksks, mem->lut_flat32,
      num_u2_blocks);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_sum,
                                mem->map_pair);
}

// Fused e-xor + key-xor: levelled 3-bit sums plus key material, reduced by
// one parity PBS placing the bit at its drift. buf_b -> buf_b.
template <typename Torus>
__host__ void
host_prince_parity_layer(CudaStreams streams, int_prince_buffer<Torus> *mem,
                         const prince_gather_map &sum3,
                         CudaRadixCiphertextFFI const *key_material,
                         const prince_lut_pattern<Torus> &parity_pat,
                         void *const *bsks, Torus *const *ksks) {
  uint32_t num_bit_blocks = prince_v2::NUM_BITS * mem->num_inputs;
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_b2, mem->buf_b,
                                sum3);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), mem->buf_b,
                       mem->buf_b2, key_material, num_bit_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  prince_use_pattern<Torus>(streams, mem->params, mem->lut_gather64,
                            parity_pat);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_b, mem->buf_b, bsks, ksks, mem->lut_gather64,
      num_bit_blocks);
}

// S-box layer as plain bit extraction, buf_u4 -> buf_b
template <typename Torus>
__host__ void host_prince_sbox_bits(CudaStreams streams,
                                    int_prince_buffer<Torus> *mem,
                                    const prince_lut_pattern<Torus> &pat,
                                    void *const *bsks, Torus *const *ksks) {
  uint32_t num_bit_blocks = prince_v2::NUM_BITS * mem->num_inputs;
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_b, mem->buf_u4,
                                mem->map_stage_x4);
  prince_use_pattern<Torus>(streams, mem->params, mem->lut_gather64, pat);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_b, mem->buf_b, bsks, ksks, mem->lut_gather64,
      num_bit_blocks);
}

// Forward round with its key xor, buf_u4 -> buf_u4: 2 PBS layers
template <typename Torus>
__host__ void host_prince_fw_round(CudaStreams streams,
                                   int_prince_buffer<Torus> *mem, uint32_t r,
                                   CudaRadixCiphertextFFI const *key_bits,
                                   void *const *bsks, Torus *const *ksks) {
  host_prince_sbox_bits<Torus>(streams, mem, mem->pat_fw_sbox[r], bsks, ksks);
  host_prince_parity_layer<Torus>(streams, mem, mem->map_fw_sum3, key_bits,
                                  mem->pat_par_fw, bsks, ksks);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_b,
                                mem->map_comb4_id);
}

// Backward round with its key xor, buf_b -> buf_b (buf_u2q for r = 4)
template <typename Torus>
__host__ void host_prince_bw_round(CudaStreams streams,
                                   int_prince_buffer<Torus> *mem, uint32_t r,
                                   CudaRadixCiphertextFFI const *kap_bw,
                                   void *const *bsks, Torus *const *ksks) {
  uint32_t num_u2_blocks = prince_v2::NUM_U2 * mem->num_inputs;
  host_prince_parity_layer<Torus>(streams, mem, mem->map_bw_sum3, kap_bw,
                                  mem->pat_par_bw, bsks, ksks);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_b,
                                mem->map_mperm_comb);
  if (r < 4) {
    host_prince_sbox_bits<Torus>(streams, mem, mem->pat_bw_sbox[r], bsks, ksks);
  } else {
    host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_u2q,
                                  mem->buf_u4, mem->map_stage_x2);
    prince_use_pattern<Torus>(streams, mem->params, mem->lut_gather64,
                              mem->pat_bw_sbox[4]);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, mem->buf_u2q, mem->buf_u2q, bsks, ksks, mem->lut_gather64,
        num_u2_blocks);
  }
}

// Middle (reflective) round S -> M' -> S^-1 with both key xors, buf_u4 -> buf_b
template <typename Torus>
__host__ void host_prince_mid_round(CudaStreams streams,
                                    int_prince_buffer<Torus> *mem,
                                    void *const *bsks, Torus *const *ksks) {
  host_prince_sbox_bits<Torus>(streams, mem, mem->pat_mid_in, bsks, ksks);
  host_prince_parity_layer<Torus>(streams, mem, mem->map_mid_sum3,
                                  mem->kap_mid_first, mem->pat_par_mid, bsks,
                                  ksks);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_u2q, mem->buf_b,
                                mem->map_perm_pair_mid);
  host_prince_xor_key_to_u4<Torus>(streams, mem, mem->buf_k_second, bsks, ksks);
  host_prince_sbox_bits<Torus>(streams, mem, mem->pat_mid_out, bsks, ksks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_prince(
    CudaStreams streams, int_prince_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_inputs,
    bool is_decrypt) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_prince_buffer<Torus>(streams, params, allocate_gpu_memory,
                                          num_inputs, is_decrypt, size_tracker);
  return size_tracker;
}

// k0 xor, 5 forward rounds, middle round, 5 backward rounds, k1 xor.
// Fresh inputs only: the input xor packs 4 * m + k, which spends the full
// 2_2 noise budget. Synchronous.
template <typename Torus>
__host__ void host_integer_prince(CudaStreams streams,
                                  CudaRadixCiphertextFFI *output,
                                  CudaRadixCiphertextFFI const *input,
                                  CudaRadixCiphertextFFI const *k0,
                                  CudaRadixCiphertextFFI const *k1,
                                  CudaRadixCiphertextFFI const *key_bits_first,
                                  CudaRadixCiphertextFFI const *key_bits_second,
                                  CudaRadixCiphertextFFI const *kap_bw_first,
                                  CudaRadixCiphertextFFI const *kap_bw_second,
                                  CudaRadixCiphertextFFI const *kap_mid_first,
                                  int_prince_buffer<Torus> *mem,
                                  void *const *bsks, Torus *const *ksks) {
  using namespace prince_v2;
  uint32_t N = mem->num_inputs;
  uint32_t num_u2_blocks = NUM_U2 * N;

  PANIC_IF_FALSE(input->num_radix_blocks == num_u2_blocks,
                 "PRINCE input should have 32 blocks per input");
  PANIC_IF_FALSE(output->num_radix_blocks == num_u2_blocks,
                 "PRINCE output should have 32 blocks per input");
  PANIC_IF_FALSE(k0->num_radix_blocks == NUM_U2 &&
                     k1->num_radix_blocks == NUM_U2,
                 "PRINCE keys should have 32 blocks");
  for (auto *k : {key_bits_first, key_bits_second, kap_bw_first, kap_bw_second,
                  kap_mid_first})
    PANIC_IF_FALSE(k->num_radix_blocks == NUM_BITS,
                   "PRINCE prepared key buffers should have 64 blocks");

  CudaRadixCiphertextFFI const *first = mem->is_decrypt ? k1 : k0;
  CudaRadixCiphertextFFI const *second = mem->is_decrypt ? k0 : k1;
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_k_first, first,
                                mem->map_key_tile);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_k_second, second,
                                mem->map_key_tile);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->key_bits_first,
                                key_bits_first, mem->map_tile64);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->key_bits_second,
                                key_bits_second, mem->map_tile64);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->kap_bw_first,
                                kap_bw_first, mem->map_tile64);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->kap_bw_second,
                                kap_bw_second, mem->map_tile64);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->kap_mid_first,
                                kap_mid_first, mem->map_tile64);

  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_u2q, input,
                                mem->map_transpose_in);

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, mem->buf_sum, mem->buf_u2q, mem->buf_k_first, bsks, ksks,
      mem->lut_flat32, num_u2_blocks, mem->params.message_modulus);
  host_prince_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_sum,
                                mem->map_pair);

  for (uint32_t r = 0; r < 5; ++r)
    host_prince_fw_round<Torus>(
        streams, mem, r,
        (r % 2 == 0) ? mem->key_bits_second : mem->key_bits_first, bsks, ksks);

  host_prince_mid_round<Torus>(streams, mem, bsks, ksks);

  for (uint32_t r = 0; r < 5; ++r)
    host_prince_bw_round<Torus>(
        streams, mem, r, (r % 2 == 0) ? mem->kap_bw_first : mem->kap_bw_second,
        bsks, ksks);

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), mem->buf_sum,
                       mem->buf_u2q, mem->buf_k_second, num_u2_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  // Last use of lut_flat32, so the high/low pattern needs no restoring
  auto active_streams_flat =
      streams.active_gpu_subset(num_u2_blocks, mem->params.pbs_type);
  mem->lut_flat32->set_lut_indexes_and_broadcast_constant(active_streams_flat,
                                                          1);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_sum, mem->buf_sum, bsks, ksks, mem->lut_flat32,
      num_u2_blocks);

  host_prince_gather_sum<Torus>(streams, mem->params, output, mem->buf_sum,
                                mem->map_transpose_out);
  cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
}

#endif // PRINCE_CUH
