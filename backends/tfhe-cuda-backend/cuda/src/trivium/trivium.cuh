#ifndef TRIVIUM_CUH
#define TRIVIUM_CUH

#include "../../include/trivium/trivium_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../linearalgebra/addition.cuh"

// CUDA kernel to reverse groups of N blocks within a buffer.
// Each group of N consecutive blocks is treated as a single "bit" and the
// order of bits is reversed.
template <typename Torus>
__global__ void reverse_blocks_kernel(Torus *dest, const Torus *src,
                                      uint32_t num_groups,
                                      uint32_t blocks_per_group,
                                      uint32_t lwe_size,
                                      uint32_t total_elements) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < total_elements) {
    uint32_t group_elements = blocks_per_group * lwe_size;
    uint32_t group_idx = tid / group_elements;
    uint32_t element_in_group = tid % group_elements;
    uint32_t reversed_group_idx = num_groups - 1 - group_idx;
    dest[reversed_group_idx * group_elements + element_in_group] =
        src[group_idx * group_elements + element_in_group];
  }
}

// Reverses the order of bits (blocks) in a ciphertext buffer.
// Uses a single CUDA kernel instead of N individual copy operations.
template <typename Torus>
void reverse_bitsliced_radix_inplace(CudaStreams streams,
                                     int_trivium_buffer<Torus> *mem,
                                     CudaRadixCiphertextFFI *radix,
                                     uint32_t num_bits_in_reg) {
  uint32_t N = mem->num_inputs;
  CudaRadixCiphertextFFI *temp = mem->state->shift_workspace;
  uint32_t total_blocks = num_bits_in_reg * N;
  uint32_t lwe_size = radix->lwe_dimension + 1;
  uint32_t total_elements = total_blocks * lwe_size;

  cuda_set_device(streams.gpu_index(0));
  int num_cuda_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(total_elements, 512, num_cuda_blocks, num_threads);

  reverse_blocks_kernel<Torus>
      <<<num_cuda_blocks, num_threads, 0, streams.stream(0)>>>(
          (Torus *)temp->ptr, (Torus *)radix->ptr, num_bits_in_reg, N,
          lwe_size, total_elements);
  check_cuda_error(cudaGetLastError());

  // Reverse metadata on CPU
  for (uint32_t i = 0; i < num_bits_in_reg; i++) {
    uint32_t rev = num_bits_in_reg - 1 - i;
    for (uint32_t j = 0; j < N; j++) {
      temp->degrees[rev * N + j] = radix->degrees[i * N + j];
      temp->noise_levels[rev * N + j] = radix->noise_levels[i * N + j];
    }
  }

  // Copy result back to radix
  cuda_memcpy_async_gpu_to_gpu(radix->ptr, temp->ptr,
                               safe_mul_sizeof<Torus>(total_blocks, lwe_size),
                               streams.stream(0), streams.gpu_index(0));
  memcpy(radix->degrees, temp->degrees,
         safe_mul_sizeof<uint64_t>(total_blocks));
  memcpy(radix->noise_levels, temp->noise_levels,
         safe_mul_sizeof<uint64_t>(total_blocks));
}

// Creates a slice of specific bits in a register without copying data.
template <typename Torus>
__host__ void slice_reg_batch(CudaRadixCiphertextFFI *slice,
                              const CudaRadixCiphertextFFI *reg,
                              uint32_t start_bit_idx, uint32_t num_bits,
                              uint32_t num_inputs) {
  as_radix_ciphertext_slice<Torus>(slice, reg, start_bit_idx * num_inputs,
                                   (start_bit_idx + num_bits) * num_inputs);
}

// Handles the shift-register update: discards old bits, shifts the rest,
// and inserts the newly computed bits at the beginning.
// Uses in-place shifting since kept region (reg_size-64 < 64) never overlaps
// the destination region (starting at offset 64).
template <typename Torus>
__host__ void shift_and_insert_batch(CudaStreams streams,
                                     int_trivium_buffer<Torus> *mem,
                                     CudaRadixCiphertextFFI *reg,
                                     CudaRadixCiphertextFFI *new_bits,
                                     uint32_t reg_size, uint32_t num_inputs) {

  constexpr uint32_t BATCH = 64;
  uint32_t num_blocks_to_keep = (reg_size - BATCH) * num_inputs;

  // Move old kept bits to the end of the register (non-overlapping since
  // reg_size - BATCH < BATCH for all Trivium registers: 93-64=29, 84-64=20,
  // 111-64=47, all < 64)
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), reg, BATCH * num_inputs,
      reg_size * num_inputs, reg, 0, num_blocks_to_keep);

  // Insert new bits at the beginning
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), reg, 0, BATCH * num_inputs,
      new_bits, 0, BATCH * num_inputs);
}

// core logic: computes 64 parallel updates for the state registers.
// It performs the XORs (additions) and the AND gates (using Bivariate PBS),
// then updates the registers and writes to output if needed.
template <typename Torus>
__host__ void
trivium_compute_64_steps(CudaStreams streams, int_trivium_buffer<Torus> *mem,
                         CudaRadixCiphertextFFI *output_dest, void *const *bsks,
                         uint64_t *const *ksks) {

  uint32_t N = mem->num_inputs;
  constexpr uint32_t BATCH = 64;
  uint32_t batch_size_blocks = BATCH * N;
  auto s = mem->state;

  CudaRadixCiphertextFFI a65_slice, a92_slice, a91_slice, a90_slice, a68_slice;
  slice_reg_batch<Torus>(&a65_slice, s->a_reg, 2, BATCH, N);
  slice_reg_batch<Torus>(&a92_slice, s->a_reg, 29, BATCH, N);
  slice_reg_batch<Torus>(&a91_slice, s->a_reg, 28, BATCH, N);
  slice_reg_batch<Torus>(&a90_slice, s->a_reg, 27, BATCH, N);
  slice_reg_batch<Torus>(&a68_slice, s->a_reg, 5, BATCH, N);

  CudaRadixCiphertextFFI b68_slice, b83_slice, b82_slice, b81_slice, b77_slice;
  slice_reg_batch<Torus>(&b68_slice, s->b_reg, 5, BATCH, N);
  slice_reg_batch<Torus>(&b83_slice, s->b_reg, 20, BATCH, N);
  slice_reg_batch<Torus>(&b82_slice, s->b_reg, 19, BATCH, N);
  slice_reg_batch<Torus>(&b81_slice, s->b_reg, 18, BATCH, N);
  slice_reg_batch<Torus>(&b77_slice, s->b_reg, 14, BATCH, N);

  CudaRadixCiphertextFFI c65_slice, c110_slice, c109_slice, c108_slice,
      c86_slice;
  slice_reg_batch<Torus>(&c65_slice, s->c_reg, 2, BATCH, N);
  slice_reg_batch<Torus>(&c110_slice, s->c_reg, 47, BATCH, N);
  slice_reg_batch<Torus>(&c109_slice, s->c_reg, 46, BATCH, N);
  slice_reg_batch<Torus>(&c108_slice, s->c_reg, 45, BATCH, N);
  slice_reg_batch<Torus>(&c86_slice, s->c_reg, 23, BATCH, N);

  // t1 = a66 + a93
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), s->temp_t1,
                       &a65_slice, &a92_slice, s->temp_t1->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // t2 = b69 + b84
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), s->temp_t2,
                       &b68_slice, &b83_slice, s->temp_t2->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // t3 = c66 + c111
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), s->temp_t3,
                       &c65_slice, &c110_slice, s->temp_t3->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_pbs_lhs, 0,
      batch_size_blocks, &c109_slice, 0, batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_pbs_lhs,
      batch_size_blocks, 2 * batch_size_blocks, &a91_slice, 0,
      batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_pbs_lhs,
      2 * batch_size_blocks, 3 * batch_size_blocks, &b82_slice, 0,
      batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_pbs_rhs, 0,
      batch_size_blocks, &c108_slice, 0, batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_pbs_rhs,
      batch_size_blocks, 2 * batch_size_blocks, &a90_slice, 0,
      batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_pbs_rhs,
      2 * batch_size_blocks, 3 * batch_size_blocks, &b81_slice, 0,
      batch_size_blocks);

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, s->packed_pbs_out, s->packed_pbs_lhs, s->packed_pbs_rhs, bsks,
      ksks, mem->luts->and_lut, 3 * batch_size_blocks,
      mem->params.message_modulus);

  CudaRadixCiphertextFFI and_res_a, and_res_b, and_res_c;
  as_radix_ciphertext_slice<Torus>(&and_res_a, s->packed_pbs_out, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&and_res_b, s->packed_pbs_out,
                                   batch_size_blocks, 2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&and_res_c, s->packed_pbs_out,
                                   2 * batch_size_blocks,
                                   3 * batch_size_blocks);

  // Create slices pointing directly into the flush input buffer to avoid
  // intermediate copies
  CudaRadixCiphertextFFI flush_new_a, flush_new_b, flush_new_c, flush_out;
  as_radix_ciphertext_slice<Torus>(&flush_new_a, s->packed_flush_in, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flush_new_b, s->packed_flush_in,
                                   batch_size_blocks, 2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flush_new_c, s->packed_flush_in,
                                   2 * batch_size_blocks,
                                   3 * batch_size_blocks);

  // a = t3 + a69 + and_res_a (computed directly into flush buffer)
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_a,
                       s->temp_t3, &a68_slice, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_a,
                       &flush_new_a, &and_res_a, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // b = t1 + b78 + and_res_b (computed directly into flush buffer)
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       s->temp_t1, &b77_slice, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       &flush_new_b, &and_res_b, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // c = t2 + c87 + and_res_c (computed directly into flush buffer)
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_c,
                       s->temp_t2, &c86_slice, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_c,
                       &flush_new_c, &and_res_c, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  uint32_t total_flush_blocks = 3 * batch_size_blocks;

  if (output_dest != nullptr) {
    // z = t1 + t2 + t3 (computed directly into flush buffer)
    as_radix_ciphertext_slice<Torus>(&flush_out, s->packed_flush_in,
                                     3 * batch_size_blocks,
                                     4 * batch_size_blocks);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_out,
                         s->temp_t1, s->temp_t2, batch_size_blocks,
                         mem->params.message_modulus,
                         mem->params.carry_modulus);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_out,
                         &flush_out, s->temp_t3, batch_size_blocks,
                         mem->params.message_modulus,
                         mem->params.carry_modulus);
    total_flush_blocks += batch_size_blocks;
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, s->packed_flush_out, s->packed_flush_in, bsks, ksks,
      mem->luts->flush_lut, total_flush_blocks);

  CudaRadixCiphertextFFI flushed_a, flushed_b, flushed_c;
  as_radix_ciphertext_slice<Torus>(&flushed_a, s->packed_flush_out, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flushed_b, s->packed_flush_out,
                                   batch_size_blocks, 2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flushed_c, s->packed_flush_out,
                                   2 * batch_size_blocks,
                                   3 * batch_size_blocks);

  shift_and_insert_batch(streams, mem, s->a_reg, &flushed_a, 93, N);
  shift_and_insert_batch(streams, mem, s->b_reg, &flushed_b, 84, N);
  shift_and_insert_batch(streams, mem, s->c_reg, &flushed_c, 111, N);

  if (output_dest != nullptr) {
    CudaRadixCiphertextFFI flushed_out;
    as_radix_ciphertext_slice<Torus>(&flushed_out, s->packed_flush_out,
                                     3 * batch_size_blocks,
                                     4 * batch_size_blocks);

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output_dest, 0,
        batch_size_blocks, &flushed_out, 0, batch_size_blocks);

    reverse_bitsliced_radix_inplace<Torus>(streams, mem, output_dest, 64);
  }
}

// Sets up the initial state: loads Key and IV, fixes constants,
// and runs the warm-up phase (1152 steps).
template <typename Torus>
__host__ void trivium_init(CudaStreams streams, int_trivium_buffer<Torus> *mem,
                           CudaRadixCiphertextFFI const *key_bitsliced,
                           CudaRadixCiphertextFFI const *iv_bitsliced,
                           void *const *bsks, uint64_t *const *ksks) {
  uint32_t N = mem->num_inputs;
  auto s = mem->state;

  CudaRadixCiphertextFFI src_key_slice;
  slice_reg_batch<Torus>(&src_key_slice, key_bitsliced, 0, 80, N);

  CudaRadixCiphertextFFI dest_a_slice;
  slice_reg_batch<Torus>(&dest_a_slice, s->a_reg, 0, 80, N);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_a_slice, &src_key_slice);

  reverse_bitsliced_radix_inplace<Torus>(streams, mem, s->a_reg, 80);

  CudaRadixCiphertextFFI src_iv_slice;
  slice_reg_batch<Torus>(&src_iv_slice, iv_bitsliced, 0, 80, N);

  CudaRadixCiphertextFFI dest_b_slice;
  slice_reg_batch<Torus>(&dest_b_slice, s->b_reg, 0, 80, N);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_b_slice, &src_iv_slice);

  reverse_bitsliced_radix_inplace<Torus>(streams, mem, s->b_reg, 80);

  CudaRadixCiphertextFFI dest_c_ones;
  slice_reg_batch<Torus>(&dest_c_ones, s->c_reg, 108, 3, N);

  host_add_scalar_one_inplace<Torus>(streams, &dest_c_ones,
                                     mem->params.message_modulus,
                                     mem->params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &dest_c_ones, &dest_c_ones, bsks, ksks, mem->luts->flush_lut,
      dest_c_ones.num_radix_blocks);

  for (int i = 0; i < 18; i++) {
    trivium_compute_64_steps(streams, mem, nullptr, bsks, ksks);
  }
}

// Main entry point: checks input validity, initializes state,
// and loops to generate the keystream in batches of 64.
template <typename Torus>
__host__ void host_trivium_generate_keystream(
    CudaStreams streams, CudaRadixCiphertextFFI *keystream_output,
    CudaRadixCiphertextFFI const *key_bitsliced,
    CudaRadixCiphertextFFI const *iv_bitsliced, uint32_t num_inputs,
    uint32_t num_steps, int_trivium_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {

  PANIC_IF_FALSE(num_steps % 64 == 0,
                 "Trivium Error: num_steps must be a multiple of 64.\n");

  trivium_init(streams, mem, key_bitsliced, iv_bitsliced, bsks, ksks);

  uint32_t num_batches = num_steps / 64;
  for (uint32_t i = 0; i < num_batches; i++) {
    CudaRadixCiphertextFFI batch_out_slice;
    slice_reg_batch<Torus>(&batch_out_slice, keystream_output, i * 64, 64,
                           num_inputs);
    trivium_compute_64_steps(streams, mem, &batch_out_slice, bsks, ksks);
  }
}

template <typename Torus>
uint64_t scratch_cuda_trivium_encrypt(CudaStreams streams,
                                      int_trivium_buffer<Torus> **mem_ptr,
                                      int_radix_params params,
                                      bool allocate_gpu_memory,
                                      uint32_t num_inputs) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_trivium_buffer<Torus>(streams, params, allocate_gpu_memory,
                                           num_inputs, size_tracker);
  return size_tracker;
}

#endif
