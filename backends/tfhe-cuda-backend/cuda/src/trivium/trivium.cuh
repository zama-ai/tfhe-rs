#ifndef TRIVIUM_CUH
#define TRIVIUM_CUH

#include "../../include/trivium/trivium_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../linearalgebra/addition.cuh"

// Creates a slice of specific bits in a register without copying data.
template <typename Torus>
__host__ void slice_reg_batch(CudaRadixCiphertextFFI *slice,
                              const CudaRadixCiphertextFFI *reg,
                              uint32_t start_bit_idx, uint32_t num_bits,
                              uint32_t num_inputs) {
  as_radix_ciphertext_slice<Torus>(slice, reg, start_bit_idx * num_inputs,
                                   (start_bit_idx + num_bits) * num_inputs);
}

// Reverses the order of bits (blocks) in a ciphertext buffer.
// Used to align the input Key/IV with the internal state format if needed.
template <typename Torus>
void reverse_bitsliced_radix_inplace(CudaStreams streams,
                                     CudaRadixCiphertextFFI *shift_workspace,
                                     CudaRadixCiphertextFFI *radix,
                                     uint32_t num_bits_in_reg,
                                     uint32_t num_inputs) {
  uint32_t N = num_inputs;
  for (uint32_t i = 0; i < num_bits_in_reg; i++) {
    uint32_t src_start = i * N;
    uint32_t src_end = (i + 1) * N;
    uint32_t dest_start = (num_bits_in_reg - 1 - i) * N;
    uint32_t dest_end = (num_bits_in_reg - i) * N;

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), shift_workspace, dest_start,
        dest_end, radix, src_start, src_end);
  }

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), radix, 0, num_bits_in_reg * N,
      shift_workspace, 0, num_bits_in_reg * N);
}

// Handles the shift-register update: discards old bits, shifts the rest,
// and inserts the newly computed bits at the beginning.
template <typename Torus>
__host__ void shift_and_insert_batch(CudaStreams streams,
                                     CudaRadixCiphertextFFI *shift_workspace,
                                     CudaRadixCiphertextFFI *reg,
                                     CudaRadixCiphertextFFI *new_bits,
                                     uint32_t reg_size, uint32_t num_inputs) {
  constexpr uint32_t BATCH = TRIVIUM_BATCH_SIZE;
  uint32_t num_blocks_to_keep = (reg_size - BATCH) * num_inputs;

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), shift_workspace, 0,
      BATCH * num_inputs, new_bits, 0, BATCH * num_inputs);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), shift_workspace,
      BATCH * num_inputs, reg_size * num_inputs, reg, 0, num_blocks_to_keep);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), reg, 0, reg_size * num_inputs,
      shift_workspace, 0, reg_size * num_inputs);
}

// Core evaluation function: computes 64 parallel updates for the state
// registers. Performs the XORs (additions) and the AND gates (Bivariate PBS),
// updates the registers in place, and writes to output if requested.
template <typename Torus>
__host__ void trivium_compute_64_steps(
    CudaStreams streams, int_trivium_buffer<Torus> *buffer,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *output_dest,
    void *const *bsks, uint64_t *const *ksks) {

  uint32_t N = buffer->num_inputs;
  constexpr uint32_t BATCH = TRIVIUM_BATCH_SIZE;
  uint32_t batch_size_blocks = BATCH * N;
  auto ws = buffer->ws;
  auto params = buffer->params;

  // Extract register taps for A (93-bit register)
  CudaRadixCiphertextFFI a65_slice, a92_slice, a91_slice, a90_slice, a68_slice;
  slice_reg_batch<Torus>(&a65_slice, a_reg, 2, BATCH, N);
  slice_reg_batch<Torus>(&a92_slice, a_reg, 29, BATCH, N);
  slice_reg_batch<Torus>(&a91_slice, a_reg, 28, BATCH, N);
  slice_reg_batch<Torus>(&a90_slice, a_reg, 27, BATCH, N);
  slice_reg_batch<Torus>(&a68_slice, a_reg, 5, BATCH, N);

  // Extract register taps for B (84-bit register)
  CudaRadixCiphertextFFI b68_slice, b83_slice, b82_slice, b81_slice, b77_slice;
  slice_reg_batch<Torus>(&b68_slice, b_reg, 5, BATCH, N);
  slice_reg_batch<Torus>(&b83_slice, b_reg, 20, BATCH, N);
  slice_reg_batch<Torus>(&b82_slice, b_reg, 19, BATCH, N);
  slice_reg_batch<Torus>(&b81_slice, b_reg, 18, BATCH, N);
  slice_reg_batch<Torus>(&b77_slice, b_reg, 14, BATCH, N);

  // Extract register taps for C (111-bit register)
  CudaRadixCiphertextFFI c65_slice, c110_slice, c109_slice, c108_slice,
      c86_slice;
  slice_reg_batch<Torus>(&c65_slice, c_reg, 2, BATCH, N);
  slice_reg_batch<Torus>(&c110_slice, c_reg, 47, BATCH, N);
  slice_reg_batch<Torus>(&c109_slice, c_reg, 46, BATCH, N);
  slice_reg_batch<Torus>(&c108_slice, c_reg, 45, BATCH, N);
  slice_reg_batch<Torus>(&c86_slice, c_reg, 23, BATCH, N);

  // Compute linear feedback terms
  // t1 <- a66 + a93
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->temp_t1,
                       &a65_slice, &a92_slice, ws->temp_t1->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);

  // t2 <- b69 + b84
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->temp_t2,
                       &b68_slice, &b83_slice, ws->temp_t2->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);

  // t3 <- c66 + c111
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->temp_t3,
                       &c65_slice, &c110_slice, ws->temp_t3->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);

  // Flush t3 (extract message bits and reset noise) so it can be reused below
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, ws->temp_t3, ws->temp_t3, bsks, ksks, buffer->luts->flush_lut,
      ws->temp_t3->num_radix_blocks);

  // Pack AND gate inputs: (c109 & c108), (a91 & a90), (b82 & b81)
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_pbs_lhs, 0,
      batch_size_blocks, &c109_slice, 0, batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_pbs_lhs,
      batch_size_blocks, 2 * batch_size_blocks, &a91_slice, 0,
      batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_pbs_lhs,
      2 * batch_size_blocks, 3 * batch_size_blocks, &b82_slice, 0,
      batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_pbs_rhs, 0,
      batch_size_blocks, &c108_slice, 0, batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_pbs_rhs,
      batch_size_blocks, 2 * batch_size_blocks, &a90_slice, 0,
      batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_pbs_rhs,
      2 * batch_size_blocks, 3 * batch_size_blocks, &b81_slice, 0,
      batch_size_blocks);

  // Execute the 3 AND gates in parallel via bivariate PBS
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, ws->packed_pbs_out, ws->packed_pbs_lhs, ws->packed_pbs_rhs, bsks,
      ksks, buffer->luts->and_lut, 3 * batch_size_blocks,
      params.message_modulus);

  // Unpack AND results: and_res_a = c109 & c108, and_res_b = a91 & a90,
  // and_res_c = b82 & b81
  CudaRadixCiphertextFFI and_res_a, and_res_b, and_res_c;
  as_radix_ciphertext_slice<Torus>(&and_res_a, ws->packed_pbs_out, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&and_res_b, ws->packed_pbs_out,
                                   batch_size_blocks, 2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&and_res_c, ws->packed_pbs_out,
                                   2 * batch_size_blocks,
                                   3 * batch_size_blocks);

  // new_a <- t3 + a69 + and_res_a
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->new_a,
                       ws->temp_t3, &a68_slice, ws->new_a->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->new_a,
                       ws->new_a, &and_res_a, ws->new_a->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);

  // new_b <- t1 + b78 + and_res_b
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->new_b,
                       ws->temp_t1, &b77_slice, ws->new_b->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->new_b,
                       ws->new_b, &and_res_b, ws->new_b->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);

  // new_c <- t2 + c87 + and_res_c
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->new_c,
                       ws->temp_t2, &c86_slice, ws->new_c->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->new_c,
                       ws->new_c, &and_res_c, ws->new_c->num_radix_blocks,
                       params.message_modulus, params.carry_modulus);

  if (output_dest != nullptr) {
    // z <- t1 + t2 + t3
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), output_dest,
                         ws->temp_t1, ws->temp_t2,
                         output_dest->num_radix_blocks, params.message_modulus,
                         params.carry_modulus);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), output_dest,
                         output_dest, ws->temp_t3,
                         output_dest->num_radix_blocks, params.message_modulus,
                         params.carry_modulus);
  }

  // Pack new_a, new_b, new_c (and z when an output is requested) into a single
  // buffer to flush them all in one PBS call
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_flush_in, 0,
      batch_size_blocks, ws->new_a, 0, batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_flush_in,
      batch_size_blocks, 2 * batch_size_blocks, ws->new_b, 0,
      batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), ws->packed_flush_in,
      2 * batch_size_blocks, 3 * batch_size_blocks, ws->new_c, 0,
      batch_size_blocks);

  uint32_t total_flush_blocks = 3 * batch_size_blocks;

  if (output_dest != nullptr) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), ws->packed_flush_in,
        3 * batch_size_blocks, 4 * batch_size_blocks, output_dest, 0,
        batch_size_blocks);
    total_flush_blocks += batch_size_blocks;
  }

  // Flush PBS: extract message bits and reset noise on new_a, new_b, new_c (and
  // z if any)
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, ws->packed_flush_out, ws->packed_flush_in, bsks, ksks,
      buffer->luts->flush_lut, total_flush_blocks);

  // Unpack flushed results
  CudaRadixCiphertextFFI flushed_a, flushed_b, flushed_c;
  as_radix_ciphertext_slice<Torus>(&flushed_a, ws->packed_flush_out, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flushed_b, ws->packed_flush_out,
                                   batch_size_blocks, 2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flushed_c, ws->packed_flush_out,
                                   2 * batch_size_blocks,
                                   3 * batch_size_blocks);

  // Update registers in place: shift left by 64 and insert the new 64 bits
  shift_and_insert_batch<Torus>(streams, ws->shift_workspace, a_reg, &flushed_a,
                                TRIVIUM_REGISTER_A_BITS, N);
  shift_and_insert_batch<Torus>(streams, ws->shift_workspace, b_reg, &flushed_b,
                                TRIVIUM_REGISTER_B_BITS, N);
  shift_and_insert_batch<Torus>(streams, ws->shift_workspace, c_reg, &flushed_c,
                                TRIVIUM_REGISTER_C_BITS, N);

  if (output_dest != nullptr) {
    CudaRadixCiphertextFFI flushed_out;
    as_radix_ciphertext_slice<Torus>(&flushed_out, ws->packed_flush_out,
                                     3 * batch_size_blocks,
                                     4 * batch_size_blocks);

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output_dest, 0,
        batch_size_blocks, &flushed_out, 0, batch_size_blocks);

    reverse_bitsliced_radix_inplace<Torus>(streams, ws->shift_workspace,
                                           output_dest, BATCH, N);
  }
}

// Sets up the initial state: loads Key and IV, fixes constants,
// and runs the warm-up phase (1152 steps).
template <typename Torus>
__host__ void
host_trivium_init(CudaStreams streams, int_trivium_buffer<Torus> *buffer,
                  CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
                  CudaRadixCiphertextFFI *c_reg,
                  const CudaRadixCiphertextFFI *key_bitsliced,
                  const CudaRadixCiphertextFFI *iv_bitsliced, void *const *bsks,
                  uint64_t *const *ksks) {

  uint32_t N = buffer->num_inputs;
  auto ws = buffer->ws;
  auto params = buffer->params;

  CudaRadixCiphertextFFI src_key_slice;
  slice_reg_batch<Torus>(&src_key_slice, key_bitsliced, 0, TRIVIUM_KEY_BITS, N);

  CudaRadixCiphertextFFI dest_a_slice;
  slice_reg_batch<Torus>(&dest_a_slice, a_reg, 0, TRIVIUM_KEY_BITS, N);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_a_slice, &src_key_slice);

  reverse_bitsliced_radix_inplace<Torus>(streams, ws->shift_workspace, a_reg,
                                         TRIVIUM_KEY_BITS, N);

  CudaRadixCiphertextFFI src_iv_slice;
  slice_reg_batch<Torus>(&src_iv_slice, iv_bitsliced, 0, TRIVIUM_IV_BITS, N);

  CudaRadixCiphertextFFI dest_b_slice;
  slice_reg_batch<Torus>(&dest_b_slice, b_reg, 0, TRIVIUM_IV_BITS, N);

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_b_slice, &src_iv_slice);

  reverse_bitsliced_radix_inplace<Torus>(streams, ws->shift_workspace, b_reg,
                                         TRIVIUM_IV_BITS, N);

  CudaRadixCiphertextFFI dest_c_ones;
  slice_reg_batch<Torus>(&dest_c_ones, c_reg, TRIVIUM_REGISTER_C_BITS - 3, 3,
                         N);

  host_add_scalar_one_inplace<Torus>(
      streams, &dest_c_ones, params.message_modulus, params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &dest_c_ones, &dest_c_ones, bsks, ksks, buffer->luts->flush_lut,
      dest_c_ones.num_radix_blocks);

  for (uint32_t i = 0; i < TRIVIUM_WARMUP_BATCHES; i++) {
    trivium_compute_64_steps(streams, buffer, a_reg, b_reg, c_reg, nullptr,
                             bsks, ksks);
  }
}

template <typename Torus>
__host__ void
host_trivium_step(CudaStreams streams, CudaRadixCiphertextFFI *keystream_output,
                  CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
                  CudaRadixCiphertextFFI *c_reg, uint32_t num_steps,
                  int_trivium_buffer<Torus> *buffer, void *const *bsks,
                  uint64_t *const *ksks) {

  PANIC_IF_FALSE(
      num_steps % TRIVIUM_BATCH_SIZE == 0,
      "Trivium Error: num_steps must be a multiple of TRIVIUM_BATCH_SIZE.\n");

  uint32_t num_batches = num_steps / TRIVIUM_BATCH_SIZE;
  for (uint32_t i = 0; i < num_batches; i++) {
    CudaRadixCiphertextFFI batch_out_slice;
    slice_reg_batch<Torus>(&batch_out_slice, keystream_output,
                           i * TRIVIUM_BATCH_SIZE, TRIVIUM_BATCH_SIZE,
                           buffer->num_inputs);

    trivium_compute_64_steps(streams, buffer, a_reg, b_reg, c_reg,
                             &batch_out_slice, bsks, ksks);
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
