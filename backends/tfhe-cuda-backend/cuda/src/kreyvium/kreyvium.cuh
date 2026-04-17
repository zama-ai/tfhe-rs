#ifndef KREYVIUM_CUH
#define KREYVIUM_CUH

#include "../../include/kreyvium/kreyvium_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../linearalgebra/addition.cuh"

// Creates a view (slice) of specific bits in a register.
// Used to access specific taps like a[65], k[127], etc.
template <typename Torus>
__host__ void slice_reg_batch_kreyvium(CudaRadixCiphertextFFI *slice,
                                       const CudaRadixCiphertextFFI *reg,
                                       uint32_t start_bit_idx,
                                       uint32_t num_bits, uint32_t num_inputs) {
  as_radix_ciphertext_slice<Torus>(slice, reg, start_bit_idx * num_inputs,
                                   (start_bit_idx + num_bits) * num_inputs);
}

// Standard shift-and-insert for Kreyvium registers A, B, C.
// Shifts the register and inserts new bits at the start.
template <typename Torus>
__host__ void shift_and_insert_batch_kreyvium(
    CudaStreams streams, CudaRadixCiphertextFFI *shift_workspace,
    CudaRadixCiphertextFFI *reg, CudaRadixCiphertextFFI *new_bits,
    uint32_t reg_size, uint32_t num_inputs) {
  constexpr uint32_t BATCH = KREYVIUM_BATCH_SIZE;
  uint32_t num_blocks_to_keep = (reg_size - BATCH) * num_inputs;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), shift_workspace, 0,
      num_blocks_to_keep, reg, BATCH * num_inputs, reg_size * num_inputs);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), shift_workspace,
      num_blocks_to_keep, reg_size * num_inputs, new_bits, 0,
      BATCH * num_inputs);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), reg, 0, reg_size * num_inputs,
      shift_workspace, 0, reg_size * num_inputs);
}

// Reverses the order of blocks in a ciphertext buffer.
// Essential for aligning Key/IV bit ordering.
template <typename Torus>
void reverse_bitsliced_radix_inplace_kreyvium(
    CudaStreams streams, CudaRadixCiphertextFFI *shift_workspace,
    CudaRadixCiphertextFFI *radix, uint32_t num_bits_in_reg,
    uint32_t num_inputs) {
  for (uint32_t i = 0; i < num_bits_in_reg; i++) {
    uint32_t src_start = i * num_inputs;
    uint32_t src_end = (i + 1) * num_inputs;
    uint32_t dest_start = (num_bits_in_reg - 1 - i) * num_inputs;
    uint32_t dest_end = (num_bits_in_reg - i) * num_inputs;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), shift_workspace, dest_start,
        dest_end, radix, src_start, src_end);
  }
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), radix, 0,
      num_bits_in_reg * num_inputs, shift_workspace, 0,
      num_bits_in_reg * num_inputs);
}

// Core Kreyvium step function: computes 64 steps in parallel.
// Includes XORs, AND gates (via PBS), Key/IV rotation, and register updates.
template <typename Torus>
__host__ void
kreyvium_compute_64_steps(CudaStreams streams, int_kreyvium_buffer<Torus> *mem,
                          CudaRadixCiphertextFFI *output_dest,
                          void *const *bsks, uint64_t *const *ksks) {
  uint32_t N = mem->num_inputs;
  constexpr uint32_t BATCH = KREYVIUM_BATCH_SIZE;
  uint32_t batch_size_blocks = BATCH * N;
  auto s = mem->state;
  auto luts = mem->luts;

  // Extract register taps for A (93-bit register)
  CudaRadixCiphertextFFI a65, a92, a91, a90, a68;
  slice_reg_batch_kreyvium<Torus>(&a65, s->a_reg, 27, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a92, s->a_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a91, s->a_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a90, s->a_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a68, s->a_reg, 24, BATCH, N);

  // Extract register taps for B (84-bit register)
  CudaRadixCiphertextFFI b68, b83, b82, b81, b77;
  slice_reg_batch_kreyvium<Torus>(&b68, s->b_reg, 15, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b83, s->b_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b82, s->b_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b81, s->b_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b77, s->b_reg, 6, BATCH, N);

  // Extract register taps for C (111-bit register)
  CudaRadixCiphertextFFI c65, c110, c109, c108, c86;
  slice_reg_batch_kreyvium<Torus>(&c65, s->c_reg, 45, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c110, s->c_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c109, s->c_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c108, s->c_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c86, s->c_reg, 24, BATCH, N);

  // Extract key and IV bits using virtual rotation offset
  CudaRadixCiphertextFFI k127, iv127;
  slice_reg_batch_kreyvium<Torus>(&k127, s->k_reg, s->k_offset, 64, N);
  slice_reg_batch_kreyvium<Torus>(&iv127, s->iv_reg, s->iv_offset, 64, N);
  s->k_offset = (s->k_offset + KREYVIUM_BATCH_SIZE) % KREYVIUM_KEY_BITS;
  s->iv_offset = (s->iv_offset + KREYVIUM_BATCH_SIZE) % KREYVIUM_IV_BITS;

  // Compute linear feedback terms:
  // temp_a = a65 + a92
  // temp_b = b68 + b83
  // temp_c = c65 + c110 + k127
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), s->temp_a, &a65,
                       &a92, s->temp_a->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), s->temp_b, &b68,
                       &b83, s->temp_b->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), s->temp_c, &c65,
                       &c110, s->temp_c->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), s->temp_c,
                       s->temp_c, &k127, s->temp_c->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, s->temp_c, s->temp_c, bsks, ksks, luts->flush_lut,
      s->temp_c->num_radix_blocks);

  // Pack AND gate inputs: (c109 & c108), (a91 & a90), (b82 & b81)
  CudaRadixCiphertextFFI *lhs_ptrs[] = {&c109, &a91, &b82};
  CudaRadixCiphertextFFI *rhs_ptrs[] = {&c108, &a90, &b81};

  for (uint32_t i = 0; i < KREYVIUM_NUM_AND_GATES; i++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), s->packed_and_lhs,
        i * batch_size_blocks, (i + 1) * batch_size_blocks, lhs_ptrs[i], 0,
        batch_size_blocks);

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), s->packed_and_rhs,
        i * batch_size_blocks, (i + 1) * batch_size_blocks, rhs_ptrs[i], 0,
        batch_size_blocks);
  }

  // Execute 3 AND gates in parallel via bivariate PBS
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, s->packed_and_out, s->packed_and_lhs, s->packed_and_rhs, bsks,
      ksks, luts->and_lut, KREYVIUM_NUM_AND_GATES * batch_size_blocks,
      mem->params.message_modulus);

  // Unpack AND results
  CudaRadixCiphertextFFI and_c109_c108, and_a91_a90, and_b82_b81;
  CudaRadixCiphertextFFI *and_out_ptrs[] = {&and_c109_c108, &and_a91_a90,
                                            &and_b82_b81};

  for (uint32_t i = 0; i < KREYVIUM_NUM_AND_GATES; i++) {
    as_radix_ciphertext_slice<Torus>(and_out_ptrs[i], s->packed_and_out,
                                     i * batch_size_blocks,
                                     (i + 1) * batch_size_blocks);
  }

  // Create slices pointing directly into flush input buffer
  // We utilize a loop here to slice the packed buffer into 4 distinct views
  CudaRadixCiphertextFFI flush_new_a, flush_new_b, flush_new_c, flush_out;
  CudaRadixCiphertextFFI *flush_in_slices[] = {&flush_new_a, &flush_new_b,
                                               &flush_new_c, &flush_out};

  for (uint32_t i = 0; i < KREYVIUM_NUM_FLUSH_PATHS; i++) {
    as_radix_ciphertext_slice<Torus>(flush_in_slices[i], s->packed_flush_in,
                                     i * batch_size_blocks,
                                     (i + 1) * batch_size_blocks);
  }

  // new_a = (c109 & c108) + a68 + temp_c
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_a,
                       &and_c109_c108, &a68, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_a,
                       &flush_new_a, s->temp_c, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // new_b = (a91 & a90) + b77 + temp_a + iv127
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       &and_a91_a90, &b77, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       &flush_new_b, s->temp_a, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       &flush_new_b, &iv127, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // new_c = (b82 & b81) + c86 + temp_b
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_c,
                       &and_b82_b81, &c86, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_c,
                       &flush_new_c, s->temp_b, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // out = temp_a + temp_b + temp_c
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_out,
                       s->temp_a, s->temp_b, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_out,
                       &flush_out, s->temp_c, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  // Apply flush PBS to extract message bits and reset noise
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, s->packed_flush_out, s->packed_flush_in, bsks, ksks,
      luts->flush_lut, s->packed_flush_out->num_radix_blocks);

  // Unpack flushed results
  CudaRadixCiphertextFFI flushed_new_a, flushed_new_b, flushed_new_c,
      flushed_out;
  CudaRadixCiphertextFFI *flush_out_slices[] = {&flushed_new_a, &flushed_new_b,
                                                &flushed_new_c, &flushed_out};

  for (uint32_t i = 0; i < KREYVIUM_NUM_FLUSH_PATHS; i++) {
    as_radix_ciphertext_slice<Torus>(flush_out_slices[i], s->packed_flush_out,
                                     i * batch_size_blocks,
                                     (i + 1) * batch_size_blocks);
  }

  // Update registers: shift and insert new 64 bits
  shift_and_insert_batch_kreyvium<Torus>(streams, s->shift_workspace, s->a_reg,
                                         &flushed_new_a,
                                         KREYVIUM_REGISTER_A_BITS, N);
  shift_and_insert_batch_kreyvium<Torus>(streams, s->shift_workspace, s->b_reg,
                                         &flushed_new_b,
                                         KREYVIUM_REGISTER_B_BITS, N);
  shift_and_insert_batch_kreyvium<Torus>(streams, s->shift_workspace, s->c_reg,
                                         &flushed_new_c,
                                         KREYVIUM_REGISTER_C_BITS, N);

  // Copy output keystream if destination provided
  if (output_dest != nullptr) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output_dest, 0,
        batch_size_blocks, &flushed_out, 0, batch_size_blocks);
  }
}

// Initialization phase: Loads Key/IV, distributes bits to registers A, B, C,
// and runs the warm-up loop.
template <typename Torus>
__host__ void kreyvium_init(CudaStreams streams,
                            int_kreyvium_buffer<Torus> *mem,
                            CudaRadixCiphertextFFI const *key_bitsliced,
                            CudaRadixCiphertextFFI const *iv_bitsliced,
                            void *const *bsks, uint64_t *const *ksks) {
  uint32_t N = mem->num_inputs;
  auto s = mem->state;
  s->k_offset = 0;
  s->iv_offset = 0;

  // k = key_bits.to_vec();
  CudaRadixCiphertextFFI src_key_slice;
  slice_reg_batch_kreyvium<Torus>(&src_key_slice, key_bitsliced, 0,
                                  KREYVIUM_KEY_BITS, N);
  CudaRadixCiphertextFFI dest_k_reg_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_k_reg_slice, s->k_reg, 0,
                                  KREYVIUM_KEY_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_k_reg_slice, &src_key_slice);

  // a[0..93] = key[35..128]
  CudaRadixCiphertextFFI k_source_for_a;
  slice_reg_batch_kreyvium<Torus>(&k_source_for_a, s->k_reg,
                                  KREYVIUM_KEY_BITS - KREYVIUM_REGISTER_A_BITS,
                                  KREYVIUM_REGISTER_A_BITS, N);
  CudaRadixCiphertextFFI dest_a_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_a_slice, s->a_reg, 0,
                                  KREYVIUM_REGISTER_A_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_a_slice, &k_source_for_a);

  // k.reverse();
  reverse_bitsliced_radix_inplace_kreyvium<Torus>(
      streams, s->shift_workspace, s->k_reg, KREYVIUM_KEY_BITS, N);

  // iv = iv_bits.to_vec();
  CudaRadixCiphertextFFI src_iv_slice;
  slice_reg_batch_kreyvium<Torus>(&src_iv_slice, iv_bitsliced, 0,
                                  KREYVIUM_IV_BITS, N);
  CudaRadixCiphertextFFI dest_iv_reg_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_iv_reg_slice, s->iv_reg, 0,
                                  KREYVIUM_IV_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_iv_reg_slice, &src_iv_slice);

  // b[0..84] = iv[44..128]
  CudaRadixCiphertextFFI iv_source_for_b;
  slice_reg_batch_kreyvium<Torus>(&iv_source_for_b, s->iv_reg,
                                  KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS,
                                  KREYVIUM_REGISTER_B_BITS, N);
  CudaRadixCiphertextFFI dest_b_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_b_slice, s->b_reg, 0,
                                  KREYVIUM_REGISTER_B_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_b_slice, &iv_source_for_b);

  // c[67..111] = iv[0..44]
  CudaRadixCiphertextFFI iv_source_for_c;
  slice_reg_batch_kreyvium<Torus>(&iv_source_for_c, s->iv_reg, 0,
                                  KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS,
                                  N);
  CudaRadixCiphertextFFI dest_c_iv_part;
  slice_reg_batch_kreyvium<Torus>(
      &dest_c_iv_part, s->c_reg,
      KREYVIUM_REGISTER_C_BITS - (KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS),
      KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_c_iv_part, &iv_source_for_c);

  // iv.reverse();
  reverse_bitsliced_radix_inplace_kreyvium<Torus>(
      streams, s->shift_workspace, s->iv_reg, KREYVIUM_IV_BITS, N);

  // for i in 0..66 { c[i + 1] = 1; }
  CudaRadixCiphertextFFI dest_c_ones;
  slice_reg_batch_kreyvium<Torus>(&dest_c_ones, s->c_reg, 1, 66, N);
  host_add_scalar_one_inplace<Torus>(streams, &dest_c_ones,
                                     mem->params.message_modulus,
                                     mem->params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &dest_c_ones, &dest_c_ones, bsks, ksks, mem->luts->flush_lut,
      dest_c_ones.num_radix_blocks);

  // for _ in 0..1152 { kreyvium.next_bit(); } -> 1152 steps is 18 batches of 64
  // steps
  for (int i = 0; i < 18; i++)
    kreyvium_compute_64_steps(streams, mem, nullptr, bsks, ksks);
}

// Main entry point: Generates keystream in batches of 64 steps.
template <typename Torus>
__host__ void host_kreyvium_generate_keystream(
    CudaStreams streams, CudaRadixCiphertextFFI *keystream_output,
    CudaRadixCiphertextFFI const *key_bitsliced,
    CudaRadixCiphertextFFI const *iv_bitsliced, uint32_t num_inputs,
    uint32_t num_steps, int_kreyvium_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {

  PANIC_IF_FALSE(
      num_steps % KREYVIUM_BATCH_SIZE == 0,
      "Kreyvium Error: num_steps must be a multiple of the batch size (64).\n");

  kreyvium_init(streams, mem, key_bitsliced, iv_bitsliced, bsks, ksks);

  uint32_t num_batches = num_steps / KREYVIUM_BATCH_SIZE;
  for (uint32_t i = 0; i < num_batches; i++) {
    CudaRadixCiphertextFFI batch_out_slice;
    slice_reg_batch_kreyvium<Torus>(&batch_out_slice, keystream_output,
                                    i * KREYVIUM_BATCH_SIZE,
                                    KREYVIUM_BATCH_SIZE, num_inputs);
    kreyvium_compute_64_steps(streams, mem, &batch_out_slice, bsks, ksks);
  }
}

template <typename Torus>
uint64_t scratch_cuda_kreyvium_encrypt(CudaStreams streams,
                                       int_kreyvium_buffer<Torus> **mem_ptr,
                                       int_radix_params params,
                                       bool allocate_gpu_memory,
                                       uint32_t num_inputs) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_kreyvium_buffer<Torus>(
      streams, params, allocate_gpu_memory, num_inputs, size_tracker);
  return size_tracker;
}

// Core evaluation function that advances the Kreyvium state by exactly 64
// steps, applying linear updates and non-linear AND gates.
//
template <typename Torus>
__host__ void kreyvium_compute_64_steps_stateful(
    CudaStreams streams, int_kreyvium_stateful_buffer<Torus> *mem,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    CudaRadixCiphertextFFI *output_dest, void *const *bsks,
    uint64_t *const *ksks) {

  uint32_t N = mem->num_inputs;
  constexpr uint32_t BATCH = KREYVIUM_BATCH_SIZE;
  uint32_t batch_size_blocks = BATCH * N;
  auto ws = mem->ws;
  auto luts = mem->luts;

  CudaRadixCiphertextFFI a65, a92, a91, a90, a68;
  slice_reg_batch_kreyvium<Torus>(&a65, a_reg, 27, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a92, a_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a91, a_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a90, a_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a68, a_reg, 24, BATCH, N);
  CudaRadixCiphertextFFI b68, b83, b82, b81, b77;
  slice_reg_batch_kreyvium<Torus>(&b68, b_reg, 15, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b83, b_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b82, b_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b81, b_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b77, b_reg, 6, BATCH, N);
  CudaRadixCiphertextFFI c65, c110, c109, c108, c86;
  slice_reg_batch_kreyvium<Torus>(&c65, c_reg, 45, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c110, c_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c109, c_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c108, c_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c86, c_reg, 24, BATCH, N);
  CudaRadixCiphertextFFI k127, iv127;
  slice_reg_batch_kreyvium<Torus>(&k127, k_reg, *k_offset, 64, N);
  slice_reg_batch_kreyvium<Torus>(&iv127, iv_reg, *iv_offset, 64, N);
  *k_offset = (*k_offset + KREYVIUM_BATCH_SIZE) % KREYVIUM_KEY_BITS;
  *iv_offset = (*iv_offset + KREYVIUM_BATCH_SIZE) % KREYVIUM_IV_BITS;

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->temp_a,
                       &a65, &a92, ws->temp_a->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->temp_b,
                       &b68, &b83, ws->temp_b->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->temp_c,
                       &c65, &c110, ws->temp_c->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), ws->temp_c,
                       ws->temp_c, &k127, ws->temp_c->num_radix_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, ws->temp_c, ws->temp_c, bsks, ksks, luts->flush_lut,
      ws->temp_c->num_radix_blocks);

  CudaRadixCiphertextFFI *lhs_ptrs[] = {&c109, &a91, &b82};
  CudaRadixCiphertextFFI *rhs_ptrs[] = {&c108, &a90, &b81};
  for (uint32_t i = 0; i < KREYVIUM_NUM_AND_GATES; i++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), ws->packed_and_lhs,
        i * batch_size_blocks, (i + 1) * batch_size_blocks, lhs_ptrs[i], 0,
        batch_size_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), ws->packed_and_rhs,
        i * batch_size_blocks, (i + 1) * batch_size_blocks, rhs_ptrs[i], 0,
        batch_size_blocks);
  }
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, ws->packed_and_out, ws->packed_and_lhs, ws->packed_and_rhs, bsks,
      ksks, luts->and_lut, KREYVIUM_NUM_AND_GATES * batch_size_blocks,
      mem->params.message_modulus);

  CudaRadixCiphertextFFI and_c109_c108, and_a91_a90, and_b82_b81;
  CudaRadixCiphertextFFI *and_out_ptrs[] = {&and_c109_c108, &and_a91_a90,
                                            &and_b82_b81};
  for (uint32_t i = 0; i < KREYVIUM_NUM_AND_GATES; i++)
    as_radix_ciphertext_slice<Torus>(and_out_ptrs[i], ws->packed_and_out,
                                     i * batch_size_blocks,
                                     (i + 1) * batch_size_blocks);

  CudaRadixCiphertextFFI flush_new_a, flush_new_b, flush_new_c, flush_out;
  CudaRadixCiphertextFFI *flush_in_slices[] = {&flush_new_a, &flush_new_b,
                                               &flush_new_c, &flush_out};
  for (uint32_t i = 0; i < KREYVIUM_NUM_FLUSH_PATHS; i++)
    as_radix_ciphertext_slice<Torus>(flush_in_slices[i], ws->packed_flush_in,
                                     i * batch_size_blocks,
                                     (i + 1) * batch_size_blocks);

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_a,
                       &and_c109_c108, &a68, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_a,
                       &flush_new_a, ws->temp_c, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       &and_a91_a90, &b77, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       &flush_new_b, ws->temp_a, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_b,
                       &flush_new_b, &iv127, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_c,
                       &and_b82_b81, &c86, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_new_c,
                       &flush_new_c, ws->temp_b, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_out,
                       ws->temp_a, ws->temp_b, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &flush_out,
                       &flush_out, ws->temp_c, batch_size_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, ws->packed_flush_out, ws->packed_flush_in, bsks, ksks,
      luts->flush_lut, ws->packed_flush_out->num_radix_blocks);

  CudaRadixCiphertextFFI flushed_new_a, flushed_new_b, flushed_new_c,
      flushed_out;
  CudaRadixCiphertextFFI *flush_out_slices[] = {&flushed_new_a, &flushed_new_b,
                                                &flushed_new_c, &flushed_out};
  for (uint32_t i = 0; i < KREYVIUM_NUM_FLUSH_PATHS; i++)
    as_radix_ciphertext_slice<Torus>(flush_out_slices[i], ws->packed_flush_out,
                                     i * batch_size_blocks,
                                     (i + 1) * batch_size_blocks);

  shift_and_insert_batch_kreyvium<Torus>(streams, ws->shift_workspace, a_reg,
                                         &flushed_new_a,
                                         KREYVIUM_REGISTER_A_BITS, N);
  shift_and_insert_batch_kreyvium<Torus>(streams, ws->shift_workspace, b_reg,
                                         &flushed_new_b,
                                         KREYVIUM_REGISTER_B_BITS, N);
  shift_and_insert_batch_kreyvium<Torus>(streams, ws->shift_workspace, c_reg,
                                         &flushed_new_c,
                                         KREYVIUM_REGISTER_C_BITS, N);

  if (output_dest != nullptr)
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output_dest, 0,
        batch_size_blocks, &flushed_out, 0, batch_size_blocks);
}

// Initializes the Kreyvium state by loading the Key and IV into the registers
// and executing the standard 1152-cycle warmup phase.
//
template <typename Torus>
__host__ void host_kreyvium_init_stateful(
    CudaStreams streams, int_kreyvium_stateful_buffer<Torus> *mem,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    CudaRadixCiphertextFFI const *key_bitsliced,
    CudaRadixCiphertextFFI const *iv_bitsliced, void *const *bsks,
    uint64_t *const *ksks) {

  uint32_t N = mem->num_inputs;
  *k_offset = 0;
  *iv_offset = 0;

  // k = key_bits.to_vec();
  CudaRadixCiphertextFFI src_key_slice;
  slice_reg_batch_kreyvium<Torus>(&src_key_slice, key_bitsliced, 0,
                                  KREYVIUM_KEY_BITS, N);
  CudaRadixCiphertextFFI dest_k_reg_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_k_reg_slice, k_reg, 0,
                                  KREYVIUM_KEY_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_k_reg_slice, &src_key_slice);

  // a[0..93] = key[35..128]
  CudaRadixCiphertextFFI k_source_for_a;
  slice_reg_batch_kreyvium<Torus>(&k_source_for_a, k_reg,
                                  KREYVIUM_KEY_BITS - KREYVIUM_REGISTER_A_BITS,
                                  KREYVIUM_REGISTER_A_BITS, N);
  CudaRadixCiphertextFFI dest_a_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_a_slice, a_reg, 0,
                                  KREYVIUM_REGISTER_A_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_a_slice, &k_source_for_a);

  // k.reverse();
  reverse_bitsliced_radix_inplace_kreyvium<Torus>(
      streams, mem->ws->shift_workspace, k_reg, KREYVIUM_KEY_BITS, N);

  // iv = iv_bits.to_vec();
  CudaRadixCiphertextFFI src_iv_slice;
  slice_reg_batch_kreyvium<Torus>(&src_iv_slice, iv_bitsliced, 0,
                                  KREYVIUM_IV_BITS, N);
  CudaRadixCiphertextFFI dest_iv_reg_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_iv_reg_slice, iv_reg, 0,
                                  KREYVIUM_IV_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_iv_reg_slice, &src_iv_slice);

  // b[0..84] = iv[44..128]
  CudaRadixCiphertextFFI iv_source_for_b;
  slice_reg_batch_kreyvium<Torus>(&iv_source_for_b, iv_reg,
                                  KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS,
                                  KREYVIUM_REGISTER_B_BITS, N);
  CudaRadixCiphertextFFI dest_b_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_b_slice, b_reg, 0,
                                  KREYVIUM_REGISTER_B_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_b_slice, &iv_source_for_b);

  // c[67..111] = iv[0..44]
  CudaRadixCiphertextFFI iv_source_for_c;
  slice_reg_batch_kreyvium<Torus>(&iv_source_for_c, iv_reg, 0,
                                  KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS,
                                  N);
  CudaRadixCiphertextFFI dest_c_iv_part;
  slice_reg_batch_kreyvium<Torus>(
      &dest_c_iv_part, c_reg,
      KREYVIUM_REGISTER_C_BITS - (KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS),
      KREYVIUM_IV_BITS - KREYVIUM_REGISTER_B_BITS, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_c_iv_part, &iv_source_for_c);

  // iv.reverse();
  reverse_bitsliced_radix_inplace_kreyvium<Torus>(
      streams, mem->ws->shift_workspace, iv_reg, KREYVIUM_IV_BITS, N);

  // for i in 0..66 { c[i + 1] = 1; }
  CudaRadixCiphertextFFI dest_c_ones;
  slice_reg_batch_kreyvium<Torus>(&dest_c_ones, c_reg, 1, 66, N);
  host_add_scalar_one_inplace<Torus>(streams, &dest_c_ones,
                                     mem->params.message_modulus,
                                     mem->params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &dest_c_ones, &dest_c_ones, bsks, ksks, mem->luts->flush_lut,
      dest_c_ones.num_radix_blocks);

  // for _ in 0..1152 { kreyvium.next_bit(); } -> 1152 steps is 18 batches of 64
  // steps
  for (int i = 0; i < 18; i++)
    kreyvium_compute_64_steps_stateful(streams, mem, a_reg, b_reg, c_reg, k_reg,
                                       iv_reg, k_offset, iv_offset, nullptr,
                                       bsks, ksks);
}

// Generates the requested number of keystream bits (in batches of 64) from an
// existing state and updates the internal registers in place.
//
template <typename Torus>
__host__ void host_kreyvium_step_stateful(
    CudaStreams streams, CudaRadixCiphertextFFI *keystream_output,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    uint32_t num_inputs, uint32_t num_steps,
    int_kreyvium_stateful_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {

  PANIC_IF_FALSE(num_steps % KREYVIUM_BATCH_SIZE == 0,
                 "Kreyvium Error: num_steps must be a multiple of 64.\n");
  uint32_t num_batches = num_steps / KREYVIUM_BATCH_SIZE;
  for (uint32_t i = 0; i < num_batches; i++) {
    CudaRadixCiphertextFFI batch_out_slice;
    slice_reg_batch_kreyvium<Torus>(&batch_out_slice, keystream_output,
                                    i * KREYVIUM_BATCH_SIZE,
                                    KREYVIUM_BATCH_SIZE, num_inputs);
    kreyvium_compute_64_steps_stateful(streams, mem, a_reg, b_reg, c_reg, k_reg,
                                       iv_reg, k_offset, iv_offset,
                                       &batch_out_slice, bsks, ksks);
  }
}

template <typename Torus>
uint64_t scratch_cuda_kreyvium_stateful_encrypt(
    CudaStreams streams, int_kreyvium_stateful_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_inputs) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_kreyvium_stateful_buffer<Torus>(
      streams, params, allocate_gpu_memory, num_inputs, size_tracker);
  return size_tracker;
}

#endif
