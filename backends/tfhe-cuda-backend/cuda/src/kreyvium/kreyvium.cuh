#ifndef KREYVIUM_CUH
#define KREYVIUM_CUH

#include "../../include/kreyvium/kreyvium_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"
#include "../integer/scalar_addition.cuh"
#include "../linearalgebra/addition.cuh"

template <typename Torus>
__host__ void slice_reg_batch_kreyvium(CudaRadixCiphertextFFI *slice,
                                       const CudaRadixCiphertextFFI *reg,
                                       uint32_t start_bit_idx,
                                       uint32_t num_bits, uint32_t num_inputs) {
  as_radix_ciphertext_slice<Torus>(slice, reg, start_bit_idx * num_inputs,
                                   (start_bit_idx + num_bits) * num_inputs);
}

template <typename Torus>
__host__ void rotate_128_batch(CudaStreams streams,
                               int_kreyvium_buffer<Torus> *mem,
                               CudaRadixCiphertextFFI *reg) {
  uint32_t N = mem->num_inputs;
  uint32_t HALF_SIZE = 64 * N;
  CudaRadixCiphertextFFI *temp = mem->state->shift_workspace;

  copy_radix_ciphertext_slice_async<Torus>(streams.stream(0),
                                           streams.gpu_index(0), temp, 0,
                                           HALF_SIZE, reg, 0, HALF_SIZE);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), reg, 0, HALF_SIZE, reg,
      HALF_SIZE, 2 * HALF_SIZE);
  copy_radix_ciphertext_slice_async<Torus>(streams.stream(0),
                                           streams.gpu_index(0), reg, HALF_SIZE,
                                           2 * HALF_SIZE, temp, 0, HALF_SIZE);
}

template <typename Torus>
__host__ void shift_and_insert_batch_kreyvium(CudaStreams streams,
                                              int_kreyvium_buffer<Torus> *mem,
                                              CudaRadixCiphertextFFI *reg,
                                              CudaRadixCiphertextFFI *new_bits,
                                              uint32_t reg_size,
                                              uint32_t num_inputs) {
  constexpr uint32_t BATCH = 64;
  CudaRadixCiphertextFFI *temp = mem->state->shift_workspace;
  uint32_t num_blocks_to_keep = (reg_size - BATCH) * num_inputs;

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), temp, 0, num_blocks_to_keep, reg,
      BATCH * num_inputs, reg_size * num_inputs);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), temp, num_blocks_to_keep,
      reg_size * num_inputs, new_bits, 0, BATCH * num_inputs);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), reg, 0, reg_size * num_inputs,
      temp, 0, reg_size * num_inputs);
}

template <typename Torus>
void reverse_bitsliced_radix_inplace_kreyvium(CudaStreams streams,
                                              int_kreyvium_buffer<Torus> *mem,
                                              CudaRadixCiphertextFFI *radix,
                                              uint32_t num_bits_in_reg) {
  uint32_t N = mem->num_inputs;
  CudaRadixCiphertextFFI *temp = mem->state->shift_workspace;

  for (uint32_t i = 0; i < num_bits_in_reg; i++) {
    uint32_t src_start = i * N;
    uint32_t src_end = (i + 1) * N;
    uint32_t dest_start = (num_bits_in_reg - 1 - i) * N;
    uint32_t dest_end = (num_bits_in_reg - i) * N;

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), temp, dest_start, dest_end,
        radix, src_start, src_end);
  }

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), radix, 0, num_bits_in_reg * N,
      temp, 0, num_bits_in_reg * N);
}

template <typename Torus>
__host__ void kreyvium_add(CudaStreams streams, int_kreyvium_buffer<Torus> *mem,
                           CudaRadixCiphertextFFI *out,
                           const CudaRadixCiphertextFFI *lhs,
                           const CudaRadixCiphertextFFI *rhs) {
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), out, lhs, rhs,
                       out->num_radix_blocks, mem->params.message_modulus,
                       mem->params.carry_modulus);
}

template <typename Torus>
__host__ void
kreyvium_compute_64_steps(CudaStreams streams, int_kreyvium_buffer<Torus> *mem,
                          CudaRadixCiphertextFFI *output_dest,
                          void *const *bsks, uint64_t *const *ksks) {

  uint32_t N = mem->num_inputs;
  constexpr uint32_t BATCH = 64;
  uint32_t batch_size_blocks = BATCH * N;
  auto s = mem->state;
  auto luts = mem->luts;

  CudaRadixCiphertextFFI a65, a92, a91, a90, a68;
  slice_reg_batch_kreyvium<Torus>(&a65, s->a_reg, 27, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a92, s->a_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a91, s->a_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a90, s->a_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&a68, s->a_reg, 24, BATCH, N);

  CudaRadixCiphertextFFI b68, b83, b82, b81, b77;
  slice_reg_batch_kreyvium<Torus>(&b68, s->b_reg, 15, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b83, s->b_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b82, s->b_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b81, s->b_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&b77, s->b_reg, 6, BATCH, N);

  CudaRadixCiphertextFFI c65, c110, c109, c108, c86;
  slice_reg_batch_kreyvium<Torus>(&c65, s->c_reg, 45, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c110, s->c_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c109, s->c_reg, 1, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c108, s->c_reg, 2, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&c86, s->c_reg, 24, BATCH, N);

  CudaRadixCiphertextFFI k127, iv127;
  slice_reg_batch_kreyvium<Torus>(&k127, s->k_reg, 0, BATCH, N);
  slice_reg_batch_kreyvium<Torus>(&iv127, s->iv_reg, 0, BATCH, N);

  kreyvium_add<Torus>(streams, mem, s->temp_a, &a65, &a92);

  kreyvium_add<Torus>(streams, mem, s->temp_b, &b68, &b83);

  kreyvium_add<Torus>(streams, mem, s->temp_c, &c65, &c110);
  kreyvium_add<Torus>(streams, mem, s->temp_c, s->temp_c, &k127);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_and_lhs, 0,
      batch_size_blocks, &c109, 0, batch_size_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_and_lhs,
      batch_size_blocks, 2 * batch_size_blocks, &a91, 0, batch_size_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_and_lhs,
      2 * batch_size_blocks, 3 * batch_size_blocks, &b82, 0, batch_size_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_and_rhs, 0,
      batch_size_blocks, &c108, 0, batch_size_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_and_rhs,
      batch_size_blocks, 2 * batch_size_blocks, &a90, 0, batch_size_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_and_rhs,
      2 * batch_size_blocks, 3 * batch_size_blocks, &b81, 0, batch_size_blocks);

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, s->packed_and_out, s->packed_and_lhs, s->packed_and_rhs, bsks,
      ksks, luts->and_lut, 3 * batch_size_blocks, mem->params.message_modulus);

  CudaRadixCiphertextFFI and_c109_c108, and_a91_a90, and_b82_b81;
  as_radix_ciphertext_slice<Torus>(&and_c109_c108, s->packed_and_out, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&and_a91_a90, s->packed_and_out,
                                   batch_size_blocks, 2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&and_b82_b81, s->packed_and_out,
                                   2 * batch_size_blocks,
                                   3 * batch_size_blocks);

  kreyvium_add<Torus>(streams, mem, s->new_a, &and_c109_c108, &a68);
  kreyvium_add<Torus>(streams, mem, s->new_a, s->new_a, s->temp_c);

  kreyvium_add<Torus>(streams, mem, s->new_b, &and_a91_a90, &b77);
  kreyvium_add<Torus>(streams, mem, s->new_b, s->new_b, s->temp_a);
  kreyvium_add<Torus>(streams, mem, s->new_b, s->new_b, &iv127);

  kreyvium_add<Torus>(streams, mem, s->new_c, &and_b82_b81, &c86);
  kreyvium_add<Torus>(streams, mem, s->new_c, s->new_c, s->temp_b);

  kreyvium_add<Torus>(streams, mem, s->out, s->temp_a, s->temp_b);
  kreyvium_add<Torus>(streams, mem, s->out, s->out, s->temp_c);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_flush_in, 0,
      batch_size_blocks, s->new_a, 0, batch_size_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_flush_in,
      batch_size_blocks, 2 * batch_size_blocks, s->new_b, 0, batch_size_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_flush_in,
      2 * batch_size_blocks, 3 * batch_size_blocks, s->new_c, 0,
      batch_size_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), s->packed_flush_in,
      3 * batch_size_blocks, 4 * batch_size_blocks, s->out, 0,
      batch_size_blocks);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, s->packed_flush_out, s->packed_flush_in, bsks, ksks,
      luts->flush_lut, 4 * batch_size_blocks);

  CudaRadixCiphertextFFI flushed_new_a, flushed_new_b, flushed_new_c,
      flushed_out;
  as_radix_ciphertext_slice<Torus>(&flushed_new_a, s->packed_flush_out, 0,
                                   batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flushed_new_b, s->packed_flush_out,
                                   batch_size_blocks, 2 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flushed_new_c, s->packed_flush_out,
                                   2 * batch_size_blocks,
                                   3 * batch_size_blocks);
  as_radix_ciphertext_slice<Torus>(&flushed_out, s->packed_flush_out,
                                   3 * batch_size_blocks,
                                   4 * batch_size_blocks);

  shift_and_insert_batch_kreyvium(streams, mem, s->a_reg, &flushed_new_a, 93,
                                  N);
  shift_and_insert_batch_kreyvium(streams, mem, s->b_reg, &flushed_new_b, 84,
                                  N);
  shift_and_insert_batch_kreyvium(streams, mem, s->c_reg, &flushed_new_c, 111,
                                  N);

  rotate_128_batch(streams, mem, s->k_reg);
  rotate_128_batch(streams, mem, s->iv_reg);

  if (output_dest != nullptr) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output_dest, 0,
        batch_size_blocks, &flushed_out, 0, batch_size_blocks);
  }
}

template <typename Torus>
__host__ void kreyvium_init(CudaStreams streams,
                            int_kreyvium_buffer<Torus> *mem,
                            CudaRadixCiphertextFFI const *key_bitsliced,
                            CudaRadixCiphertextFFI const *iv_bitsliced,
                            void *const *bsks, uint64_t *const *ksks) {
  uint32_t N = mem->num_inputs;
  auto s = mem->state;

  CudaRadixCiphertextFFI src_key_slice;
  slice_reg_batch_kreyvium<Torus>(&src_key_slice, key_bitsliced, 0, 128, N);

  CudaRadixCiphertextFFI dest_k_reg_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_k_reg_slice, s->k_reg, 0, 128, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_k_reg_slice, &src_key_slice);

  CudaRadixCiphertextFFI k_source_for_a;
  slice_reg_batch_kreyvium<Torus>(&k_source_for_a, s->k_reg, 35, 93, N);

  CudaRadixCiphertextFFI dest_a_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_a_slice, s->a_reg, 0, 93, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_a_slice, &k_source_for_a);

  reverse_bitsliced_radix_inplace_kreyvium<Torus>(streams, mem, s->k_reg, 128);

  CudaRadixCiphertextFFI src_iv_slice;
  slice_reg_batch_kreyvium<Torus>(&src_iv_slice, iv_bitsliced, 0, 128, N);

  CudaRadixCiphertextFFI dest_iv_reg_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_iv_reg_slice, s->iv_reg, 0, 128, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_iv_reg_slice, &src_iv_slice);

  CudaRadixCiphertextFFI iv_source_for_b;
  slice_reg_batch_kreyvium<Torus>(&iv_source_for_b, s->iv_reg, 44, 84, N);

  CudaRadixCiphertextFFI dest_b_slice;
  slice_reg_batch_kreyvium<Torus>(&dest_b_slice, s->b_reg, 0, 84, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_b_slice, &iv_source_for_b);

  CudaRadixCiphertextFFI iv_source_for_c;
  slice_reg_batch_kreyvium<Torus>(&iv_source_for_c, s->iv_reg, 0, 44, N);

  CudaRadixCiphertextFFI dest_c_iv_part;
  slice_reg_batch_kreyvium<Torus>(&dest_c_iv_part, s->c_reg, 67, 44, N);
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &dest_c_iv_part, &iv_source_for_c);

  reverse_bitsliced_radix_inplace_kreyvium<Torus>(streams, mem, s->iv_reg, 128);

  CudaRadixCiphertextFFI dest_c_ones;
  slice_reg_batch_kreyvium<Torus>(&dest_c_ones, s->c_reg, 1, 66, N);
  host_add_scalar_one_inplace<Torus>(streams, &dest_c_ones,
                                     mem->params.message_modulus,
                                     mem->params.carry_modulus);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &dest_c_ones, &dest_c_ones, bsks, ksks, mem->luts->flush_lut,
      dest_c_ones.num_radix_blocks);

  for (int i = 0; i < 18; i++) {
    kreyvium_compute_64_steps(streams, mem, nullptr, bsks, ksks);
  }
}

template <typename Torus>
__host__ void host_kreyvium_generate_keystream(
    CudaStreams streams, CudaRadixCiphertextFFI *keystream_output,
    CudaRadixCiphertextFFI const *key_bitsliced,
    CudaRadixCiphertextFFI const *iv_bitsliced, uint32_t num_inputs,
    uint32_t num_steps, int_kreyvium_buffer<Torus> *mem, void *const *bsks,
    uint64_t *const *ksks) {

  kreyvium_init(streams, mem, key_bitsliced, iv_bitsliced, bsks, ksks);

  uint32_t num_batches = num_steps / 64;
  for (uint32_t i = 0; i < num_batches; i++) {
    CudaRadixCiphertextFFI batch_out_slice;
    slice_reg_batch_kreyvium<Torus>(&batch_out_slice, keystream_output, i * 64,
                                    64, num_inputs);
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

#endif
