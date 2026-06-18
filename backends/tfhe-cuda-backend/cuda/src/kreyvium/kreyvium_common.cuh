#ifndef KREYVIUM_COMMON_CUH
#define KREYVIUM_COMMON_CUH

#include "../integer/radix_ciphertext.cuh"

// Creates a view (slice) of specific bits in a register.
// Used to access specific taps like a[65], k[127], etc.
template <typename Torus>
__host__ void slice_reg_batch_impl(CudaRadixCiphertextFFI *slice,
                                   const CudaRadixCiphertextFFI *reg,
                                   uint32_t start_bit_idx, uint32_t num_bits,
                                   uint32_t num_inputs) {
  as_radix_ciphertext_slice<Torus>(slice, reg, start_bit_idx * num_inputs,
                                   (start_bit_idx + num_bits) * num_inputs);
}

// Standard shift-and-insert for Kreyvium registers A, B, C.
// Shifts the register and inserts new bits at the start.
template <typename Torus>
__host__ void shift_and_insert_batch_impl(
    CudaStreams streams, CudaRadixCiphertextFFI *shift_workspace,
    CudaRadixCiphertextFFI *reg, CudaRadixCiphertextFFI *new_bits,
    uint32_t reg_size, uint32_t num_inputs, uint32_t batch_size) {
  uint32_t num_blocks_to_keep = (reg_size - batch_size) * num_inputs;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), shift_workspace, 0,
      num_blocks_to_keep, reg, batch_size * num_inputs, reg_size * num_inputs);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), shift_workspace,
      num_blocks_to_keep, reg_size * num_inputs, new_bits, 0,
      batch_size * num_inputs);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), reg, 0, reg_size * num_inputs,
      shift_workspace, 0, reg_size * num_inputs);
}

// Reverses the order of blocks in a ciphertext buffer.
// Essential for aligning Key/IV bit ordering.
template <typename Torus>
void reverse_bitsliced_radix_inplace_impl(
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

#endif
