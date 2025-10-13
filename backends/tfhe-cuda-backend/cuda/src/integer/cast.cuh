#ifndef CAST_CUH
#define CAST_CUH

#include "device.h"
#include "integer.cuh"
#include "integer/cast.h"
#include "integer/integer_utilities.h"

template <typename Torus>
__host__ void host_extend_radix_with_trivial_zero_blocks_msb(
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    CudaStreams streams) {
  PUSH_RANGE("extend only")
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), output, 0,
      input->num_radix_blocks, input, 0, input->num_radix_blocks);
  POP_RANGE()
}

template <typename Torus>
__host__ void host_trim_radix_blocks_lsb(CudaRadixCiphertextFFI *output,
                                         CudaRadixCiphertextFFI const *input,
                                         CudaStreams streams) {

  const uint32_t input_start_lwe_index =
      input->num_radix_blocks - output->num_radix_blocks;

  PANIC_IF_FALSE(input->num_radix_blocks > output->num_radix_blocks,
                 "Cuda error: input num blocks (%d) should be greater than "
                 "output num blocks (%d)",
                 input->num_radix_blocks, output->num_radix_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), output, 0,
      output->num_radix_blocks, input, input_start_lwe_index,
      input->num_radix_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_extend_radix_with_sign_msb(
    CudaStreams streams, int_extend_radix_with_sign_msb_buffer<Torus> **mem_ptr,
    const int_radix_params params, uint32_t num_radix_blocks,
    uint32_t num_additional_blocks, const bool allocate_gpu_memory) {
  PUSH_RANGE("scratch cast/extend")
  uint64_t size_tracker = 0;

  *mem_ptr = new int_extend_radix_with_sign_msb_buffer<Torus>(
      streams, params, num_radix_blocks, num_additional_blocks,
      allocate_gpu_memory, size_tracker);
  POP_RANGE()
  return size_tracker;
}

template <typename Torus>
__host__ void host_extend_radix_with_sign_msb(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input,
    int_extend_radix_with_sign_msb_buffer<Torus> *mem_ptr,
    uint32_t num_additional_blocks, void *const *bsks, Torus *const *ksks) {

  if (num_additional_blocks == 0) {
    PUSH_RANGE("cast/extend no addblocks")
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       output, input);
    POP_RANGE()
    return;
  }
  PUSH_RANGE("cast/extend")
  const uint32_t input_blocks = input->num_radix_blocks;

  PANIC_IF_FALSE(input_blocks > 0, "Cuda error: input blocks cannot be zero");

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), output, 0, input_blocks, input,
      0, input_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->last_block, 0, 1, input,
      input_blocks - 1, input_blocks);

  host_apply_univariate_lut(streams, mem_ptr->padding_block,
                            mem_ptr->last_block, mem_ptr->lut, ksks, bsks);

  for (uint32_t i = 0; i < num_additional_blocks; ++i) {
    uint32_t dst_block_idx = input_blocks + i;

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output, dst_block_idx,
        dst_block_idx + 1, mem_ptr->padding_block, 0, 1);
  }
  POP_RANGE()
}

#endif
