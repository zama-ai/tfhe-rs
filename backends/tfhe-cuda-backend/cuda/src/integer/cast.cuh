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
__host__ void
host_trim_radix_blocks_msb(CudaRadixCiphertextFFI *output_radix,
                           const CudaRadixCiphertextFFI *input_radix,
                           CudaStreams streams) {

  PANIC_IF_FALSE(input_radix->num_radix_blocks >=
                     output_radix->num_radix_blocks,
                 "Cuda error: input radix ciphertext has fewer blocks than "
                 "required to keep");

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), output_radix, 0,
      output_radix->num_radix_blocks, input_radix, 0,
      output_radix->num_radix_blocks);
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

template <typename Torus, typename KSTorus>
__host__ void host_extend_radix_with_sign_msb(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input,
    int_extend_radix_with_sign_msb_buffer<Torus> *mem_ptr,
    uint32_t num_additional_blocks, void *const *bsks, KSTorus *const *ksks) {

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

template <typename Torus>
uint64_t scratch_cuda_cast_to_unsigned(
    CudaStreams streams, int_cast_to_unsigned_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_input_blocks,
    uint32_t target_num_blocks, bool input_is_signed,
    bool requires_full_propagate, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_cast_to_unsigned_buffer<Torus>(
      streams, params, num_input_blocks, target_num_blocks, input_is_signed,
      requires_full_propagate, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void
host_cast_to_unsigned(CudaStreams streams, CudaRadixCiphertextFFI *output,
                      CudaRadixCiphertextFFI *input,
                      int_cast_to_unsigned_buffer<Torus> *mem_ptr,
                      uint32_t target_num_blocks, bool input_is_signed,
                      void *const *bsks, Torus *const *ksks) {

  uint32_t current_num_blocks = input->num_radix_blocks;

  if (mem_ptr->requires_full_propagate) {
    host_full_propagate_inplace<Torus>(streams, input, mem_ptr->prop_buffer,
                                       ksks, bsks, current_num_blocks);
  }

  if (target_num_blocks > current_num_blocks) {
    uint32_t num_blocks_to_add = target_num_blocks - current_num_blocks;

    if (input_is_signed) {
      host_extend_radix_with_sign_msb<Torus>(
          streams, output, input, mem_ptr->extend_buffer, num_blocks_to_add,
          bsks, (Torus **)ksks);
    } else {
      host_extend_radix_with_trivial_zero_blocks_msb<Torus>(output, input,
                                                            streams);
    }

  } else if (target_num_blocks < current_num_blocks) {
    host_trim_radix_blocks_msb<Torus>(output, input, streams);

  } else {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), output, 0, current_num_blocks,
        input, 0, current_num_blocks);
  }
}

template <typename Torus>
uint64_t
scratch_cuda_cast_to_signed(CudaStreams streams,
                            int_cast_to_signed_buffer<Torus> **mem_ptr,
                            int_radix_params params, uint32_t num_input_blocks,
                            uint32_t target_num_blocks, bool input_is_signed,
                            bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_cast_to_signed_buffer<Torus>(
      streams, params, num_input_blocks, target_num_blocks, input_is_signed,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void
host_cast_to_signed(CudaStreams streams, CudaRadixCiphertextFFI *output,
                    CudaRadixCiphertextFFI const *input,
                    int_cast_to_signed_buffer<Torus> *mem_ptr,
                    bool input_is_signed, void *const *bsks, Torus **ksks) {

  uint32_t current_num_blocks = input->num_radix_blocks;
  uint32_t target_num_blocks = mem_ptr->target_num_blocks;

  if (input_is_signed) {
    if (target_num_blocks > current_num_blocks) {
      uint32_t num_blocks_to_add = target_num_blocks - current_num_blocks;
      host_extend_radix_with_sign_msb<Torus>(streams, output, input,
                                             mem_ptr->extend_buffer,
                                             num_blocks_to_add, bsks, ksks);
    } else {
      host_trim_radix_blocks_msb<Torus>(output, input, streams);
    }
  } else {
    if (target_num_blocks > current_num_blocks) {
      host_extend_radix_with_trivial_zero_blocks_msb<Torus>(output, input,
                                                            streams);
    } else {
      host_trim_radix_blocks_msb<Torus>(output, input, streams);
    }
  }
}

#endif
