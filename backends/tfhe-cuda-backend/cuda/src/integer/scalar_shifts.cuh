#ifndef CUDA_INTEGER_SCALAR_SHIFT_CUH
#define CUDA_INTEGER_SCALAR_SHIFT_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/scalar_shifts.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_logical_scalar_shift(
    CudaStreams streams, int_logical_scalar_shift_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_logical_scalar_shift_buffer<Torus>(
      streams, shift_type, params, num_radix_blocks, allocate_gpu_memory,
      size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ void host_logical_scalar_shift_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array, uint32_t shift,
    int_logical_scalar_shift_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t num_blocks) {

  if (lwe_array->num_radix_blocks < num_blocks)
    PANIC("Cuda error: input does not have enough blocks")
  auto params = mem->params;
  auto message_modulus = params.message_modulus;

  size_t num_bits_in_block = (size_t)log2_int(message_modulus);
  size_t total_num_bits = num_bits_in_block * num_blocks;
  shift = shift % total_num_bits;

  if (shift == 0) {
    return;
  }
  size_t rotations = std::min(shift / num_bits_in_block, (size_t)num_blocks);
  size_t shift_within_block = shift % num_bits_in_block;

  CudaRadixCiphertextFFI *full_rotated_buffer = mem->tmp_rotated;
  CudaRadixCiphertextFFI rotated_buffer;
  as_radix_ciphertext_slice<Torus>(&rotated_buffer, full_rotated_buffer, 1,
                                   full_rotated_buffer->num_radix_blocks);

  if (mem->shift_type == LEFT_SHIFT) {
    // rotate right as the blocks are from LSB to MSB
    host_radix_blocks_rotate_right<Torus>(streams, &rotated_buffer, lwe_array,
                                          rotations, num_blocks);

    // create trivial assign for value = 0
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &rotated_buffer, 0, rotations);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, 0, num_blocks,
        &rotated_buffer, 0, num_blocks);

    if (shift_within_block == 0 || rotations == num_blocks) {
      return;
    }

    auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];
    CudaRadixCiphertextFFI partial_current_blocks;
    as_radix_ciphertext_slice<Torus>(&partial_current_blocks, lwe_array,
                                     rotations, lwe_array->num_radix_blocks);
    CudaRadixCiphertextFFI partial_previous_blocks;
    as_radix_ciphertext_slice<Torus>(&partial_previous_blocks,
                                     full_rotated_buffer, rotations,
                                     full_rotated_buffer->num_radix_blocks);

    size_t partial_block_count = num_blocks - rotations;

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &partial_current_blocks, &partial_current_blocks,
        &partial_previous_blocks, bsks, ksks, lut_bivariate,
        partial_block_count, lut_bivariate->params.message_modulus);

  } else {
    // right shift
    host_radix_blocks_rotate_left<Torus>(streams, &rotated_buffer, lwe_array,
                                         rotations, num_blocks);

    // rotate left as the blocks are from LSB to MSB
    // create trivial assign for value = 0
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &rotated_buffer,
        num_blocks - rotations, num_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, 0, num_blocks,
        &rotated_buffer, 0, num_blocks);

    if (shift_within_block == 0 || rotations == num_blocks) {
      return;
    }

    auto partial_current_blocks = lwe_array;
    CudaRadixCiphertextFFI partial_next_blocks;
    as_radix_ciphertext_slice<Torus>(&partial_next_blocks, &rotated_buffer, 1,
                                     rotated_buffer.num_radix_blocks);
    auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

    size_t partial_block_count = num_blocks - rotations;

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, partial_current_blocks, partial_current_blocks,
        &partial_next_blocks, bsks, ksks, lut_bivariate, partial_block_count,
        lut_bivariate->params.message_modulus);
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_arithmetic_scalar_shift(
    CudaStreams streams, int_arithmetic_scalar_shift_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_arithmetic_scalar_shift_buffer<Torus>(
      streams, shift_type, params, num_radix_blocks, allocate_gpu_memory,
      size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ void host_arithmetic_scalar_shift_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array, uint32_t shift,
    int_arithmetic_scalar_shift_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks) {

  auto num_blocks = lwe_array->num_radix_blocks;
  auto params = mem->params;
  auto message_modulus = params.message_modulus;

  size_t num_bits_in_block = (size_t)log2_int(message_modulus);
  size_t total_num_bits = num_bits_in_block * num_blocks;
  shift = shift % total_num_bits;

  if (shift == 0) {
    return;
  }
  size_t rotations = std::min(shift / num_bits_in_block, (size_t)num_blocks);
  size_t shift_within_block = shift % num_bits_in_block;

  CudaRadixCiphertextFFI padding_block;
  as_radix_ciphertext_slice<Torus>(&padding_block, mem->tmp_rotated,
                                   num_blocks + 1, num_blocks + 2);
  CudaRadixCiphertextFFI last_block_copy;
  as_radix_ciphertext_slice<Torus>(&last_block_copy, mem->tmp_rotated,
                                   num_blocks + 2, num_blocks + 3);

  if (mem->shift_type == RIGHT_SHIFT) {
    host_radix_blocks_rotate_left<Torus>(streams, mem->tmp_rotated, lwe_array,
                                         rotations, num_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, 0, num_blocks,
        mem->tmp_rotated, 0, num_blocks);

    if (num_bits_in_block == 1) {
      // if there is only 1 bit in the msg part, it means shift_within block is
      // 0 thus only rotations is required.

      // We still need to pad with the value of the sign bit.
      // And here since a block only has 1 bit of message
      // we can optimize things by not doing the pbs to extract this sign bit
      for (uint i = 0; i < num_blocks; i++) {
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0), mem->tmp_rotated,
            num_blocks - rotations + i, num_blocks - rotations + i + 1,
            mem->tmp_rotated, num_blocks - rotations - 1,
            num_blocks - rotations);
      }
      return;
    }

    if (num_blocks != rotations) {
      // In the arithmetic shift case we have to pad with the value of the sign
      // bit. This creates the need for a different shifting lut than in the
      // logical shift case. We also need another PBS to create the padding
      // block.
      CudaRadixCiphertextFFI last_block;
      as_radix_ciphertext_slice<Torus>(&last_block, lwe_array,
                                       num_blocks - rotations - 1,
                                       num_blocks - rotations);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &last_block_copy, 0, 1,
          mem->tmp_rotated, num_blocks - rotations - 1, num_blocks - rotations);
      if (shift_within_block != 0) {
        auto partial_current_blocks = lwe_array;
        CudaRadixCiphertextFFI partial_next_blocks;
        as_radix_ciphertext_slice<Torus>(&partial_next_blocks, mem->tmp_rotated,
                                         1, mem->tmp_rotated->num_radix_blocks);
        size_t partial_block_count = num_blocks - rotations;
        auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

        integer_radix_apply_bivariate_lookup_table<Torus>(
            streams, partial_current_blocks, partial_current_blocks,
            &partial_next_blocks, bsks, ksks, lut_bivariate,
            partial_block_count, lut_bivariate->params.message_modulus);
      }
      // Since our CPU threads will be working on different streams we shall
      // Ensure the work in the main stream is completed
      streams.synchronize();
      auto lut_univariate_padding_block =
          mem->lut_buffers_univariate[num_bits_in_block - 1];
      integer_radix_apply_univariate_lookup_table<Torus>(
          mem->local_streams_1, &padding_block, &last_block_copy, bsks, ksks,
          lut_univariate_padding_block, 1);
      // Replace blocks 'pulled' from the left with the correct padding
      // block
      for (uint i = 0; i < rotations; i++) {
        copy_radix_ciphertext_slice_async<Torus>(
            mem->local_streams_1.stream(0), mem->local_streams_1.gpu_index(0),
            lwe_array, num_blocks - rotations + i,
            num_blocks - rotations + i + 1, &padding_block, 0, 1);
      }
      if (shift_within_block != 0) {
        auto lut_univariate_shift_last_block =
            mem->lut_buffers_univariate[shift_within_block - 1];
        integer_radix_apply_univariate_lookup_table<Torus>(
            mem->local_streams_2, &last_block, &last_block_copy, bsks, ksks,
            lut_univariate_shift_last_block, 1);
      }

      mem->local_streams_1.synchronize();
      mem->local_streams_2.synchronize();
    }
  } else {
    PANIC("Cuda error (scalar shift): left scalar shift is never of the "
          "arithmetic type")
  }
}

#endif // CUDA_SCALAR_SHIFT_CUH
