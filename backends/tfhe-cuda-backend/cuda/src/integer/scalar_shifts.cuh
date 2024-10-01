#ifndef CUDA_INTEGER_SCALAR_SHIFT_CUH
#define CUDA_INTEGER_SCALAR_SHIFT_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "types/complex/operations.cuh"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__host__ void scratch_cuda_integer_radix_logical_scalar_shift_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_logical_scalar_shift_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool allocate_gpu_memory) {

  *mem_ptr = new int_logical_scalar_shift_buffer<Torus>(
      streams, gpu_indexes, gpu_count, shift_type, params, num_radix_blocks,
      allocate_gpu_memory);
}

template <typename Torus>
__host__ void host_integer_radix_logical_scalar_shift_kb_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, uint32_t shift,
    int_logical_scalar_shift_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t num_blocks) {

  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;

  size_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  size_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  size_t num_bits_in_block = (size_t)log2_int(message_modulus);
  size_t total_num_bits = num_bits_in_block * num_blocks;
  shift = shift % total_num_bits;

  if (shift == 0) {
    return;
  }
  size_t rotations = std::min(shift / num_bits_in_block, (size_t)num_blocks);
  size_t shift_within_block = shift % num_bits_in_block;

  Torus *full_rotated_buffer = mem->tmp_rotated;
  Torus *rotated_buffer = &full_rotated_buffer[big_lwe_size];

  if (mem->shift_type == LEFT_SHIFT) {
    // rotate right as the blocks are from LSB to MSB
    host_radix_blocks_rotate_right<Torus>(streams, gpu_indexes, gpu_count,
                                          rotated_buffer, lwe_array, rotations,
                                          num_blocks, big_lwe_size);

    // create trivial assign for value = 0
    cuda_memset_async(rotated_buffer, 0, rotations * big_lwe_size_bytes,
                      streams[0], gpu_indexes[0]);
    cuda_memcpy_async_gpu_to_gpu(lwe_array, rotated_buffer,
                                 num_blocks * big_lwe_size_bytes, streams[0],
                                 gpu_indexes[0]);

    if (shift_within_block == 0 || rotations == num_blocks) {
      return;
    }

    auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];
    auto partial_current_blocks = &lwe_array[rotations * big_lwe_size];
    auto partial_previous_blocks =
        &full_rotated_buffer[rotations * big_lwe_size];

    size_t partial_block_count = num_blocks - rotations;

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, partial_current_blocks,
        partial_current_blocks, partial_previous_blocks, bsks, ksks,
        partial_block_count, lut_bivariate,
        lut_bivariate->params.message_modulus);

  } else {
    // right shift
    host_radix_blocks_rotate_left<Torus>(streams, gpu_indexes, gpu_count,
                                         rotated_buffer, lwe_array, rotations,
                                         num_blocks, big_lwe_size);

    // rotate left as the blocks are from LSB to MSB
    // create trivial assign for value = 0
    cuda_memset_async(rotated_buffer + (num_blocks - rotations) * big_lwe_size,
                      0, rotations * big_lwe_size_bytes, streams[0],
                      gpu_indexes[0]);
    cuda_memcpy_async_gpu_to_gpu(lwe_array, rotated_buffer,
                                 num_blocks * big_lwe_size_bytes, streams[0],
                                 gpu_indexes[0]);

    if (shift_within_block == 0 || rotations == num_blocks) {
      return;
    }

    auto partial_current_blocks = lwe_array;
    auto partial_next_blocks = &rotated_buffer[big_lwe_size];
    auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

    size_t partial_block_count = num_blocks - rotations;

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, partial_current_blocks,
        partial_current_blocks, partial_next_blocks, bsks, ksks,
        partial_block_count, lut_bivariate,
        lut_bivariate->params.message_modulus);
  }
}

template <typename Torus>
__host__ void scratch_cuda_integer_radix_arithmetic_scalar_shift_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_arithmetic_scalar_shift_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool allocate_gpu_memory) {

  *mem_ptr = new int_arithmetic_scalar_shift_buffer<Torus>(
      streams, gpu_indexes, gpu_count, shift_type, params, num_radix_blocks,
      allocate_gpu_memory);
}

template <typename Torus>
__host__ void host_integer_radix_arithmetic_scalar_shift_kb_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, uint32_t shift,
    int_arithmetic_scalar_shift_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t num_blocks) {

  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;

  size_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  size_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  size_t num_bits_in_block = (size_t)log2_int(message_modulus);
  size_t total_num_bits = num_bits_in_block * num_blocks;
  shift = shift % total_num_bits;

  if (shift == 0) {
    return;
  }
  size_t rotations = std::min(shift / num_bits_in_block, (size_t)num_blocks);
  size_t shift_within_block = shift % num_bits_in_block;

  Torus *rotated_buffer = mem->tmp_rotated;
  Torus *padding_block = &rotated_buffer[(num_blocks + 1) * big_lwe_size];
  Torus *last_block_copy = &padding_block[big_lwe_size];

  if (mem->shift_type == RIGHT_SHIFT) {
    host_radix_blocks_rotate_left<Torus>(streams, gpu_indexes, gpu_count,
                                         rotated_buffer, lwe_array, rotations,
                                         num_blocks, big_lwe_size);
    cuda_memcpy_async_gpu_to_gpu(lwe_array, rotated_buffer,
                                 num_blocks * big_lwe_size_bytes, streams[0],
                                 gpu_indexes[0]);

    if (num_bits_in_block == 1) {
      // if there is only 1 bit in the msg part, it means shift_within block is
      // 0 thus only rotations is required.

      // We still need to pad with the value of the sign bit.
      // And here since a block only has 1 bit of message
      // we can optimize things by not doing the pbs to extract this sign bit

      Torus *block_src =
          rotated_buffer + (num_blocks - rotations - 1) * big_lwe_size;
      Torus *block_dest =
          rotated_buffer + (num_blocks - rotations) * big_lwe_size;
      for (uint i = 0; i < num_blocks; i++) {
        cuda_memcpy_async_gpu_to_gpu(block_dest, block_src, big_lwe_size_bytes,
                                     streams[0], gpu_indexes[0]);
        block_dest += big_lwe_size;
      }
      return;
    }

    if (num_blocks != rotations) {
      // In the arithmetic shift case we have to pad with the value of the sign
      // bit. This creates the need for a different shifting lut than in the
      // logical shift case. We also need another PBS to create the padding
      // block.
      Torus *last_block =
          lwe_array + (num_blocks - rotations - 1) * big_lwe_size;
      cuda_memcpy_async_gpu_to_gpu(
          last_block_copy,
          rotated_buffer + (num_blocks - rotations - 1) * big_lwe_size,
          big_lwe_size_bytes, streams[0], gpu_indexes[0]);
      if (shift_within_block != 0) {
        auto partial_current_blocks = lwe_array;
        auto partial_next_blocks = &rotated_buffer[big_lwe_size];
        size_t partial_block_count = num_blocks - rotations;
        auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

        integer_radix_apply_bivariate_lookup_table_kb<Torus>(
            streams, gpu_indexes, gpu_count, partial_current_blocks,
            partial_current_blocks, partial_next_blocks, bsks, ksks,
            partial_block_count, lut_bivariate,
            lut_bivariate->params.message_modulus);
      }
      // Since our CPU threads will be working on different streams we shall
      // assert the work in the main stream is completed
      for (uint j = 0; j < gpu_count; j++) {
        cuda_synchronize_stream(streams[j], gpu_indexes[j]);
      }
      auto lut_univariate_padding_block =
          mem->lut_buffers_univariate[num_bits_in_block - 1];
      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          mem->local_streams_1, gpu_indexes, gpu_count, padding_block,
          last_block_copy, bsks, ksks, 1, lut_univariate_padding_block);
      // Replace blocks 'pulled' from the left with the correct padding
      // block
      for (uint i = 0; i < rotations; i++) {
        cuda_memcpy_async_gpu_to_gpu(lwe_array + (num_blocks - rotations + i) *
                                                     big_lwe_size,
                                     padding_block, big_lwe_size_bytes,
                                     mem->local_streams_1[0], gpu_indexes[0]);
      }
      if (shift_within_block != 0) {
        auto lut_univariate_shift_last_block =
            mem->lut_buffers_univariate[shift_within_block - 1];
        integer_radix_apply_univariate_lookup_table_kb<Torus>(
            mem->local_streams_2, gpu_indexes, gpu_count, last_block,
            last_block_copy, bsks, ksks, 1, lut_univariate_shift_last_block);
      }
      for (uint j = 0; j < mem->active_gpu_count; j++) {
        cuda_synchronize_stream(mem->local_streams_1[j], gpu_indexes[j]);
        cuda_synchronize_stream(mem->local_streams_2[j], gpu_indexes[j]);
      }
    }
  } else {
    PANIC("Cuda error (scalar shift): left scalar shift is never of the "
          "arithmetic type")
  }
}

#endif // CUDA_SCALAR_SHIFT_CUH
