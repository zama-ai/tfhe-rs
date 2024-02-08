#ifndef CUDA_INTEGER_SHIFT_OPS_CUH
#define CUDA_INTEGER_SHIFT_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer.h"
#include "pbs/bootstrap_low_latency.cuh"
#include "pbs/bootstrap_multibit.cuh"
#include "types/complex/operations.cuh"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__host__ void scratch_cuda_integer_radix_scalar_shift_kb(
    cuda_stream_t *stream, int_shift_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, SHIFT_TYPE shift_type,
    bool allocate_gpu_memory) {

  cudaSetDevice(stream->gpu_index);
  *mem_ptr = new int_shift_buffer<Torus>(stream, shift_type, params,
                                         num_radix_blocks, allocate_gpu_memory);
}

template <typename Torus>
__host__ void host_integer_radix_scalar_shift_kb_inplace(
    cuda_stream_t *stream, Torus *lwe_array, uint32_t shift,
    int_shift_buffer<Torus> *mem, void *bsk, Torus *ksk, uint32_t num_blocks) {

  cudaSetDevice(stream->gpu_index);
  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;

  size_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  size_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  size_t num_bits_in_block = (size_t)log2(message_modulus);
  size_t total_num_bits = num_bits_in_block * num_blocks;
  shift = shift % total_num_bits;

  if (shift == 0) {
    return;
  }
  size_t rotations = std::min(shift / num_bits_in_block, (size_t)num_blocks);
  size_t shift_within_block = shift % num_bits_in_block;

  Torus *full_rotated_buffer = mem->tmp_rotated;
  Torus *rotated_buffer = &full_rotated_buffer[big_lwe_size];

  auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

  // rotate right all the blocks in radix ciphertext
  // copy result in new buffer
  // 256 threads are used in every block
  // block_count blocks will be used in the grid
  // one block is responsible to process single lwe ciphertext
  if (mem->shift_type == LEFT_SHIFT) {
    radix_blocks_rotate_right<<<num_blocks, 256, 0, stream->stream>>>(
        rotated_buffer, lwe_array, rotations, num_blocks, big_lwe_size);

    // create trivial assign for value = 0
    cuda_memset_async(rotated_buffer, 0, rotations * big_lwe_size_bytes,
                      stream);
    cuda_memcpy_async_gpu_to_gpu(lwe_array, rotated_buffer,
                                 num_blocks * big_lwe_size_bytes, stream);

    if (shift_within_block == 0 || rotations == num_blocks) {
      return;
    }

    auto partial_current_blocks = &lwe_array[rotations * big_lwe_size];
    auto partial_previous_blocks =
        &full_rotated_buffer[rotations * big_lwe_size];

    size_t partial_block_count = num_blocks - rotations;

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        stream, partial_current_blocks, partial_current_blocks,
        partial_previous_blocks, bsk, ksk, partial_block_count, lut_bivariate);

  } else {
    // right shift
    radix_blocks_rotate_left<<<num_blocks, 256, 0, stream->stream>>>(
        rotated_buffer, lwe_array, rotations, num_blocks, big_lwe_size);

    // rotate left as the blocks are from LSB to MSB
    // create trivial assign for value = 0
    cuda_memset_async(rotated_buffer + (num_blocks - rotations) * big_lwe_size,
                      0, rotations * big_lwe_size_bytes, stream);
    cuda_memcpy_async_gpu_to_gpu(lwe_array, rotated_buffer,
                                 num_blocks * big_lwe_size_bytes, stream);

    if (shift_within_block == 0 || rotations == num_blocks) {
      return;
    }

    auto partial_current_blocks = lwe_array;
    auto partial_next_blocks = &rotated_buffer[big_lwe_size];

    size_t partial_block_count = num_blocks - rotations;

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        stream, partial_current_blocks, partial_current_blocks,
        partial_next_blocks, bsk, ksk, partial_block_count, lut_bivariate);
  }
}

#endif // CUDA_SCALAR_OPS_CUH
