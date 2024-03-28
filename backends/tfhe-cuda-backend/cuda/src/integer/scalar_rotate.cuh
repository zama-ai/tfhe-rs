#ifndef CUDA_INTEGER_SCALAR_ROTATE_OPS_CUH
#define CUDA_INTEGER_SCALAR_ROTATE_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "types/complex/operations.cuh"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__host__ void scratch_cuda_integer_radix_scalar_rotate_kb(
    cuda_stream_t *stream, int_logical_scalar_shift_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool allocate_gpu_memory) {

  cudaSetDevice(stream->gpu_index);
  *mem_ptr = new int_logical_scalar_shift_buffer<Torus>(
      stream, shift_type, params, num_radix_blocks, allocate_gpu_memory);
}

template <typename Torus>
__host__ void host_integer_radix_scalar_rotate_kb_inplace(
    cuda_stream_t *stream, Torus *lwe_array, uint32_t n,
    int_logical_scalar_shift_buffer<Torus> *mem, void *bsk, Torus *ksk,
    uint32_t num_blocks) {

  cudaSetDevice(stream->gpu_index);
  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;

  size_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  size_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  size_t num_bits_in_message = (size_t)log2(message_modulus);
  size_t total_num_bits = num_bits_in_message * num_blocks;
  n = n % total_num_bits;

  if (n == 0) {
    return;
  }
  size_t rotations = n / num_bits_in_message;
  size_t shift_within_block = n % num_bits_in_message;

  Torus *rotated_buffer = mem->tmp_rotated;

  auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

  // rotate right all the blocks in radix ciphertext
  // copy result in new buffer
  // 256 threads are used in every block
  // block_count blocks will be used in the grid
  // one block is responsible to process single lwe ciphertext
  if (mem->shift_type == LEFT_SHIFT) {
    radix_blocks_rotate_right<<<num_blocks, 256, 0, stream->stream>>>(
        rotated_buffer, lwe_array, rotations, num_blocks, big_lwe_size);

    cuda_memcpy_async_gpu_to_gpu(lwe_array, rotated_buffer,
                                 num_blocks * big_lwe_size_bytes, stream);

    if (shift_within_block == 0) {
      return;
    }

    auto receiver_blocks = lwe_array;
    auto giver_blocks = rotated_buffer;
    radix_blocks_rotate_right<<<num_blocks, 256, 0, stream->stream>>>(
        giver_blocks, lwe_array, 1, num_blocks, big_lwe_size);

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        stream, lwe_array, receiver_blocks, giver_blocks, bsk, ksk, num_blocks,
        lut_bivariate);

  } else {
    // left shift
    radix_blocks_rotate_left<<<num_blocks, 256, 0, stream->stream>>>(
        rotated_buffer, lwe_array, rotations, num_blocks, big_lwe_size);

    cuda_memcpy_async_gpu_to_gpu(lwe_array, rotated_buffer,
                                 num_blocks * big_lwe_size_bytes, stream);

    if (shift_within_block == 0) {
      return;
    }

    auto receiver_blocks = lwe_array;
    auto giver_blocks = rotated_buffer;
    radix_blocks_rotate_left<<<num_blocks, 256, 0, stream->stream>>>(
        giver_blocks, lwe_array, 1, num_blocks, big_lwe_size);

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        stream, lwe_array, receiver_blocks, giver_blocks, bsk, ksk, num_blocks,
        lut_bivariate);
  }
}

#endif // CUDA_INTEGER_SCALAR_ROTATE_OPS_CUH
