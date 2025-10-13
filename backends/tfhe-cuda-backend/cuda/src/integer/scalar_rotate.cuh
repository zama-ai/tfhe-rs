#ifndef CUDA_INTEGER_SCALAR_ROTATE_OPS_CUH
#define CUDA_INTEGER_SCALAR_ROTATE_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/scalar_shifts.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_scalar_rotate(
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
__host__ void
host_scalar_rotate_inplace(CudaStreams streams,
                           CudaRadixCiphertextFFI *lwe_array, uint32_t n,
                           int_logical_scalar_shift_buffer<Torus> *mem,
                           void *const *bsks, Torus *const *ksks) {

  auto num_blocks = lwe_array->num_radix_blocks;
  auto params = mem->params;
  auto message_modulus = params.message_modulus;

  size_t num_bits_in_message = (size_t)log2_int(message_modulus);
  size_t total_num_bits = num_bits_in_message * num_blocks;
  n = n % total_num_bits;

  if (n == 0) {
    return;
  }
  size_t rotations = n / num_bits_in_message;
  size_t shift_within_block = n % num_bits_in_message;

  auto rotated_buffer = mem->tmp_rotated;

  // rotate right all the blocks in radix ciphertext
  // copy result in new buffer
  // 256 threads are used in every block
  // block_count blocks will be used in the grid
  // one block is responsible to process single lwe ciphertext
  if (mem->shift_type == LEFT_SHIFT) {
    // rotate right as the blocks are from LSB to MSB
    host_radix_blocks_rotate_right<Torus>(streams, rotated_buffer, lwe_array,
                                          rotations, num_blocks);

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, 0, num_blocks,
        rotated_buffer, 0, num_blocks);

    if (shift_within_block == 0) {
      return;
    }

    auto receiver_blocks = lwe_array;
    auto giver_blocks = rotated_buffer;
    host_radix_blocks_rotate_right<Torus>(streams, giver_blocks, lwe_array, 1,
                                          num_blocks);

    auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, lwe_array, receiver_blocks, giver_blocks, bsks, ksks,
        lut_bivariate, num_blocks, lut_bivariate->params.message_modulus);

  } else {
    // rotate left as the blocks are from LSB to MSB
    host_radix_blocks_rotate_left<Torus>(streams, rotated_buffer, lwe_array,
                                         rotations, num_blocks);

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, 0, num_blocks,
        rotated_buffer, 0, num_blocks);

    if (shift_within_block == 0) {
      return;
    }

    auto receiver_blocks = lwe_array;
    auto giver_blocks = rotated_buffer;
    host_radix_blocks_rotate_left<Torus>(streams, giver_blocks, lwe_array, 1,
                                         num_blocks);

    auto lut_bivariate = mem->lut_buffers_bivariate[shift_within_block - 1];

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, lwe_array, receiver_blocks, giver_blocks, bsks, ksks,
        lut_bivariate, num_blocks, lut_bivariate->params.message_modulus);
  }
}

#endif // CUDA_INTEGER_SCALAR_ROTATE_OPS_CUH
