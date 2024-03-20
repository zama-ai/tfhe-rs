#ifndef CUDA_INTEGER_SCALAR_MUL_CUH
#define CUDA_INTEGER_SCALAR_MUL_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer.h"
#include "multiplication.cuh"
#include "scalar_shifts.cuh"
#include "utils/kernel_dimensions.cuh"
#include <stdio.h>

template <typename T>
__global__ void device_small_scalar_radix_multiplication(T *output_lwe_array,
                                                         T *input_lwe_array,
                                                         T scalar,
                                                         uint32_t lwe_dimension,
                                                         uint32_t num_blocks) {
  int index = blockIdx.x * blockDim.x + threadIdx.x;
  int lwe_size = lwe_dimension + 1;
  if (index < num_blocks * lwe_size) {
    // Here we take advantage of the wrapping behaviour of uint
    output_lwe_array[index] = input_lwe_array[index] * scalar;
  }
}

template <typename T>
__host__ void scratch_cuda_integer_radix_scalar_mul_kb(
    cuda_stream_t *stream, int_scalar_mul_buffer<T> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    bool allocate_gpu_memory) {

  cudaSetDevice(stream->gpu_index);
  size_t sm_size = (params.big_lwe_dimension + 1) * sizeof(T);
  check_cuda_error(cudaFuncSetAttribute(
      tree_add_chunks<T>, cudaFuncAttributeMaxDynamicSharedMemorySize,
      sm_size));
  cudaFuncSetCacheConfig(tree_add_chunks<T>, cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  *mem_ptr = new int_scalar_mul_buffer<T>(stream, params, num_radix_blocks,
                                          allocate_gpu_memory);
}

template <typename T, class params>
__host__ void host_integer_scalar_mul_radix(
    cuda_stream_t *stream, T *lwe_array, T *decomposed_scalar,
    T *has_at_least_one_set, int_scalar_mul_buffer<T> *mem, void *bsk, T *ksk,
    uint32_t input_lwe_dimension, uint32_t message_modulus,
    uint32_t num_radix_blocks, uint32_t num_scalars) {

  if (num_radix_blocks == 0 | num_scalars == 0)
    return;

  cudaSetDevice(stream->gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  uint32_t lwe_size = input_lwe_dimension + 1;
  uint32_t lwe_size_bytes = lwe_size * sizeof(T);
  uint32_t msg_bits = (uint32_t)std::log2(message_modulus);
  uint32_t num_ciphertext_bits = msg_bits * num_radix_blocks;

  T *preshifted_buffer = mem->preshifted_buffer;
  T *all_shifted_buffer = mem->all_shifted_buffer;

  for (size_t shift_amount = 0; shift_amount < msg_bits; shift_amount++) {
    T *ptr = preshifted_buffer + shift_amount * lwe_size * num_radix_blocks;
    if (has_at_least_one_set[shift_amount] == 1) {
      cuda_memcpy_async_gpu_to_gpu(ptr, lwe_array,
                                   lwe_size_bytes * num_radix_blocks, stream);
      host_integer_radix_logical_scalar_shift_kb_inplace(
          stream, ptr, shift_amount, mem->logical_scalar_shift_buffer, bsk, ksk,
          num_radix_blocks);
    } else {
      // create trivial assign for value = 0
      cuda_memset_async(ptr, 0, num_radix_blocks * lwe_size_bytes, stream);
    }
  }
  size_t j = 0;
  for (size_t i = 0; i < min(num_scalars, num_ciphertext_bits); i++) {
    if (decomposed_scalar[i] == 1) {
      // Perform a block shift
      T *preshifted_radix_ct =
          preshifted_buffer + (i % msg_bits) * num_radix_blocks * lwe_size;
      T *block_shift_buffer =
          all_shifted_buffer + j * num_radix_blocks * lwe_size;
      radix_blocks_rotate_right<<<num_radix_blocks, 256, 0, stream->stream>>>(
          block_shift_buffer, preshifted_radix_ct, i / msg_bits,
          num_radix_blocks, lwe_size);
      // create trivial assign for value = 0
      cuda_memset_async(block_shift_buffer, 0, (i / msg_bits) * lwe_size_bytes,
                        stream);
      j++;
    }
  }

  if (j == 0) {
    // lwe array = 0
    cuda_memset_async(lwe_array, 0, num_radix_blocks * lwe_size_bytes, stream);
  } else {
    int terms_degree[j * num_radix_blocks];
    for (int i = 0; i < j * num_radix_blocks; i++) {
      terms_degree[i] = message_modulus - 1;
    }
    host_integer_sum_ciphertexts_vec_kb<T, params>(
        stream, lwe_array, all_shifted_buffer, terms_degree, bsk, ksk,
        mem->sum_ciphertexts_vec_mem, num_radix_blocks, j);
  }
}

// Small scalar_mul is used in shift/rotate
template <typename T>
__host__ void host_integer_small_scalar_mul_radix(
    cuda_stream_t *stream, T *output_lwe_array, T *input_lwe_array, T scalar,
    uint32_t input_lwe_dimension, uint32_t input_lwe_ciphertext_count) {

  cudaSetDevice(stream->gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  device_small_scalar_radix_multiplication<<<grid, thds, 0, stream->stream>>>(
      output_lwe_array, input_lwe_array, scalar, input_lwe_dimension,
      input_lwe_ciphertext_count);
  check_cuda_error(cudaGetLastError());
}
#endif
