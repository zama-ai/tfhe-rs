#ifndef CUDA_INTEGER_ADD_CUH
#define CUDA_INTEGER_ADD_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer/integer_utilities.h"
#include "utils/kernel_dimensions.cuh"
#include <stdio.h>

template <typename Torus>
__global__ void device_integer_radix_scalar_addition_inplace(
    Torus *lwe_array, Torus const *scalar_input, int32_t num_blocks,
    uint32_t lwe_dimension, uint64_t delta) {

  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    lwe_array[tid * (lwe_dimension + 1) + lwe_dimension] +=
        scalar_input[tid] * delta;
  }
}

template <typename Torus>
__host__ void host_integer_radix_scalar_addition_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, Torus const *scalar_input,
    uint32_t lwe_dimension, uint32_t input_lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus) {
  cudaSetDevice(gpu_indexes[0]);

  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_integer_radix_scalar_addition_inplace<Torus>
      <<<grid, thds, 0, streams[0]>>>(lwe_array, scalar_input,
                                      input_lwe_ciphertext_count, lwe_dimension,
                                      delta);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__global__ void device_integer_radix_add_scalar_one_inplace(
    Torus *lwe_array, int32_t num_blocks, uint32_t lwe_dimension,
    uint64_t delta) {

  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    Torus *body = lwe_array + tid * (lwe_dimension + 1) + lwe_dimension;
    *body += delta;
  }
}

template <typename Torus>
__host__ void host_integer_radix_add_scalar_one_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, uint32_t lwe_dimension,
    uint32_t input_lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus) {
  cudaSetDevice(gpu_indexes[0]);

  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_integer_radix_add_scalar_one_inplace<Torus>
      <<<grid, thds, 0, streams[0]>>>(lwe_array, input_lwe_ciphertext_count,
                                      lwe_dimension, delta);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__global__ void device_integer_radix_scalar_subtraction_inplace(
    Torus *lwe_array, Torus *scalar_input, int32_t num_blocks,
    uint32_t lwe_dimension, uint64_t delta) {

  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    Torus scalar = scalar_input[tid];
    Torus *body = lwe_array + tid * (lwe_dimension + 1) + lwe_dimension;

    *body -= scalar * delta;
  }
}

template <typename Torus>
__host__ void host_integer_radix_scalar_subtraction_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, Torus *scalar_input,
    uint32_t lwe_dimension, uint32_t input_lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus) {
  cudaSetDevice(gpu_indexes[0]);

  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_integer_radix_scalar_subtraction_inplace<Torus>
      <<<grid, thds, 0, streams[0]>>>(lwe_array, scalar_input,
                                      input_lwe_ciphertext_count, lwe_dimension,
                                      delta);
  check_cuda_error(cudaGetLastError());
}
#endif
