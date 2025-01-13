#ifndef CUDA_MULT_CUH
#define CUDA_MULT_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "../utils/kernel_dimensions.cuh"
#include "device.h"
#include "linear_algebra.h"
#include <fstream>
#include <iostream>
#include <vector>

template <typename T>
__global__ void cleartext_vec_multiplication(T *output, T const *lwe_input,
                                             T const *cleartext_input,
                                             const uint32_t input_lwe_dimension,
                                             const uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    int cleartext_index = index / (input_lwe_dimension + 1);
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] * cleartext_input[cleartext_index];
  }
}

template <typename T>
__host__ void host_cleartext_vec_multiplication(
    cudaStream_t stream, uint32_t gpu_index, T *output, T const *lwe_input,
    T const *cleartext_input, const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count) {

  cudaSetDevice(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cleartext_vec_multiplication<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, cleartext_input, input_lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void
cleartext_multiplication(T *output, T const *lwe_input, T cleartext_input,
                         uint32_t input_lwe_dimension, uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] * cleartext_input;
  }
}

template <typename T>
__host__ void
host_cleartext_multiplication(cudaStream_t stream, uint32_t gpu_index,
                              T *output, T const *lwe_input, T cleartext_input,
                              uint32_t input_lwe_dimension,
                              uint32_t input_lwe_ciphertext_count) {

  cudaSetDevice(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cleartext_multiplication<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, cleartext_input, input_lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

#endif // CUDA_MULT_H
