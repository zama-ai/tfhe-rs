#ifndef CUDA_ADD_CUH
#define CUDA_ADD_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "../utils/kernel_dimensions.cuh"
#include "device.h"
#include "linear_algebra.h"
#include <stdio.h>

template <typename T>
__global__ void plaintext_addition(T *output, T *lwe_input, T *plaintext_input,
                                   uint32_t input_lwe_dimension,
                                   uint32_t num_entries) {

  int tid = threadIdx.x;
  int plaintext_index = blockIdx.x * blockDim.x + tid;
  if (plaintext_index < num_entries) {
    int index =
        plaintext_index * (input_lwe_dimension + 1) + input_lwe_dimension;
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] + plaintext_input[plaintext_index];
  }
}

template <typename T>
__host__ void host_addition_plaintext(cuda_stream_t *stream, T *output,
                                      T *lwe_input, T *plaintext_input,
                                      uint32_t lwe_dimension,
                                      uint32_t lwe_ciphertext_count) {

  cudaSetDevice(stream->gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(
      output, lwe_input, (lwe_dimension + 1) * lwe_ciphertext_count, stream);
  plaintext_addition<<<grid, thds, 0, stream->stream>>>(
      output, lwe_input, plaintext_input, lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void addition(T *output, T *input_1, T *input_2,
                         uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] + input_2[index];
  }
}

// Coefficient-wise addition
template <typename T>
__host__ void host_addition(cuda_stream_t *stream, T *output, T *input_1,
                            T *input_2, uint32_t input_lwe_dimension,
                            uint32_t input_lwe_ciphertext_count) {

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

  addition<<<grid, thds, 0, stream->stream>>>(output, input_1, input_2,
                                              num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void subtraction(T *output, T *input_1, T *input_2,
                            uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] - input_2[index];
  }
}

// Coefficient-wise subtraction
template <typename T>
__host__ void host_subtraction(cuda_stream_t *stream, T *output, T *input_1,
                               T *input_2, uint32_t input_lwe_dimension,
                               uint32_t input_lwe_ciphertext_count) {

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

  subtraction<<<grid, thds, 0, stream->stream>>>(output, input_1, input_2,
                                                 num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void radix_body_subtraction_inplace(T *lwe_ct, T *plaintext_input,
                                               uint32_t input_lwe_dimension,
                                               uint32_t num_entries) {

  int tid = threadIdx.x;
  int plaintext_index = blockIdx.x * blockDim.x + tid;
  if (plaintext_index < num_entries) {
    int index =
        plaintext_index * (input_lwe_dimension + 1) + input_lwe_dimension;
    // Here we take advantage of the wrapping behaviour of uint
    lwe_ct[index] -= plaintext_input[plaintext_index];
  }
}

template <typename T>
__host__ void host_subtraction_plaintext(cuda_stream_t *stream, T *output,
                                         T *lwe_input, T *plaintext_input,
                                         uint32_t input_lwe_dimension,
                                         uint32_t input_lwe_ciphertext_count) {

  cudaSetDevice(stream->gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(output, lwe_input,
                               input_lwe_ciphertext_count *
                                   (input_lwe_dimension + 1) * sizeof(T),
                               stream);

  radix_body_subtraction_inplace<<<grid, thds, 0, stream->stream>>>(
      output, plaintext_input, input_lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}
#endif // CUDA_ADD_H
