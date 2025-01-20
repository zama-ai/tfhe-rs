#ifndef CUDA_ADD_CUH
#define CUDA_ADD_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "helper_multi_gpu.h"
#include "integer/integer.h"
#include "linear_algebra.h"
#include "utils/kernel_dimensions.cuh"
#include <stdio.h>

template <typename T>
__global__ void plaintext_addition(T *output, T const *lwe_input,
                                   T const *plaintext_input,
                                   const uint32_t input_lwe_dimension,
                                   const uint32_t num_entries) {

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
__global__ void plaintext_addition_scalar(T *output, T const *lwe_input,
                                          const T plaintext_input,
                                          const uint32_t input_lwe_dimension,
                                          const uint32_t num_entries) {

  int tid = threadIdx.x;
  int lwe_index = blockIdx.x * blockDim.x + tid;
  if (lwe_index < num_entries) {
    int index = lwe_index * (input_lwe_dimension + 1) + input_lwe_dimension;
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] + plaintext_input;
  }
}

template <typename T>
__host__ void host_addition_plaintext(cudaStream_t stream, uint32_t gpu_index,
                                      T *output, T const *lwe_input,
                                      T const *plaintext_input,
                                      const uint32_t lwe_dimension,
                                      const uint32_t lwe_ciphertext_count) {

  cudaSetDevice(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(
      output, lwe_input, (lwe_dimension + 1) * lwe_ciphertext_count * sizeof(T),
      stream, gpu_index);
  plaintext_addition<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, plaintext_input, lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__host__ void host_addition_plaintext_scalar(
    cudaStream_t stream, uint32_t gpu_index, T *output, T const *lwe_input,
    const T plaintext_input, const uint32_t lwe_dimension,
    const uint32_t lwe_ciphertext_count) {

  cudaSetDevice(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(
      output, lwe_input, (lwe_dimension + 1) * lwe_ciphertext_count * sizeof(T),
      stream, gpu_index);
  plaintext_addition_scalar<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, plaintext_input, lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void addition(T *output, T const *input_1, T const *input_2,
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
__host__ void host_addition(cudaStream_t stream, uint32_t gpu_index,
                            CudaRadixCiphertextFFI *output,
                            CudaRadixCiphertextFFI const *input_1,
                            CudaRadixCiphertextFFI const *input_2) {

  cudaSetDevice(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = output->lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = output->num_radix_blocks * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  addition<T><<<grid, thds, 0, stream>>>(
      static_cast<T *>(output->ptr), static_cast<const T *>(input_1->ptr),
      static_cast<const T *>(input_2->ptr), num_entries);
  check_cuda_error(cudaGetLastError());
  for (uint i = 0; i < output->num_radix_blocks; i++) {
    output->degrees[i] = input_1->degrees[i] + input_2->degrees[i];
    output->noise_levels[i] =
        input_1->noise_levels[i] + input_2->noise_levels[i];
  }
}

// Coefficient-wise addition
template <typename T>
__host__ void legacy_host_addition(cudaStream_t stream, uint32_t gpu_index,
                                   T *output, T const *input_1,
                                   T const *input_2,
                                   const uint32_t input_lwe_dimension,
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

  addition<T><<<grid, thds, 0, stream>>>(output, input_1, input_2, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void pack_for_overflowing_ops(T *output, T const *input_1,
                                         T const *input_2, uint32_t num_entries,
                                         uint32_t message_modulus) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] * message_modulus + input_2[index];
  }
}

template <typename T>
__host__ void host_pack_for_overflowing_ops(cudaStream_t stream,
                                            uint32_t gpu_index, T *output,
                                            T const *input_1, T const *input_2,
                                            uint32_t input_lwe_dimension,
                                            uint32_t input_lwe_ciphertext_count,
                                            uint32_t message_modulus) {

  cudaSetDevice(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  pack_for_overflowing_ops<T><<<grid, thds, 0, stream>>>(
      &output[(input_lwe_ciphertext_count - 1) * lwe_size],
      &input_1[(input_lwe_ciphertext_count - 1) * lwe_size],
      &input_2[(input_lwe_ciphertext_count - 1) * lwe_size], lwe_size,
      message_modulus);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void subtraction(T *output, T const *input_1, T const *input_2,
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
__host__ void host_subtraction(cudaStream_t stream, uint32_t gpu_index,
                               T *output, T const *input_1, T const *input_2,
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

  subtraction<T>
      <<<grid, thds, 0, stream>>>(output, input_1, input_2, num_entries);
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
__host__ void host_subtraction_plaintext(cudaStream_t stream,
                                         uint32_t gpu_index, T *output,
                                         T *lwe_input, T *plaintext_input,
                                         uint32_t input_lwe_dimension,
                                         uint32_t input_lwe_ciphertext_count) {

  cudaSetDevice(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(output, lwe_input,
                               input_lwe_ciphertext_count *
                                   (input_lwe_dimension + 1) * sizeof(T),
                               stream, gpu_index);

  radix_body_subtraction_inplace<T><<<grid, thds, 0, stream>>>(
      output, plaintext_input, input_lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void
unchecked_sub_with_correcting_term(T *output, T const *input_1,
                                   T const *input_2, uint32_t num_entries,
                                   uint32_t lwe_size, uint32_t message_modulus,
                                   uint32_t carry_modulus, uint32_t degree) {
  uint32_t msg_mod = message_modulus;
  uint64_t z = max((uint64_t)ceil(degree / msg_mod), (uint64_t)1);
  z *= msg_mod;
  uint64_t delta = (1ULL << 63) / (message_modulus * carry_modulus);

  uint64_t w = z * delta;

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] + ((0 - input_2[index]));
    if (index % lwe_size == lwe_size - 1)
      output[index] += w;
  }
}
template <typename T>
__host__ void host_unchecked_sub_with_correcting_term(
    cudaStream_t stream, uint32_t gpu_index, T *output, T const *input_1,
    T const *input_2, uint32_t input_lwe_dimension,
    uint32_t input_lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, uint32_t degree) {

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

  unchecked_sub_with_correcting_term<T><<<grid, thds, 0, stream>>>(
      output, input_1, input_2, num_entries, lwe_size, message_modulus,
      carry_modulus, degree);
  check_cuda_error(cudaGetLastError());
}

#endif // CUDA_ADD_H
