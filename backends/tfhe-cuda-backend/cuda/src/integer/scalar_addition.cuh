#ifndef CUDA_INTEGER_ADD_CUH
#define CUDA_INTEGER_ADD_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "helper_multi_gpu.h"
#include "utils/kernel_dimensions.cuh"
#include <stdio.h>

template <typename Torus>
__global__ void
device_scalar_addition_inplace(Torus *lwe_array, Torus const *scalar_input,
                               int32_t num_blocks, uint32_t lwe_dimension,
                               uint64_t delta) {

  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    lwe_array[tid * (lwe_dimension + 1) + lwe_dimension] +=
        scalar_input[tid] * delta;
  }
}

template <typename Torus>
__host__ void host_scalar_addition_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array,
    Torus const *scalar_input, Torus const *h_scalar_input,
    uint32_t num_scalars, uint32_t message_modulus, uint32_t carry_modulus) {
  if (lwe_array->num_radix_blocks < num_scalars)
    PANIC("Cuda error: num scalars should be smaller or equal to input num "
          "radix blocks")
  cuda_set_device(streams.gpu_index(0));

  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_scalars;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_scalar_addition_inplace<Torus><<<grid, thds, 0, streams.stream(0)>>>(
      (Torus *)lwe_array->ptr, scalar_input, num_scalars,
      lwe_array->lwe_dimension, delta);
  check_cuda_error(cudaGetLastError());
  for (uint i = 0; i < num_scalars; i++) {
    lwe_array->degrees[i] = lwe_array->degrees[i] + h_scalar_input[i];
  }
}

template <typename Torus>
__global__ void
device_add_scalar_one_inplace(Torus *lwe_array, int32_t num_blocks,
                              uint32_t lwe_dimension, uint64_t delta) {

  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    Torus *body = lwe_array + tid * (lwe_dimension + 1) + lwe_dimension;
    *body += delta;
  }
}

template <typename Torus>
__host__ void host_add_scalar_one_inplace(CudaStreams streams,
                                          CudaRadixCiphertextFFI *lwe_array,
                                          uint32_t message_modulus,
                                          uint32_t carry_modulus) {
  cuda_set_device(streams.gpu_index(0));

  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_array->num_radix_blocks;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_add_scalar_one_inplace<Torus><<<grid, thds, 0, streams.stream(0)>>>(
      (Torus *)lwe_array->ptr, lwe_array->num_radix_blocks,
      lwe_array->lwe_dimension, delta);
  check_cuda_error(cudaGetLastError());
  for (uint i = 0; i < lwe_array->num_radix_blocks; i++) {
    lwe_array->degrees[i] = lwe_array->degrees[i] + 1;
  }
}

template <typename Torus>
__global__ void
device_scalar_subtraction_inplace(Torus *lwe_array, Torus *scalar_input,
                                  int32_t num_blocks, uint32_t lwe_dimension,
                                  uint64_t delta) {

  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    Torus scalar = scalar_input[tid];
    Torus *body = lwe_array + tid * (lwe_dimension + 1) + lwe_dimension;

    *body -= scalar * delta;
  }
}

template <typename Torus>
__host__ void host_scalar_subtraction_inplace(
    CudaStreams streams, Torus *lwe_array, Torus *scalar_input,
    uint32_t lwe_dimension, uint32_t input_lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus) {
  cuda_set_device(streams.gpu_index(0));

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

  device_scalar_subtraction_inplace<Torus>
      <<<grid, thds, 0, streams.stream(0)>>>(lwe_array, scalar_input,
                                             input_lwe_ciphertext_count,
                                             lwe_dimension, delta);
  check_cuda_error(cudaGetLastError());
}
#endif
