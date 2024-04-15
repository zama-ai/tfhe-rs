#ifndef CUDA_CIPHERTEXT_CUH
#define CUDA_CIPHERTEXT_CUH

#include "ciphertext.h"
#include "device.h"
#include <cstdint>

template <typename T>
void cuda_convert_lwe_ciphertext_vector_to_gpu(cudaStream_t stream,
                                               uint32_t gpu_index, T *dest,
                                               T *src, uint32_t number_of_cts,
                                               uint32_t lwe_dimension) {
  cudaSetDevice(gpu_index);
  uint64_t size = number_of_cts * (lwe_dimension + 1) * sizeof(T);
  cuda_memcpy_async_to_gpu(dest, src, size, stream, gpu_index);
}

template <typename T>
void cuda_convert_lwe_ciphertext_vector_to_cpu(cudaStream_t stream,
                                               uint32_t gpu_index, T *dest,
                                               T *src, uint32_t number_of_cts,
                                               uint32_t lwe_dimension) {
  cudaSetDevice(gpu_index);
  uint64_t size = number_of_cts * (lwe_dimension + 1) * sizeof(T);
  cuda_memcpy_async_to_cpu(dest, src, size, stream, gpu_index);
}

#endif
