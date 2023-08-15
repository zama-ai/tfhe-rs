#ifndef CUDA_CIPHERTEXT_CUH
#define CUDA_CIPHERTEXT_CUH

#include "ciphertext.h"
#include "device.h"
#include <cstdint>

template <typename T>
void cuda_convert_lwe_ciphertext_vector_to_gpu(T *dest, T *src,
                                               cuda_stream_t *stream,
                                               uint32_t number_of_cts,
                                               uint32_t lwe_dimension) {
  cudaSetDevice(stream->gpu_index);
  uint64_t size = number_of_cts * (lwe_dimension + 1) * sizeof(T);
  cuda_memcpy_async_to_gpu(dest, src, size, stream);
}

void cuda_convert_lwe_ciphertext_vector_to_gpu_64(void *dest, void *src,
                                                  cuda_stream_t *stream,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension) {
  cuda_convert_lwe_ciphertext_vector_to_gpu<uint64_t>(
      (uint64_t *)dest, (uint64_t *)src, stream, number_of_cts, lwe_dimension);
}

template <typename T>
void cuda_convert_lwe_ciphertext_vector_to_cpu(T *dest, T *src,
                                               cuda_stream_t *stream,
                                               uint32_t number_of_cts,
                                               uint32_t lwe_dimension) {
  cudaSetDevice(stream->gpu_index);
  uint64_t size = number_of_cts * (lwe_dimension + 1) * sizeof(T);
  cuda_memcpy_async_to_cpu(dest, src, size, stream);
}

void cuda_convert_lwe_ciphertext_vector_to_cpu_64(void *dest, void *src,
                                                  cuda_stream_t *stream,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension) {
  cuda_convert_lwe_ciphertext_vector_to_cpu<uint64_t>(
      (uint64_t *)dest, (uint64_t *)src, stream, number_of_cts, lwe_dimension);
}

#endif
