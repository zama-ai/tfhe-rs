#include "ciphertext.cuh"

void cuda_convert_lwe_ciphertext_vector_to_gpu_64(void *stream,
                                                  uint32_t gpu_index,
                                                  void *dest, void *src,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension) {
  cuda_convert_lwe_ciphertext_vector_to_gpu<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)dest,
      (uint64_t *)src, number_of_cts, lwe_dimension);
}

void cuda_convert_lwe_ciphertext_vector_to_cpu_64(void *stream,
                                                  uint32_t gpu_index,
                                                  void *dest, void *src,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension) {
  cuda_convert_lwe_ciphertext_vector_to_cpu<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)dest,
      (uint64_t *)src, number_of_cts, lwe_dimension);
}
