#ifndef CUDA_CIPHERTEXT_H
#define CUDA_CIPHERTEXT_H

#include <cstdint>

extern "C" {
void cuda_convert_lwe_ciphertext_vector_to_gpu_64(void *dest, void *src,
                                                  void *v_stream,
                                                  uint32_t gpu_index,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension);
void cuda_convert_lwe_ciphertext_vector_to_cpu_64(void *dest, void *src,
                                                  void *v_stream,
                                                  uint32_t gpu_index,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension);
};
#endif
