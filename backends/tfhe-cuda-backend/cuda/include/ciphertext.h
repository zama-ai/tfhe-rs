#ifndef CUDA_CIPHERTEXT_H
#define CUDA_CIPHERTEXT_H

#include "device.h"
#include <cstdint>

extern "C" {
void cuda_convert_lwe_ciphertext_vector_to_gpu_64(void *stream,
                                                  uint32_t gpu_index,
                                                  void *dest, void *src,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension);
void cuda_convert_lwe_ciphertext_vector_to_cpu_64(void *stream,
                                                  uint32_t gpu_index,
                                                  void *dest, void *src,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension);

void cuda_glwe_sample_extract_64(void *stream, uint32_t gpu_index,
                                 void *lwe_array_out, void *glwe_array_in,
                                 uint32_t *nth_array, uint32_t num_glwes,
                                 uint32_t glwe_dimension,
                                 uint32_t polynomial_size);
};
#endif
