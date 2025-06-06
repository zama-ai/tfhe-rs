#ifndef CUDA_CIPHERTEXT_H
#define CUDA_CIPHERTEXT_H

#include "stdint.h"

extern "C" {

void cuda_convert_lwe_ciphertext_vector_to_gpu_64(void *stream,
                                                  uint32_t gpu_index,
                                                  void *dest, void const *src,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension);
void cuda_convert_lwe_ciphertext_vector_to_cpu_64(void *stream,
                                                  uint32_t gpu_index,
                                                  void *dest, void const *src,
                                                  uint32_t number_of_cts,
                                                  uint32_t lwe_dimension);

void cuda_glwe_sample_extract_64(void *stream, uint32_t gpu_index,
                                 void *lwe_array_out, void const *glwe_array_in,
                                 uint32_t const *nth_array, uint32_t num_nths,
                                 uint32_t lwe_per_glwe, uint32_t glwe_dimension,
                                 uint32_t polynomial_size);

void cuda_modulus_switch_inplace_64(void *stream, uint32_t gpu_index,
                                    void *lwe_array_out, uint32_t size,
                                    uint32_t log_modulus);

void cuda_improve_noise_modulus_switch_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *lwe_array_indexes,
    void const *encrypted_zeros, uint32_t lwe_size, uint32_t num_lwes,
    uint32_t num_zeros, double input_variance, double r_sigma, double bound,
    uint32_t log_modulus);

void cuda_glwe_sample_extract_128(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *glwe_array_in, uint32_t const *nth_array, uint32_t num_nths,
    uint32_t lwe_per_glwe, uint32_t glwe_dimension, uint32_t polynomial_size);
}

#endif
