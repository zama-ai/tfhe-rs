#ifndef CUDA_LINALG_H_
#define CUDA_LINALG_H_

#include <stdint.h>

extern "C" {

void cuda_negate_lwe_ciphertext_vector_32(void *stream, uint32_t gpu_index,
                                          void *lwe_array_out,
                                          void const *lwe_array_in,
                                          uint32_t input_lwe_dimension,
                                          uint32_t input_lwe_ciphertext_count);
void cuda_negate_lwe_ciphertext_vector_64(void *stream, uint32_t gpu_index,
                                          void *lwe_array_out,
                                          void const *lwe_array_in,
                                          uint32_t input_lwe_dimension,
                                          uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_32(void *stream, uint32_t gpu_index,
                                       void *lwe_array_out,
                                       void const *lwe_array_in_1,
                                       void const *lwe_array_in_2,
                                       uint32_t input_lwe_dimension,
                                       uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_64(void *stream, uint32_t gpu_index,
                                       void *lwe_array_out,
                                       void const *lwe_array_in_1,
                                       void const *lwe_array_in_2,
                                       uint32_t input_lwe_dimension,
                                       uint32_t input_lwe_ciphertext_count);

void cuda_add_lwe_ciphertext_vector_plaintext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *plaintext_array_in,
    uint32_t input_lwe_dimension, uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *plaintext_array_in,
    uint32_t input_lwe_dimension, uint32_t input_lwe_ciphertext_count);
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *cleartext_array_in,
    uint32_t input_lwe_dimension, uint32_t input_lwe_ciphertext_count);
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *cleartext_array_in,
    uint32_t input_lwe_dimension, uint32_t input_lwe_ciphertext_count);
}

#endif // CUDA_LINALG_H_
