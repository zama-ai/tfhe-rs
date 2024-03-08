#ifndef CUDA_LINALG_H_
#define CUDA_LINALG_H_

#include "programmable_bootstrap.h"
#include <cstdint>
#include <device.h>

extern "C" {

void cuda_negate_lwe_ciphertext_vector_32(cuda_stream_t *stream,
                                          void *lwe_array_out,
                                          void *lwe_array_in,
                                          uint32_t input_lwe_dimension,
                                          uint32_t input_lwe_ciphertext_count);
void cuda_negate_lwe_ciphertext_vector_64(cuda_stream_t *stream,
                                          void *lwe_array_out,
                                          void *lwe_array_in,
                                          uint32_t input_lwe_dimension,
                                          uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_32(cuda_stream_t *stream,
                                       void *lwe_array_out,
                                       void *lwe_array_in_1,
                                       void *lwe_array_in_2,
                                       uint32_t input_lwe_dimension,
                                       uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_64(cuda_stream_t *stream,
                                       void *lwe_array_out,
                                       void *lwe_array_in_1,
                                       void *lwe_array_in_2,
                                       uint32_t input_lwe_dimension,
                                       uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_plaintext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *plaintext_array_in, uint32_t input_lwe_dimension,
    uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *plaintext_array_in, uint32_t input_lwe_dimension,
    uint32_t input_lwe_ciphertext_count);
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *cleartext_array_in, uint32_t input_lwe_dimension,
    uint32_t input_lwe_ciphertext_count);
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *cleartext_array_in, uint32_t input_lwe_dimension,
    uint32_t input_lwe_ciphertext_count);
}

#endif // CUDA_LINALG_H_
