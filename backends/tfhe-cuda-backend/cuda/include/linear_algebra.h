#ifndef CUDA_LINALG_H_
#define CUDA_LINALG_H_

#include "integer/integer.h"
#include <stdint.h>

extern "C" {

void cuda_negate_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
void cuda_negate_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_1,
    CudaRadixCiphertextFFI const *lwe_array_in_2);
void cuda_add_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_1,
    CudaRadixCiphertextFFI const *lwe_array_in_2);
void cuda_add_lwe_ciphertext_vector_plaintext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *plaintext_array_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *plaintext_array_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *cleartext_array_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *cleartext_array_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
void cuda_add_lwe_ciphertext_vector_plaintext_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, const uint64_t plaintext_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
}

#endif // CUDA_LINALG_H_
