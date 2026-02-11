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
void cuda_add_lwe_ciphertext_vector_32(void *stream, uint32_t gpu_index,
                                       CudaRadixCiphertextFFI *output,
                                       CudaRadixCiphertextFFI const *input_1,
                                       CudaRadixCiphertextFFI const *input_2);
void cuda_add_lwe_ciphertext_vector_64(void *stream, uint32_t gpu_index,
                                       CudaRadixCiphertextFFI *output,
                                       CudaRadixCiphertextFFI const *input_1,
                                       CudaRadixCiphertextFFI const *input_2);
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

void scratch_cuda_wrapping_polynomial_mul_one_to_many_64_async(
    void *stream, uint32_t gpu_index, uint32_t polynomial_size,
    int8_t **circulant_buf);

void cleanup_cuda_wrapping_polynomial_mul_one_to_many_64(void *stream,
                                                         uint32_t gpu_index,
                                                         int8_t *circulant_buf);

void cuda_wrapping_polynomial_mul_one_to_many_64_async(
    void *stream, uint32_t gpu_index, void *result, void const *poly_lhs,
    int8_t *circulant, void const *poly_rhs, uint32_t polynomial_size,
    uint32_t n_rhs);
void cuda_glwe_wrapping_polynomial_mul_one_to_many_64_async(
    void *stream, uint32_t gpu_index, void *result, void const *poly_lhs,
    int8_t *circulant, void const *poly_rhs, uint32_t polynomial_size,
    uint32_t glwe_dimension, uint32_t n_rhs);
void cuda_add_lwe_ciphertext_vector_plaintext_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, const uint64_t plaintext_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count);
}

#endif // CUDA_LINALG_H_
