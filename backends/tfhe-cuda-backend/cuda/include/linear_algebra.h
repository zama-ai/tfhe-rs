#ifndef CUDA_LINALG_H_
#define CUDA_LINALG_H_

#include "integer/integer.h"
#include <stdint.h>

extern "C" {

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
void cuda_add_lwe_ciphertext_vector_inplace_64(
    void *stream, uint32_t gpu_index, CudaRadixCiphertextFFI *lwe_array_inout,
    CudaRadixCiphertextFFI const *input_2);
}

#endif // CUDA_LINALG_H_
