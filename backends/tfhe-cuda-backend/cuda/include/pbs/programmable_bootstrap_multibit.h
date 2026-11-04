#ifndef CUDA_MULTI_BIT_H
#define CUDA_MULTI_BIT_H

#include "bootstrap_key_params.h"
#include "pbs_enums.h"
#include "stdint.h"

extern "C" {

bool has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
    CudaLweBootstrapKeyParamsFFI bsk_params, uint32_t num_samples,
    uint32_t max_shared_memory);

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    CudaLweBootstrapKeyParamsFFI bsk_params);

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_128_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    CudaLweBootstrapKeyParamsFFI bsk_params);

uint64_t scratch_cuda_multi_bit_programmable_bootstrap_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

void cuda_multi_bit_programmable_bootstrap_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, CudaLweBootstrapKeyParamsFFI bsk_params,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

void cleanup_cuda_multi_bit_programmable_bootstrap_64(void *stream,
                                                      uint32_t gpu_index,
                                                      int8_t **buffer);

// Noise-tests-namespaced wrappers for scratch/cleanup, so that callers
// working with the noise-tests PBS variant use a consistent naming scheme.
uint64_t scratch_cuda_multi_bit_programmable_bootstrap_noise_tests_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

void cleanup_cuda_multi_bit_programmable_bootstrap_noise_tests_64(
    void *stream, uint32_t gpu_index, int8_t **buffer);

// Noise tests variant: 64-bit torus, polynomial_size=2048 only. Uses the
// NOISE_TESTS keybundle mode for noise analysis purposes.
void cuda_multi_bit_programmable_bootstrap_noise_tests_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, CudaLweBootstrapKeyParamsFFI bsk_params,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

uint64_t scratch_cuda_multi_bit_programmable_bootstrap_128_async(
    void *stream, uint32_t gpu_index, int8_t **buffer,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

void cuda_multi_bit_programmable_bootstrap_128_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lwe_array_in, void const *lwe_input_indexes,
    void const *bootstrapping_key, int8_t *mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);

void cleanup_cuda_multi_bit_programmable_bootstrap_128(void *stream,
                                                       const uint32_t gpu_index,
                                                       int8_t **buffer);

uint64_t scratch_cuda_multi_bit_programmable_bootstrap_noise_tests_128_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

void cleanup_cuda_multi_bit_programmable_bootstrap_noise_tests_128(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer);

void cuda_multi_bit_programmable_bootstrap_noise_tests_128_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lwe_array_in, void const *lwe_input_indexes,
    void const *bootstrapping_key, int8_t *buffer,
    CudaLweBootstrapKeyParamsFFI bsk_params, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);
}

#endif // CUDA_MULTI_BIT_H
