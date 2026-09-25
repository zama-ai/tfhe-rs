#ifndef CUDA_BOOTSTRAP_TESTING_128_HEADERS_H
#define CUDA_BOOTSTRAP_TESTING_128_HEADERS_H

#include "pbs_enums.h"
#include "programmable_bootstrap.h"
#include <stdint.h>

// Per-variant entry points for 128-bit PBS (vanilla).
// These bypass the env-driven dispatch of
// scratch_cuda_programmable_bootstrap_128_vector and directly invoke the
// requested variant, allowing tests to exercise each independently.

uint64_t scratch_cuda_programmable_bootstrap_128_default_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_128_default_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples);

uint64_t scratch_cuda_programmable_bootstrap_128_cg_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_128_cg_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples);

uint64_t scratch_cuda_programmable_bootstrap_128_tbc_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_128_tbc_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples);

#endif // CUDA_BOOTSTRAP_TESTING_128_HEADERS_H
