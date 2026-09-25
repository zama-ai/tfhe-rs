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

// CG support check for 128-bit halfhalf PBS.
bool supports_cooperative_groups_on_programmable_bootstrap_128_halfhalf(
    int glwe_dimension, int polynomial_size, int max_level_count,
    int num_samples, uint32_t max_shared_memory);

// Per-variant entry points for 128-bit halfhalf PBS.

uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_default_async(
    void *stream, uint32_t gpu_index, int8_t **buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_128_halfhalf_default_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples);

uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_cg_async(
    void *stream, uint32_t gpu_index, int8_t **buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_128_halfhalf_cg_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples);

// Support check for the relaxed arithmetic flavor of the 128-bit halfhalf PBS,
// so a test can skip instead of tripping the flavor's shape refusal. It returns
// false whenever the parameters are not the noise-squashing shape the flavor is
// compiled for, or the device has no distributed shared memory. The production
// dispatcher does not call this; it checks support through the .cuh template.
bool supports_relaxed_on_programmable_bootstrap_128_halfhalf(
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t max_shared_memory);

uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
    void *stream, uint32_t gpu_index, int8_t **buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_128_halfhalf_relaxed_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params, uint32_t num_samples);

#endif // CUDA_BOOTSTRAP_TESTING_128_HEADERS_H
