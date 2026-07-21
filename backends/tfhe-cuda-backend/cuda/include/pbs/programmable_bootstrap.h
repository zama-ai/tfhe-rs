#ifndef CUDA_BOOTSTRAP_H
#define CUDA_BOOTSTRAP_H

#include "pbs_enums.h"
#include <stdint.h>

extern "C" {
void cuda_fourier_polynomial_mul_async(void *stream, uint32_t gpu_index,
                                       void const *input1, void const *input2,
                                       void *output, uint32_t polynomial_size,
                                       uint32_t total_polynomials);

void cuda_fourier_polynomial_mul_fft16x4x16_async(
    void *stream, uint32_t gpu_index, void const *input1, void const *input2,
    void *output, uint32_t polynomial_size, uint32_t total_polynomials);

// Test-only: forward-only negacyclic FFT using the classic NSMFFT_direct core.
// Output is in NSMFFT_direct's native (bit-reversed) frequency order.
void cuda_forward_fft_classic_async(void *stream, uint32_t gpu_index,
                                    void const *input, void *output,
                                    uint32_t polynomial_size,
                                    uint32_t total_polynomials);

// Test-only: forward-only negacyclic FFT using the throughput-oriented
// FFT16x4x16 core. Output is in NATURAL frequency order. Hardcoded to
// polynomial_size == 2048 and requires sm_90 (H100).
void cuda_forward_fft16x4x16_async(void *stream, uint32_t gpu_index,
                                   void const *input, void *output,
                                   uint32_t polynomial_size,
                                   uint32_t total_polynomials);

// Test-only: inverse-only negacyclic FFT using the throughput-oriented
// FFT16x4x16 core. The clean inverse of cuda_forward_fft16x4x16_async: input
// and time-domain output are both in NATURAL order. Hardcoded to
// polynomial_size == 2048 and requires sm_90 (H100).
void cuda_backward_fft16x4x16_async(void *stream, uint32_t gpu_index,
                                    void const *input, void *output,
                                    uint32_t polynomial_size,
                                    uint32_t total_polynomials);

// Returns true iff the given GPU can run the FFT16x4x16 core, i.e. it has
// compute capability 9.x (Hopper) or newer, whose named-barrier / mbarrier
// primitives the core relies on. Lets callers (e.g. tests) gate the specialized
// path at runtime instead of failing on older architectures.
bool cuda_fft16x4x16_is_supported_async(uint32_t gpu_index);

void cuda_convert_lwe_programmable_bootstrap_key_32_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

void cuda_convert_lwe_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

void cuda_convert_lwe_programmable_bootstrap_key_128_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

uint64_t scratch_cuda_programmable_bootstrap_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

uint64_t scratch_cuda_programmable_bootstrap_128_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_lwe_ciphertext_vector_32_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

void cuda_programmable_bootstrap_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

void cuda_programmable_bootstrap_128_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key, int8_t *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples);

void cleanup_cuda_programmable_bootstrap_64(void *stream, uint32_t gpu_index,
                                            int8_t **pbs_buffer);

void cleanup_cuda_programmable_bootstrap_128(void *stream, uint32_t gpu_index,
                                             int8_t **pbs_buffer);
}
#endif // CUDA_BOOTSTRAP_H
