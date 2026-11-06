#ifndef CUDA_BOOTSTRAP_H
#define CUDA_BOOTSTRAP_H

#include "pbs_enums.h"
#include <stdint.h>

extern "C" {
void cuda_fourier_polynomial_mul_async(void *stream, uint32_t gpu_index,
                                       void const *input1, void const *input2,
                                       void *output, uint32_t polynomial_size,
                                       uint32_t total_polynomials);

void cuda_fourier_polynomial_mul_fft16x16x4_async(
    void *stream, uint32_t gpu_index, void const *input1, void const *input2,
    void *output, uint32_t polynomial_size, uint32_t total_polynomials);

// Test-only: forward-only negacyclic FFT using the classic NSMFFT_direct core.
// Output is in NSMFFT_direct's native (bit-reversed) frequency order.
void cuda_forward_fft_classic_async(void *stream, uint32_t gpu_index,
                                    void const *input, void *output,
                                    uint32_t polynomial_size,
                                    uint32_t total_polynomials);

// Test-only: forward-only negacyclic FFT using the paired FFT16x16x4 transform
// of the specialized 2_2_params PBS. Output is in NATURAL frequency order.
// Hardcoded to polynomial_size == 2048; two polynomials per block, so
// total_polynomials must be even. Runs on compute capability 8.x and newer.
void cuda_forward_fft16x16x4_async(void *stream, uint32_t gpu_index,
                                   void const *input, void *output,
                                   uint32_t polynomial_size,
                                   uint32_t total_polynomials);

// Test-only: inverse-only negacyclic FFT using the paired FFT16x16x4 transform.
// The clean inverse of cuda_forward_fft16x16x4_async: natural-order input and
// natural-order time-domain output, no 1/N. Same restrictions as the forward.
void cuda_backward_fft16x16x4_async(void *stream, uint32_t gpu_index,
                                    void const *input, void *output,
                                    uint32_t polynomial_size,
                                    uint32_t total_polynomials);

// Returns true iff the given GPU has compute capability 9.x (Hopper) or newer,
// the only architecture the 128-bit PBS golden data is validated on. Lets the
// pbs128 golden tests gate themselves at runtime.
bool cuda_pbs128_golden_is_supported_async(uint32_t gpu_index);

// True iff the GPU reproduces the committed PBS golden data bit for bit:
// compute capability 8.x (Ampere) or newer, checked on A100, L40 and H100.
bool cuda_pbs_golden_is_supported_async(uint32_t gpu_index);

// True iff the GPU runs the FFT16x16x4 transforms and reproduces the committed
// FFT golden data bit for bit: compute capability 8.x (Ampere) or newer,
// checked on A100, L40 and H100. A deliberate twin of the PBS golden probe
// above: the two policies are independent and may diverge.
bool cuda_fft16x16x4_is_supported_async(uint32_t gpu_index);

// The (polynomial_size, base_log, level_count) order deliberately matches the
// scratch and the launch: all three share the 2_2 specialized selection gate.
void cuda_convert_lwe_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count);

void cuda_convert_lwe_programmable_bootstrap_key_128_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t level_count);

uint64_t scratch_cuda_programmable_bootstrap_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

uint64_t scratch_cuda_programmable_bootstrap_128_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

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
                                            int8_t **buffer);

void cleanup_cuda_programmable_bootstrap_128(void *stream, uint32_t gpu_index,
                                             int8_t **buffer);
}
#endif // CUDA_BOOTSTRAP_H
