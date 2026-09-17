#ifndef CUDA_BOOTSTRAP_TESTING_HEADERS_H
#define CUDA_BOOTSTRAP_TESTING_HEADERS_H

#include "pbs_enums.h"
#include <stdint.h>

template <typename Torus>
bool specialized_2_2_params_checker(uint32_t polynomial_size,
                                    uint32_t glwe_dimension,
                                    uint32_t level_count,
                                    uint32_t max_shared_memory);

// True when the CG kernel can run, ignoring the specialized 2_2 preference of
// the auto dispatch.
template <typename Torus>
bool cg_params_checker(int glwe_dimension, int polynomial_size, int level_count,
                       int num_samples, uint32_t max_shared_memory);

// True when the throughput oriented 2_2 kernel can run (H100-class GPUs).
template <typename Torus>
bool specialized_2_2_use_throughput_oriented(uint32_t polynomial_size,
                                             uint32_t glwe_dimension,
                                             uint32_t level_count,
                                             uint32_t lwe_dimension,
                                             uint32_t max_shared_memory);

uint64_t scratch_cuda_programmable_bootstrap_tbc_generic_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

uint64_t scratch_cuda_programmable_bootstrap_tbc_2_2_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_tbc_64_generic_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

void cuda_programmable_bootstrap_tbc_64_2_2_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

// The cuda bootstrap key is converted from torus to fourier domain using
// the automatic logic that checks if the parameters match the specialized
// 2_2_params. The layout is different in the specialized because the
// input/output data of the FFT lives in registers, and if the layout is not
// changed, global memory reads of the bsk are not coalesced. In the backend
// tests, we want to be able to use other pbs flavors that need the shared
// memory FFT layouts, so we provide the following functions to bypass the
// check and force the desired layout.

// i) Force standard (non-specialized) FFT layout for the BSK, this is needed
// when using step1/step2 or cg pbs on a H100 GPU.
void cuda_convert_lwe_programmable_bootstrap_key_standard_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

// ii) Force specialized 2_2_params natural-order FFT layout for the BSK. This
// is needed when we want to run the specialized non tbc flavor on a GPU that is
// not high-end (bad FP64 ratio). On those GPUs, the automatic fft layout is the
// shared memory one, and that is why we need to force the specialized one. On a
// H100 the automatic layout is the throughput one, so this also forces the
// natural-order layout there.
void cuda_convert_lwe_programmable_bootstrap_key_specialized_2_2_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

// iii) Force the bit-reversed FFT16x4x16 layout consumed by the throughput
// oriented 2_2_params kernel (H100 only).
void cuda_convert_lwe_programmable_bootstrap_key_specialized_2_2_throughput_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

uint64_t scratch_cuda_programmable_bootstrap_specialized_2_2_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_specialized_2_2_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

// Force the throughput oriented 2_2 flavor. It shares the scratch of the
// specialized 2_2 flavor, but the bsk must be in the throughput layout.
void cuda_programmable_bootstrap_specialized_2_2_throughput_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

uint64_t scratch_cuda_multi_bit_programmable_bootstrap_tbc_generic_64_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

uint64_t scratch_cuda_multi_bit_programmable_bootstrap_tbc_2_2_64_async(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

void cuda_multi_bit_programmable_bootstrap_tbc_64_generic_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride);

void cuda_multi_bit_programmable_bootstrap_tbc_64_2_2_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride);
#endif // CUDA_BOOTSTRAP_TESTING_HEADERS_H
