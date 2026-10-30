#ifndef CUDA_BOOTSTRAP_TESTING_HEADERS_H
#define CUDA_BOOTSTRAP_TESTING_HEADERS_H

#include "pbs_enums.h"
#include <stdint.h>

// Hard constraints of the 2_2 specialized (throughput-oriented) classical PBS
// kernel, without the compute capability policy of the automatic selection.
// Tests gate on this to decide whether the forced 2_2 specialized entry points
// can run.
template <typename Torus>
bool pbs_2_2_specialized_params_checker(
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count,
    uint32_t lwe_dimension, uint32_t base_log, uint32_t max_shared_memory);

// The automatic selection gate, exposed so tests and benchmarks can predict
// which flavor and key layout the automatic path picks on this device.
template <typename Torus>
bool supports_2_2_specialized_pbs(uint32_t polynomial_size,
                                  uint32_t glwe_dimension, uint32_t level_count,
                                  uint32_t lwe_dimension, uint32_t base_log,
                                  uint32_t max_shared_memory);

// The cuda bootstrap key is converted from torus to fourier domain using the
// automatic logic that checks if the parameters match the 2_2
// parameters. The 2_2 specialized layout is different because the input/output
// data of the FFT lives in registers, and if the layout is not changed, global
// memory reads of the bsk are not coalesced. In the backend tests, we want to
// be able to pin either flavor regardless of what the automatic gate would
// pick, so the following entry points force the layout, the buffer variant and
// the launched kernel.

// Force the default FFT layout for the BSK: needed when testing the DEFAULT
// (split step-one/step-two) flavor on parameters the automatic gate would
// route to the 2_2 specialized layout.
void cuda_convert_lwe_programmable_bootstrap_key_default_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t level_count);

// Force the FFT16x16x4 2_2 specialized layout for the BSK, bypassing the
// compute capability policy of the automatic gate.
void cuda_convert_lwe_programmable_bootstrap_key_2_2_specialized_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t level_count);

uint64_t scratch_cuda_programmable_bootstrap_default_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_default_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_many_lut, uint32_t lut_stride);

uint64_t scratch_cuda_programmable_bootstrap_2_2_specialized_64_async(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_programmable_bootstrap_2_2_specialized_64_async(
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
