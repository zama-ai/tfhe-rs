#ifndef CUDA_MULTI_BIT_H
#define CUDA_MULTI_BIT_H

#include "pbs_enums.h"
#include "stdint.h"

extern "C" {

bool has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t num_samples);

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size, uint32_t grouping_factor);

void scratch_cuda_multi_bit_programmable_bootstrap_64(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t lut_count,
    uint32_t lut_stride);

void cleanup_cuda_multi_bit_programmable_bootstrap(void *stream,
                                                   uint32_t gpu_index,
                                                   int8_t **pbs_buffer);
}

#endif // CUDA_MULTI_BIT_H
