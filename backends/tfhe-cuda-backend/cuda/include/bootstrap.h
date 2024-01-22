#ifndef CUDA_BOOTSTRAP_H
#define CUDA_BOOTSTRAP_H

#include "device.h"
#include <cstdint>

enum PBS_TYPE { MULTI_BIT = 0, LOW_LAT = 1, AMORTIZED = 2 };

extern "C" {
void cuda_fourier_polynomial_mul(void *input1, void *input2, void *output,
                                 cuda_stream_t *stream,
                                 uint32_t polynomial_size,
                                 uint32_t total_polynomials);

void cuda_convert_lwe_bootstrap_key_32(void *dest, void *src,
                                       cuda_stream_t *stream,
                                       uint32_t input_lwe_dim,
                                       uint32_t glwe_dim, uint32_t level_count,
                                       uint32_t polynomial_size);

void cuda_convert_lwe_bootstrap_key_64(void *dest, void *src,
                                       cuda_stream_t *stream,
                                       uint32_t input_lwe_dim,
                                       uint32_t glwe_dim, uint32_t level_count,
                                       uint32_t polynomial_size);

void scratch_cuda_bootstrap_amortized_32(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory);

void scratch_cuda_bootstrap_amortized_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory);

void cuda_bootstrap_amortized_lwe_ciphertext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory);

void cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory);

void cleanup_cuda_bootstrap_amortized(cuda_stream_t *stream,
                                      int8_t **pbs_buffer);

void scratch_cuda_bootstrap_low_latency_32(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void scratch_cuda_bootstrap_low_latency_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory);

void cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory);

void cleanup_cuda_bootstrap_low_latency(cuda_stream_t *stream,
                                        int8_t **pbs_buffer);

uint64_t get_buffer_size_bootstrap_amortized_64(
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory);

uint64_t get_buffer_size_bootstrap_low_latency_64(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory);
}

#ifdef __CUDACC__
__device__ inline int get_start_ith_ggsw(int i, uint32_t polynomial_size,
                                         int glwe_dimension,
                                         uint32_t level_count);

template <typename T>
__device__ T *get_ith_mask_kth_block(T *ptr, int i, int k, int level,
                                     uint32_t polynomial_size,
                                     int glwe_dimension, uint32_t level_count);

template <typename T>
__device__ T *get_ith_body_kth_block(T *ptr, int i, int k, int level,
                                     uint32_t polynomial_size,
                                     int glwe_dimension, uint32_t level_count);

template <typename T>
__device__ T *get_multi_bit_ith_lwe_gth_group_kth_block(
    T *ptr, int g, int i, int k, int level, uint32_t grouping_factor,
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count);

#endif

#endif // CUDA_BOOTSTRAP_H
