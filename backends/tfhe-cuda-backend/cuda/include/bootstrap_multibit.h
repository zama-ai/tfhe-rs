#ifndef CUDA_MULTI_BIT_H
#define CUDA_MULTI_BIT_H

#include <cstdint>

extern "C" {

bool has_support_to_cuda_bootstrap_fast_multi_bit(uint32_t glwe_dimension,
                                                  uint32_t polynomial_size,
                                                  uint32_t level_count,
                                                  uint32_t num_samples,
                                                  uint32_t max_shared_memory);

void cuda_convert_lwe_multi_bit_bootstrap_key_64(
    void *dest, void *src, cuda_stream_t *stream, uint32_t input_lwe_dim,
    uint32_t glwe_dim, uint32_t level_count, uint32_t polynomial_size,
    uint32_t grouping_factor);

void scratch_cuda_multi_bit_pbs_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t chunk_size = 0);

void cuda_multi_bit_pbs_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t chunk_size = 0);

void cleanup_cuda_multi_bit_pbs(cuda_stream_t *stream, int8_t **pbs_buffer);
}

template <typename Torus, typename STorus>
void scratch_cuda_fast_multi_bit_pbs(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t lwe_chunk_size = 0);

template <typename Torus>
void cuda_fast_multi_bit_pbs_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0);

template <typename Torus, typename STorus>
void scratch_cuda_multi_bit_pbs(cuda_stream_t *stream, int8_t **pbs_buffer,
                                uint32_t lwe_dimension, uint32_t glwe_dimension,
                                uint32_t polynomial_size, uint32_t level_count,
                                uint32_t grouping_factor,
                                uint32_t input_lwe_ciphertext_count,
                                uint32_t max_shared_memory,
                                bool allocate_gpu_memory,
                                uint32_t lwe_chunk_size = 0);

template <typename Torus>
void cuda_multi_bit_pbs_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0);

#ifdef __CUDACC__
__host__ uint32_t get_lwe_chunk_size(uint32_t lwe_dimension,
                                     uint32_t level_count,
                                     uint32_t glwe_dimension,
                                     uint32_t num_samples);

__host__ uint32_t get_average_lwe_chunk_size(uint32_t lwe_dimension,
                                             uint32_t level_count,
                                             uint32_t glwe_dimension,
                                             uint32_t ct_count);

__host__ uint64_t get_max_buffer_size_multibit_bootstrap(
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_input_lwe_ciphertext_count);
#endif

#endif // CUDA_MULTI_BIT_H
