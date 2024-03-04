#ifndef CUDA_MULTI_BIT_H
#define CUDA_MULTI_BIT_H

#include "bootstrap.h"
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
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0);

void scratch_cuda_generic_multi_bit_pbs_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t lwe_chunk_size = 0);

void cuda_generic_multi_bit_pbs_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0);

void cleanup_cuda_multi_bit_pbs_32(cuda_stream_t *stream, int8_t **pbs_buffer);
void cleanup_cuda_multi_bit_pbs_64(cuda_stream_t *stream, int8_t **pbs_buffer);
}

template <typename Torus, typename STorus>
void scratch_cuda_fast_multi_bit_pbs(
    cuda_stream_t *stream, pbs_buffer<Torus, MULTI_BIT> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size = 0);

template <typename Torus>
void cuda_fast_multi_bit_pbs_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size = 0);

template <typename Torus, typename STorus>
void scratch_cuda_multi_bit_pbs(
    cuda_stream_t *stream, pbs_buffer<Torus, MULTI_BIT> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size = 0);

template <typename Torus>
void cuda_multi_bit_pbs_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size = 0);

template <typename Torus> struct pbs_buffer<Torus, PBS_TYPE::MULTI_BIT> {
  double2 *keybundle_fft;
  Torus *global_accumulator;
  double2 *global_accumulator_fft;

  PBS_VARIANT pbs_variant;

  pbs_buffer(cuda_stream_t *stream, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, uint32_t lwe_chunk_size,
             PBS_VARIANT pbs_variant, bool allocate_gpu_memory) {
    this->pbs_variant = pbs_variant;
    auto max_shared_memory = cuda_get_max_shared_memory(stream->gpu_index);

    if (allocate_gpu_memory) {
      switch (pbs_variant) {
      case DEFAULT:
      case FAST:
        keybundle_fft = (double2 *)cuda_malloc_async(
            input_lwe_ciphertext_count * lwe_chunk_size * level_count *
                (glwe_dimension + 1) * (glwe_dimension + 1) *
                (polynomial_size / 2) * sizeof(double2),
            stream);
        global_accumulator = (Torus *)cuda_malloc_async(
            input_lwe_ciphertext_count * (glwe_dimension + 1) *
                polynomial_size * sizeof(Torus),
            stream);
        global_accumulator_fft = (double2 *)cuda_malloc_async(
            input_lwe_ciphertext_count * (glwe_dimension + 1) * level_count *
                (polynomial_size / 2) * sizeof(double2),
            stream);
        break;
      default:
        PANIC("Cuda error (PBS): unsupported implementation variant.")
      }
    }
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(keybundle_fft, stream);
    cuda_drop_async(global_accumulator, stream);
    cuda_drop_async(global_accumulator_fft, stream);
  }
};

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
