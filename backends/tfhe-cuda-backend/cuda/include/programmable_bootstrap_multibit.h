#ifndef CUDA_MULTI_BIT_H
#define CUDA_MULTI_BIT_H

#include "programmable_bootstrap.h"
#include <cstdint>

extern "C" {

bool has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t num_samples, uint32_t max_shared_memory);

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
    void *dest, void *src, cuda_stream_t *stream, uint32_t input_lwe_dim,
    uint32_t glwe_dim, uint32_t level_count, uint32_t polynomial_size,
    uint32_t grouping_factor);

void scratch_cuda_multi_bit_programmable_bootstrap_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t chunk_size = 0);

void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0);

void scratch_cuda_generic_multi_bit_programmable_bootstrap_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t lwe_chunk_size = 0);

void cuda_generic_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0);

void cleanup_cuda_multi_bit_programmable_bootstrap(cuda_stream_t *stream,
                                                   int8_t **pbs_buffer);
}

template <typename Torus, typename STorus>
void scratch_cuda_cg_multi_bit_programmable_bootstrap(
    cuda_stream_t *stream, pbs_buffer<Torus, MULTI_BIT> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size = 0);

template <typename Torus>
void cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size = 0);

template <typename Torus, typename STorus>
void scratch_cuda_multi_bit_programmable_bootstrap(
    cuda_stream_t *stream, pbs_buffer<Torus, MULTI_BIT> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size = 0);

template <typename Torus>
void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size = 0);

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle(
    uint32_t polynomial_size);
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one(
    uint32_t polynomial_size);
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two(
    uint32_t polynomial_size);
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one(
    uint32_t polynomial_size);
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_cg_multibit_programmable_bootstrap(
    uint32_t polynomial_size);
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap(
    uint32_t polynomial_size);

template <typename Torus> struct pbs_buffer<Torus, PBS_TYPE::MULTI_BIT> {
  int8_t *d_mem_keybundle = NULL;
  int8_t *d_mem_acc_step_one = NULL;
  int8_t *d_mem_acc_step_two = NULL;
  int8_t *d_mem_acc_cg = NULL;

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

    uint64_t full_sm_keybundle =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<
            Torus>(polynomial_size);
    uint64_t full_sm_accumulate_step_one =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<Torus>(
            polynomial_size);
    uint64_t partial_sm_accumulate_step_one =
        get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
            Torus>(polynomial_size);
    uint64_t full_sm_accumulate_step_two =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<Torus>(
            polynomial_size);
    uint64_t full_sm_cg_accumulate =
        get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<Torus>(
            polynomial_size);
    uint64_t partial_sm_cg_accumulate =
        get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

    auto num_blocks_keybundle = input_lwe_ciphertext_count * lwe_chunk_size *
                                (glwe_dimension + 1) * (glwe_dimension + 1) *
                                level_count;
    auto num_blocks_acc_step_one =
        level_count * (glwe_dimension + 1) * input_lwe_ciphertext_count;
    auto num_blocks_acc_step_two =
        input_lwe_ciphertext_count * (glwe_dimension + 1);
    auto num_blocks_acc_cg =
        level_count * (glwe_dimension + 1) * input_lwe_ciphertext_count;

    if (allocate_gpu_memory) {
      // Keybundle
      if (max_shared_memory < full_sm_keybundle)
        d_mem_keybundle = (int8_t *)cuda_malloc_async(
            num_blocks_keybundle * full_sm_keybundle, stream);

      switch (pbs_variant) {
      case DEFAULT:
        // Accumulator step one
        if (max_shared_memory < partial_sm_accumulate_step_one)
          d_mem_acc_step_one = (int8_t *)cuda_malloc_async(
              num_blocks_acc_step_one * full_sm_accumulate_step_one, stream);
        else if (max_shared_memory < full_sm_accumulate_step_one)
          d_mem_acc_step_one = (int8_t *)cuda_malloc_async(
              num_blocks_acc_step_one * partial_sm_accumulate_step_one, stream);

        // Accumulator step two
        if (max_shared_memory < full_sm_accumulate_step_two)
          d_mem_acc_step_two = (int8_t *)cuda_malloc_async(
              num_blocks_acc_step_two * full_sm_accumulate_step_two, stream);
        break;
      case CG:
        // Accumulator CG
        if (max_shared_memory < partial_sm_cg_accumulate)
          d_mem_acc_cg = (int8_t *)cuda_malloc_async(
              num_blocks_acc_cg * full_sm_cg_accumulate, stream);
        else if (max_shared_memory < full_sm_cg_accumulate)
          d_mem_acc_cg = (int8_t *)cuda_malloc_async(
              num_blocks_acc_cg * partial_sm_cg_accumulate, stream);
        break;
      default:
        PANIC("Cuda error (PBS): unsupported implementation variant.")
      }

      keybundle_fft = (double2 *)cuda_malloc_async(
          num_blocks_keybundle * (polynomial_size / 2) * sizeof(double2),
          stream);
      global_accumulator = (Torus *)cuda_malloc_async(
          num_blocks_acc_step_two * polynomial_size * sizeof(Torus), stream);
      global_accumulator_fft = (double2 *)cuda_malloc_async(
          num_blocks_acc_step_one * (polynomial_size / 2) * sizeof(double2),
          stream);
    }
  }

  void release(cuda_stream_t *stream) {

    if (d_mem_keybundle)
      cuda_drop_async(d_mem_keybundle, stream);
    switch (pbs_variant) {
    case DEFAULT:
      if (d_mem_acc_step_one)
        cuda_drop_async(d_mem_acc_step_one, stream);
      if (d_mem_acc_step_two)
        cuda_drop_async(d_mem_acc_step_two, stream);
      break;
    case CG:
      if (d_mem_acc_cg)
        cuda_drop_async(d_mem_acc_cg, stream);
      break;
    default:
      PANIC("Cuda error (PBS): unsupported implementation variant.")
    }

    cuda_drop_async(keybundle_fft, stream);
    cuda_drop_async(global_accumulator, stream);
    cuda_drop_async(global_accumulator_fft, stream);
  }
};

#ifdef __CUDACC__

__host__ uint32_t get_lwe_chunk_size(uint32_t ct_count);

#endif

#endif // CUDA_MULTI_BIT_H
