#ifndef CUDA_MULTI_BIT_UTILITIES_H
#define CUDA_MULTI_BIT_UTILITIES_H

#include "pbs_utilities.h"

template <typename Torus>
bool supports_distributed_shared_memory_on_multibit_programmable_bootstrap(
    uint32_t polynomial_size);

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_tbc_multi_bit(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count);

#if CUDA_ARCH >= 900
template <typename Torus>
void scratch_cuda_tbc_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template <typename Torus>
void cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);
#endif

template <typename Torus>
void scratch_cuda_cg_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template <typename Torus>
void cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);

template <typename Torus>
void scratch_cuda_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template <typename Torus>
void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);

template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_full_sm_cg_multibit_programmable_bootstrap(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size);
template <typename Torus>
uint64_t get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size);

template <typename Torus, class params>
uint32_t get_lwe_chunk_size(uint32_t gpu_index, uint32_t max_num_pbs,
                            uint32_t polynomial_size);

template <typename Torus> struct pbs_buffer<Torus, PBS_TYPE::MULTI_BIT> {
  int8_t *d_mem_keybundle = NULL;
  int8_t *d_mem_acc_step_one = NULL;
  int8_t *d_mem_acc_step_two = NULL;
  int8_t *d_mem_acc_cg = NULL;
  int8_t *d_mem_acc_tbc = NULL;
  uint32_t lwe_chunk_size;
  double2 *keybundle_fft;
  Torus *global_accumulator;
  double2 *global_join_buffer;

  PBS_VARIANT pbs_variant;

  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, uint32_t lwe_chunk_size,
             PBS_VARIANT pbs_variant, bool allocate_gpu_memory) {
    this->pbs_variant = pbs_variant;
    this->lwe_chunk_size = lwe_chunk_size;
    auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

    // default
    uint64_t full_sm_keybundle =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<
            Torus>(polynomial_size);
    uint64_t full_sm_accumulate_step_one =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<Torus>(
            polynomial_size);
    uint64_t full_sm_accumulate_step_two =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<Torus>(
            polynomial_size);
    uint64_t partial_sm_accumulate_step_one =
        get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
            Torus>(polynomial_size);
    // cg
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

#if CUDA_ARCH >= 900
    uint64_t full_sm_tbc_accumulate =
        get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);
    uint64_t partial_sm_tbc_accumulate =
        get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);
    uint64_t minimum_sm_tbc =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);
    auto num_blocks_acc_tbc = num_blocks_acc_cg;
#endif

    if (allocate_gpu_memory) {
      // Keybundle
      if (max_shared_memory < full_sm_keybundle)
        d_mem_keybundle = (int8_t *)cuda_malloc_async(
            num_blocks_keybundle * full_sm_keybundle, stream, gpu_index);

      switch (pbs_variant) {
      case PBS_VARIANT::CG:
        // Accumulator CG
        if (max_shared_memory < partial_sm_cg_accumulate)
          d_mem_acc_cg = (int8_t *)cuda_malloc_async(
              num_blocks_acc_cg * full_sm_cg_accumulate, stream, gpu_index);
        else if (max_shared_memory < full_sm_cg_accumulate)
          d_mem_acc_cg = (int8_t *)cuda_malloc_async(
              num_blocks_acc_cg * partial_sm_cg_accumulate, stream, gpu_index);
        break;
      case PBS_VARIANT::DEFAULT:
        // Accumulator step one
        if (max_shared_memory < partial_sm_accumulate_step_one)
          d_mem_acc_step_one = (int8_t *)cuda_malloc_async(
              num_blocks_acc_step_one * full_sm_accumulate_step_one, stream,
              gpu_index);
        else if (max_shared_memory < full_sm_accumulate_step_one)
          d_mem_acc_step_one = (int8_t *)cuda_malloc_async(
              num_blocks_acc_step_one * partial_sm_accumulate_step_one, stream,
              gpu_index);

        // Accumulator step two
        if (max_shared_memory < full_sm_accumulate_step_two)
          d_mem_acc_step_two = (int8_t *)cuda_malloc_async(
              num_blocks_acc_step_two * full_sm_accumulate_step_two, stream,
              gpu_index);
        break;
#if CUDA_ARCH >= 900
      case TBC:
        // There is a minimum amount of memory we need to run the TBC PBS, which
        // is minimum_sm_tbc. We know that minimum_sm_tbc bytes are available
        // because otherwise the previous check would have redirected
        // computation to some other variant. If over that we don't have more
        // partial_sm_tbc_accumulate bytes, TBC PBS will run on NOSM. If we have
        // partial_sm_tbc_accumulate but not full_sm_tbc_accumulate bytes, it
        // will run on PARTIALSM. Otherwise, FULLSM.
        //
        // NOSM mode actually requires minimum_sm_tbc shared memory bytes.

        // Accumulator TBC
        if (max_shared_memory < partial_sm_tbc_accumulate + minimum_sm_tbc)
          d_mem_acc_tbc = (int8_t *)cuda_malloc_async(
              num_blocks_acc_tbc * full_sm_tbc_accumulate, stream, gpu_index);
        else if (max_shared_memory < full_sm_tbc_accumulate + minimum_sm_tbc)
          d_mem_acc_tbc = (int8_t *)cuda_malloc_async(
              num_blocks_acc_tbc * partial_sm_tbc_accumulate, stream,
              gpu_index);
        break;
#endif
      default:
        PANIC("Cuda error (PBS): unsupported implementation variant.")
      }

      keybundle_fft = (double2 *)cuda_malloc_async(
          num_blocks_keybundle * (polynomial_size / 2) * sizeof(double2),
          stream, gpu_index);
      global_accumulator = (Torus *)cuda_malloc_async(
          input_lwe_ciphertext_count * (glwe_dimension + 1) * polynomial_size *
              sizeof(Torus),
          stream, gpu_index);
      global_join_buffer = (double2 *)cuda_malloc_async(
          level_count * (glwe_dimension + 1) * input_lwe_ciphertext_count *
              (polynomial_size / 2) * sizeof(double2),
          stream, gpu_index);
    }
  }

  void release(cudaStream_t stream, uint32_t gpu_index) {

    if (d_mem_keybundle)
      cuda_drop_async(d_mem_keybundle, stream, gpu_index);
    switch (pbs_variant) {
    case DEFAULT:
      if (d_mem_acc_step_one)
        cuda_drop_async(d_mem_acc_step_one, stream, gpu_index);
      if (d_mem_acc_step_two)
        cuda_drop_async(d_mem_acc_step_two, stream, gpu_index);
      break;
    case CG:
      if (d_mem_acc_cg)
        cuda_drop_async(d_mem_acc_cg, stream, gpu_index);
      break;
#if CUDA_ARCH >= 900
    case TBC:
      if (d_mem_acc_tbc)
        cuda_drop_async(d_mem_acc_tbc, stream, gpu_index);
      break;
#endif
    default:
      PANIC("Cuda error (PBS): unsupported implementation variant.")
    }

    cuda_drop_async(keybundle_fft, stream, gpu_index);
    cuda_drop_async(global_accumulator, stream, gpu_index);
    cuda_drop_async(global_join_buffer, stream, gpu_index);
  }
};

#endif // CUDA_MULTI_BIT_UTILITIES_H
