#ifndef CUDA_MULTI_BIT_UTILITIES_H
#define CUDA_MULTI_BIT_UTILITIES_H

#include "checked_arithmetic.h"
#include "pbs_utilities.h"

template <typename Torus>
bool supports_distributed_shared_memory_on_multibit_programmable_bootstrap(
    uint32_t polynomial_size, uint32_t max_shared_memory);

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_tbc_multi_bit(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory);

#if CUDA_ARCH >= 900
template <typename Torus>
uint64_t scratch_cuda_tbc_multi_bit_programmable_bootstrap(
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
uint64_t scratch_cuda_cg_multi_bit_programmable_bootstrap(
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
uint64_t scratch_cuda_multi_bit_programmable_bootstrap(
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
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_128_keybundle(
    uint32_t polynomial_size);
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
uint64_t get_lwe_chunk_size(uint32_t gpu_index, uint32_t max_num_pbs,
                            uint32_t polynomial_size, uint32_t glwe_dimension,
                            uint32_t level_count, uint64_t full_sm_keybundle);
template <typename Torus, class params>
uint64_t get_lwe_chunk_size_128(uint32_t gpu_index, uint32_t max_num_pbs,
                                uint32_t polynomial_size,
                                uint32_t glwe_dimension, uint32_t level_count,
                                uint64_t full_sm_keybundle);
template <typename Torus>
struct pbs_buffer<Torus, PBS_TYPE::MULTI_BIT> : public pbs_buffer_base {
  int8_t *d_mem_keybundle = NULL;
  int8_t *d_mem_acc_step_one = NULL;
  int8_t *d_mem_acc_step_two = NULL;
  int8_t *d_mem_acc_cg = NULL;
  int8_t *d_mem_acc_tbc = NULL;
  uint64_t lwe_chunk_size;
  double2 *keybundle_fft;
  Torus *global_accumulator;
  double2 *global_join_buffer;

  PBS_VARIANT pbs_variant;
  bool gpu_memory_allocated;

  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, uint64_t lwe_chunk_size,
             PBS_VARIANT pbs_variant, bool allocate_gpu_memory,
             uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    cuda_set_device(gpu_index);

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

    size_t num_blocks_keybundle = safe_mul(
        (size_t)input_lwe_ciphertext_count, (size_t)lwe_chunk_size,
        safe_mul((size_t)(glwe_dimension + 1), (size_t)(glwe_dimension + 1)),
        (size_t)level_count);
    size_t num_blocks_acc_step_one =
        safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1),
                 (size_t)input_lwe_ciphertext_count);
    size_t num_blocks_acc_step_two = safe_mul(
        (size_t)input_lwe_ciphertext_count, (size_t)(glwe_dimension + 1));
    size_t num_blocks_acc_cg =
        safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1),
                 (size_t)input_lwe_ciphertext_count);

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
    size_t num_blocks_acc_tbc = num_blocks_acc_cg;
#endif

    // Keybundle
    if (max_shared_memory < full_sm_keybundle)
      d_mem_keybundle = (int8_t *)cuda_malloc_with_size_tracking_async(
          safe_mul(num_blocks_keybundle, full_sm_keybundle), stream, gpu_index,
          size_tracker, allocate_gpu_memory);

    switch (pbs_variant) {
    case PBS_VARIANT::CG:
      // Accumulator CG
      if (max_shared_memory < partial_sm_cg_accumulate)
        d_mem_acc_cg = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_cg, full_sm_cg_accumulate), stream,
            gpu_index, size_tracker, allocate_gpu_memory);
      else if (max_shared_memory < full_sm_cg_accumulate)
        d_mem_acc_cg = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_cg, partial_sm_cg_accumulate), stream,
            gpu_index, size_tracker, allocate_gpu_memory);
      break;
    case PBS_VARIANT::DEFAULT:
      // Accumulator step one
      if (max_shared_memory < partial_sm_accumulate_step_one)
        d_mem_acc_step_one = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_step_one, full_sm_accumulate_step_one),
            stream, gpu_index, size_tracker, allocate_gpu_memory);
      else if (max_shared_memory < full_sm_accumulate_step_one)
        d_mem_acc_step_one = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_step_one, partial_sm_accumulate_step_one),
            stream, gpu_index, size_tracker, allocate_gpu_memory);

      // Accumulator step two
      if (max_shared_memory < full_sm_accumulate_step_two)
        d_mem_acc_step_two = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_step_two, full_sm_accumulate_step_two),
            stream, gpu_index, size_tracker, allocate_gpu_memory);
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
        d_mem_acc_tbc = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_tbc, full_sm_tbc_accumulate), stream,
            gpu_index, size_tracker, allocate_gpu_memory);
      else if (max_shared_memory < full_sm_tbc_accumulate + minimum_sm_tbc)
        d_mem_acc_tbc = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_tbc, partial_sm_tbc_accumulate), stream,
            gpu_index, size_tracker, allocate_gpu_memory);
      break;
#endif
    default:
      PANIC("Cuda error (PBS): unsupported implementation variant.")
    }

    keybundle_fft = (double2 *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<double2>(num_blocks_keybundle,
                                 (size_t)(polynomial_size / 2)),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
    global_accumulator = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>((size_t)input_lwe_ciphertext_count,
                               (size_t)(glwe_dimension + 1),
                               (size_t)polynomial_size),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
    global_join_buffer = (double2 *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<double2>(
            safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1)),
            (size_t)input_lwe_ciphertext_count, (size_t)(polynomial_size / 2)),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
  }

  void release(cudaStream_t stream, uint32_t gpu_index) override {

    if (d_mem_keybundle)
      cuda_drop_with_size_tracking_async(d_mem_keybundle, stream, gpu_index,
                                         gpu_memory_allocated);
    switch (pbs_variant) {
    case DEFAULT:
      if (d_mem_acc_step_one)
        cuda_drop_with_size_tracking_async(d_mem_acc_step_one, stream,
                                           gpu_index, gpu_memory_allocated);
      if (d_mem_acc_step_two)
        cuda_drop_with_size_tracking_async(d_mem_acc_step_two, stream,
                                           gpu_index, gpu_memory_allocated);
      break;
    case CG:
      if (d_mem_acc_cg)
        cuda_drop_with_size_tracking_async(d_mem_acc_cg, stream, gpu_index,
                                           gpu_memory_allocated);
      break;
#if CUDA_ARCH >= 900
    case TBC:
      if (d_mem_acc_tbc)
        cuda_drop_with_size_tracking_async(d_mem_acc_tbc, stream, gpu_index,
                                           gpu_memory_allocated);
      break;
#endif
    default:
      PANIC("Cuda error (PBS): unsupported implementation variant.")
    }

    cuda_drop_with_size_tracking_async(keybundle_fft, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_accumulator, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_join_buffer, stream, gpu_index,
                                       gpu_memory_allocated);

    cuda_synchronize_stream(stream, gpu_index);
  }
};

template <typename InputTorus>
struct pbs_buffer_128<InputTorus, PBS_TYPE::MULTI_BIT>
    : public pbs_buffer_base {
  int8_t *d_mem_keybundle = NULL;
  int8_t *d_mem_acc_step_one = NULL;
  int8_t *d_mem_acc_step_two = NULL;
  int8_t *d_mem_acc_cg = NULL;
  int8_t *d_mem_acc_tbc = NULL;
  uint64_t lwe_chunk_size;
  double *keybundle_fft;
  __uint128_t *global_accumulator;
  double *global_join_buffer;

  PBS_VARIANT pbs_variant;
  bool gpu_memory_allocated;

  pbs_buffer_128(cudaStream_t stream, uint32_t gpu_index,
                 uint32_t glwe_dimension, uint32_t polynomial_size,
                 uint32_t level_count, uint32_t input_lwe_ciphertext_count,
                 uint64_t lwe_chunk_size, PBS_VARIANT pbs_variant,
                 bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    cuda_set_device(gpu_index);

    this->pbs_variant = pbs_variant;
    this->lwe_chunk_size = lwe_chunk_size;
    auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

    // default
    uint64_t full_sm_keybundle =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_128_keybundle<
            __uint128_t>(polynomial_size);
    uint64_t full_sm_accumulate_step_one =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<
            __uint128_t>(polynomial_size);
    uint64_t full_sm_accumulate_step_two =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<
            __uint128_t>(polynomial_size);
    uint64_t partial_sm_accumulate_step_one =
        get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
            __uint128_t>(polynomial_size);
    // cg
    uint64_t full_sm_cg_accumulate =
        get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<__uint128_t>(
            polynomial_size);
    uint64_t partial_sm_cg_accumulate =
        get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<
            __uint128_t>(polynomial_size);

    size_t num_blocks_keybundle = safe_mul(
        (size_t)input_lwe_ciphertext_count, (size_t)lwe_chunk_size,
        safe_mul((size_t)(glwe_dimension + 1), (size_t)(glwe_dimension + 1)),
        (size_t)level_count);
    size_t num_blocks_acc_step_one =
        safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1),
                 (size_t)input_lwe_ciphertext_count);
    size_t num_blocks_acc_step_two = safe_mul(
        (size_t)input_lwe_ciphertext_count, (size_t)(glwe_dimension + 1));
    size_t num_blocks_acc_cg =
        safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1),
                 (size_t)input_lwe_ciphertext_count);

    // Keybundle
    if (max_shared_memory < full_sm_keybundle)
      d_mem_keybundle = (int8_t *)cuda_malloc_with_size_tracking_async(
          safe_mul(num_blocks_keybundle, full_sm_keybundle), stream, gpu_index,
          size_tracker, allocate_gpu_memory);

    switch (pbs_variant) {
    case PBS_VARIANT::CG:
      // Accumulator CG
      if (max_shared_memory < partial_sm_cg_accumulate)
        d_mem_acc_cg = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_cg, full_sm_cg_accumulate), stream,
            gpu_index, size_tracker, allocate_gpu_memory);
      else if (max_shared_memory < full_sm_cg_accumulate)
        d_mem_acc_cg = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_cg, partial_sm_cg_accumulate), stream,
            gpu_index, size_tracker, allocate_gpu_memory);
      break;
    case PBS_VARIANT::DEFAULT:
      // Accumulator step one
      if (max_shared_memory < partial_sm_accumulate_step_one)
        d_mem_acc_step_one = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_step_one, full_sm_accumulate_step_one),
            stream, gpu_index, size_tracker, allocate_gpu_memory);
      else if (max_shared_memory < full_sm_accumulate_step_one)
        d_mem_acc_step_one = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_step_one, partial_sm_accumulate_step_one),
            stream, gpu_index, size_tracker, allocate_gpu_memory);

      // Accumulator step two
      if (max_shared_memory < full_sm_accumulate_step_two)
        d_mem_acc_step_two = (int8_t *)cuda_malloc_with_size_tracking_async(
            safe_mul(num_blocks_acc_step_two, full_sm_accumulate_step_two),
            stream, gpu_index, size_tracker, allocate_gpu_memory);
      break;
    default:
      PANIC("Cuda error (PBS): unsupported implementation variant.")
    }

    keybundle_fft = (double *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<double>((size_t)num_blocks_keybundle,
                                (size_t)(polynomial_size / 2), (size_t)4),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
    global_accumulator = (__uint128_t *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<__uint128_t>((size_t)input_lwe_ciphertext_count,
                                     (size_t)(glwe_dimension + 1),
                                     (size_t)polynomial_size),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
    global_join_buffer = (double *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<double>(
            safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1)),
            (size_t)input_lwe_ciphertext_count,
            safe_mul((size_t)(polynomial_size / 2), (size_t)4)),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
  }

  void release(cudaStream_t stream, uint32_t gpu_index) override {

    if (d_mem_keybundle)
      cuda_drop_with_size_tracking_async(d_mem_keybundle, stream, gpu_index,
                                         gpu_memory_allocated);
    switch (pbs_variant) {
    case DEFAULT:
      if (d_mem_acc_step_one)
        cuda_drop_with_size_tracking_async(d_mem_acc_step_one, stream,
                                           gpu_index, gpu_memory_allocated);
      if (d_mem_acc_step_two)
        cuda_drop_with_size_tracking_async(d_mem_acc_step_two, stream,
                                           gpu_index, gpu_memory_allocated);
      break;
    case CG:
      if (d_mem_acc_cg)
        cuda_drop_with_size_tracking_async(d_mem_acc_cg, stream, gpu_index,
                                           gpu_memory_allocated);
      break;
    default:
      PANIC("Cuda error (PBS): unsupported implementation variant.")
    }

    cuda_drop_with_size_tracking_async(keybundle_fft, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_accumulator, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_join_buffer, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_synchronize_stream(stream, gpu_index);
  }
};

#endif // CUDA_MULTI_BIT_UTILITIES_H
