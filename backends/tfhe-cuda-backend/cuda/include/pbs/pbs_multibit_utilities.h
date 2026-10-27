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

// The variant the multi-bit scratch selects for num_samples inputs.
template <typename Torus>
PBS_VARIANT
get_multi_bit_pbs_variant(uint32_t gpu_index, uint32_t glwe_dimension,
                          uint32_t polynomial_size, uint32_t level_count,
                          uint32_t num_samples);
template <>
PBS_VARIANT
get_multi_bit_pbs_variant<uint64_t>(uint32_t gpu_index, uint32_t glwe_dimension,
                                    uint32_t polynomial_size,
                                    uint32_t level_count, uint32_t num_samples);

// The chunk size a multi-bit buffer for num_inputs inputs selects, without the
// cap that depends on the free GPU memory.
template <typename Torus>
uint64_t get_multi_bit_lwe_chunk_size(uint32_t gpu_index, uint32_t num_inputs,
                                      uint32_t polynomial_size);
template <>
uint64_t get_multi_bit_lwe_chunk_size<uint64_t>(uint32_t gpu_index,
                                                uint32_t num_inputs,
                                                uint32_t polynomial_size);

#if CUDA_ARCH >= 900
template <typename Torus>
uint64_t scratch_cuda_tbc_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template <typename Torus>
void cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async(
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
void cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async(
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
void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_async(
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
uint64_t get_lwe_chunk_size_uncapped(uint32_t gpu_index, uint32_t max_num_pbs,
                                     uint32_t polynomial_size,
                                     uint64_t full_sm_keybundle);
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
  using fft_element_type = typename pbs_fft_traits<Torus>::element_type;

  int8_t *d_mem_keybundle = nullptr;
  int8_t *d_mem_acc_step_one = nullptr;
  int8_t *d_mem_acc_step_two = nullptr;
  int8_t *d_mem_acc_cg = nullptr;
  int8_t *d_mem_acc_tbc = nullptr;
  uint64_t lwe_chunk_size;
  fft_element_type *keybundle_fft = nullptr;
  Torus *global_accumulator = nullptr;
  fft_element_type *global_join_buffer = nullptr;

  PBS_VARIANT pbs_variant;
  bool gpu_memory_allocated;

  uint32_t glwe_dimension;
  uint32_t polynomial_size;
  uint32_t level_count;
  uint32_t input_lwe_ciphertext_count;
  uint32_t max_shared_memory;
  uint32_t gpu_index;

private:
  // Variant-free part: shared fields plus the buffers every multi-bit variant
  // uses (keybundle scratch, keybundle FFT, accumulator, join buffer).
  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, uint64_t lwe_chunk_size,
             bool allocate_gpu_memory, uint64_t &size_tracker)
      : lwe_chunk_size(lwe_chunk_size),
        gpu_memory_allocated(allocate_gpu_memory),
        glwe_dimension(glwe_dimension), polynomial_size(polynomial_size),
        level_count(level_count),
        input_lwe_ciphertext_count(input_lwe_ciphertext_count),
        gpu_index(gpu_index) {
    cuda_set_device(gpu_index);
    max_shared_memory = cuda_get_max_shared_memory(gpu_index);

    uint64_t full_sm_keybundle =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<
            Torus>(polynomial_size);
    size_t num_blocks_keybundle = keybundle_block_count();

    if (max_shared_memory < full_sm_keybundle)
      d_mem_keybundle = (int8_t *)cuda_malloc_with_size_tracking_async(
          safe_mul(num_blocks_keybundle, full_sm_keybundle), stream, gpu_index,
          size_tracker, allocate_gpu_memory);

    keybundle_fft = (fft_element_type *)cuda_malloc_with_size_tracking_async(
        safe_mul(pbs_fft_traits<Torus>::coefficient_bytes, num_blocks_keybundle,
                 (size_t)(polynomial_size / 2)),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
    global_accumulator = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>((size_t)input_lwe_ciphertext_count,
                               (size_t)(glwe_dimension + 1),
                               (size_t)polynomial_size),
        stream, gpu_index, size_tracker, allocate_gpu_memory);
    global_join_buffer =
        (fft_element_type *)cuda_malloc_with_size_tracking_async(
            safe_mul(
                pbs_fft_traits<Torus>::coefficient_bytes,
                safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1)),
                (size_t)input_lwe_ciphertext_count,
                (size_t)(polynomial_size / 2)),
            stream, gpu_index, size_tracker, allocate_gpu_memory);
  }

  size_t keybundle_block_count() const {
    return safe_mul(
        (size_t)input_lwe_ciphertext_count, (size_t)lwe_chunk_size,
        safe_mul((size_t)(glwe_dimension + 1), (size_t)(glwe_dimension + 1)),
        (size_t)level_count);
  }

  size_t accumulator_block_count() const {
    return safe_mul((size_t)level_count, (size_t)(glwe_dimension + 1),
                    (size_t)input_lwe_ciphertext_count);
  }

  // Device scratch for an accumulate kernel: full_sm bytes per block when the
  // kernel runs in NOSM mode, partial_sm bytes per block in PARTIALSM mode,
  // nothing when everything fits. minimum_sm is shared memory the kernel needs
  // in every mode (TBC uses it for distributed shared memory), so it raises
  // both thresholds. Returns nullptr when nothing is needed.
  int8_t *allocate_accumulator_scratch(size_t num_blocks, uint64_t partial_sm,
                                       uint64_t full_sm, cudaStream_t stream,
                                       uint32_t gpu_index,
                                       uint64_t &size_tracker,
                                       uint64_t minimum_sm = 0) {
    uint64_t bytes_per_block = 0;
    if (max_shared_memory < partial_sm + minimum_sm)
      bytes_per_block = full_sm;
    else if (max_shared_memory < full_sm + minimum_sm)
      bytes_per_block = partial_sm;
    if (bytes_per_block == 0)
      return nullptr;
    return (int8_t *)cuda_malloc_with_size_tracking_async(
        safe_mul(num_blocks, bytes_per_block), stream, gpu_index, size_tracker,
        gpu_memory_allocated);
  }

public:
  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, uint64_t lwe_chunk_size,
             pbs_variant_tag<PBS_VARIANT::DEFAULT>, bool allocate_gpu_memory,
             uint64_t &size_tracker)
      : pbs_buffer(stream, gpu_index, glwe_dimension, polynomial_size,
                   level_count, input_lwe_ciphertext_count, lwe_chunk_size,
                   allocate_gpu_memory, size_tracker) {
    pbs_variant = PBS_VARIANT::DEFAULT;

    uint64_t full_sm_accumulate_step_one =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<Torus>(
            polynomial_size);
    uint64_t partial_sm_accumulate_step_one =
        get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
            Torus>(polynomial_size);
    uint64_t full_sm_accumulate_step_two =
        get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<Torus>(
            polynomial_size);

    d_mem_acc_step_one = allocate_accumulator_scratch(
        accumulator_block_count(), partial_sm_accumulate_step_one,
        full_sm_accumulate_step_one, stream, gpu_index, size_tracker);

    // Step two has no partial shared-memory mode.
    size_t num_blocks_acc_step_two = safe_mul(
        (size_t)input_lwe_ciphertext_count, (size_t)(glwe_dimension + 1));
    if (max_shared_memory < full_sm_accumulate_step_two)
      d_mem_acc_step_two = (int8_t *)cuda_malloc_with_size_tracking_async(
          safe_mul(num_blocks_acc_step_two, full_sm_accumulate_step_two),
          stream, gpu_index, size_tracker, allocate_gpu_memory);
  }

  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, uint64_t lwe_chunk_size,
             pbs_variant_tag<PBS_VARIANT::CG>, bool allocate_gpu_memory,
             uint64_t &size_tracker)
      : pbs_buffer(stream, gpu_index, glwe_dimension, polynomial_size,
                   level_count, input_lwe_ciphertext_count, lwe_chunk_size,
                   allocate_gpu_memory, size_tracker) {
    pbs_variant = PBS_VARIANT::CG;

    uint64_t full_sm_cg_accumulate =
        get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<Torus>(
            polynomial_size);
    uint64_t partial_sm_cg_accumulate =
        get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

    d_mem_acc_cg = allocate_accumulator_scratch(
        accumulator_block_count(), partial_sm_cg_accumulate,
        full_sm_cg_accumulate, stream, gpu_index, size_tracker);
  }

#if CUDA_ARCH >= 900
  // Used by the 64-bit PBS only; there is no 128-bit multi-bit TBC kernel.
  // Constructors of a class template are instantiated only when called.
  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, uint64_t lwe_chunk_size,
             pbs_variant_tag<PBS_VARIANT::TBC>, bool allocate_gpu_memory,
             uint64_t &size_tracker)
      : pbs_buffer(stream, gpu_index, glwe_dimension, polynomial_size,
                   level_count, input_lwe_ciphertext_count, lwe_chunk_size,
                   allocate_gpu_memory, size_tracker) {
    pbs_variant = PBS_VARIANT::TBC;

    uint64_t full_sm_tbc_accumulate =
        get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);
    uint64_t partial_sm_tbc_accumulate =
        get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);
    // We know minimum_sm_tbc bytes are available because otherwise the
    // dispatcher would have redirected computation to another variant.
    uint64_t minimum_sm_tbc =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

    d_mem_acc_tbc = allocate_accumulator_scratch(
        accumulator_block_count(), partial_sm_tbc_accumulate,
        full_sm_tbc_accumulate, stream, gpu_index, size_tracker,
        minimum_sm_tbc);
  }
#endif

private:
  // Borrows the device arrays of owner instead of allocating new ones. Only
  // try_borrow builds it.
  pbs_buffer(pbs_buffer *owner, uint32_t input_lwe_ciphertext_count,
             uint64_t lwe_chunk_size)
      : d_mem_keybundle(owner->d_mem_keybundle),
        d_mem_acc_step_one(owner->d_mem_acc_step_one),
        d_mem_acc_step_two(owner->d_mem_acc_step_two),
        d_mem_acc_cg(owner->d_mem_acc_cg), d_mem_acc_tbc(owner->d_mem_acc_tbc),
        lwe_chunk_size(lwe_chunk_size), keybundle_fft(owner->keybundle_fft),
        global_accumulator(owner->global_accumulator),
        global_join_buffer(owner->global_join_buffer),
        pbs_variant(owner->pbs_variant),
        gpu_memory_allocated(owner->gpu_memory_allocated),
        glwe_dimension(owner->glwe_dimension),
        polynomial_size(owner->polynomial_size),
        level_count(owner->level_count),
        input_lwe_ciphertext_count(input_lwe_ciphertext_count),
        max_shared_memory(owner->max_shared_memory),
        gpu_index(owner->gpu_index) {
    attach_to(owner);
  }

public:
  // Returns a buffer that borrows the device arrays of this one for num_inputs
  // inputs, or nullptr when this buffer cannot serve them. A buffer can be
  // borrowed for num_inputs only if a buffer of its own would select the same
  // variant, and the keybundle arrays of a buffer of its own fit in this one's.
  // The borrower runs with the variant of this buffer and the chunk size a
  // buffer of its own would select, and must only be used on the same stream as
  // this buffer and its other borrowers, one PBS after the other.
  pbs_buffer *try_borrow(uint32_t num_inputs) {
    if (is_borrower || num_inputs > input_lwe_ciphertext_count)
      return nullptr;
    if (get_multi_bit_pbs_variant<Torus>(gpu_index, glwe_dimension,
                                         polynomial_size, level_count,
                                         num_inputs) != pbs_variant)
      return nullptr;
    uint64_t borrower_chunk_size = get_multi_bit_lwe_chunk_size<Torus>(
        gpu_index, num_inputs, polynomial_size);
    if ((uint64_t)num_inputs * borrower_chunk_size >
        (uint64_t)input_lwe_ciphertext_count * lwe_chunk_size)
      return nullptr;
    return new pbs_buffer(this, num_inputs, borrower_chunk_size);
  }

  void release(cudaStream_t stream, uint32_t gpu_index) override {
    if (release_if_borrower())
      return;
    cuda_drop_with_size_tracking_async(d_mem_keybundle, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_mem_acc_step_one, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_mem_acc_step_two, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_mem_acc_cg, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_mem_acc_tbc, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(keybundle_fft, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_accumulator, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_join_buffer, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_synchronize_stream(stream, gpu_index);
    release_borrowers();
  }

protected:
  void clear_device_pointers() override {
    d_mem_keybundle = nullptr;
    d_mem_acc_step_one = nullptr;
    d_mem_acc_step_two = nullptr;
    d_mem_acc_cg = nullptr;
    d_mem_acc_tbc = nullptr;
    keybundle_fft = nullptr;
    global_accumulator = nullptr;
    global_join_buffer = nullptr;
  }
};

#endif // CUDA_MULTI_BIT_UTILITIES_H
