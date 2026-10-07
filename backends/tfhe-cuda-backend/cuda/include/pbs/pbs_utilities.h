#ifndef CUDA_BOOTSTRAP_UTILITIES_H
#define CUDA_BOOTSTRAP_UTILITIES_H

#include "checked_arithmetic.h"
#include "device.h"
#include "pbs_enums.h"
#include "vector_types.h"
#include <stdint.h>

// The 128-bit FFT stores one complex coefficient as four doubles
// (re_hi, re_lo, im_hi, im_lo), the f128x2 type in fft128/f128.cuh. That
// header is not visible from include/, so the count is named here and tied to
// the type by a static_assert in programmable_bootstrap_classic_128.cuh.
constexpr size_t PBS128_DOUBLES_PER_FOURIER_COEFFICIENT = 4;

// How a pbs_buffer stores Fourier-domain data for a given torus width.
// element_type is what the buffer pointers point to; coefficient_bytes is the
// size of one complex coefficient, used to size those buffers. The 64-bit PBS
// keeps one coefficient per double2. The 128-bit PBS keeps the four doubles of
// a coefficient in separate planes, so its buffers are addressed as double.
template <typename Torus> struct pbs_fft_traits {
  using element_type = double2;
  static constexpr size_t coefficient_bytes = sizeof(double2);
};

template <> struct pbs_fft_traits<__uint128_t> {
  using element_type = double;
  static constexpr size_t coefficient_bytes =
      PBS128_DOUBLES_PER_FOURIER_COEFFICIENT * sizeof(double);
};

// Selects a pbs_buffer constructor at compile time. Every scratch function
// knows its variant statically, so no runtime switch is needed to build the
// buffer. The runtime pbs_variant field is still stored because the FFI layer
// type-erases the buffer and dispatches on it.
template <PBS_VARIANT variant> struct pbs_variant_tag {};

template <typename Torus>
uint64_t get_buffer_size_full_sm_programmable_bootstrap_step_one(
    uint32_t polynomial_size) {
  size_t double_count = (sizeof(Torus) == 16) ? 2 : 1;
  return safe_mul_sizeof<Torus>(polynomial_size) + // accumulator_rotated
         safe_mul_sizeof<double>(double_count,
                                 (size_t)polynomial_size); // accumulator fft
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_programmable_bootstrap_step_two(
    uint32_t polynomial_size) {
  size_t double_count = (sizeof(Torus) == 16) ? 2 : 1;
  return safe_mul_sizeof<Torus>(polynomial_size) + // accumulator
         safe_mul_sizeof<double>(double_count,
                                 (size_t)polynomial_size); // accumulator fft
}

template <typename Torus>
uint64_t
get_buffer_size_partial_sm_programmable_bootstrap(uint32_t polynomial_size) {
  size_t double_count = (sizeof(Torus) == 16) ? 2 : 1;
  return safe_mul_sizeof<double>(double_count,
                                 (size_t)polynomial_size); // accumulator fft
}

template <typename Torus>
uint64_t
get_buffer_size_full_sm_programmable_bootstrap_tbc(uint32_t polynomial_size) {
  return safe_mul_sizeof<Torus>(polynomial_size) + // accumulator_rotated
         safe_mul_sizeof<Torus>(polynomial_size) + // accumulator
         safe_mul(pbs_fft_traits<Torus>::coefficient_bytes,
                  (size_t)(polynomial_size / 2)); // accumulator fft
}

template <typename Torus>
uint64_t get_buffer_size_partial_sm_programmable_bootstrap_tbc(
    uint32_t polynomial_size) {
  return safe_mul_sizeof<double2>(polynomial_size /
                                  2); // accumulator fft mask & body
}

template <typename Torus>
uint64_t get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap(
    uint32_t polynomial_size) {
  return safe_mul_sizeof<double2>(polynomial_size / 2); // tbc
}

template <typename Torus>
uint64_t get_buffer_size_full_sm_programmable_bootstrap_tbc_2_2_params(
    uint32_t polynomial_size) {
  // In the first implementation with 2-2 params, we need up to 5 polynomials in
  // shared memory we can optimize this later
  return safe_mul_sizeof<Torus>((size_t)polynomial_size, (size_t)5);
}

template <typename Torus>
uint64_t
get_buffer_size_full_sm_programmable_bootstrap_cg(uint32_t polynomial_size) {
  size_t double_count = (sizeof(Torus) == 16) ? 2 : 1;
  return safe_mul_sizeof<Torus>(polynomial_size) + // accumulator_rotated
         safe_mul_sizeof<Torus>(polynomial_size) + // accumulator
         safe_mul_sizeof<double>((size_t)polynomial_size,
                                 double_count); // accumulator fft
}

template <typename Torus>
uint64_t
get_buffer_size_partial_sm_programmable_bootstrap_cg(uint32_t polynomial_size) {
  size_t double_count = (sizeof(Torus) == 16) ? 2 : 1;
  return safe_mul_sizeof<double>((size_t)polynomial_size,
                                 double_count); // accumulator fft mask & body
}
template <typename Torus>
bool supports_distributed_shared_memory_on_classic_programmable_bootstrap(
    uint32_t polynomial_size, uint32_t max_shared_memory);

struct pbs_buffer_base {
  virtual void release(cudaStream_t stream, uint32_t gpu_index) = 0;
  virtual ~pbs_buffer_base() = default;
};

template <typename Torus, PBS_TYPE pbs_type> struct pbs_buffer;

template <typename Torus>
struct pbs_buffer<Torus, PBS_TYPE::CLASSICAL> : public pbs_buffer_base {
  using fft_element_type = typename pbs_fft_traits<Torus>::element_type;

  int8_t *d_mem = nullptr;

  Torus *global_accumulator = nullptr;
  fft_element_type *global_join_buffer = nullptr;

  PBS_VARIANT pbs_variant;
  PBS_MS_REDUCTION_T noise_reduction_type;
  bool gpu_memory_allocated;

  uint32_t glwe_dimension;
  uint32_t polynomial_size;
  uint32_t level_count;
  uint32_t input_lwe_ciphertext_count;
  uint32_t max_shared_memory;

private:
  // Variant-free part. Every public constructor delegates here first, then
  // sets pbs_variant and allocates what its own kernel needs.
  pbs_buffer(uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
             PBS_MS_REDUCTION_T noise_reduction_type)
      : noise_reduction_type(noise_reduction_type),
        gpu_memory_allocated(allocate_gpu_memory),
        glwe_dimension(glwe_dimension), polynomial_size(polynomial_size),
        level_count(level_count),
        input_lwe_ciphertext_count(input_lwe_ciphertext_count) {
    cuda_set_device(gpu_index);
    max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  }

  // Device scratch each block needs when the kernel cannot keep everything in
  // shared memory. Below partial_sm the kernel runs in NOSM mode and needs
  // full_sm bytes of device memory; between partial_sm and full_sm it runs in
  // PARTIALSM mode and needs the remainder; above full_sm nothing. minimum_sm
  // is shared memory the kernel needs in every mode (TBC uses it for
  // distributed shared memory), so it raises both thresholds.
  uint64_t device_scratch_per_block(uint64_t partial_sm, uint64_t full_sm,
                                    uint64_t minimum_sm = 0) const {
    if (max_shared_memory < partial_sm + minimum_sm)
      return full_sm;
    if (max_shared_memory < full_sm + minimum_sm)
      return full_sm - partial_sm;
    return 0;
  }

  void allocate_d_mem(uint64_t bytes_per_block, cudaStream_t stream,
                      uint32_t gpu_index, uint64_t &size_tracker) {
    d_mem = (int8_t *)cuda_malloc_with_size_tracking_async(
        safe_mul(bytes_per_block, (size_t)input_lwe_ciphertext_count,
                 (size_t)level_count, (size_t)(glwe_dimension + 1)),
        stream, gpu_index, size_tracker, gpu_memory_allocated);
  }

  void allocate_global_join_buffer(cudaStream_t stream, uint32_t gpu_index,
                                   uint64_t &size_tracker) {
    global_join_buffer =
        (fft_element_type *)cuda_malloc_with_size_tracking_async(
            safe_mul(
                pbs_fft_traits<Torus>::coefficient_bytes,
                safe_mul((size_t)(glwe_dimension + 1), (size_t)level_count),
                (size_t)input_lwe_ciphertext_count,
                (size_t)(polynomial_size / 2)),
            stream, gpu_index, size_tracker, gpu_memory_allocated);
  }

  void allocate_global_accumulator(cudaStream_t stream, uint32_t gpu_index,
                                   uint64_t &size_tracker) {
    global_accumulator = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>((size_t)(glwe_dimension + 1),
                               (size_t)input_lwe_ciphertext_count,
                               (size_t)polynomial_size),
        stream, gpu_index, size_tracker, gpu_memory_allocated);
  }

public:
  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t lwe_dimension,
             uint32_t glwe_dimension, uint32_t polynomial_size,
             uint32_t level_count, uint32_t input_lwe_ciphertext_count,
             pbs_variant_tag<PBS_VARIANT::DEFAULT>, bool allocate_gpu_memory,
             PBS_MS_REDUCTION_T noise_reduction_type, uint64_t &size_tracker)
      : pbs_buffer(gpu_index, glwe_dimension, polynomial_size, level_count,
                   input_lwe_ciphertext_count, allocate_gpu_memory,
                   noise_reduction_type) {
    pbs_variant = PBS_VARIANT::DEFAULT;

    uint64_t full_sm_step_one =
        get_buffer_size_full_sm_programmable_bootstrap_step_one<Torus>(
            polynomial_size);
    uint64_t full_sm_step_two =
        get_buffer_size_full_sm_programmable_bootstrap_step_two<Torus>(
            polynomial_size);
    uint64_t partial_sm =
        get_buffer_size_partial_sm_programmable_bootstrap<Torus>(
            polynomial_size);

    uint64_t partial_dm_step_one = full_sm_step_one - partial_sm;
    uint64_t partial_dm_step_two = full_sm_step_two - partial_sm;
    uint64_t full_dm = full_sm_step_one;

    // Two kernels with different full-shared-memory needs share d_mem, so
    // the middle region cannot use device_scratch_per_block: step two may
    // already fit while step one still needs its per-level remainder.
    uint64_t device_mem = 0;
    if (max_shared_memory < partial_sm) {
      device_mem = safe_mul(full_dm, (size_t)input_lwe_ciphertext_count,
                            (size_t)level_count, (size_t)(glwe_dimension + 1));
    } else if (max_shared_memory < full_sm_step_two) {
      device_mem = safe_mul(partial_dm_step_two + safe_mul(partial_dm_step_one,
                                                           (size_t)level_count),
                            (size_t)input_lwe_ciphertext_count,
                            (size_t)(glwe_dimension + 1));
    } else if (max_shared_memory < full_sm_step_one) {
      device_mem =
          safe_mul(partial_dm_step_one, (size_t)input_lwe_ciphertext_count,
                   (size_t)level_count, (size_t)(glwe_dimension + 1));
    }
    d_mem = (int8_t *)cuda_malloc_with_size_tracking_async(
        device_mem, stream, gpu_index, size_tracker, allocate_gpu_memory);

    allocate_global_join_buffer(stream, gpu_index, size_tracker);
    allocate_global_accumulator(stream, gpu_index, size_tracker);
  }

  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t lwe_dimension,
             uint32_t glwe_dimension, uint32_t polynomial_size,
             uint32_t level_count, uint32_t input_lwe_ciphertext_count,
             pbs_variant_tag<PBS_VARIANT::CG>, bool allocate_gpu_memory,
             PBS_MS_REDUCTION_T noise_reduction_type, uint64_t &size_tracker)
      : pbs_buffer(gpu_index, glwe_dimension, polynomial_size, level_count,
                   input_lwe_ciphertext_count, allocate_gpu_memory,
                   noise_reduction_type) {
    pbs_variant = PBS_VARIANT::CG;

    uint64_t full_sm = get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(
        polynomial_size);
    uint64_t partial_sm =
        get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
            polynomial_size);

    allocate_d_mem(device_scratch_per_block(partial_sm, full_sm), stream,
                   gpu_index, size_tracker);
    allocate_global_join_buffer(stream, gpu_index, size_tracker);
  }

#if CUDA_ARCH >= 900
  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t lwe_dimension,
             uint32_t glwe_dimension, uint32_t polynomial_size,
             uint32_t level_count, uint32_t input_lwe_ciphertext_count,
             pbs_variant_tag<PBS_VARIANT::TBC>, bool allocate_gpu_memory,
             PBS_MS_REDUCTION_T noise_reduction_type, uint64_t &size_tracker)
      : pbs_buffer(gpu_index, glwe_dimension, polynomial_size, level_count,
                   input_lwe_ciphertext_count, allocate_gpu_memory,
                   noise_reduction_type) {
    pbs_variant = PBS_VARIANT::TBC;

    bool supports_dsm =
        supports_distributed_shared_memory_on_classic_programmable_bootstrap<
            Torus>(polynomial_size, max_shared_memory);

    uint64_t full_sm =
        get_buffer_size_full_sm_programmable_bootstrap_tbc<Torus>(
            polynomial_size);
    uint64_t partial_sm =
        get_buffer_size_partial_sm_programmable_bootstrap_tbc<Torus>(
            polynomial_size);
    // We know minimum_sm_tbc bytes are available because otherwise the
    // dispatcher would have redirected computation to another variant.
    uint64_t minimum_sm_tbc = 0;
    if (supports_dsm)
      minimum_sm_tbc =
          get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap<Torus>(
              polynomial_size);

    allocate_d_mem(
        device_scratch_per_block(partial_sm, full_sm, minimum_sm_tbc), stream,
        gpu_index, size_tracker);
    allocate_global_join_buffer(stream, gpu_index, size_tracker);
  }

  // Used by the 128-bit PBS only. Constructors of a class template are
  // instantiated only when called, so no width check is needed here.
  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t lwe_dimension,
             uint32_t glwe_dimension, uint32_t polynomial_size,
             uint32_t level_count, uint32_t input_lwe_ciphertext_count,
             pbs_variant_tag<PBS_VARIANT::TBC_HOST_DRIVEN>,
             bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type,
             uint64_t &size_tracker)
      : pbs_buffer(gpu_index, glwe_dimension, polynomial_size, level_count,
                   input_lwe_ciphertext_count, allocate_gpu_memory,
                   noise_reduction_type) {
    pbs_variant = PBS_VARIANT::TBC_HOST_DRIVEN;
    // One blind-rotation iteration per launch, all levels in shared memory:
    // no device scratch and no join buffer.
    allocate_global_accumulator(stream, gpu_index, size_tracker);
  }
#endif

  void release(cudaStream_t stream, uint32_t gpu_index) override {
    cuda_drop_with_size_tracking_async(d_mem, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_join_buffer, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(global_accumulator, stream, gpu_index,
                                       gpu_memory_allocated);
    cuda_synchronize_stream(stream, gpu_index);
  }
};

template <typename Torus>
uint64_t get_buffer_size_programmable_bootstrap_cg(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
          polynomial_size);
  uint64_t partial_dm = full_sm - partial_sm;
  uint64_t full_dm = full_sm;
  uint64_t device_mem = 0;
  if (max_shared_memory < partial_sm) {
    device_mem = safe_mul(full_dm, (size_t)input_lwe_ciphertext_count,
                          (size_t)level_count, (size_t)(glwe_dimension + 1));
  } else if (max_shared_memory < full_sm) {
    device_mem = safe_mul(partial_dm, (size_t)input_lwe_ciphertext_count,
                          (size_t)level_count, (size_t)(glwe_dimension + 1));
  }
  uint64_t buffer_size =
      device_mem +
      safe_mul_sizeof<double2>(
          safe_mul((size_t)(glwe_dimension + 1), (size_t)level_count),
          (size_t)input_lwe_ciphertext_count, (size_t)(polynomial_size / 2));
  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_cg(uint32_t glwe_dimension,
                                                   uint32_t polynomial_size,
                                                   uint32_t level_count,
                                                   uint32_t num_samples,
                                                   uint32_t max_shared_memory);

template <typename Torus>
void cuda_programmable_bootstrap_cg_lwe_ciphertext_vector_async(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride);

template <typename Torus>
void cuda_programmable_bootstrap_lwe_ciphertext_vector_async(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride);

#if (CUDA_ARCH >= 900)
template <typename Torus>
void cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector_async(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride);

template <typename Torus>
uint64_t scratch_cuda_programmable_bootstrap_tbc(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);
#endif

template <typename Torus>
uint64_t scratch_cuda_programmable_bootstrap_cg(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

template <typename Torus>
uint64_t scratch_cuda_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_tbc(uint32_t num_samples,
                                                    uint32_t glwe_dimension,
                                                    uint32_t polynomial_size,
                                                    uint32_t level_count,
                                                    uint32_t max_shared_memory);

bool has_support_to_cuda_programmable_bootstrap_128_cg(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t num_samples, uint32_t max_shared_memory);

bool has_support_to_cuda_programmable_bootstrap_128_tbc(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory);

#ifdef __CUDACC__
__device__ inline int get_start_ith_ggsw(int i, uint32_t polynomial_size,
                                         int glwe_dimension,
                                         uint32_t level_count);

template <typename T>
__device__ const T *get_ith_mask_kth_block(const T *ptr, int i, int k,
                                           int level, uint32_t polynomial_size,
                                           int glwe_dimension,
                                           uint32_t level_count);

template <typename T>
__device__ T *get_ith_mask_kth_block(T *ptr, int i, int k, int level,
                                     uint32_t polynomial_size,
                                     int glwe_dimension, uint32_t level_count);

template <typename T, uint32_t polynomial_size, uint32_t glwe_dimension,
          uint32_t level_count, uint32_t level_id>
__device__ const T *get_ith_mask_kth_block_2_2_params(const T *ptr,
                                                      int iteration, int k);

template <typename T>
__device__ T *get_ith_body_kth_block(T *ptr, int i, int k, int level,
                                     uint32_t polynomial_size,
                                     int glwe_dimension, uint32_t level_count);

template <typename T>
__device__ const T *get_multi_bit_ith_lwe_gth_group_kth_block(
    const T *ptr, int g, int i, int k, int level, uint32_t grouping_factor,
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count);

#endif

#endif // CUDA_BOOTSTRAP_UTILITIES_H
