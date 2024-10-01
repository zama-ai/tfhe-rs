#ifndef CUDA_BOOTSTRAP_UTILITIES_H
#define CUDA_BOOTSTRAP_UTILITIES_H

#include "device.h"
#include "pbs_enums.h"
#include "vector_types.h"
#include <stdint.h>

template <typename Torus>
uint64_t get_buffer_size_full_sm_programmable_bootstrap_step_one(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_programmable_bootstrap_step_two(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
uint64_t
get_buffer_size_partial_sm_programmable_bootstrap(uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
uint64_t
get_buffer_size_full_sm_programmable_bootstrap_tbc(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
uint64_t get_buffer_size_partial_sm_programmable_bootstrap_tbc(
    uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft mask & body
}

template <typename Torus>
uint64_t get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // tbc
}

template <typename Torus>
uint64_t
get_buffer_size_full_sm_programmable_bootstrap_cg(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
uint64_t
get_buffer_size_partial_sm_programmable_bootstrap_cg(uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft mask & body
}

template <typename Torus>
bool supports_distributed_shared_memory_on_classic_programmable_bootstrap(
    uint32_t polynomial_size);

template <typename Torus, PBS_TYPE pbs_type> struct pbs_buffer;

template <typename Torus> struct pbs_buffer<Torus, PBS_TYPE::CLASSICAL> {
  int8_t *d_mem;

  Torus *global_accumulator;
  double2 *global_join_buffer;

  PBS_VARIANT pbs_variant;

  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, PBS_VARIANT pbs_variant,
             bool allocate_gpu_memory) {

    this->pbs_variant = pbs_variant;

    auto max_shared_memory = cuda_get_max_shared_memory(0);

    if (allocate_gpu_memory) {
      switch (pbs_variant) {
      case PBS_VARIANT::DEFAULT: {
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

        uint64_t device_mem = 0;
        if (max_shared_memory < partial_sm) {
          device_mem = full_dm * input_lwe_ciphertext_count * level_count *
                       (glwe_dimension + 1);
        } else if (max_shared_memory < full_sm_step_two) {
          device_mem =
              (partial_dm_step_two + partial_dm_step_one * level_count) *
              input_lwe_ciphertext_count * (glwe_dimension + 1);
        } else if (max_shared_memory < full_sm_step_one) {
          device_mem = partial_dm_step_one * input_lwe_ciphertext_count *
                       level_count * (glwe_dimension + 1);
        }
        // Otherwise, both kernels run all in shared memory
        d_mem = (int8_t *)cuda_malloc_async(device_mem, stream, gpu_index);

        global_join_buffer = (double2 *)cuda_malloc_async(
            (glwe_dimension + 1) * level_count * input_lwe_ciphertext_count *
                (polynomial_size / 2) * sizeof(double2),
            stream, gpu_index);

        global_accumulator = (Torus *)cuda_malloc_async(
            (glwe_dimension + 1) * input_lwe_ciphertext_count *
                polynomial_size * sizeof(Torus),
            stream, gpu_index);
      } break;
      case PBS_VARIANT::CG: {
        uint64_t full_sm =
            get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(
                polynomial_size);
        uint64_t partial_sm =
            get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
                polynomial_size);

        uint64_t partial_dm = full_sm - partial_sm;
        uint64_t full_dm = full_sm;
        uint64_t device_mem = 0;

        if (max_shared_memory < partial_sm) {
          device_mem = full_dm * input_lwe_ciphertext_count * level_count *
                       (glwe_dimension + 1);
        } else if (max_shared_memory < full_sm) {
          device_mem = partial_dm * input_lwe_ciphertext_count * level_count *
                       (glwe_dimension + 1);
        }

        // Otherwise, both kernels run all in shared memory
        d_mem = (int8_t *)cuda_malloc_async(device_mem, stream, gpu_index);

        global_join_buffer = (double2 *)cuda_malloc_async(
            (glwe_dimension + 1) * level_count * input_lwe_ciphertext_count *
                polynomial_size / 2 * sizeof(double2),
            stream, gpu_index);
      } break;
#if CUDA_ARCH >= 900
      case PBS_VARIANT::TBC: {

        bool supports_dsm =
            supports_distributed_shared_memory_on_classic_programmable_bootstrap<
                Torus>(polynomial_size);

        uint64_t full_sm =
            get_buffer_size_full_sm_programmable_bootstrap_tbc<Torus>(
                polynomial_size);
        uint64_t partial_sm =
            get_buffer_size_partial_sm_programmable_bootstrap_tbc<Torus>(
                polynomial_size);
        uint64_t minimum_sm_tbc = 0;
        if (supports_dsm)
          minimum_sm_tbc =
              get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap<
                  Torus>(polynomial_size);

        uint64_t partial_dm = full_sm - partial_sm;
        uint64_t full_dm = full_sm;
        uint64_t device_mem = 0;

        // There is a minimum amount of memory we need to run the TBC PBS, which
        // is minimum_sm_tbc. We know that minimum_sm_tbc bytes are available
        // because otherwise the previous check would have redirected
        // computation to some other variant. If over that we don't have more
        // partial_sm bytes, TBC PBS will run on NOSM. If we have partial_sm but
        // not full_sm bytes, it will run on PARTIALSM. Otherwise, FULLSM.
        //
        // NOSM mode actually requires minimum_sm_tbc shared memory bytes.
        if (max_shared_memory < partial_sm + minimum_sm_tbc) {
          device_mem = full_dm * input_lwe_ciphertext_count * level_count *
                       (glwe_dimension + 1);
        } else if (max_shared_memory < full_sm + minimum_sm_tbc) {
          device_mem = partial_dm * input_lwe_ciphertext_count * level_count *
                       (glwe_dimension + 1);
        }

        // Otherwise, both kernels run all in shared memory
        d_mem = (int8_t *)cuda_malloc_async(device_mem, stream, gpu_index);

        global_join_buffer = (double2 *)cuda_malloc_async(
            (glwe_dimension + 1) * level_count * input_lwe_ciphertext_count *
                polynomial_size / 2 * sizeof(double2),
            stream, gpu_index);
      } break;
#endif
      default:
        PANIC("Cuda error (PBS): unsupported implementation variant.")
      }
    }
  }

  void release(cudaStream_t stream, uint32_t gpu_index) {
    cuda_drop_async(d_mem, stream, gpu_index);
    cuda_drop_async(global_join_buffer, stream, gpu_index);

    if (pbs_variant == DEFAULT)
      cuda_drop_async(global_accumulator, stream, gpu_index);
  }
};

template <typename Torus>
uint64_t get_buffer_size_programmable_bootstrap_cg(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count) {
  int max_shared_memory = cuda_get_max_shared_memory(0);
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
          polynomial_size);
  uint64_t partial_dm = full_sm - partial_sm;
  uint64_t full_dm = full_sm;
  uint64_t device_mem = 0;
  if (max_shared_memory < partial_sm) {
    device_mem = full_dm * input_lwe_ciphertext_count * level_count *
                 (glwe_dimension + 1);
  } else if (max_shared_memory < full_sm) {
    device_mem = partial_dm * input_lwe_ciphertext_count * level_count *
                 (glwe_dimension + 1);
  }
  uint64_t buffer_size = device_mem + (glwe_dimension + 1) * level_count *
                                          input_lwe_ciphertext_count *
                                          polynomial_size / 2 * sizeof(double2);
  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_cg(uint32_t glwe_dimension,
                                                   uint32_t polynomial_size,
                                                   uint32_t level_count,
                                                   uint32_t num_samples);

template <typename Torus>
void cuda_programmable_bootstrap_cg_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride);

template <typename Torus>
void cuda_programmable_bootstrap_lwe_ciphertext_vector(
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
void cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride);

template <typename Torus>
void scratch_cuda_programmable_bootstrap_tbc(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);
#endif

template <typename Torus>
void scratch_cuda_programmable_bootstrap_cg(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template <typename Torus>
void scratch_cuda_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_tbc(uint32_t num_samples,
                                                    uint32_t glwe_dimension,
                                                    uint32_t polynomial_size,
                                                    uint32_t level_count);

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
