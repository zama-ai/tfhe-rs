#ifndef CUDA_BOOTSTRAP_H
#define CUDA_BOOTSTRAP_H

#include "device.h"
#include <cstdint>

enum PBS_TYPE { MULTI_BIT = 0, CLASSICAL = 1 };
enum PBS_VARIANT { DEFAULT = 0, CG = 1, TBC = 2 };

extern "C" {
void cuda_fourier_polynomial_mul(cudaStream_t stream, uint32_t gpu_index,
                                 void *input1, void *input2, void *output,
                                 uint32_t polynomial_size,
                                 uint32_t total_polynomials);

void cuda_convert_lwe_programmable_bootstrap_key_32(
    void *stream, uint32_t gpu_index, void *dest, void *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

void cuda_convert_lwe_programmable_bootstrap_key_64(
    void *stream, uint32_t gpu_index, void *dest, void *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size);

void scratch_cuda_programmable_bootstrap_amortized_32(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void scratch_cuda_programmable_bootstrap_amortized_64(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void cuda_programmable_bootstrap_amortized_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lut_vector, void *lut_vector_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *bootstrapping_key,
    int8_t *pbs_buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory);

void cuda_programmable_bootstrap_amortized_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lut_vector, void *lut_vector_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *bootstrapping_key,
    int8_t *pbs_buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t gpu_offset = 0);

void cleanup_cuda_programmable_bootstrap_amortized(void *stream,
                                                   uint32_t gpu_index,
                                                   int8_t **pbs_buffer);

void scratch_cuda_programmable_bootstrap_32(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void scratch_cuda_programmable_bootstrap_64(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void cuda_programmable_bootstrap_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lut_vector, void *lut_vector_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t gpu_offset = 0);

void cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lut_vector, void *lut_vector_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *bootstrapping_key,
    int8_t *buffer, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t gpu_offset = 0);

void cleanup_cuda_programmable_bootstrap(void *stream, uint32_t gpu_index,
                                         int8_t **pbs_buffer);

uint64_t get_buffer_size_programmable_bootstrap_amortized_64(
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory);

uint64_t get_buffer_size_programmable_bootstrap_64(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory);
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_programmable_bootstrap_step_one(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_programmable_bootstrap_step_two(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_programmable_bootstrap(uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_programmable_bootstrap_tbc(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_programmable_bootstrap_tbc(
    uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft mask & body
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // tbc
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_programmable_bootstrap_cg(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_programmable_bootstrap_cg(uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft mask & body
}

template <typename Torus>
__host__ bool
supports_distributed_shared_memory_on_classic_programmable_bootstrap(
    uint32_t polynomial_size, uint32_t max_shared_memory);

template <typename Torus, PBS_TYPE pbs_type> struct pbs_buffer;

template <typename Torus> struct pbs_buffer<Torus, PBS_TYPE::CLASSICAL> {
  int8_t *d_mem;

  Torus *global_accumulator;
  double2 *global_accumulator_fft;

  PBS_VARIANT pbs_variant;

  pbs_buffer(cudaStream_t stream, uint32_t gpu_index, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, PBS_VARIANT pbs_variant,
             bool allocate_gpu_memory) {

    this->pbs_variant = pbs_variant;

    auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

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

        global_accumulator_fft = (double2 *)cuda_malloc_async(
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

        global_accumulator_fft = (double2 *)cuda_malloc_async(
            (glwe_dimension + 1) * level_count * input_lwe_ciphertext_count *
                polynomial_size / 2 * sizeof(double2),
            stream, gpu_index);
      } break;
#if CUDA_ARCH >= 900
      case PBS_VARIANT::TBC: {

        bool supports_dsm =
            supports_distributed_shared_memory_on_classic_programmable_bootstrap<
                Torus>(polynomial_size, max_shared_memory);

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

        global_accumulator_fft = (double2 *)cuda_malloc_async(
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
    cuda_drop_async(global_accumulator_fft, stream, gpu_index);

    if (pbs_variant == DEFAULT)
      cuda_drop_async(global_accumulator, stream, gpu_index);
  }
};

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_programmable_bootstrap_cg(
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
                                                   uint32_t num_samples,
                                                   uint32_t max_shared_memory);

template <typename Torus>
void cuda_programmable_bootstrap_cg_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset = 0);

template <typename Torus>
void cuda_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset = 0);

#if (CUDA_ARCH >= 900)
template <typename Torus>
void cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset = 0);

template <typename Torus, typename STorus>
void scratch_cuda_programmable_bootstrap_tbc(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);
#endif

template <typename Torus, typename STorus>
void scratch_cuda_programmable_bootstrap_cg(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

template <typename Torus, typename STorus>
void scratch_cuda_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_tbc(uint32_t num_samples,
                                                    uint32_t glwe_dimension,
                                                    uint32_t polynomial_size,
                                                    uint32_t level_count,
                                                    uint32_t max_shared_memory);

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
