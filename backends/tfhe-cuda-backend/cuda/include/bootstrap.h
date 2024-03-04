#ifndef CUDA_BOOTSTRAP_H
#define CUDA_BOOTSTRAP_H

#include "device.h"
#include <cstdint>

enum PBS_TYPE { MULTI_BIT = 0, LOW_LAT = 1, AMORTIZED = 2 };
enum PBS_VARIANT { DEFAULT = 0, FAST = 1 };

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
    cuda_stream_t *stream, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void scratch_cuda_bootstrap_low_latency_64(
    cuda_stream_t *stream, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

void cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory);

void cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory);

void cleanup_cuda_bootstrap_low_latency_32(cuda_stream_t *stream,
                                           int8_t **pbs_buffer);

void cleanup_cuda_bootstrap_low_latency_64(cuda_stream_t *stream,
                                           int8_t **pbs_buffer);

uint64_t get_buffer_size_bootstrap_amortized_64(
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory);

uint64_t get_buffer_size_bootstrap_low_latency_64(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory);
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_bootstrap_low_latency_step_one(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_bootstrap_low_latency_step_two(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_bootstrap_low_latency(uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_bootstrap_fast_low_latency(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_bootstrap_fast_low_latency(
    uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft mask & body
}

template <typename Torus, PBS_TYPE pbs_type> struct pbs_buffer;

template <typename Torus> struct pbs_buffer<Torus, PBS_TYPE::LOW_LAT> {
  int8_t *d_mem;

  Torus *global_accumulator;
  double2 *global_accumulator_fft;

  PBS_VARIANT pbs_variant;

  pbs_buffer(cuda_stream_t *stream, uint32_t glwe_dimension,
             uint32_t polynomial_size, uint32_t level_count,
             uint32_t input_lwe_ciphertext_count, PBS_VARIANT pbs_variant,
             bool allocate_gpu_memory) {
    this->pbs_variant = pbs_variant;

    auto max_shared_memory = cuda_get_max_shared_memory(stream->gpu_index);

    if (allocate_gpu_memory) {
      switch (pbs_variant) {
      case PBS_VARIANT::DEFAULT: {
        uint64_t full_sm_step_one =
            get_buffer_size_full_sm_bootstrap_low_latency_step_one<Torus>(
                polynomial_size);
        uint64_t full_sm_step_two =
            get_buffer_size_full_sm_bootstrap_low_latency_step_two<Torus>(
                polynomial_size);
        uint64_t partial_sm =
            get_buffer_size_partial_sm_bootstrap_low_latency<Torus>(
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
        d_mem = (int8_t *)cuda_malloc_async(device_mem, stream);

        global_accumulator_fft = (double2 *)cuda_malloc_async(
            (glwe_dimension + 1) * level_count * input_lwe_ciphertext_count *
                (polynomial_size / 2) * sizeof(double2),
            stream);

        global_accumulator = (Torus *)cuda_malloc_async(
            (glwe_dimension + 1) * input_lwe_ciphertext_count *
                polynomial_size * sizeof(Torus),
            stream);
      } break;
      case PBS_VARIANT::FAST: {
        uint64_t full_sm =
            get_buffer_size_full_sm_bootstrap_fast_low_latency<Torus>(
                polynomial_size);
        uint64_t partial_sm =
            get_buffer_size_partial_sm_bootstrap_fast_low_latency<Torus>(
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
        d_mem = (int8_t *)cuda_malloc_async(device_mem, stream);

        global_accumulator_fft = (double2 *)cuda_malloc_async(
            (glwe_dimension + 1) * level_count * input_lwe_ciphertext_count *
                polynomial_size / 2 * sizeof(double2),
            stream);
      } break;
      default:
        PANIC("Cuda error (PBS): unsupported implementation variant.")
      }
    }
  }

  void release(cuda_stream_t *stream) {
    cuda_drop_async(d_mem, stream);
    cuda_drop_async(global_accumulator_fft, stream);

    if (pbs_variant == DEFAULT)
      cuda_drop_async(global_accumulator, stream);
  }
};

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_bootstrap_fast_low_latency(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {

  uint64_t full_sm = get_buffer_size_full_sm_bootstrap_fast_low_latency<Torus>(
      polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_bootstrap_fast_low_latency<Torus>(
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
bool has_support_to_cuda_bootstrap_fast_low_latency(uint32_t glwe_dimension,
                                                    uint32_t polynomial_size,
                                                    uint32_t level_count,
                                                    uint32_t num_samples,
                                                    uint32_t max_shared_memory);

template <typename Torus>
void cuda_bootstrap_fast_low_latency_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, LOW_LAT> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory);

template <typename Torus>
void cuda_bootstrap_low_latency_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, LOW_LAT> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory);

template <typename Torus, typename STorus>
void scratch_cuda_fast_bootstrap_low_latency(
    cuda_stream_t *stream, pbs_buffer<Torus, LOW_LAT> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

template <typename Torus, typename STorus>
void scratch_cuda_bootstrap_low_latency(
    cuda_stream_t *stream, pbs_buffer<Torus, LOW_LAT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

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
