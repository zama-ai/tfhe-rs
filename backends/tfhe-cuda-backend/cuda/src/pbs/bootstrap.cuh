#include "../../include/bootstrap.h"
#include "../../include/device.h"
#include "../include/device.h"
#include "bootstrap_low_latency.cuh"
#include "bootstrap_multibit.cuh"

template <typename Torus>
void execute_pbs(cuda_stream_t *stream, Torus *lwe_array_out,
                 Torus *lwe_output_indexes, Torus *lut_vector,
                 Torus *lut_vector_indexes, Torus *lwe_array_in,
                 Torus *lwe_input_indexes, void *bootstrapping_key,
                 int8_t *pbs_buffer, uint32_t glwe_dimension,
                 uint32_t lwe_dimension, uint32_t polynomial_size,
                 uint32_t base_log, uint32_t level_count,
                 uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
                 uint32_t num_luts, uint32_t lwe_idx,
                 uint32_t max_shared_memory, PBS_TYPE pbs_type) {
  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case LOW_LAT:
      cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
      break;
    case AMORTIZED:
      cuda_bootstrap_amortized_lwe_ciphertext_vector_32(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
      break;
    default:
      break;
    }
    break;
  case sizeof(uint64_t):
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      cuda_multi_bit_pbs_lwe_ciphertext_vector_64(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, grouping_factor, base_log, level_count,
          input_lwe_ciphertext_count, num_luts, lwe_idx, max_shared_memory);
      break;
    case LOW_LAT:
      cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
      break;
    case AMORTIZED:
      cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
    break;
  default:
    PANIC("Cuda error: unsupported modulus size: only 32 and 64 bit integer "
          "moduli are supported.")
  }
}

template <typename Torus>
void execute_scratch_pbs(cuda_stream_t *stream, int8_t **pbs_buffer,
                         uint32_t glwe_dimension, uint32_t lwe_dimension,
                         uint32_t polynomial_size, uint32_t level_count,
                         uint32_t grouping_factor,
                         uint32_t input_lwe_ciphertext_count,
                         uint32_t max_shared_memory, PBS_TYPE pbs_type,
                         bool allocate_gpu_memory) {
  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case LOW_LAT:
      scratch_cuda_bootstrap_low_latency_32(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    case AMORTIZED:
      scratch_cuda_bootstrap_amortized_32(
          stream, pbs_buffer, glwe_dimension, polynomial_size,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
    break;
  case sizeof(uint64_t):
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      scratch_cuda_multi_bit_pbs_64(
          stream, pbs_buffer, lwe_dimension, glwe_dimension, polynomial_size,
          level_count, grouping_factor, input_lwe_ciphertext_count,
          max_shared_memory, allocate_gpu_memory);
      break;
    case LOW_LAT:
      scratch_cuda_bootstrap_low_latency_64(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    case AMORTIZED:
      scratch_cuda_bootstrap_amortized_64(
          stream, pbs_buffer, glwe_dimension, polynomial_size,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
    break;
  default:
    PANIC("Cuda error: unsupported modulus size: only 32 and 64 bit integer "
          "moduli are supported.")
  }
}
