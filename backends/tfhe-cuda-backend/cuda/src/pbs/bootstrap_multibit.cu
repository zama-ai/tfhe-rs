#include "../polynomial/parameters.cuh"
#include "bootstrap_fast_multibit.cuh"
#include "bootstrap_multibit.cuh"
#include "bootstrap_multibit.h"

void cuda_multi_bit_pbs_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx) {

  if (base_log > 64)
    PANIC("Cuda error (multi-bit PBS): base log should be > number of bits in "
          "the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<256>>(
            glwe_dimension, level_count, num_samples)) {
      host_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<256>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    } else {
      host_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<256>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    }
    break;
  case 512:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<512>>(
            glwe_dimension, level_count, num_samples)) {
      host_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<512>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    } else {
      host_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<512>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    }
    break;
  case 1024:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<1024>>(
            glwe_dimension, level_count, num_samples)) {
      host_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<1024>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    } else {
      host_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<1024>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    }
    break;
  case 2048:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<2048>>(
            glwe_dimension, level_count, num_samples)) {
      host_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<2048>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    } else {
      host_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<2048>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    }
    break;
  case 4096:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<4096>>(
            glwe_dimension, level_count, num_samples)) {
      host_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<4096>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    } else {
      host_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<4096>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    }
    break;
  case 8192:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<8192>>(
            glwe_dimension, level_count, num_samples)) {
      host_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<8192>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    } else {
      host_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<8192>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    }
    break;
  case 16384:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<16384>>(
            glwe_dimension, level_count, num_samples)) {
      host_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<16384>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    } else {
      host_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<16384>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<uint64_t *>(bootstrapping_key),
          (pbs_multibit_buffer<uint64_t> *)pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_luts, lwe_idx);
    }
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

void scratch_cuda_multi_bit_pbs_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<256>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count)) {
      scratch_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<256>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    } else {
      scratch_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<256>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    }
    break;
  case 512:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<512>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count)) {
      scratch_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<512>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    } else {
      scratch_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<512>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    }
    break;
  case 1024:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<1024>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count)) {
      scratch_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<1024>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    } else {
      scratch_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<1024>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    }
    break;
  case 2048:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<2048>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count)) {
      scratch_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<2048>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    } else {
      scratch_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<2048>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    }
    break;
  case 4096:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<4096>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count)) {
      scratch_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<4096>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    } else {
      scratch_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<4096>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    }
    break;
  case 8192:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<8192>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count)) {
      scratch_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<8192>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    } else {
      scratch_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<8192>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    }
    break;
  case 16384:
    if (verify_cuda_bootstrap_fast_multi_bit_grid_size<uint64_t,
                                                       AmortizedDegree<16384>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count)) {
      scratch_fast_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<16384>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    } else {
      scratch_multi_bit_pbs<uint64_t, int64_t, AmortizedDegree<16384>>(
          stream, (pbs_multibit_buffer<uint64_t> **)pbs_buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, grouping_factor, allocate_gpu_memory);
    }
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

void cleanup_cuda_multi_bit_pbs(cuda_stream_t *stream, int8_t **mem_ptr_void) {
  pbs_multibit_buffer<uint64_t> *mem_ptr =
      (pbs_multibit_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(stream);
}

// Returns the maximum buffer size required to execute batches up to
// max_input_lwe_ciphertext_count
// todo: Deprecate this function
__host__ uint64_t get_max_buffer_size_multibit_bootstrap(
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_input_lwe_ciphertext_count) {

  uint64_t max_buffer_size = 0;
  for (uint32_t input_lwe_ciphertext_count = 1;
       input_lwe_ciphertext_count <= max_input_lwe_ciphertext_count;
       input_lwe_ciphertext_count *= 2) {
    max_buffer_size = std::max(max_buffer_size,
                               get_buffer_size_multibit_bootstrap<uint64_t>(
                                   glwe_dimension, polynomial_size, level_count,
                                   input_lwe_ciphertext_count, 2));
  }

  return max_buffer_size;
}
