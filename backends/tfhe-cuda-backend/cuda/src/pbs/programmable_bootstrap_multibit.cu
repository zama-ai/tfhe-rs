#include "../polynomial/parameters.cuh"
#include "pbs/programmable_bootstrap_multibit.h"
#include "programmable_bootstrap_cg_multibit.cuh"
#include "programmable_bootstrap_multibit.cuh"

#if (CUDA_ARCH >= 900)
#include "programmable_bootstrap_tbc_multibit.cuh"
#endif

bool has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t num_samples, uint32_t max_shared_memory) {
  return supports_cooperative_groups_on_multibit_programmable_bootstrap<
      uint64_t>(glwe_dimension, polynomial_size, level_count, num_samples,
                max_shared_memory);
}

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_tbc_multi_bit(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory) {
#if CUDA_ARCH >= 900
  if ((glwe_dimension + 1) * level_count > 8)
    return false;

  switch (polynomial_size) {
  case 256:
    return supports_thread_block_clusters_on_multibit_programmable_bootstrap<
        Torus, AmortizedDegree<256>>(num_samples, glwe_dimension,
                                     polynomial_size, level_count,
                                     max_shared_memory);
  case 512:
    return supports_thread_block_clusters_on_multibit_programmable_bootstrap<
        Torus, AmortizedDegree<512>>(num_samples, glwe_dimension,
                                     polynomial_size, level_count,
                                     max_shared_memory);
  case 1024:
    return supports_thread_block_clusters_on_multibit_programmable_bootstrap<
        Torus, AmortizedDegree<1024>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 2048:
    return supports_thread_block_clusters_on_multibit_programmable_bootstrap<
        Torus, AmortizedDegree<2048>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 4096:
    return supports_thread_block_clusters_on_multibit_programmable_bootstrap<
        Torus, AmortizedDegree<4096>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 8192:
    return supports_thread_block_clusters_on_multibit_programmable_bootstrap<
        Torus, AmortizedDegree<8192>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 16384:
    return supports_thread_block_clusters_on_multibit_programmable_bootstrap<
        Torus, AmortizedDegree<16384>>(num_samples, glwe_dimension,
                                       polynomial_size, level_count,
                                       max_shared_memory);
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
#else
  return false;
#endif
}

template <typename Torus>
void cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  switch (polynomial_size) {
  case 256:
    host_cg_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 512:
    host_cg_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 1024:
    host_cg_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 2048:
    host_cg_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 4096:
    host_cg_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 8192:
    host_cg_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 16384:
    host_cg_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

template <typename Torus>
void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  switch (polynomial_size) {
  case 256:
    host_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 512:
    host_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 1024:
    host_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 2048:
    host_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 4096:
    host_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 8192:
    host_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 16384:
    host_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lut_vector_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *bootstrapping_key,
    int8_t *mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_many_lut,
    uint32_t lut_stride) {

  PANIC_IF_FALSE(base_log <= 64,
                 "Cuda error (multi-bit PBS): base log (%d) should be <= 64",
                 base_log);

  pbs_buffer<uint64_t, MULTI_BIT> *buffer =
      (pbs_buffer<uint64_t, MULTI_BIT> *)mem_ptr;

  switch (buffer->pbs_variant) {
  case PBS_VARIANT::TBC:
#if CUDA_ARCH >= 900
    cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_output_indexes),
        static_cast<const uint64_t *>(lut_vector),
        static_cast<const uint64_t *>(lut_vector_indexes),
        static_cast<const uint64_t *>(lwe_array_in),
        static_cast<const uint64_t *>(lwe_input_indexes),
        static_cast<const uint64_t *>(bootstrapping_key), buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
#else
    PANIC("Cuda error (multi-bit PBS): TBC pbs is not supported.")
#endif
  case PBS_VARIANT::CG:
    cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_output_indexes),
        static_cast<const uint64_t *>(lut_vector),
        static_cast<const uint64_t *>(lut_vector_indexes),
        static_cast<const uint64_t *>(lwe_array_in),
        static_cast<const uint64_t *>(lwe_input_indexes),
        static_cast<const uint64_t *>(bootstrapping_key), buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case PBS_VARIANT::DEFAULT:
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_output_indexes),
        static_cast<const uint64_t *>(lut_vector),
        static_cast<const uint64_t *>(lut_vector_indexes),
        static_cast<const uint64_t *>(lwe_array_in),
        static_cast<const uint64_t *>(lwe_input_indexes),
        static_cast<const uint64_t *>(bootstrapping_key), buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported implementation variant.")
  }
}

template <typename Torus>
uint64_t scratch_cuda_cg_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    return scratch_cg_multi_bit_programmable_bootstrap<Torus,
                                                       AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 512:
    return scratch_cg_multi_bit_programmable_bootstrap<Torus,
                                                       AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 1024:
    return scratch_cg_multi_bit_programmable_bootstrap<Torus,
                                                       AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 2048:
    return scratch_cg_multi_bit_programmable_bootstrap<Torus,
                                                       AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 4096:
    return scratch_cg_multi_bit_programmable_bootstrap<Torus,
                                                       AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 8192:
    return scratch_cg_multi_bit_programmable_bootstrap<Torus,
                                                       AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 16384:
    return scratch_cg_multi_bit_programmable_bootstrap<Torus,
                                                       AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

template <typename Torus>
uint64_t scratch_cuda_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    return scratch_multi_bit_programmable_bootstrap<Torus,
                                                    AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 512:
    return scratch_multi_bit_programmable_bootstrap<Torus,
                                                    AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 1024:
    return scratch_multi_bit_programmable_bootstrap<Torus,
                                                    AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 2048:
    return scratch_multi_bit_programmable_bootstrap<Torus,
                                                    AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 4096:
    return scratch_multi_bit_programmable_bootstrap<Torus,
                                                    AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 8192:
    return scratch_multi_bit_programmable_bootstrap<Torus,
                                                    AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 16384:
    return scratch_multi_bit_programmable_bootstrap<Torus,
                                                    AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

uint64_t scratch_cuda_multi_bit_programmable_bootstrap_64(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  bool supports_cg =
      supports_cooperative_groups_on_multibit_programmable_bootstrap<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, cuda_get_max_shared_memory(gpu_index));
#if (CUDA_ARCH >= 900)
  // On H100s we should be using TBC until num_samples < num_sms / 2.
  // After that we switch to CG until not supported anymore.
  // At this point we return to TBC.
  int num_sms = 0;
  check_cuda_error(cudaDeviceGetAttribute(
      &num_sms, cudaDevAttrMultiProcessorCount, gpu_index));

  bool supports_tbc =
      has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          level_count, cuda_get_max_shared_memory(gpu_index));

  if (supports_tbc)
    return scratch_cuda_tbc_multi_bit_programmable_bootstrap<uint64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, allocate_gpu_memory);
  else
#endif
      if (supports_cg)
    return scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, allocate_gpu_memory);
  else
    return scratch_cuda_multi_bit_programmable_bootstrap<uint64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, allocate_gpu_memory);
}

void cleanup_cuda_multi_bit_programmable_bootstrap(void *stream,
                                                   uint32_t gpu_index,
                                                   int8_t **buffer) {
  auto x = (pbs_buffer<uint64_t, MULTI_BIT> *)(*buffer);
  x->release(static_cast<cudaStream_t>(stream), gpu_index);
  delete x;
  *buffer = nullptr;
}

/**
 * Computes divisors of the product of num_sms (streaming multiprocessors on the
 * GPU) and max_blocks_per_sm (maximum active blocks per SM to launch
 * device_multi_bit_programmable_bootstrap_keybundle) smaller than its square
 * root, based on max_num_pbs. If log2(max_num_pbs) <= 13, selects the first
 * suitable divisor. If greater, calculates an offset as max(1,log2(max_num_pbs)
 * - 13) for additional logic.
 *
 * The value 13 was empirically determined based on memory requirements for
 * benchmarking on an RTX 4090 GPU, balancing performance and resource use.
 */
template <typename Torus, class params>
uint64_t get_lwe_chunk_size(uint32_t gpu_index, uint32_t max_num_pbs,
                            uint32_t polynomial_size, uint32_t glwe_dimension,
                            uint32_t level_count, uint64_t full_sm_keybundle) {

  int max_blocks_per_sm;
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_blocks_per_sm,
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        polynomial_size / params::opt, full_sm_keybundle));
  } else {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_blocks_per_sm,
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        polynomial_size / params::opt, 0));
  }

  int num_sms = 0;
  check_cuda_error(cudaDeviceGetAttribute(
      &num_sms, cudaDevAttrMultiProcessorCount, gpu_index));

  size_t total_mem, free_mem;
  check_cuda_error(cudaMemGetInfo(&free_mem, &total_mem));
  // Estimate the size of one chunk
  uint64_t size_one_chunk = (uint64_t)max_num_pbs * polynomial_size *
                            (glwe_dimension + 1) * (glwe_dimension + 1) *
                            level_count * sizeof(Torus);

  // We calculate the maximum number of chunks that can fit in the 50% of free
  // memory. We don't want the pbs temp array uses more than 50% of the free
  // memory if 1 chunk doesn't fit in the 50% of free memory we panic
  uint32_t max_num_chunks =
      static_cast<uint32_t>(free_mem / (2 * size_one_chunk));
  PANIC_IF_FALSE(
      max_num_chunks > 0,
      "Cuda error (multi-bit PBS): Not enough GPU memory to allocate PBS "
      "temporary arrays. free_mem: %lu, size_one_chunk: %lu, max_num_chunks: "
      "%u, max_num_pbs %u",
      free_mem, size_one_chunk, max_num_chunks, max_num_pbs);
  int x = num_sms * max_blocks_per_sm;
  int count = 0;

  int divisor = 1;
  int ith_divisor = 0;

#if CUDA_ARCH < 900
  // We pick a smaller divisor on GPUs other than H100, so 256-bit integer
  // multiplication can run
  int log2_max_num_pbs = log2_int(max_num_pbs);
  if (log2_max_num_pbs > 13)
    ith_divisor = log2_max_num_pbs - 11;
#else
  // When having few samples we are interested in using a larger chunksize so
  // the keybundle can saturate the GPU. To obtain homogeneous waves we use half
  // of the sms as the chunksize, by doing so we always get a multiple of the
  // number of sms, removing the tailing effect. We don't divide by 4 because
  // some flavors of H100 might not have a number of sms divisible by 4. This is
  // applied only to few number of samples(8) because it can have a negative
  // effect of over saturation.
  if (max_num_pbs <= 8) {
    return (max_num_chunks > num_sms / 2) ? num_sms / 2 : max_num_chunks;
  }
#endif

  for (int i = sqrt(x); i >= 1; i--) {
    if (x % i == 0) {
      if (count == ith_divisor) {
        divisor = i;
        break;
      } else {
        count++;
      }
    }
  }
  return (max_num_chunks > divisor) ? divisor : max_num_chunks;
}

template uint64_t scratch_cuda_multi_bit_programmable_bootstrap<uint64_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, MULTI_BIT> **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template void
cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t const *lwe_output_indexes, uint64_t const *lut_vector,
    uint64_t const *lut_vector_indexes, uint64_t const *lwe_array_in,
    uint64_t const *lwe_input_indexes, uint64_t const *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);

template uint64_t scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, MULTI_BIT> **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template void
cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t const *lwe_output_indexes, uint64_t const *lut_vector,
    uint64_t const *lut_vector_indexes, uint64_t const *lwe_array_in,
    uint64_t const *lwe_input_indexes, uint64_t const *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);

template bool
has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory);

#if (CUDA_ARCH >= 900)
template <typename Torus>
uint64_t scratch_cuda_tbc_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    return scratch_tbc_multi_bit_programmable_bootstrap<Torus,
                                                        AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 512:
    return scratch_tbc_multi_bit_programmable_bootstrap<Torus,
                                                        AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 1024:
    return scratch_tbc_multi_bit_programmable_bootstrap<Torus,
                                                        AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 2048:
    return scratch_tbc_multi_bit_programmable_bootstrap<Torus,
                                                        AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 4096:
    return scratch_tbc_multi_bit_programmable_bootstrap<Torus,
                                                        AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 8192:
    return scratch_tbc_multi_bit_programmable_bootstrap<Torus,
                                                        AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 16384:
    return scratch_tbc_multi_bit_programmable_bootstrap<Torus,
                                                        AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}
template <typename Torus>
void cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  if (base_log > 32)
    PANIC("Cuda error (multi-bit PBS): base log should be <= 32")

  switch (polynomial_size) {
  case 256:
    host_tbc_multi_bit_programmable_bootstrap<uint64_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 512:
    host_tbc_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 1024:
    host_tbc_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 2048: {
    int num_sms = 0;
    check_cuda_error(cudaDeviceGetAttribute(
        &num_sms, cudaDevAttrMultiProcessorCount, gpu_index));

    if (4 * num_sms < num_samples * level_count * (glwe_dimension + 1))
      host_tbc_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<2048>>(
          static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
          lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
          lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_many_lut, lut_stride);
    else
      host_tbc_multi_bit_programmable_bootstrap<Torus, Degree<2048>>(
          static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
          lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
          lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, grouping_factor, base_log,
          level_count, num_samples, num_many_lut, lut_stride);

    break;
  }
  case 4096:
    host_tbc_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 8192:
    host_tbc_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  case 16384:
    host_tbc_multi_bit_programmable_bootstrap<Torus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

template uint64_t scratch_cuda_tbc_multi_bit_programmable_bootstrap<uint64_t>(
    void *stream, uint32_t gpu_index, pbs_buffer<uint64_t, MULTI_BIT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

template void
cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t const *lwe_output_indexes, uint64_t const *lut_vector,
    uint64_t const *lut_vector_indexes, uint64_t const *lwe_array_in,
    uint64_t const *lwe_input_indexes, uint64_t const *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride);
#endif
