#include "../polynomial/parameters.cuh"
#include "programmable_bootstrap_cg_multibit.cuh"
#include "programmable_bootstrap_multibit.cuh"
#include "programmable_bootstrap_multibit.h"

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
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t gpu_offset, uint32_t lwe_chunk_size) {

  if (base_log > 64)
    PANIC("Cuda error (multi-bit PBS): base log should be > number of bits in "
          "the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    host_cg_multi_bit_programmable_bootstrap<uint64_t, int64_t,
                                             AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 512:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 1024:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 2048:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 4096:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 8192:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 16384:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
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
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t gpu_offset, uint32_t lwe_chunk_size) {

  if (base_log > 64)
    PANIC("Cuda error (multi-bit PBS): base log should be > number of bits in "
          "the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    host_multi_bit_programmable_bootstrap<uint64_t, int64_t,
                                          AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 512:
    host_multi_bit_programmable_bootstrap<Torus, int64_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 1024:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 2048:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 4096:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 8192:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 16384:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lut_vector, void *lut_vector_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *bootstrapping_key,
    int8_t *mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset,
    uint32_t lwe_chunk_size) {

  pbs_buffer<uint64_t, MULTI_BIT> *buffer =
      (pbs_buffer<uint64_t, MULTI_BIT> *)mem_ptr;

  switch (buffer->pbs_variant) {
  case PBS_VARIANT::TBC:
#if CUDA_ARCH >= 900
    cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<uint64_t *>(bootstrapping_key),
        (pbs_buffer<uint64_t, MULTI_BIT> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
#else
    PANIC("Cuda error (multi-bit PBS): TBC pbs is not supported.")
#endif
    break;
  case PBS_VARIANT::CG:
    cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<uint64_t *>(bootstrapping_key), buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case PBS_VARIANT::DEFAULT:
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<uint64_t *>(bootstrapping_key), buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported implementation variant.")
  }
}

template <typename Torus, typename STorus>
void scratch_cuda_cg_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size) {

  switch (polynomial_size) {
  case 256:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 512:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 1024:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 2048:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 4096:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 8192:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 16384:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

template <typename Torus, typename STorus>
void scratch_cuda_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size) {

  switch (polynomial_size) {
  case 256:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 512:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 1024:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 2048:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 4096:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 8192:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 16384:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

void scratch_cuda_multi_bit_programmable_bootstrap_64(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t lwe_chunk_size) {

#if (CUDA_ARCH >= 900)
  if (has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          level_count, max_shared_memory))
    scratch_cuda_tbc_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer,
        lwe_dimension, glwe_dimension, polynomial_size, level_count,
        grouping_factor, input_lwe_ciphertext_count, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
  else
#endif
      if (supports_cooperative_groups_on_multibit_programmable_bootstrap<
              uint64_t>(glwe_dimension, polynomial_size, level_count,
                        input_lwe_ciphertext_count, max_shared_memory))
    scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory,
        lwe_chunk_size);
  else
    scratch_cuda_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer,
        lwe_dimension, glwe_dimension, polynomial_size, level_count,
        grouping_factor, input_lwe_ciphertext_count, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
}

void cleanup_cuda_multi_bit_programmable_bootstrap(void *stream,
                                                   uint32_t gpu_index,
                                                   int8_t **buffer) {
  cudaSetDevice(gpu_index);
  auto x = (pbs_buffer<uint64_t, MULTI_BIT> *)(*buffer);
  x->release(static_cast<cudaStream_t>(stream), gpu_index);
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
__host__ uint32_t get_lwe_chunk_size(uint32_t gpu_index, uint32_t max_num_pbs,
                                     uint32_t polynomial_size,
                                     uint32_t max_shared_memory) {

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<Torus>(
          polynomial_size);

  int max_blocks_per_sm;
  if (max_shared_memory < full_sm_keybundle)
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_blocks_per_sm,
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        polynomial_size / params::opt, full_sm_keybundle);
  else
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_blocks_per_sm,
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        polynomial_size / params::opt, 0);

  int num_sms = 0;
  check_cuda_error(cudaDeviceGetAttribute(
      &num_sms, cudaDevAttrMultiProcessorCount, gpu_index));

  int x = num_sms * max_blocks_per_sm;
  int count = 0;

  int divisor = 1;
  int ith_divisor = 0;

#if CUDA_ARCH < 900
  // We pick a smaller divisor on GPUs other than H100, so 256-bit integer
  // multiplication can run
  int log2_max_num_pbs = std::log2(max_num_pbs);
  if (log2_max_num_pbs > 13)
    ith_divisor = log2_max_num_pbs - 11;
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

  return divisor;
}

template void scratch_cuda_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, MULTI_BIT> **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t lwe_chunk_size);

template void
cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, uint64_t *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t gpu_offset, uint32_t lwe_chunk_size);

template void
scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, MULTI_BIT> **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size);

template void
cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, uint64_t *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t gpu_offset, uint32_t lwe_chunk_size);

template bool
has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory);

#if (CUDA_ARCH >= 900)
template <typename Torus, typename STorus>
void scratch_cuda_tbc_multi_bit_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size) {

  switch (polynomial_size) {
  case 256:
    scratch_tbc_multi_bit_programmable_bootstrap<Torus, STorus,
                                                 AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 512:
    scratch_tbc_multi_bit_programmable_bootstrap<Torus, STorus,
                                                 AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 1024:
    scratch_tbc_multi_bit_programmable_bootstrap<Torus, STorus,
                                                 AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 2048:
    scratch_tbc_multi_bit_programmable_bootstrap<Torus, STorus,
                                                 AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 4096:
    scratch_tbc_multi_bit_programmable_bootstrap<Torus, STorus,
                                                 AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 8192:
    scratch_tbc_multi_bit_programmable_bootstrap<Torus, STorus,
                                                 AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  case 16384:
    scratch_tbc_multi_bit_programmable_bootstrap<Torus, STorus,
                                                 AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, max_shared_memory,
        allocate_gpu_memory, lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}
template <typename Torus>
void cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t gpu_offset, uint32_t lwe_chunk_size) {

  if (base_log > 64)
    PANIC("Cuda error (multi-bit PBS): base log should be > number of bits in "
          "the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    host_tbc_multi_bit_programmable_bootstrap<uint64_t, int64_t,
                                              AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 512:
    host_tbc_multi_bit_programmable_bootstrap<Torus, int64_t,
                                              AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 1024:
    host_tbc_multi_bit_programmable_bootstrap<Torus, int64_t,
                                              AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 2048:
    host_tbc_multi_bit_programmable_bootstrap<Torus, int64_t,
                                              AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 4096:
    host_tbc_multi_bit_programmable_bootstrap<Torus, int64_t,
                                              AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 8192:
    host_tbc_multi_bit_programmable_bootstrap<Torus, int64_t,
                                              AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  case 16384:
    host_tbc_multi_bit_programmable_bootstrap<Torus, int64_t,
                                              AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, pbs_buffer, glwe_dimension,
        lwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, gpu_offset,
        lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

template void
scratch_cuda_tbc_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
    void *stream, uint32_t gpu_index, pbs_buffer<uint64_t, MULTI_BIT> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size);

template void
cuda_tbc_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, uint64_t *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t gpu_offset, uint32_t lwe_chunk_size);
#endif
