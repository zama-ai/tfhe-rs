#include "../polynomial/parameters.cuh"
#include "programmable_bootstrap_cg_multibit.cuh"
#include "programmable_bootstrap_multibit.cuh"
#include "programmable_bootstrap_multibit.h"

bool has_support_to_cuda_programmable_bootstrap_cg_multi_bit(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t num_samples, uint32_t max_shared_memory) {
  return supports_cooperative_groups_on_multibit_programmable_bootstrap<
      uint64_t>(glwe_dimension, polynomial_size, level_count, num_samples,
                max_shared_memory);
}

template <typename Torus>
void cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size) {

  if (base_log > 64)
    PANIC("Cuda error (multi-bit PBS): base log should be > number of bits in "
          "the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    host_cg_multi_bit_programmable_bootstrap<uint64_t, int64_t,
                                             AmortizedDegree<256>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 512:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<512>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 1024:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<1024>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 2048:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<2048>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 4096:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<4096>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 8192:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<8192>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 16384:
    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
                                             AmortizedDegree<16384>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

template <typename Torus>
void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, Torus *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size) {

  if (base_log > 64)
    PANIC("Cuda error (multi-bit PBS): base log should be > number of bits in "
          "the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    host_multi_bit_programmable_bootstrap<uint64_t, int64_t,
                                          AmortizedDegree<256>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 512:
    host_multi_bit_programmable_bootstrap<Torus, int64_t, AmortizedDegree<512>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 1024:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<1024>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 2048:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<2048>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 4096:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<4096>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 8192:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<8192>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  case 16384:
    host_multi_bit_programmable_bootstrap<Torus, int64_t,
                                          AmortizedDegree<16384>>(
        stream, lwe_array_out, lwe_output_indexes, lut_vector,
        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
        max_shared_memory, lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size) {

  if (supports_cooperative_groups_on_multibit_programmable_bootstrap<uint64_t>(
          glwe_dimension, polynomial_size, level_count, num_samples,
          max_shared_memory))
    cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<uint64_t *>(bootstrapping_key),
        (pbs_buffer<uint64_t, MULTI_BIT> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, lwe_chunk_size);
  else
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<uint64_t *>(bootstrapping_key),
        (pbs_buffer<uint64_t, MULTI_BIT> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        num_samples, num_luts, lwe_idx, max_shared_memory, lwe_chunk_size);
}

template <typename Torus, typename STorus>
void scratch_cuda_cg_multi_bit_programmable_bootstrap(
    cuda_stream_t *stream, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size) {

  switch (polynomial_size) {
  case 256:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<256>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 512:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<512>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 1024:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<1024>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 2048:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<2048>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 4096:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<4096>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 8192:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<8192>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 16384:
    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
                                                AmortizedDegree<16384>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
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
    cuda_stream_t *stream, pbs_buffer<Torus, MULTI_BIT> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size) {

  switch (polynomial_size) {
  case 256:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<256>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 512:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<512>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 1024:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<1024>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 2048:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<2048>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 4096:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<4096>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 8192:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<8192>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  case 16384:
    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
                                             AmortizedDegree<16384>>(
        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
        level_count, input_lwe_ciphertext_count, grouping_factor,
        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}

void scratch_cuda_multi_bit_programmable_bootstrap_64(
    cuda_stream_t *stream, int8_t **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t lwe_chunk_size) {

  if (supports_cooperative_groups_on_multibit_programmable_bootstrap<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory))
    scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
        stream, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count, grouping_factor,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory,
        lwe_chunk_size);
  else
    scratch_cuda_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
        stream, (pbs_buffer<uint64_t, MULTI_BIT> **)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, level_count, grouping_factor,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory,
        lwe_chunk_size);
}

void cleanup_cuda_multi_bit_programmable_bootstrap(cuda_stream_t *stream,
                                                   int8_t **buffer) {
  auto x = (pbs_buffer<uint64_t, MULTI_BIT> *)(*buffer);
  x->release(stream);
}

// Returns a chunk size that is not optimal but close to
__host__ uint32_t get_lwe_chunk_size(uint32_t ct_count) {

#if CUDA_ARCH >= 900
  // Tesla H100
  return (ct_count > 10000) ? 30 : 64;
#elif CUDA_ARCH >= 800
  // Tesla A100
  return (ct_count > 10000) ? 30 : 45;
#elif CUDA_ARCH >= 700
  // Tesla V100
  return (ct_count > 10000) ? 12 : 18;
#else
  // Generic case
  return (ct_count > 10000) ? 2 : 1;
#endif
}

template void scratch_cuda_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
    cuda_stream_t *stream, pbs_buffer<uint64_t, MULTI_BIT> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size);

template void
cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    cuda_stream_t *stream, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, uint64_t *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size);

template void
scratch_cuda_cg_multi_bit_programmable_bootstrap<uint64_t, int64_t>(
    cuda_stream_t *stream, pbs_buffer<uint64_t, MULTI_BIT> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory, uint32_t lwe_chunk_size);

template void
cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    cuda_stream_t *stream, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, uint64_t *bootstrapping_key,
    pbs_buffer<uint64_t, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory,
    uint32_t lwe_chunk_size);
