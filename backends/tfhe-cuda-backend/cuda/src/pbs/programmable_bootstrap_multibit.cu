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
//  case 16384:
//    host_cg_multi_bit_programmable_bootstrap<Torus, int64_t,
//                                             AmortizedDegree<16384>>(
//        stream, lwe_array_out, lwe_output_indexes, lut_vector,
//        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
//        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
//        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
//        max_shared_memory, lwe_chunk_size);
//    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..8192].")
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
//  case 16384:
//    host_multi_bit_programmable_bootstrap<Torus, int64_t,
//                                          AmortizedDegree<16384>>(
//        stream, lwe_array_out, lwe_output_indexes, lut_vector,
//        lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
//        pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size,
//        grouping_factor, base_log, level_count, num_samples, num_luts, lwe_idx,
//        max_shared_memory, lwe_chunk_size);
//    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..8192].")
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
//  case 16384:
//    scratch_cg_multi_bit_programmable_bootstrap<Torus, STorus,
//                                                AmortizedDegree<16384>>(
//        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
//        level_count, input_lwe_ciphertext_count, grouping_factor,
//        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
//    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..8192].")
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
//  case 16384:
//    scratch_multi_bit_programmable_bootstrap<Torus, STorus,
//                                             AmortizedDegree<16384>>(
//        stream, buffer, lwe_dimension, glwe_dimension, polynomial_size,
//        level_count, input_lwe_ciphertext_count, grouping_factor,
//        max_shared_memory, allocate_gpu_memory, lwe_chunk_size);
//    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..8192].")
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

// Pick the best possible chunk size for each GPU
__host__ uint32_t get_lwe_chunk_size(uint32_t lwe_dimension,
                                     uint32_t level_count,
                                     uint32_t glwe_dimension,
                                     uint32_t num_samples) {

  cudaDeviceProp deviceProp;
  cudaGetDeviceProperties(&deviceProp, 0); // Assuming device 0

  const char *v100Name = "V100"; // Known name of V100 GPU
  const char *a100Name = "A100"; // Known name of A100 GPU
  const char *h100Name = "H100"; // Known name of H100 GPU

  if (std::strstr(deviceProp.name, v100Name) != nullptr) {
    // Tesla V100
    if (num_samples == 1)
      return 60;
    else if (num_samples == 2)
      return 40;
    else if (num_samples <= 4)
      return 20;
    else if (num_samples <= 8)
      return 10;
    else if (num_samples <= 16)
      return 40;
    else if (num_samples <= 32)
      return 27;
    else if (num_samples <= 64)
      return 20;
    else if (num_samples <= 128)
      return 18;
    else if (num_samples <= 256)
      return 16;
    else if (num_samples <= 512)
      return 15;
    else if (num_samples <= 1024)
      return 15;
    else
      return 12;
  } else if (std::strstr(deviceProp.name, a100Name) != nullptr) {
    // Tesla A100
    if (num_samples < 4)
      return 11;
    else if (num_samples < 8)
      return 6;
    else if (num_samples < 16)
      return 13;
    else if (num_samples < 64)
      return 19;
    else if (num_samples < 128)
      return 1;
    else if (num_samples < 512)
      return 19;
    else if (num_samples < 1024)
      return 17;
    else if (num_samples < 8192)
      return 19;
    else if (num_samples < 16384)
      return 12;
    else
      return 9;
  } else if (std::strstr(deviceProp.name, h100Name) != nullptr) {
    // Tesla H100
    if (num_samples < 1024)
      return 128;
    else if (num_samples < 4096)
      return 64;
    else
      return 32;
  }

  // Generic case
  return 1;
}

// Returns a chunk size that is not optimal but close to
__host__ uint32_t get_average_lwe_chunk_size(uint32_t lwe_dimension,
                                             uint32_t level_count,
                                             uint32_t glwe_dimension,
                                             uint32_t ct_count) {

  cudaDeviceProp deviceProp;
  cudaGetDeviceProperties(&deviceProp, 0); // Assuming device 0

  const char *v100Name = "V100"; // Known name of V100 GPU
  const char *a100Name = "A100"; // Known name of A100 GPU
  const char *h100Name = "H100"; // Known name of H100 GPU

  if (std::strstr(deviceProp.name, v100Name) != nullptr) {
    // Tesla V100
    return (ct_count > 10000) ? 12 : 18;
  } else if (std::strstr(deviceProp.name, a100Name) != nullptr) {
    // Tesla A100
    return (ct_count > 10000) ? 30 : 45;
  } else if (std::strstr(deviceProp.name, h100Name) != nullptr) {
    // Tesla H100
    return 64;
  }

  // Generic case
  return (ct_count > 10000) ? 2 : 1;
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
    max_buffer_size =
        std::max(max_buffer_size,
                 get_buffer_size_multibit_programmable_bootstrap<uint64_t>(
                     glwe_dimension, polynomial_size, level_count,
                     input_lwe_ciphertext_count,
                     get_average_lwe_chunk_size(lwe_dimension, level_count,
                                                glwe_dimension,
                                                input_lwe_ciphertext_count)));
  }

  return max_buffer_size;
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
