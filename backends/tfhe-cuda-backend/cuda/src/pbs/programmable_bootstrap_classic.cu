#include "programmable_bootstrap_cg_classic.cuh"
#include "programmable_bootstrap_classic.cuh"
#if (CUDA_ARCH >= 900)
#include "programmable_bootstrap_tbc_classic.cuh"
#endif

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_cg(uint32_t glwe_dimension,
                                                   uint32_t polynomial_size,
                                                   uint32_t level_count,
                                                   uint32_t num_samples,
                                                   uint32_t max_shared_memory) {
  return supports_cooperative_groups_on_programmable_bootstrap<Torus>(
      glwe_dimension, polynomial_size, level_count, num_samples,
      max_shared_memory);
}

template <typename Torus>
bool has_support_to_cuda_programmable_bootstrap_tbc(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory) {
#if CUDA_ARCH >= 900
  switch (polynomial_size) {
  case 256:
    return supports_thread_block_clusters_on_classic_programmable_bootstrap<
        Torus, AmortizedDegree<256>>(num_samples, glwe_dimension,
                                     polynomial_size, level_count,
                                     max_shared_memory);
  case 512:
    return supports_thread_block_clusters_on_classic_programmable_bootstrap<
        Torus, AmortizedDegree<512>>(num_samples, glwe_dimension,
                                     polynomial_size, level_count,
                                     max_shared_memory);
  case 1024:
    return supports_thread_block_clusters_on_classic_programmable_bootstrap<
        Torus, AmortizedDegree<1024>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 2048:
    return supports_thread_block_clusters_on_classic_programmable_bootstrap<
        Torus, AmortizedDegree<2048>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 4096:
    return supports_thread_block_clusters_on_classic_programmable_bootstrap<
        Torus, AmortizedDegree<4096>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 8192:
    return supports_thread_block_clusters_on_classic_programmable_bootstrap<
        Torus, AmortizedDegree<8192>>(num_samples, glwe_dimension,
                                      polynomial_size, level_count,
                                      max_shared_memory);
  case 16384:
    return supports_thread_block_clusters_on_classic_programmable_bootstrap<
        Torus, AmortizedDegree<16384>>(num_samples, glwe_dimension,
                                       polynomial_size, level_count,
                                       max_shared_memory);
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
#else
  return false;
#endif
}

#if (CUDA_ARCH >= 900)
template <typename Torus, typename STorus>
void scratch_cuda_programmable_bootstrap_tbc(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    scratch_programmable_bootstrap_tbc<Torus, STorus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 512:
    scratch_programmable_bootstrap_tbc<Torus, STorus, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 1024:
    scratch_programmable_bootstrap_tbc<Torus, STorus, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 2048:
    scratch_programmable_bootstrap_tbc<Torus, STorus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 4096:
    scratch_programmable_bootstrap_tbc<Torus, STorus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 8192:
    scratch_programmable_bootstrap_tbc<Torus, STorus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 16384:
    scratch_programmable_bootstrap_tbc<Torus, STorus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

template <typename Torus>
void cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory) {

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap_tbc<Torus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory);
    break;
  case 512:
    host_programmable_bootstrap_tbc<Torus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory);
    break;
  case 1024:
    host_programmable_bootstrap_tbc<Torus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory);
    break;
  case 2048:
    host_programmable_bootstrap_tbc<Torus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory);
    break;
  case 4096:
    host_programmable_bootstrap_tbc<Torus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory);
    break;
  case 8192:
    host_programmable_bootstrap_tbc<Torus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory);
    break;
  case 16384:
    host_programmable_bootstrap_tbc<Torus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}
#endif

/*
 * Returns the buffer size for 64 bits executions
 */
uint64_t get_buffer_size_programmable_bootstrap_64(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {

  if (has_support_to_cuda_programmable_bootstrap_cg<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory))
    return get_buffer_size_programmable_bootstrap_cg<uint64_t>(
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory);
  else
    return get_buffer_size_programmable_bootstrap_cg<uint64_t>(
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory);
}

template <typename Torus, typename STorus>
void scratch_cuda_programmable_bootstrap_cg(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    scratch_programmable_bootstrap_cg<Torus, STorus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 512:
    scratch_programmable_bootstrap_cg<Torus, STorus, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 1024:
    scratch_programmable_bootstrap_cg<Torus, STorus, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 2048:
    scratch_programmable_bootstrap_cg<Torus, STorus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 4096:
    scratch_programmable_bootstrap_cg<Torus, STorus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 8192:
    scratch_programmable_bootstrap_cg<Torus, STorus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 16384:
    scratch_programmable_bootstrap_cg<Torus, STorus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, pbs_buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

template <typename Torus, typename STorus>
void scratch_cuda_programmable_bootstrap(
    void *stream, uint32_t gpu_index, pbs_buffer<Torus, CLASSICAL> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    scratch_programmable_bootstrap<Torus, STorus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory);
    break;
  case 512:
    scratch_programmable_bootstrap<Torus, STorus, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory);
    break;
  case 1024:
    scratch_programmable_bootstrap<Torus, STorus, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory);
    break;
  case 2048:
    scratch_programmable_bootstrap<Torus, STorus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory);
    break;
  case 4096:
    scratch_programmable_bootstrap<Torus, STorus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory);
    break;
  case 8192:
    scratch_programmable_bootstrap<Torus, STorus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory);
    break;
  case 16384:
    scratch_programmable_bootstrap<Torus, STorus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        max_shared_memory, allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the classical PBS on 32 bits inputs, into `buffer`. It also
 * configures SM options on the GPU in case FULLSM or PARTIALSM mode is going to
 * be used.
 */
void scratch_cuda_programmable_bootstrap_32(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

#if (CUDA_ARCH >= 900)
  if (has_support_to_cuda_programmable_bootstrap_tbc<uint32_t>(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          level_count, max_shared_memory))
    scratch_cuda_programmable_bootstrap_tbc<uint32_t, int32_t>(
        stream, gpu_index, (pbs_buffer<uint32_t, CLASSICAL> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
  else
#endif
      if (has_support_to_cuda_programmable_bootstrap_cg<uint32_t>(
              glwe_dimension, polynomial_size, level_count,
              input_lwe_ciphertext_count, max_shared_memory))
    scratch_cuda_programmable_bootstrap_cg<uint32_t, int32_t>(
        stream, gpu_index, (pbs_buffer<uint32_t, CLASSICAL> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
  else
    scratch_cuda_programmable_bootstrap<uint32_t, int32_t>(
        stream, gpu_index, (pbs_buffer<uint32_t, CLASSICAL> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
}

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the PBS on 64 bits inputs, into `buffer`. It also configures SM options on
 * the GPU in case FULLSM or PARTIALSM mode is going to be used.
 */
void scratch_cuda_programmable_bootstrap_64(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

#if (CUDA_ARCH >= 900)
  if (has_support_to_cuda_programmable_bootstrap_tbc<uint64_t>(
          input_lwe_ciphertext_count, glwe_dimension, polynomial_size,
          level_count, max_shared_memory))
    scratch_cuda_programmable_bootstrap_tbc<uint64_t, int64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
  else
#endif
      if (has_support_to_cuda_programmable_bootstrap_cg<uint64_t>(
              glwe_dimension, polynomial_size, level_count,
              input_lwe_ciphertext_count, max_shared_memory))
    scratch_cuda_programmable_bootstrap_cg<uint64_t, int64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
  else
    scratch_cuda_programmable_bootstrap<uint64_t, int64_t>(
        stream, gpu_index, (pbs_buffer<uint64_t, CLASSICAL> **)buffer,
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
}

template <typename Torus>
void cuda_programmable_bootstrap_cg_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset) {

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap_cg<Torus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 512:
    host_programmable_bootstrap_cg<Torus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 1024:
    host_programmable_bootstrap_cg<Torus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 2048:
    host_programmable_bootstrap_cg<Torus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 4096:
    host_programmable_bootstrap_cg<Torus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 8192:
    host_programmable_bootstrap_cg<Torus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 16384:
    host_programmable_bootstrap_cg<Torus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

template <typename Torus>
void cuda_programmable_bootstrap_lwe_ciphertext_vector(
    void *stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset) {

  switch (polynomial_size) {
  case 256:
    host_programmable_bootstrap<Torus, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 512:
    host_programmable_bootstrap<Torus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 1024:
    host_programmable_bootstrap<Torus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 2048:
    host_programmable_bootstrap<Torus, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 4096:
    host_programmable_bootstrap<Torus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 8192:
    host_programmable_bootstrap<Torus, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  case 16384:
    host_programmable_bootstrap<Torus, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, bootstrapping_key, buffer, glwe_dimension,
        lwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, max_shared_memory, gpu_offset);
    break;
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

/* Perform bootstrapping on a batch of input u32 LWE ciphertexts.
 */
void cuda_programmable_bootstrap_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lut_vector, void *lut_vector_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *bootstrapping_key,
    int8_t *mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t gpu_offset) {

  if (base_log > 32)
    PANIC("Cuda error (classical PBS): base log should be > number of bits "
          "in the ciphertext representation (32)");

  pbs_buffer<uint64_t, CLASSICAL> *buffer =
      (pbs_buffer<uint64_t, CLASSICAL> *)mem_ptr;

  switch (buffer->pbs_variant) {
  case TBC:
#if CUDA_ARCH >= 900
    cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector<uint32_t>(
        stream, gpu_index, static_cast<uint32_t *>(lwe_array_out),
        static_cast<uint32_t *>(lwe_output_indexes),
        static_cast<uint32_t *>(lut_vector),
        static_cast<uint32_t *>(lut_vector_indexes),
        static_cast<uint32_t *>(lwe_array_in),
        static_cast<uint32_t *>(lwe_input_indexes),
        static_cast<double2 *>(bootstrapping_key),
        (pbs_buffer<uint32_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, lwe_idx, max_shared_memory);
#else
    PANIC("Cuda error (PBS): TBC pbs is not supported.")
#endif
    break;
  case CG:
    cuda_programmable_bootstrap_cg_lwe_ciphertext_vector<uint32_t>(
        stream, gpu_index, static_cast<uint32_t *>(lwe_array_out),
        static_cast<uint32_t *>(lwe_output_indexes),
        static_cast<uint32_t *>(lut_vector),
        static_cast<uint32_t *>(lut_vector_indexes),
        static_cast<uint32_t *>(lwe_array_in),
        static_cast<uint32_t *>(lwe_input_indexes),
        static_cast<double2 *>(bootstrapping_key),
        (pbs_buffer<uint32_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, lwe_idx, max_shared_memory, gpu_offset);
    break;
  case DEFAULT:
    cuda_programmable_bootstrap_lwe_ciphertext_vector<uint32_t>(
        stream, gpu_index, static_cast<uint32_t *>(lwe_array_out),
        static_cast<uint32_t *>(lwe_output_indexes),
        static_cast<uint32_t *>(lut_vector),
        static_cast<uint32_t *>(lut_vector_indexes),
        static_cast<uint32_t *>(lwe_array_in),
        static_cast<uint32_t *>(lwe_input_indexes),
        static_cast<double2 *>(bootstrapping_key),
        (pbs_buffer<uint32_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, lwe_idx, max_shared_memory, gpu_offset);
    break;
  default:
    PANIC("Cuda error (PBS): unknown pbs variant.")
  }
}

/* Perform bootstrapping on a batch of input u64 LWE ciphertexts.
 *
 * - `v_stream` is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 *  - lwe_array_out: output batch of num_samples bootstrapped ciphertexts c =
 * (a0,..an-1,b) where n is the LWE dimension
 *  - lut_vector: should hold as many luts of size polynomial_size
 * as there are input ciphertexts, but actually holds
 * num_luts vectors to reduce memory usage
 *  - lut_vector_indexes: stores the index corresponding to
 * which lut to use for each sample in
 * lut_vector
 *  - lwe_array_in: input batch of num_samples LWE ciphertexts, containing n
 * mask values + 1 body value
 *  - bootstrapping_key: GGSW encryption of the LWE secret key sk1
 * under secret key sk2
 * bsk = Z + sk1 H
 * where H is the gadget matrix and Z is a matrix (k+1).l
 * containing GLWE encryptions of 0 under sk2.
 * bsk is thus a tensor of size (k+1)^2.l.N.n
 * where l is the number of decomposition levels and
 * k is the GLWE dimension, N is the polynomial size for
 * GLWE. The polynomial size for GLWE and the lut
 * are the same because they have to be in the same ring
 * to be multiplied.
 * - lwe_dimension: size of the Torus vector used to encrypt the input
 * LWE ciphertexts - referred to as n above (~ 600)
 * - glwe_dimension: size of the polynomial vector used to encrypt the LUT
 * GLWE ciphertexts - referred to as k above. Only the value 1 is supported for
 * this parameter.
 * - polynomial_size: size of the test polynomial (lut) and size of the
 * GLWE polynomial (~1024)
 * - base_log: log base used for the gadget matrix - B = 2^base_log (~8)
 * - level_count: number of decomposition levels in the gadget matrix (~4)
 * - num_samples: number of encrypted input messages
 * - num_luts: parameter to set the actual number of luts to be
 * used
 * - lwe_idx: the index of the LWE input to consider for the GPU of index
 * gpu_index. In case of multi-GPU computing, it is assumed that only a part of
 * the input LWE array is copied to each GPU, but the whole LUT array is copied
 * (because the case when the number of LUTs is smaller than the number of input
 * LWEs is not trivial to take into account in the data repartition on the
 * GPUs). `lwe_idx` is used to determine which LUT to consider for a given LWE
 * input in the LUT array `lut_vector`.
 *  - 'max_shared_memory' maximum amount of shared memory to be used inside
 * device functions
 *
 * This function calls a wrapper to a device kernel that performs the
 * bootstrapping:
 * 	- the kernel is templatized based on integer discretization and
 * polynomial degree
 * 	- num_samples * level_count * (glwe_dimension + 1) blocks of threads are
 * launched, where each thread	is going to handle one or more polynomial
 * coefficients at each stage, for a given level of decomposition, either for
 * the LUT mask or its body:
 * 		- perform the blind rotation
 * 		- round the result
 * 		- get the decomposition for the current level
 * 		- switch to the FFT domain
 * 		- multiply with the bootstrapping key
 * 		- come back to the coefficients representation
 * 	- between each stage a synchronization of the threads is necessary (some
 * synchronizations happen at the block level, some happen between blocks, using
 * cooperative groups).
 * 	- in case the device has enough shared memory, temporary arrays used for
 * the different stages (accumulators) are stored into the shared memory
 * 	- the accumulators serve to combine the results for all decomposition
 * levels
 * 	- the constant memory (64K) is used for storing the roots of identity
 * values for the FFT
 */
void cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lut_vector, void *lut_vector_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *bootstrapping_key,
    int8_t *mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t gpu_offset) {
  if (base_log > 64)
    PANIC("Cuda error (classical PBS): base log should be > number of bits "
          "in the ciphertext representation (64)");

  pbs_buffer<uint64_t, CLASSICAL> *buffer =
      (pbs_buffer<uint64_t, CLASSICAL> *)mem_ptr;

  switch (buffer->pbs_variant) {
  case PBS_VARIANT::TBC:
#if (CUDA_ARCH >= 900)
    cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<double2 *>(bootstrapping_key),
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, lwe_idx, max_shared_memory);
#else
    PANIC("Cuda error (PBS): TBC pbs is not supported.")
#endif
    break;
  case PBS_VARIANT::CG:
    cuda_programmable_bootstrap_cg_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<double2 *>(bootstrapping_key),
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, lwe_idx, max_shared_memory, gpu_offset);
    break;
  case PBS_VARIANT::DEFAULT:
    cuda_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
        stream, gpu_index, static_cast<uint64_t *>(lwe_array_out),
        static_cast<uint64_t *>(lwe_output_indexes),
        static_cast<uint64_t *>(lut_vector),
        static_cast<uint64_t *>(lut_vector_indexes),
        static_cast<uint64_t *>(lwe_array_in),
        static_cast<uint64_t *>(lwe_input_indexes),
        static_cast<double2 *>(bootstrapping_key),
        (pbs_buffer<uint64_t, CLASSICAL> *)buffer, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, num_samples,
        num_luts, lwe_idx, max_shared_memory, gpu_offset);
    break;
  default:
    PANIC("Cuda error (PBS): unknown pbs variant.")
  }
}

/*
 * This cleanup function frees the data on GPU for the PBS buffer for 32 or 64
 * bits inputs.
 */
void cleanup_cuda_programmable_bootstrap(void *stream, uint32_t gpu_index,
                                         int8_t **buffer) {
  cudaSetDevice(gpu_index);
  auto x = (pbs_buffer<uint64_t, CLASSICAL> *)(*buffer);
  x->release(static_cast<cudaStream_t>(stream), gpu_index);
}

template bool has_support_to_cuda_programmable_bootstrap_cg<uint64_t>(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t num_samples, uint32_t max_shared_memory);

template void cuda_programmable_bootstrap_cg_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<uint64_t, CLASSICAL> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset);

template void cuda_programmable_bootstrap_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<uint64_t, CLASSICAL> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset);

template void scratch_cuda_programmable_bootstrap_cg<uint64_t, int64_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, CLASSICAL> **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

template void scratch_cuda_programmable_bootstrap<uint64_t, int64_t>(
    void *stream, uint32_t gpu_index, pbs_buffer<uint64_t, CLASSICAL> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

template void cuda_programmable_bootstrap_cg_lwe_ciphertext_vector<uint32_t>(
    void *stream, uint32_t gpu_index, uint32_t *lwe_array_out,
    uint32_t *lwe_output_indexes, uint32_t *lut_vector,
    uint32_t *lut_vector_indexes, uint32_t *lwe_array_in,
    uint32_t *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<uint32_t, CLASSICAL> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset);

template void cuda_programmable_bootstrap_lwe_ciphertext_vector<uint32_t>(
    void *stream, uint32_t gpu_index, uint32_t *lwe_array_out,
    uint32_t *lwe_output_indexes, uint32_t *lut_vector,
    uint32_t *lut_vector_indexes, uint32_t *lwe_array_in,
    uint32_t *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<uint32_t, CLASSICAL> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory, uint32_t gpu_offset);

template void scratch_cuda_programmable_bootstrap_cg<uint32_t, int32_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint32_t, CLASSICAL> **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

template void scratch_cuda_programmable_bootstrap<uint32_t, int32_t>(
    void *stream, uint32_t gpu_index, pbs_buffer<uint32_t, CLASSICAL> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);

template bool has_support_to_cuda_programmable_bootstrap_tbc<uint32_t>(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory);
template bool has_support_to_cuda_programmable_bootstrap_tbc<uint64_t>(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory);

#if CUDA_ARCH >= 900
template void cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector<uint32_t>(
    void *stream, uint32_t gpu_index, uint32_t *lwe_array_out,
    uint32_t *lwe_output_indexes, uint32_t *lut_vector,
    uint32_t *lut_vector_indexes, uint32_t *lwe_array_in,
    uint32_t *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<uint32_t, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory);
template void cuda_programmable_bootstrap_tbc_lwe_ciphertext_vector<uint64_t>(
    void *stream, uint32_t gpu_index, uint64_t *lwe_array_out,
    uint64_t *lwe_output_indexes, uint64_t *lut_vector,
    uint64_t *lut_vector_indexes, uint64_t *lwe_array_in,
    uint64_t *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<uint64_t, CLASSICAL> *buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, uint32_t num_luts,
    uint32_t lwe_idx, uint32_t max_shared_memory);
template void scratch_cuda_programmable_bootstrap_tbc<uint32_t, int32_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint32_t, CLASSICAL> **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);
template void scratch_cuda_programmable_bootstrap_tbc<uint64_t, int64_t>(
    void *stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, CLASSICAL> **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory);
#endif
