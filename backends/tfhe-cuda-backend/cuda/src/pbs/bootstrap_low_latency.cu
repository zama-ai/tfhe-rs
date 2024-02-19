#include "bootstrap_fast_low_latency.cuh"
#include "bootstrap_low_latency.cuh"
/*
 * Returns the buffer size for 64 bits executions
 */
uint64_t get_buffer_size_bootstrap_low_latency_64(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {

  switch (polynomial_size) {
  case 256:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<256>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      return get_buffer_size_bootstrap_fast_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
    else
      return get_buffer_size_bootstrap_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
  case 512:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<512>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      return get_buffer_size_bootstrap_fast_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
    else
      return get_buffer_size_bootstrap_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
  case 1024:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<1024>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      return get_buffer_size_bootstrap_fast_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
    else
      return get_buffer_size_bootstrap_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
  case 2048:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<2048>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      return get_buffer_size_bootstrap_fast_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
    else
      return get_buffer_size_bootstrap_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
  case 4096:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<4096>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      return get_buffer_size_bootstrap_fast_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
    else
      return get_buffer_size_bootstrap_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
  case 8192:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<8192>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      return get_buffer_size_bootstrap_fast_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
    else
      return get_buffer_size_bootstrap_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
  case 16384:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<
            uint64_t, AmortizedDegree<16384>>(glwe_dimension, level_count,
                                              input_lwe_ciphertext_count,
                                              max_shared_memory))
      return get_buffer_size_bootstrap_fast_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
    else
      return get_buffer_size_bootstrap_low_latency<uint64_t>(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory);
  default:
    PANIC("Cuda error (low latency PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the low latency PBS on 32 bits inputs, into `pbs_buffer`. It also
 * configures SM options on the GPU in case FULLSM or PARTIALSM mode is going to
 * be used.
 */
void scratch_cuda_bootstrap_low_latency_32(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<256>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint32_t, int32_t,
                                         AmortizedDegree<256>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint32_t, int32_t, Degree<256>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 512:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<512>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint32_t, int32_t,
                                         AmortizedDegree<512>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint32_t, int32_t, Degree<512>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 2048:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<2048>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint32_t, int32_t,
                                         AmortizedDegree<2048>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint32_t, int32_t, Degree<2048>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 4096:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<4096>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint32_t, int32_t,
                                         AmortizedDegree<4096>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint32_t, int32_t, Degree<4096>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 8192:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<8192>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint32_t, int32_t,
                                         AmortizedDegree<8192>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint32_t, int32_t, Degree<8192>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 16384:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<
            uint32_t, AmortizedDegree<16384>>(glwe_dimension, level_count,
                                              input_lwe_ciphertext_count,
                                              max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint32_t, int32_t,
                                         AmortizedDegree<16384>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint32_t, int32_t, Degree<16384>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (low latency PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the low_latency PBS on 64 bits inputs, into `pbs_buffer`. It also
 * configures SM options on the GPU in case FULLSM or PARTIALSM mode is going to
 * be used.
 */
void scratch_cuda_bootstrap_low_latency_64(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<256>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint64_t, int64_t,
                                         AmortizedDegree<256>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint64_t, int64_t, Degree<256>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 512:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<512>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint64_t, int64_t,
                                         AmortizedDegree<512>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint64_t, int64_t, Degree<512>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 1024:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<1024>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint64_t, int64_t,
                                         AmortizedDegree<1024>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint64_t, int64_t, Degree<1024>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 2048:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<2048>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint64_t, int64_t,
                                         AmortizedDegree<2048>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint64_t, int64_t, Degree<2048>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 4096:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<4096>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint64_t, int64_t,
                                         AmortizedDegree<4096>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint64_t, int64_t, Degree<4096>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 8192:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<8192>>(
            glwe_dimension, level_count, input_lwe_ciphertext_count,
            max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint64_t, int64_t,
                                         AmortizedDegree<8192>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint64_t, int64_t, Degree<8192>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  case 16384:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<
            uint64_t, AmortizedDegree<16384>>(glwe_dimension, level_count,
                                              input_lwe_ciphertext_count,
                                              max_shared_memory))
      scratch_bootstrap_fast_low_latency<uint64_t, int64_t,
                                         AmortizedDegree<16384>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    else
      scratch_bootstrap_low_latency<uint64_t, int64_t, Degree<16384>>(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (low latency PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

/* Perform bootstrapping on a batch of input u32 LWE ciphertexts.
 * This function performs best for small numbers of inputs. Beyond a certain
 * number of inputs (the exact number depends on the cryptographic parameters),
 * the kernel cannot be launched and it is necessary to split the kernel call
 * into several calls on smaller batches of inputs. For more details on this
 * operation, head on to the equivalent u64 operation.
 */
void cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory) {

  if (base_log > 32)
    PANIC("Cuda error (low latency PBS): base log should be > number of bits "
          "in the ciphertext representation (32)");

  switch (polynomial_size) {
  case 256:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<256>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint32_t, AmortizedDegree<256>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint32_t, Degree<256>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 512:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<512>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint32_t, AmortizedDegree<512>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint32_t, Degree<512>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 1024:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<1024>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint32_t, AmortizedDegree<1024>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint32_t, Degree<1024>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 2048:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<2048>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint32_t, AmortizedDegree<2048>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint32_t, Degree<2048>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 4096:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<4096>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint32_t, AmortizedDegree<4096>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint32_t, Degree<4096>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 8192:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<8192>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint32_t, AmortizedDegree<8192>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint32_t, Degree<8192>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 16384:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<
            uint32_t, AmortizedDegree<16384>>(glwe_dimension, level_count,
                                              num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint32_t, AmortizedDegree<16384>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint32_t, Degree<16384>>(
          stream, static_cast<uint32_t *>(lwe_array_out),
          static_cast<uint32_t *>(lwe_output_indexes),
          static_cast<uint32_t *>(lut_vector),
          static_cast<uint32_t *>(lut_vector_indexes),
          static_cast<uint32_t *>(lwe_array_in),
          static_cast<uint32_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  default:
    PANIC("Cuda error (low latency PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

/* Perform bootstrapping on a batch of input u64 LWE ciphertexts.
 * This function performs best for small numbers of inputs. Beyond a certain
 * number of inputs (the exact number depends on the cryptographic parameters),
 * the kernel cannot be launched and it is necessary to split the kernel call
 * into several calls on smaller batches of inputs.
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
void cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lut_vector, void *lut_vector_indexes, void *lwe_array_in,
    void *lwe_input_indexes, void *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_luts, uint32_t lwe_idx, uint32_t max_shared_memory) {
  if (base_log > 64)
    PANIC("Cuda error (low latency PBS): base log should be > number of bits "
          "in the ciphertext representation (64)");

  switch (polynomial_size) {
  case 256:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<256>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint64_t, AmortizedDegree<256>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint64_t, Degree<256>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 512:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint64_t,
                                                         AmortizedDegree<512>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint64_t, AmortizedDegree<512>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint64_t, Degree<512>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 1024:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<1024>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint64_t, AmortizedDegree<1024>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint64_t, Degree<1024>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 2048:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<2048>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint64_t, AmortizedDegree<2048>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint64_t, Degree<2048>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 4096:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<4096>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint64_t, AmortizedDegree<4096>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint64_t, Degree<4096>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 8192:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<uint32_t,
                                                         AmortizedDegree<8192>>(
            glwe_dimension, level_count, num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint64_t, AmortizedDegree<8192>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint64_t, Degree<8192>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  case 16384:
    if (verify_cuda_bootstrap_fast_low_latency_grid_size<
            uint64_t, AmortizedDegree<16384>>(glwe_dimension, level_count,
                                              num_samples, max_shared_memory))
      host_bootstrap_fast_low_latency<uint64_t, AmortizedDegree<16384>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    else
      host_bootstrap_low_latency<uint64_t, Degree<16384>>(
          stream, static_cast<uint64_t *>(lwe_array_out),
          static_cast<uint64_t *>(lwe_output_indexes),
          static_cast<uint64_t *>(lut_vector),
          static_cast<uint64_t *>(lut_vector_indexes),
          static_cast<uint64_t *>(lwe_array_in),
          static_cast<uint64_t *>(lwe_input_indexes),
          static_cast<double2 *>(bootstrapping_key), pbs_buffer, glwe_dimension,
          lwe_dimension, polynomial_size, base_log, level_count, num_samples,
          num_luts, max_shared_memory);
    break;
  default:
    PANIC("Cuda error (low latency PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

/*
 * This cleanup function frees the data for the low latency PBS on GPU in
 * pbs_buffer for 32 or 64 bits inputs.
 */
void cleanup_cuda_bootstrap_low_latency(cuda_stream_t *stream,
                                        int8_t **pbs_buffer) {
  // Free memory
  cuda_drop_async(*pbs_buffer, stream);
}
