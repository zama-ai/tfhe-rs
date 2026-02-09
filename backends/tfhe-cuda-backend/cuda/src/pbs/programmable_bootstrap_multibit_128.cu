#include "programmable_bootstrap_cg_multibit.cuh"
#include "programmable_bootstrap_multibit_128.cuh"

template <typename InputTorus>
uint64_t scratch_cuda_multi_bit_programmable_bootstrap_128(
    void *stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    return scratch_multi_bit_programmable_bootstrap_128<InputTorus,
                                                        Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 512:
    return scratch_multi_bit_programmable_bootstrap_128<InputTorus,
                                                        Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 1024:
    return scratch_multi_bit_programmable_bootstrap_128<InputTorus,
                                                        Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 2048:
    return scratch_multi_bit_programmable_bootstrap_128<InputTorus,
                                                        Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    return scratch_multi_bit_programmable_bootstrap_128<InputTorus,
                                                        AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..4096].")
  }
}

template <typename InputTorus>
uint64_t scratch_cuda_cg_multi_bit_programmable_bootstrap_128(
    void *stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  switch (polynomial_size) {
  case 256:
    return scratch_cg_multi_bit_programmable_bootstrap_128<InputTorus,
                                                           Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 512:
    return scratch_cg_multi_bit_programmable_bootstrap_128<InputTorus,
                                                           Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 1024:
    return scratch_cg_multi_bit_programmable_bootstrap_128<InputTorus,
                                                           Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 2048:
    return scratch_cg_multi_bit_programmable_bootstrap_128<InputTorus,
                                                           Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    return scratch_cg_multi_bit_programmable_bootstrap_128<
        InputTorus, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, buffer, glwe_dimension,
        polynomial_size, level_count, input_lwe_ciphertext_count,
        allocate_gpu_memory);
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..4096].")
  }
}

uint64_t scratch_cuda_multi_bit_programmable_bootstrap_128_vector_64(
    void *stream, uint32_t gpu_index, int8_t **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  bool supports_cg =
      supports_cooperative_groups_on_multibit_programmable_bootstrap_128<
          __uint128_t>(glwe_dimension, polynomial_size, level_count,
                       input_lwe_ciphertext_count,
                       cuda_get_max_shared_memory(gpu_index));

  if (supports_cg)
    return scratch_cuda_cg_multi_bit_programmable_bootstrap_128<uint64_t>(
        stream, gpu_index,
        reinterpret_cast<pbs_buffer_128<uint64_t, MULTI_BIT> **>(buffer),
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, allocate_gpu_memory);
  else
    return scratch_cuda_multi_bit_programmable_bootstrap_128<uint64_t>(
        stream, gpu_index,
        reinterpret_cast<pbs_buffer_128<uint64_t, MULTI_BIT> **>(buffer),
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, allocate_gpu_memory);
}

template <typename InputTorus>
void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_128(
    void *stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    InputTorus const *lwe_output_indexes, __uint128_t const *lut_vector,
    InputTorus const *lwe_array_in, InputTorus const *lwe_input_indexes,
    __uint128_t const *bootstrapping_key,
    pbs_buffer_128<InputTorus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  switch (polynomial_size) {
  case 256:
    host_multi_bit_programmable_bootstrap_128<InputTorus, Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 512:
    host_multi_bit_programmable_bootstrap_128<InputTorus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 1024:
    host_multi_bit_programmable_bootstrap_128<InputTorus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 2048:
    host_multi_bit_programmable_bootstrap_128<InputTorus, Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    host_multi_bit_programmable_bootstrap_128<InputTorus,
                                              AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..4096].")
  }
}

template <typename InputTorus>
void cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_128(
    void *stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    InputTorus const *lwe_output_indexes, __uint128_t const *lut_vector,
    InputTorus const *lwe_array_in, InputTorus const *lwe_input_indexes,
    __uint128_t const *bootstrapping_key,
    pbs_buffer_128<InputTorus, MULTI_BIT> *pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  switch (polynomial_size) {
  case 256:
    host_cg_multi_bit_programmable_bootstrap_128<InputTorus, Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 512:
    host_cg_multi_bit_programmable_bootstrap_128<InputTorus, Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 1024:
    host_cg_multi_bit_programmable_bootstrap_128<InputTorus, Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 2048:
    host_cg_multi_bit_programmable_bootstrap_128<InputTorus, Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    host_cg_multi_bit_programmable_bootstrap_128<InputTorus,
                                                 AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, lwe_array_out,
        lwe_output_indexes, lut_vector, lwe_array_in, lwe_input_indexes,
        bootstrapping_key, pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, grouping_factor, base_log, level_count, num_samples,
        num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..4096].")
  }
}

void cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_128(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lut_vector,
    void const *lwe_array_in, void const *lwe_input_indexes,
    void const *bootstrapping_key, int8_t *mem_ptr, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  if (base_log > 64)
    PANIC("Cuda error (multi-bit PBS): base log should be <= 64")

  auto *buffer =
      reinterpret_cast<pbs_buffer_128<uint64_t, MULTI_BIT> *>(mem_ptr);
  switch (buffer->pbs_variant) {
  case PBS_VARIANT::CG:
    cuda_cg_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_128<
        uint64_t>(stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
                  static_cast<const uint64_t *>(lwe_output_indexes),
                  static_cast<const __uint128_t *>(lut_vector),
                  static_cast<const uint64_t *>(lwe_array_in),
                  static_cast<const uint64_t *>(lwe_input_indexes),
                  static_cast<const __uint128_t *>(bootstrapping_key), buffer,
                  lwe_dimension, glwe_dimension, polynomial_size,
                  grouping_factor, base_log, level_count, num_samples,
                  num_many_lut, lut_stride);
    break;
  case PBS_VARIANT::DEFAULT:
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_128<uint64_t>(
        stream, gpu_index, static_cast<__uint128_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_output_indexes),
        static_cast<const __uint128_t *>(lut_vector),
        static_cast<const uint64_t *>(lwe_array_in),
        static_cast<const uint64_t *>(lwe_input_indexes),
        static_cast<const __uint128_t *>(bootstrapping_key), buffer,
        lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
        base_log, level_count, num_samples, num_many_lut, lut_stride);
    break;
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported implementation variant.")
  }
}

void cleanup_cuda_multi_bit_programmable_bootstrap_128(void *stream,
                                                       const uint32_t gpu_index,
                                                       int8_t **buffer) {
  const auto x =
      reinterpret_cast<pbs_buffer_128<uint64_t, MULTI_BIT> *>(*buffer);
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
uint64_t get_lwe_chunk_size_128(uint32_t gpu_index, uint32_t max_num_pbs,
                                uint32_t polynomial_size,
                                uint32_t glwe_dimension, uint32_t level_count,
                                uint64_t full_sm_keybundle) {

  int max_blocks_per_sm;
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_blocks_per_sm,
        device_multi_bit_programmable_bootstrap_keybundle_128<Torus, params,
                                                              NOSM>,
        polynomial_size / params::opt, full_sm_keybundle));
  } else {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_blocks_per_sm,
        device_multi_bit_programmable_bootstrap_keybundle_128<Torus, params,
                                                              FULLSM>,
        polynomial_size / params::opt, 0));
  }

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
  int log2_max_num_pbs = log2_int(max_num_pbs);
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
