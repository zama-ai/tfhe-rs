#include "zk.cuh"

uint64_t scratch_cuda_expand_without_verification_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t computing_ks_level,
    uint32_t computing_ks_base_log, uint32_t casting_input_dimension,
    uint32_t casting_output_dimension, uint32_t casting_ks_level,
    uint32_t casting_ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, const uint32_t *num_lwes_per_compact_list,
    const bool *is_boolean_array, const uint32_t is_boolean_array_len,
    uint32_t num_compact_lists, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, KS_TYPE casting_key_type,
    bool allocate_gpu_memory, EXPAND_KIND expand_kind,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  // Since CUDA backend works with the concept of "big" and "small" key, instead
  // of "input" and "output", we need to do this or otherwise our PBS will throw
  // an exception. Since we store the casting direction, this is not a problem.
  auto casting_big_dimension =
      std::max(casting_input_dimension, casting_output_dimension);
  auto casting_small_dimension =
      std::min(casting_input_dimension, casting_output_dimension);

  int_radix_params computing_params(
      pbs_type, glwe_dimension, polynomial_size, big_lwe_dimension,
      small_lwe_dimension, computing_ks_level, computing_ks_base_log, pbs_level,
      pbs_base_log, grouping_factor, message_modulus, carry_modulus,
      noise_reduction_type);

  int_radix_params casting_params(
      pbs_type, glwe_dimension, polynomial_size, casting_big_dimension,
      casting_small_dimension, casting_ks_level, casting_ks_base_log, pbs_level,
      pbs_base_log, grouping_factor, message_modulus, carry_modulus,
      noise_reduction_type);

  return scratch_cuda_expand_without_verification<uint64_t>(
      CudaStreams(streams),
      reinterpret_cast<zk_expand_mem<uint64_t> **>(mem_ptr),
      num_lwes_per_compact_list, is_boolean_array, is_boolean_array_len,
      num_compact_lists, computing_params, casting_params, casting_key_type,
      allocate_gpu_memory, expand_kind);
}

void cuda_expand_without_verification_64_async(
    CudaStreamsFFI streams, void *lwe_array_out,
    const void *lwe_flattened_compact_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *computing_ksks, void *const *casting_keys) {

  auto expand_buffer = reinterpret_cast<zk_expand_mem<uint64_t> *>(mem_ptr);

  switch (expand_buffer->casting_params.big_lwe_dimension) {
  case 256:
    host_expand_without_verification<uint64_t, AmortizedDegree<256>>(
        streams, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_flattened_compact_array_in),
        expand_buffer, (uint64_t **)casting_keys, bsks,
        (uint64_t **)(computing_ksks));
    break;
  case 512:
    host_expand_without_verification<uint64_t, AmortizedDegree<512>>(
        streams, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_flattened_compact_array_in),
        expand_buffer, (uint64_t **)casting_keys, bsks,
        (uint64_t **)(computing_ksks));
    break;
  case 1024:
    host_expand_without_verification<uint64_t, AmortizedDegree<1024>>(
        streams, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_flattened_compact_array_in),
        expand_buffer, (uint64_t **)casting_keys, bsks,
        (uint64_t **)(computing_ksks));
    break;
  case 2048:
    host_expand_without_verification<uint64_t, AmortizedDegree<2048>>(
        streams, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_flattened_compact_array_in),
        expand_buffer, (uint64_t **)casting_keys, bsks,
        (uint64_t **)(computing_ksks));
    break;
  case 4096:
    host_expand_without_verification<uint64_t, AmortizedDegree<4096>>(
        streams, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_flattened_compact_array_in),
        expand_buffer, (uint64_t **)casting_keys, bsks,
        (uint64_t **)(computing_ksks));
    break;
  case 8192:
    host_expand_without_verification<uint64_t, AmortizedDegree<8192>>(
        streams, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_flattened_compact_array_in),
        expand_buffer, (uint64_t **)casting_keys, bsks,
        (uint64_t **)(computing_ksks));
    break;
  case 16384:
    host_expand_without_verification<uint64_t, AmortizedDegree<16384>>(
        streams, static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_flattened_compact_array_in),
        expand_buffer, (uint64_t **)casting_keys, bsks,
        (uint64_t **)(computing_ksks));
    break;
  default:
    PANIC("CUDA error: lwe_dimension not supported."
          "Supported n's are powers of two"
          " in the interval [256..16384].");
    break;
  }
}

void cleanup_cuda_expand_without_verification_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void) {

  zk_expand_mem<uint64_t> *mem_ptr =
      reinterpret_cast<zk_expand_mem<uint64_t> *>(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
