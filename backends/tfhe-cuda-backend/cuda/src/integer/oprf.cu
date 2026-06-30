#include "integer/oprf.cuh"

uint64_t scratch_cuda_integer_grouped_oprf_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks_to_process,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    uint32_t message_bits_per_block, uint32_t total_random_bits,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_grouped_oprf<uint64_t>(
      CudaStreams(streams), (int_grouped_oprf_memory<uint64_t> **)mem_ptr,
      params, num_blocks_to_process, message_bits_per_block, total_random_bits,
      allocate_gpu_memory);
}

void cuda_integer_grouped_oprf_64_async(CudaStreamsFFI streams,
                                        CudaRadixCiphertextFFI *radix_lwe_out,
                                        const void *seeded_lwe_input,
                                        uint32_t num_blocks_to_process,
                                        int8_t *mem, void *const *bsks) {

  host_integer_grouped_oprf<uint64_t>(
      CudaStreams(streams), radix_lwe_out, (const uint64_t *)seeded_lwe_input,
      num_blocks_to_process, (int_grouped_oprf_memory<uint64_t> *)mem, bsks);
}

void cleanup_cuda_integer_grouped_oprf_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void) {

  int_grouped_oprf_memory<uint64_t> *mem_ptr =
      (int_grouped_oprf_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_grouped_oprf_custom_range_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks_intermediate,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    uint32_t message_bits_per_block, uint32_t num_input_random_bits,
    uint32_t num_scalar_bits, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_grouped_oprf_custom_range<uint64_t>(
      CudaStreams(streams),
      (int_grouped_oprf_custom_range_memory<uint64_t> **)mem_ptr, params,
      num_blocks_intermediate, message_bits_per_block, num_input_random_bits,
      num_scalar_bits, allocate_gpu_memory);
}

void cuda_integer_grouped_oprf_custom_range_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *radix_lwe_out,
    uint32_t num_blocks_intermediate, const void *seeded_lwe_input,
    const uint64_t *decomposed_scalar, const uint64_t *has_at_least_one_set,
    uint32_t num_scalars, uint32_t shift, int8_t *mem, void *const *bsks,
    void *const *compute_bsks, void *const *ksks) {

  host_integer_grouped_oprf_custom_range<uint64_t>(
      CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
      (const uint64_t *)seeded_lwe_input, decomposed_scalar,
      has_at_least_one_set, num_scalars, shift,
      (int_grouped_oprf_custom_range_memory<uint64_t> *)mem, bsks, compute_bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_integer_grouped_oprf_custom_range_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void) {
  int_grouped_oprf_custom_range_memory<uint64_t> *mem_ptr =
      (int_grouped_oprf_custom_range_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_grouped_oprf_custom_range_with_rerand_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks_intermediate,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    uint32_t message_bits_per_block, uint32_t num_input_random_bits,
    uint32_t num_scalar_bits, PBS_MS_REDUCTION_T noise_reduction_type,
    CudaLweKeyswitchKeyParamsFFI rerand_ksk_params, RERAND_MODE rerand_mode) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  int_radix_params rerand_params(
      PBS_TYPE::CLASSICAL, 0, 0, rerand_ksk_params.input_lwe_dimension,
      rerand_ksk_params.output_lwe_dimension, rerand_ksk_params.level_count,
      rerand_ksk_params.base_log, 0, 0, 0, message_modulus, carry_modulus,
      PBS_MS_REDUCTION_T::NO_REDUCTION);

  return scratch_cuda_integer_grouped_oprf_custom_range_with_rerand<uint64_t>(
      CudaStreams(streams),
      (int_grouped_oprf_custom_range_with_rerand_memory<uint64_t> **)mem_ptr,
      params, rerand_params, num_blocks_intermediate, message_bits_per_block,
      num_input_random_bits, num_scalar_bits, rerand_mode, allocate_gpu_memory);
}

void cuda_integer_grouped_oprf_custom_range_with_rerand_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *radix_lwe_out,
    uint32_t num_blocks_intermediate, const void *seeded_lwe_input,
    const uint64_t *decomposed_scalar, const uint64_t *has_at_least_one_set,
    uint32_t num_scalars, uint32_t shift,
    const void *lwe_flattened_encryptions_of_zero_compact_array_in, int8_t *mem,
    void *const *bsks, void *const *compute_bsks, void *const *ksks,
    void *const *rerand_ksks) {

  auto mem_ptr =
      (int_grouped_oprf_custom_range_with_rerand_memory<uint64_t> *)mem;

  switch (mem_ptr->rerand_memory->params.big_lwe_dimension) {
  case 256:
    host_integer_grouped_oprf_custom_range_with_rerand<uint64_t,
                                                       AmortizedDegree<256>>(
        CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
        (const uint64_t *)seeded_lwe_input, decomposed_scalar,
        has_at_least_one_set, num_scalars, shift,
        (const uint64_t *)lwe_flattened_encryptions_of_zero_compact_array_in,
        mem_ptr, bsks, compute_bsks, (uint64_t *const *)ksks,
        (uint64_t *const *)rerand_ksks);
    break;
  case 512:
    host_integer_grouped_oprf_custom_range_with_rerand<uint64_t,
                                                       AmortizedDegree<512>>(
        CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
        (const uint64_t *)seeded_lwe_input, decomposed_scalar,
        has_at_least_one_set, num_scalars, shift,
        (const uint64_t *)lwe_flattened_encryptions_of_zero_compact_array_in,
        mem_ptr, bsks, compute_bsks, (uint64_t *const *)ksks,
        (uint64_t *const *)rerand_ksks);
    break;
  case 1024:
    host_integer_grouped_oprf_custom_range_with_rerand<uint64_t,
                                                       AmortizedDegree<1024>>(
        CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
        (const uint64_t *)seeded_lwe_input, decomposed_scalar,
        has_at_least_one_set, num_scalars, shift,
        (const uint64_t *)lwe_flattened_encryptions_of_zero_compact_array_in,
        mem_ptr, bsks, compute_bsks, (uint64_t *const *)ksks,
        (uint64_t *const *)rerand_ksks);
    break;
  case 2048:
    host_integer_grouped_oprf_custom_range_with_rerand<uint64_t,
                                                       AmortizedDegree<2048>>(
        CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
        (const uint64_t *)seeded_lwe_input, decomposed_scalar,
        has_at_least_one_set, num_scalars, shift,
        (const uint64_t *)lwe_flattened_encryptions_of_zero_compact_array_in,
        mem_ptr, bsks, compute_bsks, (uint64_t *const *)ksks,
        (uint64_t *const *)rerand_ksks);
    break;
  case 4096:
    host_integer_grouped_oprf_custom_range_with_rerand<uint64_t,
                                                       AmortizedDegree<4096>>(
        CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
        (const uint64_t *)seeded_lwe_input, decomposed_scalar,
        has_at_least_one_set, num_scalars, shift,
        (const uint64_t *)lwe_flattened_encryptions_of_zero_compact_array_in,
        mem_ptr, bsks, compute_bsks, (uint64_t *const *)ksks,
        (uint64_t *const *)rerand_ksks);
    break;
  case 8192:
    host_integer_grouped_oprf_custom_range_with_rerand<uint64_t,
                                                       AmortizedDegree<8192>>(
        CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
        (const uint64_t *)seeded_lwe_input, decomposed_scalar,
        has_at_least_one_set, num_scalars, shift,
        (const uint64_t *)lwe_flattened_encryptions_of_zero_compact_array_in,
        mem_ptr, bsks, compute_bsks, (uint64_t *const *)ksks,
        (uint64_t *const *)rerand_ksks);
    break;
  case 16384:
    host_integer_grouped_oprf_custom_range_with_rerand<uint64_t,
                                                       AmortizedDegree<16384>>(
        CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
        (const uint64_t *)seeded_lwe_input, decomposed_scalar,
        has_at_least_one_set, num_scalars, shift,
        (const uint64_t *)lwe_flattened_encryptions_of_zero_compact_array_in,
        mem_ptr, bsks, compute_bsks, (uint64_t *const *)ksks,
        (uint64_t *const *)rerand_ksks);
    break;
  default:
    PANIC("CUDA error: compact public key dimension not supported. Supported "
          "dimensions are powers of two in the interval [256..16384].");
    break;
  }
}

void cleanup_cuda_integer_grouped_oprf_custom_range_with_rerand_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  int_grouped_oprf_custom_range_with_rerand_memory<uint64_t> *mem_ptr =
      (int_grouped_oprf_custom_range_with_rerand_memory<uint64_t>
           *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
