#include "integer/oprf.cuh"

uint64_t scratch_cuda_integer_grouped_oprf_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_to_process,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, uint32_t message_bits_per_block,
    uint32_t total_random_bits, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

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
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_intermediate,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, uint32_t message_bits_per_block,
    uint32_t num_input_random_bits, uint32_t num_scalar_bits,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

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
    void *const *ksks) {

  host_integer_grouped_oprf_custom_range<uint64_t>(
      CudaStreams(streams), radix_lwe_out, num_blocks_intermediate,
      (const uint64_t *)seeded_lwe_input, decomposed_scalar,
      has_at_least_one_set, num_scalars, shift,
      (int_grouped_oprf_custom_range_memory<uint64_t> *)mem, bsks,
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
