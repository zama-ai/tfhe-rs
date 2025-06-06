#include "scalar_div.cuh"

uint64_t scratch_cuda_integer_unsigned_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory, bool is_divisor_power_of_two,
    bool log2_divisor_exceeds_threshold, bool multiplier_exceeds_threshold,
    uint32_t num_scalar_bits, uint32_t ilog2_divisor, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_unsigned_scalar_div_radix<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_unsigned_scalar_div_mem<uint64_t> **)mem_ptr, num_blocks,
      allocate_gpu_memory, is_divisor_power_of_two,
      log2_divisor_exceeds_threshold, multiplier_exceeds_threshold,
      num_scalar_bits, ilog2_divisor);
}

void cuda_integer_unsigned_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *numerator_ct, int8_t *mem_ptr, void *const *ksks,
    uint64_t const *decomposed_scalar, uint64_t const *has_at_least_one_set,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_scalars, bool multiplier_exceeds_threshold,
    bool is_divisor_power_of_two, bool log2_divisor_exceeds_threshold,
    uint32_t ilog2_divisor, uint64_t shift_pre, uint32_t shift_post,
    uint64_t rhs) {

  host_integer_unsigned_scalar_div_radix<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, numerator_ct,
      (int_unsigned_scalar_div_mem<uint64_t> *)mem_ptr, (uint64_t **)ksks,
      decomposed_scalar, has_at_least_one_set, ms_noise_reduction_key, bsks,
      num_scalars, multiplier_exceeds_threshold, is_divisor_power_of_two,
      log2_divisor_exceeds_threshold, ilog2_divisor, shift_pre, shift_post,
      rhs);
}

void cleanup_cuda_integer_unsigned_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_unsigned_scalar_div_mem<uint64_t> *mem_ptr =
      (int_unsigned_scalar_div_mem<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);
}
