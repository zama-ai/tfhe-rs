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

uint64_t scratch_cuda_integer_signed_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t num_scalar_bits, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    bool is_absolute_divisor_one, bool is_divisor_negative,
    bool l_exceed_threshold, bool is_power_of_two, bool multiplier_is_small,
    bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_signed_scalar_div_radix_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_signed_scalar_div_mem<uint64_t> **)mem_ptr, num_blocks,
      num_scalar_bits, allocate_gpu_memory, is_absolute_divisor_one,
      is_divisor_negative, l_exceed_threshold, is_power_of_two,
      multiplier_is_small);
}

void cuda_integer_signed_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *numerator_ct, int8_t *mem_ptr, void *const *ksks,
    void *const *bsks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key,
    bool is_absolute_divisor_one, bool is_divisor_negative,
    bool l_exceed_threshold, bool is_power_of_two, bool multiplier_is_small,
    uint32_t l, uint32_t shift_post, bool is_rhs_power_of_two, bool is_rhs_zero,
    bool is_rhs_one, uint32_t rhs_shift, uint32_t numerator_bits,
    uint32_t num_scalars, uint64_t const *decomposed_scalar,
    uint64_t const *has_at_least_one_set) {

  host_integer_signed_scalar_div_radix_kb<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, numerator_ct,
      (int_signed_scalar_div_mem<uint64_t> *)mem_ptr, (uint64_t **)ksks, bsks,
      ms_noise_reduction_key, is_absolute_divisor_one, is_divisor_negative,
      l_exceed_threshold, is_power_of_two, multiplier_is_small, l, shift_post,
      is_rhs_power_of_two, is_rhs_zero, is_rhs_one, rhs_shift, numerator_bits,
      num_scalars, decomposed_scalar, has_at_least_one_set);
}

void cleanup_cuda_integer_signed_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_signed_scalar_div_mem<uint64_t> *mem_ptr =
      (int_signed_scalar_div_mem<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_integer_unsigned_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory, bool is_divisor_power_of_two,
    bool log2_divisor_exceeds_threshold, bool multiplier_exceeds_threshold,
    uint32_t num_scalar_bits_for_div, uint32_t num_scalar_bits_for_mul,
    uint32_t ilog2_divisor, uint64_t divisor, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_unsigned_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_unsigned_scalar_div_rem_buffer<uint64_t> **)mem_ptr, num_blocks,
      allocate_gpu_memory, is_divisor_power_of_two,
      log2_divisor_exceeds_threshold, multiplier_exceeds_threshold,
      num_scalar_bits_for_div, num_scalar_bits_for_mul, ilog2_divisor, divisor);
}

void cuda_integer_unsigned_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *quotient_ct, CudaRadixCiphertextFFI *remainder_ct,
    int8_t *mem_ptr, void *const *ksks, void *const *bsks,
    uint64_t const *decomposed_scalar_for_div,
    uint64_t const *decomposed_scalar_for_mul,
    uint64_t const *has_at_least_one_set_for_div,
    uint64_t const *has_at_least_one_set_for_mul,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key,
    uint32_t num_scalars_for_div, uint32_t num_scalars_for_mul,
    bool multiplier_exceeds_threshold, bool is_divisor_power_of_two,
    bool log2_divisor_exceeds_threshold, uint32_t ilog2_divisor,
    uint64_t divisor, uint64_t shift_pre, uint32_t shift_post, uint64_t rhs,
    void const *clear_blocks, void const *h_clear_blocks,
    uint32_t num_clear_blocks) {

  host_integer_unsigned_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, quotient_ct,
      remainder_ct, (int_unsigned_scalar_div_rem_buffer<uint64_t> *)mem_ptr,
      (uint64_t **)ksks, bsks, decomposed_scalar_for_div,
      decomposed_scalar_for_mul, has_at_least_one_set_for_div,
      has_at_least_one_set_for_mul, ms_noise_reduction_key, num_scalars_for_div,
      num_scalars_for_mul, multiplier_exceeds_threshold,
      is_divisor_power_of_two, log2_divisor_exceeds_threshold, ilog2_divisor,
      divisor, shift_pre, shift_post, rhs, (uint64_t *)clear_blocks,
      (uint64_t *)h_clear_blocks, num_clear_blocks);
}

void cleanup_cuda_integer_unsigned_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_unsigned_scalar_div_rem_buffer<uint64_t> *mem_ptr =
      (int_unsigned_scalar_div_rem_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_integer_signed_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    uint32_t num_scalar_bits_for_div, uint32_t num_scalar_bits_for_mul,
    bool is_absolute_divisor_one, bool is_divisor_negative,
    bool l_exceed_threshold, bool is_absolute_divisor_power_of_two,
    bool is_divisor_zero, bool multiplier_is_small, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_signed_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_signed_scalar_div_rem_buffer<uint64_t> **)mem_ptr, num_blocks,
      allocate_gpu_memory, num_scalar_bits_for_div, num_scalar_bits_for_mul,
      is_absolute_divisor_one, is_divisor_negative, l_exceed_threshold,
      is_absolute_divisor_power_of_two, is_divisor_zero, multiplier_is_small);
}

void cuda_integer_signed_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *quotient_ct, CudaRadixCiphertextFFI *remainder_ct,
    int8_t *mem_ptr, void *const *ksks, void *const *bsks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    bool is_absolute_divisor_one, bool is_divisor_negative,
    bool is_divisor_zero, bool l_exceed_threshold,
    bool is_absolute_divisor_power_of_two, bool multiplier_is_small, uint32_t l,
    uint32_t shift_post, bool is_rhs_power_of_two, bool is_rhs_zero,
    bool is_rhs_one, uint32_t rhs_shift, uint32_t divisor_shift,
    uint32_t numerator_bits, uint32_t num_scalars_for_div,
    uint32_t num_scalars_for_mul, uint64_t const *decomposed_scalar_for_div,
    uint64_t const *decomposed_scalar_for_mul,
    uint64_t const *has_at_least_one_set_for_div,
    uint64_t const *has_at_least_one_set_for_mul) {

  host_integer_signed_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, quotient_ct,
      remainder_ct, (int_signed_scalar_div_rem_buffer<uint64_t> *)mem_ptr,
      (uint64_t **)ksks, bsks, ms_noise_reduction_key, is_absolute_divisor_one,
      is_divisor_negative, is_divisor_zero, l_exceed_threshold,
      is_absolute_divisor_power_of_two, multiplier_is_small, l, shift_post,
      is_rhs_power_of_two, is_rhs_zero, is_rhs_one, rhs_shift, divisor_shift,
      numerator_bits, num_scalars_for_div, num_scalars_for_mul,
      decomposed_scalar_for_div, decomposed_scalar_for_mul,
      has_at_least_one_set_for_div, has_at_least_one_set_for_mul);
}

void cleanup_cuda_integer_signed_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_signed_scalar_div_rem_buffer<uint64_t> *mem_ptr =
      (int_signed_scalar_div_rem_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
