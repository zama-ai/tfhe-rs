#include "scalar_div.cuh"

uint64_t scratch_cuda_integer_unsigned_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, const CudaScalarDivisorFFI *scalar_properties,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_unsigned_scalar_div_radix<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_unsigned_scalar_div_mem<uint64_t> **)mem_ptr, num_blocks,
      scalar_properties, allocate_gpu_memory);
}

void cuda_integer_unsigned_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *numerator_ct, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties) {

  host_integer_unsigned_scalar_div_radix<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, numerator_ct,
      (int_unsigned_scalar_div_mem<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks,
      ms_noise_reduction_key, scalar_properties);
}

void cleanup_cuda_integer_unsigned_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_unsigned_scalar_div_mem<uint64_t> *mem_ptr =
      (int_unsigned_scalar_div_mem<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_signed_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, const CudaScalarDivisorFFI *scalar_properties,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_signed_scalar_div_radix_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_signed_scalar_div_mem<uint64_t> **)mem_ptr, num_blocks,
      scalar_properties, allocate_gpu_memory);
}

void cuda_integer_signed_scalar_div_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *numerator_ct, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties, uint32_t numerator_bits) {

  host_integer_signed_scalar_div_radix_kb<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, numerator_ct,
      (int_signed_scalar_div_mem<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks,
      ms_noise_reduction_key, scalar_properties, numerator_bits);
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
    PBS_TYPE pbs_type, const CudaScalarDivisorFFI *scalar_properties,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_unsigned_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_unsigned_scalar_div_rem_buffer<uint64_t> **)mem_ptr, num_blocks,
      scalar_properties, allocate_gpu_memory);
}

void cuda_integer_unsigned_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *quotient_ct, CudaRadixCiphertextFFI *remainder_ct,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties, void const *clear_blocks,
    void const *h_clear_blocks, uint32_t num_clear_blocks) {

  host_integer_unsigned_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, quotient_ct,
      remainder_ct, (int_unsigned_scalar_div_rem_buffer<uint64_t> *)mem_ptr,
      bsks, (uint64_t **)ksks, ms_noise_reduction_key, scalar_properties,
      (uint64_t *)clear_blocks, (uint64_t *)h_clear_blocks, num_clear_blocks);
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
    PBS_TYPE pbs_type, const CudaScalarDivisorFFI *scalar_properties,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_integer_signed_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_signed_scalar_div_rem_buffer<uint64_t> **)mem_ptr, num_blocks,
      scalar_properties, allocate_gpu_memory);
}

void cuda_integer_signed_scalar_div_rem_radix_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *quotient_ct, CudaRadixCiphertextFFI *remainder_ct,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    const CudaScalarDivisorFFI *scalar_properties, uint32_t numerator_bits) {

  host_integer_signed_scalar_div_rem_radix<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, quotient_ct,
      remainder_ct, (int_signed_scalar_div_rem_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks, ms_noise_reduction_key, scalar_properties,
      numerator_bits);
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
