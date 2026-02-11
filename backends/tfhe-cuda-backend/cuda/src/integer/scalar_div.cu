#include "scalar_div.cuh"

uint64_t scratch_cuda_integer_unsigned_scalar_div_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_integer_unsigned_scalar_div_radix<uint64_t>(
      CudaStreams(streams), params,
      (int_unsigned_scalar_div_mem<uint64_t> **)mem_ptr, num_blocks,
      scalar_divisor_ffi, allocate_gpu_memory);
}

void cuda_integer_unsigned_scalar_div_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *numerator_ct,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaScalarDivisorFFI *scalar_divisor_ffi) {

  host_integer_unsigned_scalar_div_radix<uint64_t>(
      CudaStreams(streams), numerator_ct,
      (int_unsigned_scalar_div_mem<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks,
      scalar_divisor_ffi);
}

void cleanup_cuda_integer_unsigned_scalar_div_radix_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void) {

  int_unsigned_scalar_div_mem<uint64_t> *mem_ptr =
      (int_unsigned_scalar_div_mem<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_signed_scalar_div_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_integer_signed_scalar_div_radix<uint64_t>(
      CudaStreams(streams), params,
      (int_signed_scalar_div_mem<uint64_t> **)mem_ptr, num_blocks,
      scalar_divisor_ffi, allocate_gpu_memory);
}

void cuda_integer_signed_scalar_div_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *numerator_ct,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaScalarDivisorFFI *scalar_divisor_ffi, uint32_t numerator_bits) {

  host_integer_signed_scalar_div_radix<uint64_t>(
      CudaStreams(streams), numerator_ct,
      (int_signed_scalar_div_mem<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks,
      scalar_divisor_ffi, numerator_bits);
}

void cleanup_cuda_integer_signed_scalar_div_radix_64(CudaStreamsFFI streams,
                                                     int8_t **mem_ptr_void) {

  int_signed_scalar_div_mem<uint64_t> *mem_ptr =
      (int_signed_scalar_div_mem<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_unsigned_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint32_t const active_bits_divisor, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_integer_unsigned_scalar_div_rem_radix<uint64_t>(
      CudaStreams(streams), params,
      (int_unsigned_scalar_div_rem_buffer<uint64_t> **)mem_ptr, num_blocks,
      scalar_divisor_ffi, active_bits_divisor, allocate_gpu_memory);
}

void cuda_integer_unsigned_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *quotient_ct,
    CudaRadixCiphertextFFI *remainder_ct, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint64_t const *divisor_has_at_least_one_set,
    uint64_t const *decomposed_divisor, uint32_t const num_scalars_divisor,
    void const *clear_blocks, void const *h_clear_blocks,
    uint32_t num_clear_blocks) {

  host_integer_unsigned_scalar_div_rem_radix<uint64_t>(
      CudaStreams(streams), quotient_ct, remainder_ct,
      (int_unsigned_scalar_div_rem_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks, scalar_divisor_ffi, divisor_has_at_least_one_set,
      decomposed_divisor, num_scalars_divisor, (uint64_t *)clear_blocks,
      (uint64_t *)h_clear_blocks, num_clear_blocks);
}

void cleanup_cuda_integer_unsigned_scalar_div_rem_radix_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {

  int_unsigned_scalar_div_rem_buffer<uint64_t> *mem_ptr =
      (int_unsigned_scalar_div_rem_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_signed_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type,
    const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint32_t const active_bits_divisor, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_integer_signed_scalar_div_rem_radix<uint64_t>(
      CudaStreams(streams), params,
      (int_signed_scalar_div_rem_buffer<uint64_t> **)mem_ptr, num_blocks,
      scalar_divisor_ffi, active_bits_divisor, allocate_gpu_memory);
}

void cuda_integer_signed_scalar_div_rem_radix_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *quotient_ct,
    CudaRadixCiphertextFFI *remainder_ct, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint64_t const *divisor_has_at_least_one_set,
    uint64_t const *decomposed_divisor, uint32_t const num_scalars_divisor,
    uint32_t numerator_bits) {

  host_integer_signed_scalar_div_rem_radix<uint64_t>(
      CudaStreams(streams), quotient_ct, remainder_ct,
      (int_signed_scalar_div_rem_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks, scalar_divisor_ffi, divisor_has_at_least_one_set,
      decomposed_divisor, num_scalars_divisor, numerator_bits);
}

void cleanup_cuda_integer_signed_scalar_div_rem_radix_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {

  int_signed_scalar_div_rem_buffer<uint64_t> *mem_ptr =
      (int_signed_scalar_div_rem_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
