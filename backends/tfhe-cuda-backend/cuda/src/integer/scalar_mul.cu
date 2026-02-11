#include "integer/scalar_mul.cuh"

uint64_t scratch_cuda_integer_scalar_mul_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t num_scalar_bits,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_cuda_scalar_mul<uint64_t>(
      CudaStreams(streams), (int_scalar_mul_buffer<uint64_t> **)mem_ptr,
      num_blocks, params, num_scalar_bits, allocate_gpu_memory);
}

void cuda_integer_scalar_mul_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    uint64_t const *decomposed_scalar, uint64_t const *has_at_least_one_set,
    int8_t *mem, void *const *bsks, void *const *ksks, uint32_t polynomial_size,
    uint32_t message_modulus, uint32_t num_scalars) {

  host_integer_scalar_mul_radix<uint64_t>(
      CudaStreams(streams), lwe_array, decomposed_scalar, has_at_least_one_set,
      reinterpret_cast<int_scalar_mul_buffer<uint64_t> *>(mem), bsks,
      (uint64_t **)(ksks), message_modulus, num_scalars);
}

void cleanup_cuda_integer_scalar_mul_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void) {

  int_scalar_mul_buffer<uint64_t> *mem_ptr =
      (int_scalar_mul_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

void cuda_small_scalar_multiplication_integer_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array, uint64_t scalar,
    const uint32_t message_modulus, const uint32_t carry_modulus) {

  host_integer_small_scalar_mul_radix<uint64_t>(CudaStreams(streams), lwe_array,
                                                lwe_array, scalar,
                                                message_modulus, carry_modulus);
}
