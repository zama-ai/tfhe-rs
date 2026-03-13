#include "subtraction.cuh"

uint64_t scratch_cuda_sub_and_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, uint32_t requested_flag, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ks_level, ks_base_log, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_sub_and_propagate_single_carry<uint64_t>(
      CudaStreams(streams), (int_sub_and_propagate<uint64_t> **)mem_ptr,
      num_blocks, params, requested_flag, allocate_gpu_memory);
}

void cuda_sub_and_propagate_single_carry_64_inplace_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lhs_array,
    const CudaRadixCiphertextFFI *rhs_array, CudaRadixCiphertextFFI *carry_out,
    const CudaRadixCiphertextFFI *carry_in, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t requested_flag, uint32_t uses_carry) {
  PUSH_RANGE("sub")
  host_sub_and_propagate_single_carry<uint64_t>(
      CudaStreams(streams), lhs_array, rhs_array, carry_out, carry_in,
      (int_sub_and_propagate<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks),
      requested_flag, uses_carry);
  POP_RANGE()
}

void cleanup_cuda_sub_and_propagate_single_carry_64_inplace(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup sub")
  int_sub_and_propagate<uint64_t> *mem_ptr =
      (int_sub_and_propagate<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  POP_RANGE()
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
