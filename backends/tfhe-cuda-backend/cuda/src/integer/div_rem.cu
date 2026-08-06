#include "integer/div_rem.cuh"

uint64_t scratch_cuda_integer_div_rem_64_async(
    CudaStreamsFFI streams, bool is_signed, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  PUSH_RANGE("scratch div")
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_div_rem<uint64_t>(
      CudaStreams(streams), is_signed, (int_div_rem_memory<uint64_t> **)mem_ptr,
      num_blocks, params, allocate_gpu_memory);
  POP_RANGE()
}

void cuda_integer_div_rem_64_async(CudaStreamsFFI streams,
                                   CudaRadixCiphertextFFI *quotient_ffi,
                                   CudaRadixCiphertextFFI *remainder_ffi,
                                   CudaRadixCiphertextFFI const *numerator_ffi,
                                   CudaRadixCiphertextFFI const *divisor_ffi,
                                   bool is_signed, int8_t *mem_ptr,
                                   void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext quotient_local(*quotient_ffi);
  CudaRadixCiphertext *quotient = &quotient_local;
  CudaRadixCiphertext remainder_local(*remainder_ffi);
  CudaRadixCiphertext *remainder = &remainder_local;
  const CudaRadixCiphertext numerator_local(*numerator_ffi);
  const CudaRadixCiphertext *numerator = &numerator_local;
  const CudaRadixCiphertext divisor_local(*divisor_ffi);
  const CudaRadixCiphertext *divisor = &divisor_local;

  PANIC_IF_FALSE(quotient_ffi != numerator_ffi,
                 "Quotient and numerator pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(quotient_ffi != divisor_ffi,
                 "Quotient and divisor pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(remainder_ffi != numerator_ffi,
                 "Remainder and numerator pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(remainder_ffi != divisor_ffi,
                 "Remainder and divisor pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(quotient_ffi != remainder_ffi,
                 "Quotient and remainder pointers must be different for "
                 "out-of-place operations");
  PUSH_RANGE("div")
  auto mem = (int_div_rem_memory<uint64_t> *)mem_ptr;

  host_integer_div_rem<uint64_t>(CudaStreams(streams), quotient, remainder,
                                 numerator, divisor, is_signed, bsks,
                                 (uint64_t **)(ksks), mem);
  POP_RANGE()
}

void cleanup_cuda_integer_div_rem_64(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup div")
  int_div_rem_memory<uint64_t> *mem_ptr =
      (int_div_rem_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
