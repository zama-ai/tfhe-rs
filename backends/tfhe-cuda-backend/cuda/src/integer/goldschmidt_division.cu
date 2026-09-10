#include "integer/goldschmidt_division.cuh"

uint64_t scratch_cuda_goldschmidt_division_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t num_blocks,
    uint32_t iterations, uint32_t lut_precision, uint32_t message_modulus,
    uint32_t carry_modulus, CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  return scratch_cuda_goldschmidt_division<uint64_t>(
      CudaStreams(streams),
      (int_goldschmidt_division_buffer<uint64_t> **)mem_ptr, num_blocks,
      iterations, lut_precision, params, allocate_gpu_memory);
}

void cuda_goldschmidt_division_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, CudaRadixCiphertextFFI const *numerator,
    CudaRadixCiphertextFFI const *denominator, uint32_t iterations,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks) {
  PANIC_IF_FALSE(quotient != numerator && quotient != denominator &&
                     remainder != numerator && remainder != denominator &&
                     quotient != remainder,
                 "Output and input pointers must be different for "
                 "out-of-place operations");
  host_goldschmidt_division<uint64_t>(
      CudaStreams(streams), quotient, remainder, numerator, denominator,
      (int_goldschmidt_division_buffer<uint64_t> *)mem_ptr, iterations, bsks,
      (uint64_t **)(ksks));
}

void cleanup_cuda_goldschmidt_division_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup goldschmidt division")
  int_goldschmidt_division_buffer<uint64_t> *mem_ptr =
      (int_goldschmidt_division_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
