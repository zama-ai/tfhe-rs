#include "integer/cmux.cuh"

uint64_t scratch_cuda_cmux_64_async(CudaStreamsFFI streams, int8_t **mem_ptr,
                                    CudaLweBootstrapKeyParamsFFI bsk_params,
                                    CudaLweKeyswitchKeyParamsFFI ksk_params,
                                    uint32_t lwe_ciphertext_count,
                                    uint32_t message_modulus,
                                    uint32_t carry_modulus,
                                    bool allocate_gpu_memory,
                                    PBS_MS_REDUCTION_T noise_reduction_type) {
  PUSH_RANGE("scratch cmux")
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  std::function<uint64_t(uint64_t)> predicate_lut_f =
      [](uint64_t x) -> uint64_t { return x == 1; };

  uint64_t ret = scratch_cuda_cmux<uint64_t>(
      CudaStreams(streams), (int_cmux_buffer<uint64_t> **)mem_ptr,
      predicate_lut_f, lwe_ciphertext_count, params, allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

void cuda_cmux_64_async(CudaStreamsFFI streams,
                        CudaRadixCiphertextFFI const *lwe_array_out_ffi,
                        CudaRadixCiphertextFFI const *lwe_condition_ffi,
                        CudaRadixCiphertextFFI const *lwe_array_true_ffi,
                        CudaRadixCiphertextFFI const *lwe_array_false_ffi,
                        int8_t *mem_ptr, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext lwe_array_out_local(*lwe_array_out_ffi);
  const CudaRadixCiphertext *lwe_array_out = &lwe_array_out_local;
  const CudaRadixCiphertext lwe_condition_local(*lwe_condition_ffi);
  const CudaRadixCiphertext *lwe_condition = &lwe_condition_local;
  const CudaRadixCiphertext lwe_array_true_local(*lwe_array_true_ffi);
  const CudaRadixCiphertext *lwe_array_true = &lwe_array_true_local;
  const CudaRadixCiphertext lwe_array_false_local(*lwe_array_false_ffi);
  const CudaRadixCiphertext *lwe_array_false = &lwe_array_false_local;

  PANIC_IF_FALSE(
      lwe_array_out_ffi != lwe_condition_ffi,
      "Output and condition pointers must be different for out-of-place "
      "operations");
  PANIC_IF_FALSE(
      lwe_array_out_ffi != lwe_array_true_ffi,
      "Output and true-branch pointers must be different for out-of-place "
      "operations");
  PANIC_IF_FALSE(
      lwe_array_out_ffi != lwe_array_false_ffi,
      "Output and false-branch pointers must be different for out-of-place "
      "operations");
  PUSH_RANGE("cmux")
  host_cmux<uint64_t>(CudaStreams(streams), lwe_array_out, lwe_condition,
                      lwe_array_true, lwe_array_false,
                      (int_cmux_buffer<uint64_t> *)mem_ptr, bsks,
                      (uint64_t **)(ksks));
  POP_RANGE()
}

void cleanup_cuda_cmux_64(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup cmux")
  int_cmux_buffer<uint64_t> *mem_ptr =
      (int_cmux_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
