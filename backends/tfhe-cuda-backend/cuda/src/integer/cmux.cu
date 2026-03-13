#include "integer/cmux.cuh"

uint64_t scratch_cuda_cmux_64_async(CudaStreamsFFI streams, int8_t **mem_ptr,
                                    CudaLweBootstrapKeyParamsFFI bsk_params,
                                    uint32_t ks_level, uint32_t ks_base_log,
                                    uint32_t lwe_ciphertext_count,
                                    uint32_t message_modulus,
                                    uint32_t carry_modulus,
                                    bool allocate_gpu_memory,
                                    PBS_MS_REDUCTION_T noise_reduction_type) {
  PUSH_RANGE("scratch cmux")
  int_radix_params params(bsk_params, ks_level, ks_base_log, message_modulus,
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
                        CudaRadixCiphertextFFI *lwe_array_out,
                        CudaRadixCiphertextFFI const *lwe_condition,
                        CudaRadixCiphertextFFI const *lwe_array_true,
                        CudaRadixCiphertextFFI const *lwe_array_false,
                        int8_t *mem_ptr, void *const *bsks, void *const *ksks) {
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
