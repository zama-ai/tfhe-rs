#include "integer/abs.cuh"

uint64_t scratch_cuda_integer_abs_inplace_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, bool is_signed,
    CudaLweBootstrapKeyParamsFFI bsk_params, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ks_level, ks_base_log, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_abs<uint64_t>(
      CudaStreams(streams), (int_abs_buffer<uint64_t> **)mem_ptr, is_signed,
      num_blocks, params, allocate_gpu_memory);
}

void cuda_integer_abs_inplace_64_async(CudaStreamsFFI streams,
                                       CudaRadixCiphertextFFI *ct,
                                       int8_t *mem_ptr, bool is_signed,
                                       void *const *bsks, void *const *ksks) {

  auto mem = (int_abs_buffer<uint64_t> *)mem_ptr;

  host_integer_abs<uint64_t>(CudaStreams(streams), ct, bsks,
                             (uint64_t **)(ksks), mem, is_signed);
}

void cleanup_cuda_integer_abs_inplace_64(CudaStreamsFFI streams,
                                         int8_t **mem_ptr_void) {
  int_abs_buffer<uint64_t> *mem_ptr =
      (int_abs_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
