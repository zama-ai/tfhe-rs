#include "../../include/kreyvium/fast_kreyvium.h"
#include "fast_kreyvium.cuh"

void cuda_fast_kreyvium_init_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *a_reg,
    CudaRadixCiphertextFFI *b_reg, CudaRadixCiphertextFFI *c_reg,
    CudaRadixCiphertextFFI *k_reg, CudaRadixCiphertextFFI *iv_reg,
    uint32_t *k_offset, uint32_t *iv_offset, const CudaRadixCiphertextFFI *key,
    const CudaRadixCiphertextFFI *iv_in, uint32_t num_inputs, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks) {
  auto buffer = (int_fast_kreyvium_buffer<uint64_t> *)mem_ptr;
  host_fast_kreyvium_init<uint64_t>(CudaStreams(streams), buffer, a_reg, b_reg,
                                    c_reg, k_reg, iv_reg, k_offset, iv_offset,
                                    key, iv_in, bsks, (uint64_t *const *)ksks);
}

void cuda_fast_kreyvium_step_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *keystream_output,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    uint32_t num_inputs, uint32_t num_steps, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {
  auto buffer = (int_fast_kreyvium_buffer<uint64_t> *)mem_ptr;
  host_fast_kreyvium_step<uint64_t>(CudaStreams(streams), keystream_output,
                                    a_reg, b_reg, c_reg, k_reg, iv_reg,
                                    k_offset, iv_offset, num_inputs, num_steps,
                                    buffer, bsks, (uint64_t *const *)ksks);
}

uint64_t scratch_cuda_fast_kreyvium_init_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  return scratch_cuda_fast_kreyvium_encrypt<uint64_t>(
      CudaStreams(streams), (int_fast_kreyvium_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_fast_kreyvium_init(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void) {
  int_fast_kreyvium_buffer<uint64_t> *mem_ptr =
      (int_fast_kreyvium_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_fast_kreyvium_step_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  return scratch_cuda_fast_kreyvium_encrypt<uint64_t>(
      CudaStreams(streams), (int_fast_kreyvium_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_fast_kreyvium_step(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void) {
  int_fast_kreyvium_buffer<uint64_t> *mem_ptr =
      (int_fast_kreyvium_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
