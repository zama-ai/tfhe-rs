#include "../../include/trivium/trivium.h"
#include "trivium.cuh"

void cuda_trivium_init_async(CudaStreamsFFI streams,
                             CudaRadixCiphertextFFI *a_reg,
                             CudaRadixCiphertextFFI *b_reg,
                             CudaRadixCiphertextFFI *c_reg,
                             const CudaRadixCiphertextFFI *key,
                             const CudaRadixCiphertextFFI *iv,
                             uint32_t num_inputs, int8_t *mem_ptr,
                             void *const *bsks, void *const *ksks) {

  auto buffer = (int_trivium_buffer<uint64_t> *)mem_ptr;
  host_trivium_init<uint64_t>(CudaStreams(streams), buffer, a_reg, b_reg, c_reg,
                              key, iv, bsks, (uint64_t *const *)ksks);
}

void cuda_trivium_step_async(CudaStreamsFFI streams,
                             CudaRadixCiphertextFFI *keystream_output,
                             CudaRadixCiphertextFFI *a_reg,
                             CudaRadixCiphertextFFI *b_reg,
                             CudaRadixCiphertextFFI *c_reg, uint32_t num_inputs,
                             uint32_t num_steps, int8_t *mem_ptr,
                             void *const *bsks, void *const *ksks) {

  auto buffer = (int_trivium_buffer<uint64_t> *)mem_ptr;
  host_trivium_step<uint64_t>(CudaStreams(streams), keystream_output, a_reg,
                              b_reg, c_reg, num_steps, buffer, bsks,
                              (uint64_t *const *)ksks);
}

uint64_t scratch_cuda_trivium_init_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_trivium_encrypt<uint64_t>(
      CudaStreams(streams), (int_trivium_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_trivium_init(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  int_trivium_buffer<uint64_t> *mem_ptr =
      (int_trivium_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_trivium_step_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_trivium_encrypt<uint64_t>(
      CudaStreams(streams), (int_trivium_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_trivium_step(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  int_trivium_buffer<uint64_t> *mem_ptr =
      (int_trivium_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
