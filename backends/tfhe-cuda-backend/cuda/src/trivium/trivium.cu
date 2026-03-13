#include "../../include/trivium/trivium.h"
#include "trivium.cuh"

uint64_t scratch_cuda_trivium_generate_keystream_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type,
    uint32_t num_inputs) {

  int_radix_params params(bsk_params, ks_level, ks_base_log, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_trivium_encrypt<uint64_t>(
      CudaStreams(streams), (int_trivium_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_inputs);
}

void cuda_trivium_generate_keystream_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *keystream_output,
    const CudaRadixCiphertextFFI *key, const CudaRadixCiphertextFFI *iv,
    uint32_t num_inputs, uint32_t num_steps, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  auto buffer = (int_trivium_buffer<uint64_t> *)mem_ptr;

  host_trivium_generate_keystream<uint64_t>(
      CudaStreams(streams), keystream_output, key, iv, num_inputs, num_steps,
      buffer, bsks, (uint64_t *const *)ksks);
}

void cleanup_cuda_trivium_generate_keystream_64(CudaStreamsFFI streams,
                                                int8_t **mem_ptr_void) {

  int_trivium_buffer<uint64_t> *mem_ptr =
      (int_trivium_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
