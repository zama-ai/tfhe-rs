#include "../../include/prince/prince.h"
#include "prince.cuh"

uint64_t scratch_cuda_integer_prince_key_prep_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_prince_key_prep<uint64_t>(
      CudaStreams(streams), (int_prince_key_prep_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory);
}

void cuda_integer_prince_key_prep_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *key_bits_first,
    CudaRadixCiphertextFFI *key_bits_second,
    CudaRadixCiphertextFFI *kap_bw_first, CudaRadixCiphertextFFI *kap_bw_second,
    CudaRadixCiphertextFFI *kap_mid_first, CudaRadixCiphertextFFI const *k0,
    CudaRadixCiphertextFFI const *k1, bool is_decrypt, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks) {

  auto *mem = (int_prince_key_prep_buffer<uint64_t> *)mem_ptr;
  host_integer_prince_key_prep<uint64_t>(
      CudaStreams(streams), key_bits_first, key_bits_second, kap_bw_first,
      kap_bw_second, kap_mid_first, k0, k1, is_decrypt, mem, bsks,
      (uint64_t **)ksks);
}

void cleanup_cuda_integer_prince_key_prep_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void) {

  auto *mem = (int_prince_key_prep_buffer<uint64_t> *)(*mem_ptr_void);
  mem->release(CudaStreams(streams));
  delete mem;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_prince_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_prince_inputs,
    bool is_decrypt) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_prince<uint64_t>(
      CudaStreams(streams), (int_prince_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_prince_inputs, is_decrypt);
}

void cuda_integer_prince_64_async(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *output,
                                  CudaRadixCiphertextFFI const *input,
                                  CudaRadixCiphertextFFI const *k0,
                                  CudaRadixCiphertextFFI const *k1,
                                  CudaRadixCiphertextFFI const *key_bits_first,
                                  CudaRadixCiphertextFFI const *key_bits_second,
                                  CudaRadixCiphertextFFI const *kap_bw_first,
                                  CudaRadixCiphertextFFI const *kap_bw_second,
                                  CudaRadixCiphertextFFI const *kap_mid_first,
                                  uint32_t num_prince_inputs, int8_t *mem_ptr,
                                  void *const *bsks, void *const *ksks) {

  auto *mem = (int_prince_buffer<uint64_t> *)mem_ptr;
  PANIC_IF_FALSE(mem->num_inputs == num_prince_inputs,
                 "PRINCE scratch was created for a different number of inputs");

  host_integer_prince<uint64_t>(CudaStreams(streams), output, input, k0, k1,
                                key_bits_first, key_bits_second, kap_bw_first,
                                kap_bw_second, kap_mid_first, mem, bsks,
                                (uint64_t **)ksks);
}

void cleanup_cuda_integer_prince_64(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void) {

  auto *mem = (int_prince_buffer<uint64_t> *)(*mem_ptr_void);
  mem->release(CudaStreams(streams));
  delete mem;
  *mem_ptr_void = nullptr;
}
