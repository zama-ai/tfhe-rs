#include "../../include/kreyvium/kreyvium.h"
#include "kreyvium.cuh"

void cuda_kreyvium_init_async(CudaStreamsFFI streams,
                              CudaRadixCiphertextFFI const *a_reg_ffi,
                              CudaRadixCiphertextFFI const *b_reg_ffi,
                              CudaRadixCiphertextFFI const *c_reg_ffi,
                              CudaRadixCiphertextFFI const *k_reg_ffi,
                              CudaRadixCiphertextFFI const *iv_reg_ffi,
                              uint32_t *k_offset, uint32_t *iv_offset,
                              const CudaRadixCiphertextFFI *key_ffi,
                              const CudaRadixCiphertextFFI *iv_in_ffi,
                              uint32_t num_inputs, int8_t *mem_ptr,
                              void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext a_reg_local(*a_reg_ffi);
  const CudaRadixCiphertext *a_reg = &a_reg_local;
  CudaRadixCiphertext b_reg_local(*b_reg_ffi);
  const CudaRadixCiphertext *b_reg = &b_reg_local;
  CudaRadixCiphertext c_reg_local(*c_reg_ffi);
  const CudaRadixCiphertext *c_reg = &c_reg_local;
  CudaRadixCiphertext k_reg_local(*k_reg_ffi);
  const CudaRadixCiphertext *k_reg = &k_reg_local;
  CudaRadixCiphertext iv_reg_local(*iv_reg_ffi);
  const CudaRadixCiphertext *iv_reg = &iv_reg_local;
  const CudaRadixCiphertext key_local(*key_ffi);
  const CudaRadixCiphertext *key = &key_local;
  const CudaRadixCiphertext iv_in_local(*iv_in_ffi);
  const CudaRadixCiphertext *iv_in = &iv_in_local;

  auto buffer = (int_kreyvium_buffer<uint64_t> *)mem_ptr;
  host_kreyvium_init<uint64_t>(CudaStreams(streams), buffer, a_reg, b_reg,
                               c_reg, k_reg, iv_reg, k_offset, iv_offset, key,
                               iv_in, bsks, (uint64_t *const *)ksks);
}

void cuda_kreyvium_step_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI const *keystream_output_ffi,
    CudaRadixCiphertextFFI const *a_reg_ffi,
    CudaRadixCiphertextFFI const *b_reg_ffi,
    CudaRadixCiphertextFFI const *c_reg_ffi,
    CudaRadixCiphertextFFI const *k_reg_ffi,
    CudaRadixCiphertextFFI const *iv_reg_ffi, uint32_t *k_offset,
    uint32_t *iv_offset, uint32_t num_inputs, uint32_t num_steps,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext keystream_output_local(*keystream_output_ffi);
  const CudaRadixCiphertext *keystream_output = &keystream_output_local;
  CudaRadixCiphertext a_reg_local(*a_reg_ffi);
  const CudaRadixCiphertext *a_reg = &a_reg_local;
  CudaRadixCiphertext b_reg_local(*b_reg_ffi);
  const CudaRadixCiphertext *b_reg = &b_reg_local;
  CudaRadixCiphertext c_reg_local(*c_reg_ffi);
  const CudaRadixCiphertext *c_reg = &c_reg_local;
  CudaRadixCiphertext k_reg_local(*k_reg_ffi);
  const CudaRadixCiphertext *k_reg = &k_reg_local;
  CudaRadixCiphertext iv_reg_local(*iv_reg_ffi);
  const CudaRadixCiphertext *iv_reg = &iv_reg_local;

  auto buffer = (int_kreyvium_buffer<uint64_t> *)mem_ptr;
  host_kreyvium_step<uint64_t>(CudaStreams(streams), keystream_output, a_reg,
                               b_reg, c_reg, k_reg, iv_reg, k_offset, iv_offset,
                               num_inputs, num_steps, buffer, bsks,
                               (uint64_t *const *)ksks);
}

uint64_t scratch_cuda_kreyvium_init_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  return scratch_cuda_kreyvium_encrypt<uint64_t>(
      CudaStreams(streams), (int_kreyvium_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_kreyvium_init(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  int_kreyvium_buffer<uint64_t> *mem_ptr =
      (int_kreyvium_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_kreyvium_step_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);
  return scratch_cuda_kreyvium_encrypt<uint64_t>(
      CudaStreams(streams), (int_kreyvium_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_kreyvium_step(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  int_kreyvium_buffer<uint64_t> *mem_ptr =
      (int_kreyvium_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
