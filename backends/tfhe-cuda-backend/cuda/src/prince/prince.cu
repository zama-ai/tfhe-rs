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

/// @brief C entry of host_integer_prince_key_prep, contract in prince.h.
///
/// @param key_bits_first Output, k_first as 64 bits.
/// @param key_bits_second Output, k_second as 64 bits.
/// @param kap_bw_first Output, M'(SR^-1(k_first)) as 64 bits.
/// @param kap_bw_second Output, same for k_second.
/// @param kap_mid_first Output, M'(k_first) as 64 bits.
/// @param k_first First key half in circuit order, 32 blocks.
/// @param k_second Second key half in circuit order, 32 blocks.
/// @param mem_ptr Scratch from scratch_cuda_integer_prince_key_prep_64_async.
void cuda_integer_prince_key_prep_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *key_bits_first,
    CudaRadixCiphertextFFI *key_bits_second,
    CudaRadixCiphertextFFI *kap_bw_first, CudaRadixCiphertextFFI *kap_bw_second,
    CudaRadixCiphertextFFI *kap_mid_first,
    CudaRadixCiphertextFFI const *k_first,
    CudaRadixCiphertextFFI const *k_second, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  auto *mem = (int_prince_key_prep_buffer<uint64_t> *)mem_ptr;
  host_integer_prince_key_prep<uint64_t>(
      CudaStreams(streams), key_bits_first, key_bits_second, kap_bw_first,
      kap_bw_second, kap_mid_first, k_first, k_second, mem, bsks,
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

/// @brief C entry of host_integer_prince, contract in prince.h.
///
/// @param output 32 blocks of 2 bits per input, instance-major.
/// @param input Same layout as output, fresh encryptions.
/// @param k_first First key half in circuit order, 32 blocks.
/// @param k_second Second key half in circuit order, 32 blocks.
/// @param key_bits_first From cuda_integer_prince_key_prep_64_async.
/// @param key_bits_second From cuda_integer_prince_key_prep_64_async.
/// @param kap_bw_first From cuda_integer_prince_key_prep_64_async.
/// @param kap_bw_second From cuda_integer_prince_key_prep_64_async.
/// @param kap_mid_first From cuda_integer_prince_key_prep_64_async.
/// @param mem_ptr Scratch from scratch_cuda_integer_prince_64_async, same
/// batch size and direction.
void cuda_integer_prince_64_async(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *output,
                                  CudaRadixCiphertextFFI const *input,
                                  CudaRadixCiphertextFFI const *k_first,
                                  CudaRadixCiphertextFFI const *k_second,
                                  CudaRadixCiphertextFFI const *key_bits_first,
                                  CudaRadixCiphertextFFI const *key_bits_second,
                                  CudaRadixCiphertextFFI const *kap_bw_first,
                                  CudaRadixCiphertextFFI const *kap_bw_second,
                                  CudaRadixCiphertextFFI const *kap_mid_first,
                                  int8_t *mem_ptr, void *const *bsks,
                                  void *const *ksks) {

  auto *mem = (int_prince_buffer<uint64_t> *)mem_ptr;
  host_integer_prince<uint64_t>(CudaStreams(streams), output, input, k_first,
                                k_second, key_bits_first, key_bits_second,
                                kap_bw_first, kap_bw_second, kap_mid_first, mem,
                                bsks, (uint64_t **)ksks);
}

void cleanup_cuda_integer_prince_64(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void) {

  auto *mem = (int_prince_buffer<uint64_t> *)(*mem_ptr_void);
  mem->release(CudaStreams(streams));
  delete mem;
  *mem_ptr_void = nullptr;
}
