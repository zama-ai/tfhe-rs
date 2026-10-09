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

/// @brief Turns a PRINCEv2 key pair into the material the circuit reads, once
/// per pair and direction. Any number of cuda_integer_prince_64_async calls
/// can then reuse it.
///
/// Done once so the rounds can just add the key inside their parity PBS.
/// Outputs have no batch dimension, the circuit tiles them. Asynchronous.
///
/// @param key_bits_first Output, the 64 bits of k_first
/// @param key_bits_second Output, the 64 bits of k_second
/// @param kap_bw_first Output, M'(SR^-1(k_first)) as 64 bits, the key as the
/// backward rounds see it
/// @param kap_bw_second Output, same for k_second
/// @param k_first k0 to encrypt, k1 to decrypt. 32 fresh blocks of 2 bits,
/// MSB first
/// @param k_second k1 to encrypt, k0 to decrypt, same layout
/// @param mem_ptr From scratch_cuda_integer_prince_key_prep_64_async
void cuda_integer_prince_key_prep_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *key_bits_first,
    CudaRadixCiphertextFFI *key_bits_second,
    CudaRadixCiphertextFFI *kap_bw_first, CudaRadixCiphertextFFI *kap_bw_second,
    CudaRadixCiphertextFFI const *k_first,
    CudaRadixCiphertextFFI const *k_second, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  auto *mem = (int_prince_key_prep_buffer<uint64_t> *)mem_ptr;
  host_integer_prince_key_prep<uint64_t>(
      CudaStreams(streams), key_bits_first, key_bits_second, kap_bw_first,
      kap_bw_second, k_first, k_second, mem, bsks, (uint64_t **)ksks);
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

/// @brief Runs PRINCEv2 [BEK+20] on a batch of 64-bit blocks under an
/// encrypted key, 26 PBS layers whatever the batch size. The direction comes
/// from the scratch and the key order used at key prep. Asynchronous.
///
/// Inputs must be fresh, the first key xor packs 4 * m + k in one block and
/// eats the whole 2_2 noise budget.
///
/// @param output num_prince_inputs blocks of 64 bits, each as 32 blocks of 2
/// bits MSB first, one input after the other
/// @param input Same layout, fresh
/// @param k_first Same key half as given to key prep, 32 blocks
/// @param k_second Same, 32 blocks
/// @param key_bits_first From cuda_integer_prince_key_prep_64_async
/// @param key_bits_second From cuda_integer_prince_key_prep_64_async
/// @param kap_bw_first From cuda_integer_prince_key_prep_64_async
/// @param kap_bw_second From cuda_integer_prince_key_prep_64_async
/// @param mem_ptr From scratch_cuda_integer_prince_64_async, same batch size
/// and direction
void cuda_integer_prince_64_async(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *output,
                                  CudaRadixCiphertextFFI const *input,
                                  CudaRadixCiphertextFFI const *k_first,
                                  CudaRadixCiphertextFFI const *k_second,
                                  CudaRadixCiphertextFFI const *key_bits_first,
                                  CudaRadixCiphertextFFI const *key_bits_second,
                                  CudaRadixCiphertextFFI const *kap_bw_first,
                                  CudaRadixCiphertextFFI const *kap_bw_second,
                                  int8_t *mem_ptr, void *const *bsks,
                                  void *const *ksks) {

  auto *mem = (int_prince_buffer<uint64_t> *)mem_ptr;
  host_integer_prince<uint64_t>(CudaStreams(streams), output, input, k_first,
                                k_second, key_bits_first, key_bits_second,
                                kap_bw_first, kap_bw_second, mem, bsks,
                                (uint64_t **)ksks);
}

void cleanup_cuda_integer_prince_64(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void) {

  auto *mem = (int_prince_buffer<uint64_t> *)(*mem_ptr_void);
  mem->release(CudaStreams(streams));
  delete mem;
  *mem_ptr_void = nullptr;
}
