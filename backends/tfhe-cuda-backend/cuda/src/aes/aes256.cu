#include "../../include/aes/aes.h"
#include "aes256.cuh"

/// @brief AES-256 CTR under an encrypted key, the AES-128 pipeline with 14
/// rounds. Asynchronous.
///
/// @param output num_aes_inputs blocks of 128 bits, one bit per radix block,
/// MSB of state byte 0 first, one input after the other
/// @param iv 128 one bit blocks, same order, shared by every input before its
/// counter is added
/// @param round_keys 15 round keys of 128 one bit blocks, as
/// cuda_integer_key_expansion_256_64_async writes them
/// @param counter_bits_le_all_blocks Plaintext on the host, the counter of
/// each input as 128 bits, LSB first, one input after the other
/// @param num_aes_inputs Batch size, same as at scratch time
/// @param mem_ptr From scratch_cuda_integer_aes_ctr_256_encrypt_64_async,
/// same batch size
void cuda_integer_aes_ctr_256_encrypt_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const uint64_t *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks) {

  host_integer_aes_ctr_256_encrypt<uint64_t>(
      CudaStreams(streams), output, iv, round_keys, counter_bits_le_all_blocks,
      num_aes_inputs, (int_aes_encrypt_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks);
}

/// @brief Allocates the scratch of cuda_integer_key_expansion_256_64_async
/// and returns its GPU size.
///
/// @param mem_ptr Receives the scratch
/// @param bsk_params Bootstrapping key parameters
/// @param ksk_params Keyswitching key parameters
/// @param noise_reduction_type Modulus switch noise reduction
uint64_t scratch_cuda_integer_key_expansion_256_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_key_expansion_256<uint64_t>(
      CudaStreams(streams), (int_key_expansion_256_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory);
}

/// @brief Expands an encrypted 256-bit key into the 15 round keys of
/// AES-256. Asynchronous.
///
/// @param expanded_keys Output, 60 words as 1920 one bit blocks MSB first,
/// round key r at blocks [128 r, 128 (r + 1))
/// @param key 256 one bit blocks, MSB first
/// @param mem_ptr From scratch_cuda_integer_key_expansion_256_64_async
void cuda_integer_key_expansion_256_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  host_integer_key_expansion_256<uint64_t>(
      CudaStreams(streams), expanded_keys, key,
      (int_key_expansion_256_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks);
}

/// @brief Releases the scratch of cuda_integer_key_expansion_256_64_async.
///
/// @param mem_ptr_void Scratch to release, nullptr afterwards
void cleanup_cuda_integer_key_expansion_256_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void) {
  int_key_expansion_256_buffer<uint64_t> *mem_ptr =
      (int_key_expansion_256_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
