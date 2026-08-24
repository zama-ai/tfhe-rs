#include "../../include/aes/aes.h"
#include "aes.cuh"

/// @brief Allocates the scratch of cuda_integer_aes_ctr_encrypt_64_async and
/// returns its GPU footprint in bytes, so the caller can lower
/// sbox_parallelism until it fits.
///
/// @param mem_ptr Receives the scratch.
/// @param bsk_params Bootstrapping key parameters.
/// @param ksk_params Keyswitching key parameters.
/// @param noise_reduction_type Modulus switch noise reduction to apply.
/// @param num_aes_inputs Number of 128-bit blocks every later call encrypts.
/// @param sbox_parallelism State bytes one S-box pass handles at once, a
/// divisor of 16. Bootstrap width and memory both scale with it.
uint64_t scratch_cuda_integer_aes_ctr_encrypt_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_aes_encrypt<uint64_t>(
      CudaStreams(streams), (int_aes_encrypt_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism);
}

/// @brief Allocates the scratch of cuda_integer_aes_ctr_256_encrypt_64_async
/// and returns its GPU footprint in bytes. Same layout as the AES-128 one:
/// the round count is the only difference between the two ciphers.
///
/// @param mem_ptr Receives the scratch.
/// @param bsk_params Bootstrapping key parameters.
/// @param ksk_params Keyswitching key parameters.
/// @param noise_reduction_type Modulus switch noise reduction to apply.
/// @param num_aes_inputs Number of 128-bit blocks every later call encrypts.
/// @param sbox_parallelism State bytes one S-box pass handles at once, a
/// divisor of 16. Bootstrap width and memory both scale with it.
uint64_t scratch_cuda_integer_aes_ctr_256_encrypt_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_aes_encrypt<uint64_t>(
      CudaStreams(streams), (int_aes_encrypt_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism);
}

/// @brief AES-128 in CTR mode under an encrypted key: adds each input's
/// counter to the IV, runs the 10 rounds on the sums and returns the
/// keystream blocks. Asynchronous.
///
/// @param output num_aes_inputs blocks of 128 bits, one bit per radix block,
/// most significant bit of state byte 0 first, input after input.
/// @param iv 128 blocks of one bit, same bit order: the nonce every input
/// starts from before its counter is added.
/// @param round_keys 11 round keys of 128 blocks, one bit each, as
/// cuda_integer_key_expansion_64_async writes them.
/// @param counter_bits_le_all_blocks Host side, num_aes_inputs * 128
/// plaintext bits, one per entry: the counter added to the IV for each input,
/// least significant bit first, input after input.
/// @param num_aes_inputs Number of blocks, the batch size the scratch was
/// allocated for.
/// @param mem_ptr Scratch allocated by
/// scratch_cuda_integer_aes_ctr_encrypt_64_async for the same batch size.
void cuda_integer_aes_ctr_encrypt_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const uint64_t *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks) {

  host_integer_aes_ctr_encrypt<uint64_t>(
      CudaStreams(streams), output, iv, round_keys, counter_bits_le_all_blocks,
      num_aes_inputs, (int_aes_encrypt_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks);
}

/// @brief Releases the scratch of cuda_integer_aes_ctr_encrypt_64_async.
///
/// @param mem_ptr_void Scratch to release, set to nullptr on return.
void cleanup_cuda_integer_aes_ctr_encrypt_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void) {

  int_aes_encrypt_buffer<uint64_t> *mem_ptr =
      (int_aes_encrypt_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

/// @brief Releases the scratch of cuda_integer_aes_ctr_256_encrypt_64_async.
///
/// @param mem_ptr_void Scratch to release, set to nullptr on return.
void cleanup_cuda_integer_aes_ctr_256_encrypt_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void) {

  int_aes_encrypt_buffer<uint64_t> *mem_ptr =
      (int_aes_encrypt_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

/// @brief Allocates the scratch of cuda_integer_key_expansion_64_async and
/// returns its GPU footprint in bytes.
///
/// @param mem_ptr Receives the scratch.
/// @param bsk_params Bootstrapping key parameters.
/// @param ksk_params Keyswitching key parameters.
/// @param noise_reduction_type Modulus switch noise reduction to apply.
uint64_t scratch_cuda_integer_key_expansion_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_key_expansion<uint64_t>(
      CudaStreams(streams), (int_key_expansion_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory);
}

/// @brief Expands an encrypted 128-bit key into the 11 round keys of
/// AES-128. Asynchronous.
///
/// @param expanded_keys Output, 44 words of 32 bits as 1408 blocks of one
/// bit, most significant bit first: round key r sits at blocks
/// [128 r, 128 (r + 1)).
/// @param key 128 blocks of one bit, most significant bit first.
/// @param mem_ptr Scratch allocated by
/// scratch_cuda_integer_key_expansion_64_async.
void cuda_integer_key_expansion_64_async(CudaStreamsFFI streams,
                                         CudaRadixCiphertextFFI *expanded_keys,
                                         CudaRadixCiphertextFFI const *key,
                                         int8_t *mem_ptr, void *const *bsks,
                                         void *const *ksks) {

  host_integer_key_expansion<uint64_t>(
      CudaStreams(streams), expanded_keys, key,
      (int_key_expansion_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks);
}

/// @brief Releases the scratch of cuda_integer_key_expansion_64_async.
///
/// @param mem_ptr_void Scratch to release, set to nullptr on return.
void cleanup_cuda_integer_key_expansion_64(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void) {
  int_key_expansion_buffer<uint64_t> *mem_ptr =
      (int_key_expansion_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
