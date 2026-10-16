#ifndef AES_H
#define AES_H
#include "../integer/integer.h"

extern "C" {
/// @brief Allocates the scratch of cuda_integer_aes_ctr_encrypt_64_async and
/// returns its GPU size, so the caller can lower sbox_parallelism until it
/// fits.
///
/// @param mem_ptr Receives the scratch
/// @param bsk_params Bootstrapping key parameters
/// @param ksk_params Keyswitching key parameters
/// @param noise_reduction_type Modulus switch noise reduction
/// @param num_aes_inputs Blocks every later call encrypts
/// @param sbox_parallelism State bytes per S-box pass, divides 16. PBS width
/// and memory both scale with it
uint64_t scratch_cuda_integer_aes_ctr_encrypt_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism);

/// @brief Allocates the scratch of cuda_integer_aes_ctr_256_encrypt_64_async
/// and returns its GPU size. Same buffer as AES-128, only the round count
/// differs.
///
/// @param mem_ptr Receives the scratch
/// @param bsk_params Bootstrapping key parameters
/// @param ksk_params Keyswitching key parameters
/// @param noise_reduction_type Modulus switch noise reduction
/// @param num_aes_inputs Blocks every later call encrypts
/// @param sbox_parallelism State bytes per S-box pass, divides 16. PBS width
/// and memory both scale with it
uint64_t scratch_cuda_integer_aes_ctr_256_encrypt_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism);

/// @brief AES-128 CTR under an encrypted key, adds each input's counter to
/// the IV and runs the 10 rounds on it, giving the keystream. Asynchronous.
///
/// @param output num_aes_inputs blocks of 128 bits, one bit per radix block,
/// MSB of state byte 0 first, one input after the other
/// @param iv 128 one bit blocks, same order, shared by every input before its
/// counter is added
/// @param round_keys 11 round keys of 128 one bit blocks, as
/// cuda_integer_key_expansion_64_async writes them
/// @param counter_bits_le_all_blocks Plaintext on the host, the counter of
/// each input as 128 bits, LSB first, one input after the other
/// @param num_aes_inputs Batch size, same as at scratch time
/// @param mem_ptr From scratch_cuda_integer_aes_ctr_encrypt_64_async, same
/// batch size
void cuda_integer_aes_ctr_encrypt_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const uint64_t *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks);

/// @brief Releases the scratch of cuda_integer_aes_ctr_encrypt_64_async.
///
/// @param mem_ptr_void Scratch to release, nullptr afterwards
void cleanup_cuda_integer_aes_ctr_encrypt_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void);

/// @brief Releases the scratch of cuda_integer_aes_ctr_256_encrypt_64_async.
///
/// @param mem_ptr_void Scratch to release, nullptr afterwards
void cleanup_cuda_integer_aes_ctr_256_encrypt_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void);

/// @brief Allocates the scratch of cuda_integer_key_expansion_64_async and
/// returns its GPU size.
///
/// @param mem_ptr Receives the scratch
/// @param bsk_params Bootstrapping key parameters
/// @param ksk_params Keyswitching key parameters
/// @param noise_reduction_type Modulus switch noise reduction
uint64_t scratch_cuda_integer_key_expansion_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

/// @brief Expands an encrypted 128-bit key into the 11 round keys of
/// AES-128. Asynchronous.
///
/// @param expanded_keys Output, 44 words as 1408 one bit blocks MSB first,
/// round key r at blocks [128 r, 128 (r + 1))
/// @param key 128 one bit blocks, MSB first
/// @param mem_ptr From scratch_cuda_integer_key_expansion_64_async
void cuda_integer_key_expansion_64_async(CudaStreamsFFI streams,
                                         CudaRadixCiphertextFFI *expanded_keys,
                                         CudaRadixCiphertextFFI const *key,
                                         int8_t *mem_ptr, void *const *bsks,
                                         void *const *ksks);

/// @brief Releases the scratch of cuda_integer_key_expansion_64_async.
///
/// @param mem_ptr_void Scratch to release, nullptr afterwards
void cleanup_cuda_integer_key_expansion_64(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void);

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
    int8_t *mem_ptr, void *const *bsks, void *const *ksks);

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
    PBS_MS_REDUCTION_T noise_reduction_type);

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
    void *const *ksks);

/// @brief Releases the scratch of cuda_integer_key_expansion_256_64_async.
///
/// @param mem_ptr_void Scratch to release, nullptr afterwards
void cleanup_cuda_integer_key_expansion_256_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void);
}

#endif
