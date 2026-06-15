#ifndef CUDA_INTEGER_KV_STORE_H
#define CUDA_INTEGER_KV_STORE_H

#include "../../pbs/pbs_enums.h"
#include "../integer.h"

extern "C" {

/// @brief Allocates the scratch buffer for kv_store get.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
/// buffer
/// @param bsk_params         Bootstrap key parameters (PBS type, dimensions,
/// decomposition)
/// @param ksk_params         Keyswitch key parameters (dimensions,
/// decomposition)
/// @param num_entries        Number of stored key-value pairs
/// @param num_key_blocks     Number of radix blocks per key
/// @param num_value_blocks   Number of radix blocks per value
/// @param noise_reduction_type  Noise reduction strategy for PBS
uint64_t scratch_cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

/// @brief Retrieves the encrypted value for a key from an encrypted kv_store.
///
/// Compares the encrypted key against all stored clear keys and extracts
/// the matching value. Does not leak which key was accessed.
///
/// @param lwe_array_out_result       Output ciphertext receiving the looked-up
/// value
/// @param lwe_array_out_boolean      Output single-block ciphertext: 1 if key
/// found, 0 otherwise
/// @param lwe_array_out_selectors    Output per-entry boolean selectors (one
/// block per entry; encrypts 1 if the entry corresponds to the looked-up key)
/// @param lwe_array_in_encrypted_key Input encrypted key to look up
/// @param lwe_array_in_values        Input flat array of all stored encrypted
/// values
/// @param h_decomposed_clear_keys    Host-side clear keys decomposed into radix
/// blocks
/// @param mem                        Scratch buffer from
/// scratch_cuda_kv_store_get_64_async
/// @param ksks                       Key-switching keys (one per GPU)
void cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_result,
    CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI *lwe_array_out_selectors,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem, void *const *bsks,
    void *const *ksks);

/// @brief Releases the scratch buffer allocated by
/// scratch_cuda_kv_store_get_64_async.
///
/// @param mem_ptr_void  Pointer to the scratch buffer pointer (set to nullptr
/// on return)
void cleanup_cuda_kv_store_get_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void);

/// @brief Allocates the scratch buffer for kv_store update.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
/// buffer
/// @param bsk_params         Bootstrap key parameters (PBS type, dimensions,
/// decomposition)
/// @param ksk_params         Keyswitch key parameters (dimensions,
/// decomposition)
/// @param num_entries        Number of stored key-value pairs
/// @param num_key_blocks     Number of radix blocks per key
/// @param num_value_blocks   Number of radix blocks per value
/// @param noise_reduction_type  Noise reduction strategy for PBS
uint64_t scratch_cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

/// @brief Updates the encrypted value for a key in an encrypted kv_store.
///
/// For each entry, if the stored clear key matches the encrypted query key,
/// the old value is replaced with lwe_in_new_value; otherwise kept unchanged.
///
/// @param lwe_check_out_block          Output single-block ciphertext: 1 if key
/// found, 0 otherwise
/// @param lwe_array_out_values         Output flat array of all stored
/// encrypted values (updated)
/// @param lwe_array_in_encrypted_key   Input encrypted key to match
/// @param lwe_array_in_values          Input flat array of current stored
/// encrypted values
/// @param lwe_in_new_value             Input encrypted replacement value
/// @param h_decomposed_clear_keys      Host-side clear keys decomposed into
/// radix blocks
/// @param mem_ptr                      Scratch buffer from
/// scratch_cuda_kv_store_update_64_async
/// @param ksks                         Key-switching keys (one per GPU)
void cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block,
    CudaRadixCiphertextFFI *lwe_array_out_values,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    CudaRadixCiphertextFFI const *lwe_in_new_value,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

/// @brief Releases the scratch buffer allocated by
/// scratch_cuda_kv_store_update_64_async.
///
/// @param mem_ptr_void  Pointer to the scratch buffer pointer (set to nullptr
/// on return)
void cleanup_cuda_kv_store_update_64(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void);

/// @brief Allocates the scratch buffer for kv_store map.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
/// buffer
/// @param bsk_params         Bootstrap key parameters (PBS type, dimensions,
/// decomposition)
/// @param ksk_params         Keyswitch key parameters (dimensions,
/// decomposition)
/// @param num_entries        Number of stored key-value pairs
/// @param num_value_blocks   Number of radix blocks per value
/// @param noise_reduction_type  Noise reduction strategy for PBS
uint64_t scratch_cuda_kv_store_map_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_value_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

/// @brief Applies a conditional update to all entries using pre-computed
/// selectors.
///
/// For each entry, if the corresponding selector is 1, the old encrypted
/// value is replaced with lwe_in_new_value; otherwise the old value is kept.
///
/// @param lwe_check_out_block       Output single-block ciphertext: 1 if at
/// least one selector was true
/// @param lwe_array_out_values      Output flat array of all stored encrypted
/// values (updated)
/// @param lwe_array_in_values       Input flat array of current stored
/// encrypted values
/// @param lwe_in_new_value          Input encrypted replacement value
/// @param lwe_array_in_selectors    Input per-entry boolean selectors (1 =
/// entry must be replaced, 0 = entry should be kept)
/// @param mem_ptr                   Scratch buffer from
/// scratch_cuda_kv_store_map_64_async
/// @param ksks                      Key-switching keys (one per GPU)
void cuda_kv_store_map_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block,
    CudaRadixCiphertextFFI *lwe_array_out_values,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    CudaRadixCiphertextFFI const *lwe_in_new_value,
    CudaRadixCiphertextFFI const *lwe_array_in_selectors, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks);

/// @brief Releases the scratch buffer allocated by
/// scratch_cuda_kv_store_map_64_async.
///
/// @param mem_ptr_void  Pointer to the scratch buffer pointer (set to nullptr
/// on return)
void cleanup_cuda_kv_store_map_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void);

/// @brief Allocates the scratch buffer for kv_store contains_key.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
/// buffer
/// @param bsk_params         Bootstrap key parameters (PBS type, dimensions,
/// decomposition)
/// @param ksk_params         Keyswitch key parameters (dimensions,
/// decomposition)
/// @param num_entries        Number of stored keys
/// @param num_key_blocks     Number of radix blocks per key
/// @param noise_reduction_type  Noise reduction strategy for PBS
uint64_t scratch_cuda_kv_store_contains_key_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_key_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

/// @brief Checks whether a clear key exists in the encrypted kv_store.
///
/// Compares the encrypted key against all stored clear keys and OR-reduces
/// the per-entry booleans into a single key-found flag.
///
/// @param lwe_array_out_boolean      Output single-block ciphertext: 1 if key
/// found, 0 otherwise
/// @param lwe_array_in_encrypted_key Input encrypted key to look up
/// @param h_decomposed_clear_keys    Host-side clear keys decomposed into radix
/// blocks
/// @param mem_ptr                    Scratch buffer from
/// scratch_cuda_kv_store_contains_key_64_async
/// @param ksks                       Key-switching keys (one per GPU)
void cuda_kv_store_contains_key_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

/// @brief Releases the scratch buffer allocated by
/// scratch_cuda_kv_store_contains_key_64_async.
///
/// @param mem_ptr_void  Pointer to the scratch buffer pointer (set to nullptr
/// on return)
void cleanup_cuda_kv_store_contains_key_64(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void);
}

#endif // CUDA_INTEGER_KV_STORE_H
