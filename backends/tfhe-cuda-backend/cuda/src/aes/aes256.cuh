#pragma once

#include "../../include/aes/aes_utilities.h"
#include "aes.cuh"

/// @brief AES-256-CTR entry point: the AES-128 pipeline with 14 rounds.
/// Round function and counter addition are shared verbatim.
///
/// @param output num_aes_inputs blocks of AES_STATE_BITS bits, one per radix
/// block, most significant bit of state byte 0 first, input after input.
/// @param iv AES_STATE_BITS blocks of one bit, same bit order, shared by
/// every input.
/// @param round_keys 15 round keys of AES_STATE_BITS blocks, one bit each.
/// @param counter_bits_le_all_blocks Host side, AES_STATE_BITS *
/// num_aes_inputs bits, one per entry, least significant bit first, input
/// after input.
/// @param num_aes_inputs Blocks to encrypt, the batch size mem was
/// allocated for.
/// @param mem FULL_ENCRYPTION buffer for num_aes_inputs.
template <typename Torus, typename KSTorus>
__host__ void host_integer_aes_ctr_256_encrypt(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const Torus *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {

  constexpr uint32_t ROUNDS = 14;

  PANIC_IF_FALSE(mem->main_workspaces->has_full_encryption_buffers,
                 "AES CTR encryption requires a buffer allocated with the "
                 "FULL_ENCRYPTION scope, got a SBOX_ONLY one");

  CudaRadixCiphertextFFI *transposed_states =
      &mem->main_workspaces->main_bitsliced_states_buffer;

  host_radix_gather_sum<Torus>(streams, mem->params, transposed_states, iv,
                               mem->linear_tables->iv_broadcast);

  vectorized_aes_add_counter_inplace<Torus>(streams, transposed_states,
                                            counter_bits_le_all_blocks,
                                            num_aes_inputs, mem, bsks, ksks);

  vectorized_aes_rounds_inplace<Torus>(streams, transposed_states, round_keys,
                                       ROUNDS, num_aes_inputs, mem, bsks, ksks);

  host_radix_gather_sum<Torus>(streams, mem->params, output, transposed_states,
                               mem->linear_tables->to_blocks);
}

/// @brief Allocates the AES-256 key schedule state, including its embedded
/// S-box-only encrypt buffer, and reports the footprint in bytes.
///
/// @param mem_ptr Receives the key schedule state.
template <typename Torus>
uint64_t scratch_cuda_integer_key_expansion_256(
    CudaStreams streams, int_key_expansion_256_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_key_expansion_256_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/// @brief AES-256 key expansion entry point: 15 round keys from a 256-bit
/// key.
///
/// @param expanded_keys Output, 1920 blocks of one bit, most significant bit
/// first, round key r at blocks [128 r, 128 (r + 1)).
/// @param key 256 blocks of one bit, most significant bit first.
/// @param mem AES-256 key schedule state.
template <typename Torus, typename KSTorus>
__host__ void host_integer_key_expansion_256(
    CudaStreams streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key, int_key_expansion_256_buffer<Torus> *mem,
    void *const *bsks, KSTorus *const *ksks) {
  host_integer_key_expansion_generic(streams, expanded_keys, key, mem, bsks,
                                     ksks);
}
