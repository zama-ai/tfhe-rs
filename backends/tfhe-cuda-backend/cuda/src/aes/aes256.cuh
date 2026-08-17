#pragma once

#include "../../include/aes/aes_utilities.h"
#include "aes.cuh"

/**
 * AES-256-CTR entry point: the AES-128 pipeline with 14 rounds. Round
 * function and counter addition are shared verbatim.
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_aes_ctr_256_encrypt(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const Torus *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks,
    KSTorus *const *ksks) {

  constexpr uint32_t NUM_BITS = AES_STATE_BITS;
  constexpr uint32_t ROUNDS = 14;

  PANIC_IF_FALSE(mem->main_workspaces->main_bitsliced_states_buffer != nullptr,
                 "AES CTR encryption requires a buffer allocated with the "
                 "FULL_ENCRYPTION scope, got a SBOX_ONLY one");

  CudaRadixCiphertextFFI *transposed_states =
      mem->main_workspaces->main_bitsliced_states_buffer;

  host_aes_broadcast_bits<Torus>(streams.stream(0), streams.gpu_index(0),
                                 transposed_states, iv, NUM_BITS,
                                 num_aes_inputs);

  vectorized_aes_add_counter_inplace<Torus>(streams, transposed_states,
                                            counter_bits_le_all_blocks,
                                            num_aes_inputs, mem, bsks, ksks);

  vectorized_aes_rounds_inplace<Torus>(streams, transposed_states, round_keys,
                                       ROUNDS, num_aes_inputs, mem, bsks, ksks);

  host_aes_bitsliced_to_blocks<Torus>(streams.stream(0), streams.gpu_index(0),
                                      output, transposed_states, NUM_BITS,
                                      num_aes_inputs);
}

/**
 * Allocates the AES-256 key schedule state.
 */
template <typename Torus>
uint64_t scratch_cuda_integer_key_expansion_256(
    CudaStreams streams, int_key_expansion_256_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_key_expansion_256_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/**
 * AES-256 key expansion entry point: 15 round keys from a 256-bit key.
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_key_expansion_256(
    CudaStreams streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key, int_key_expansion_256_buffer<Torus> *mem,
    void *const *bsks, KSTorus *const *ksks) {
  host_integer_key_expansion_generic(streams, expanded_keys, key, mem, bsks,
                                     ksks);
}
