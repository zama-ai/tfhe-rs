#pragma once

#include "../../include/aes/aes_utilities.h"
#include "aes.cuh"

/// @brief Allocates the AES-256 key schedule state and returns its GPU size.
///
/// @param mem_ptr Receives the state
template <typename Torus>
uint64_t scratch_cuda_integer_key_expansion_256(
    CudaStreams streams, int_key_expansion_256_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_key_expansion_256_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/// @brief AES-256 key expansion, 15 round keys from a 256-bit key.
///
/// @param expanded_keys Output, 1920 one bit blocks MSB first, round key r at
/// blocks [128 r, 128 (r + 1))
/// @param key 256 one bit blocks, MSB first
/// @param mem AES-256 key schedule state
template <typename Torus, typename KSTorus>
__host__ void host_integer_key_expansion_256(
    CudaStreams streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key, int_key_expansion_256_buffer<Torus> *mem,
    void *const *bsks, KSTorus *const *ksks) {
  host_integer_key_expansion_generic(streams, expanded_keys, key, mem, bsks,
                                     ksks);
}
