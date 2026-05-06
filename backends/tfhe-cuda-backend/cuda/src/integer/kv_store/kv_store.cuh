#pragma once

#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/kv_store/kv_store.h"
#include "integer/kv_store/kv_store_utilities.h"
#include "integer/vector_find.cuh"

template <typename Torus>
__host__ void
host_kv_store_get(CudaStreams streams,
                  CudaRadixCiphertextFFI *lwe_array_out_result,
                  CudaRadixCiphertextFFI *lwe_array_out_boolean,
                  CudaRadixCiphertextFFI *lwe_array_out_selectors,
                  CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
                  CudaRadixCiphertextFFI const *lwe_array_in_values,
                  const uint64_t *h_decomposed_clear_keys,
                  int_kv_store_get_buffer<Torus> *mem_ptr, void *const *bsks,
                  Torus *const *ksks) {

  auto num_key_blocks = mem_ptr->num_key_blocks;
  auto num_value_blocks = mem_ptr->num_value_blocks;
  auto num_entries = mem_ptr->num_entries;
  auto message_modulus = mem_ptr->message_modulus;
  auto carry_modulus = mem_ptr->carry_modulus;
  auto mem_eq_selectors_buffer = mem_ptr->mem_eq_selectors_buffer;
  auto selectors_list = mem_ptr->selectors_list;
  auto tmp_lwe_trivially_encrypted_clear_keys =
      mem_ptr->tmp_lwe_trivially_encrypted_clear_keys;
  auto d_decomposed_clear_keys = mem_ptr->d_decomposed_clear_keys;
  auto mem_zero_out_batch_buffer = mem_ptr->mem_zero_out_batch_buffer;
  auto one_hot_vector_predicate = mem_ptr->one_hot_vector_predicate;
  auto tmp_cmux_array = mem_ptr->tmp_cmux_array;

  // Step 1: equality selectors (key-block-count dependent)
  // Checks equality between all cleartext keys and the encrypted_key.
  // Returns an array with encrypted booleans with the result.
  for (uint32_t i = 0; i < num_entries; i++) {
    as_radix_ciphertext_slice<Torus>(&selectors_list[i],
                                     lwe_array_out_selectors, i, i + 1);
  }

  host_compute_equality_selectors<Torus>(
      streams, selectors_list, lwe_array_in_encrypted_key, num_key_blocks,
      h_decomposed_clear_keys, mem_eq_selectors_buffer, bsks, ksks);

  // Generate trivial encryptions of the clear keys (key-block-count dependent)
  uint64_t *d_decomposed_clear_key = d_decomposed_clear_keys;
  const uint64_t *h_decomposed_clear_key = h_decomposed_clear_keys;
  for (uint32_t i = 0; i < num_entries; i++) {
    CudaRadixCiphertextFFI current_entry;
    as_radix_ciphertext_slice<Torus>(
        &current_entry, tmp_lwe_trivially_encrypted_clear_keys,
        i * num_key_blocks, (i + 1) * num_key_blocks);

    set_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &current_entry,
        d_decomposed_clear_key, h_decomposed_clear_key, num_key_blocks,
        message_modulus, carry_modulus);

    d_decomposed_clear_key += num_key_blocks;
    h_decomposed_clear_key += num_key_blocks;
  }

  // Step 2: One-hot vector (value-block-count dependent)
  // Generates an array where the only non-zero encrypted message is the one we
  // are looking for, in case it is contained in the store.
  auto lwe_one_hot_vector = tmp_cmux_array;
  zero_out_if_batch(streams, lwe_one_hot_vector, lwe_array_in_values,
                    lwe_array_out_selectors, mem_zero_out_batch_buffer,
                    one_hot_vector_predicate, bsks, ksks, num_entries,
                    num_value_blocks);

  // Step 3: Sum all elements in the vector (value-block-count dependent)
  host_binary_tree_sum<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_result,
      lwe_one_hot_vector, num_entries, num_value_blocks,
      mem_ptr->params.polynomial_size, message_modulus, carry_modulus);

  //  OR all selectors
  auto at_least_one_true_buffer = mem_ptr->at_least_one_true_buffer;
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_array_out_boolean, lwe_array_out_selectors,
      at_least_one_true_buffer, bsks, ksks, num_entries);
}

template <typename Torus>
uint64_t scratch_cuda_kv_store_get(
    CudaStreams streams, int_kv_store_get_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_entries, uint32_t num_key_blocks,
    uint32_t num_value_blocks, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_kv_store_get_buffer<Torus>(
      streams, params, num_entries, num_key_blocks, num_value_blocks,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void
host_kv_store_update(CudaStreams streams,
                     CudaRadixCiphertextFFI *lwe_check_out_block,
                     CudaRadixCiphertextFFI *lwe_array_out_values,
                     CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
                     CudaRadixCiphertextFFI const *lwe_array_in_values,
                     CudaRadixCiphertextFFI const *lwe_in_new_value,
                     const uint64_t *h_decomposed_clear_keys,
                     int_kv_store_update_buffer<Torus> *mem_ptr,
                     void *const *bsks, KSTorus *const *ksks) {

  auto num_entries = mem_ptr->num_entries;
  auto num_key_blocks = mem_ptr->num_key_blocks;
  auto num_value_blocks = mem_ptr->num_value_blocks;
  auto mem_eq_selectors_buffer = mem_ptr->mem_eq_selectors_buffer;
  auto selectors_list = mem_ptr->selectors_list;
  uint32_t total_value_blocks = static_cast<uint32_t>(safe_mul(
      static_cast<size_t>(num_entries), static_cast<size_t>(num_value_blocks)));

  PANIC_IF_FALSE(
      lwe_array_out_values->num_radix_blocks >= total_value_blocks &&
          lwe_array_in_values->num_radix_blocks >= total_value_blocks,
      "Cuda error: output or input values radix ciphertext does not have "
      "enough blocks");

  PANIC_IF_FALSE(
      lwe_in_new_value->num_radix_blocks >= num_value_blocks,
      "Cuda error: new_value radix ciphertext does not have enough blocks");

  cuda_set_device(streams.gpu_index(0));

  // Step 1: equality selectors (key-block-count dependent)
  // Checks equality between all cleartext keys and the encrypted_key.
  host_compute_equality_selectors<Torus>(
      streams, selectors_list, lwe_array_in_encrypted_key, num_key_blocks,
      h_decomposed_clear_keys, mem_eq_selectors_buffer, bsks, ksks);

  // Step 2: batched CMUX (value-block-count dependent)
  // For each entry, select new_value where selector==1, old_value otherwise.
  // The true branch (new_value) is replicated across all entries.
  host_cmux_batch<Torus, KSTorus>(
      streams, lwe_array_out_values, lwe_in_new_value, lwe_array_in_values,
      mem_ptr->selectors_contiguous, mem_ptr->cmux_batch_buffer, bsks, ksks,
      num_entries, num_value_blocks, true);

  // Step 3: OR all selectors to produce the key-found boolean
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_check_out_block, mem_ptr->selectors_contiguous,
      mem_ptr->at_least_one_true_buffer, bsks, ksks, num_entries);
}

template <typename Torus>
uint64_t scratch_cuda_kv_store_update(
    CudaStreams streams, int_kv_store_update_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_entries, uint32_t num_key_blocks,
    uint32_t num_value_blocks, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_kv_store_update_buffer<Torus>(
      streams, params, num_entries, num_key_blocks, num_value_blocks,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void
host_kv_store_map(CudaStreams streams,
                  CudaRadixCiphertextFFI *lwe_check_out_block,
                  CudaRadixCiphertextFFI *lwe_array_out_values,
                  CudaRadixCiphertextFFI const *lwe_array_in_values,
                  CudaRadixCiphertextFFI const *lwe_in_new_value,
                  CudaRadixCiphertextFFI const *lwe_array_in_selectors,
                  int_kv_store_map_buffer<Torus> *mem_ptr, void *const *bsks,
                  KSTorus *const *ksks) {

  auto num_entries = mem_ptr->num_entries;
  auto num_value_blocks = mem_ptr->num_value_blocks;
  uint32_t total_value_blocks = static_cast<uint32_t>(safe_mul(
      static_cast<size_t>(num_entries), static_cast<size_t>(num_value_blocks)));

  PANIC_IF_FALSE(
      lwe_array_out_values->num_radix_blocks >= total_value_blocks &&
          lwe_array_in_values->num_radix_blocks >= total_value_blocks,
      "Cuda error: output or input values radix ciphertext does not have "
      "enough blocks");

  PANIC_IF_FALSE(
      lwe_in_new_value->num_radix_blocks >= num_value_blocks,
      "Cuda error: new_value radix ciphertext does not have enough blocks");

  cuda_set_device(streams.gpu_index(0));

  // Batched CMUX: for each entry, select new_value where selector==1,
  // old_value otherwise. The true branch (new_value) is replicated across all
  // entries.
  host_cmux_batch<Torus, KSTorus>(
      streams, lwe_array_out_values, lwe_in_new_value, lwe_array_in_values,
      lwe_array_in_selectors, mem_ptr->cmux_batch_buffer, bsks, ksks,
      num_entries, num_value_blocks, true);

  // OR all selectors to produce the key-found boolean
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_check_out_block, lwe_array_in_selectors,
      mem_ptr->at_least_one_true_buffer, bsks, ksks, num_entries);
}

template <typename Torus>
uint64_t
scratch_cuda_kv_store_map(CudaStreams streams,
                          int_kv_store_map_buffer<Torus> **mem_ptr,
                          int_radix_params params, uint32_t num_entries,
                          uint32_t num_value_blocks, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_kv_store_map_buffer<Torus>(
      streams, params, num_entries, num_value_blocks, allocate_gpu_memory,
      size_tracker);
  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void host_kv_store_contains_key(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    const uint64_t *h_decomposed_clear_keys,
    int_kv_store_contains_key_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks) {

  auto num_entries = mem_ptr->num_entries;
  auto num_key_blocks = mem_ptr->num_key_blocks;
  auto selectors_list = mem_ptr->selectors_list;

  cuda_set_device(streams.gpu_index(0));

  // Step 1: equality selectors (key-block-count dependent)
  // Checks equality between all cleartext keys and the encrypted_key.
  host_compute_equality_selectors<Torus>(
      streams, selectors_list, lwe_array_in_encrypted_key, num_key_blocks,
      h_decomposed_clear_keys, mem_ptr->mem_eq_selectors_buffer, bsks, ksks);

  // Step 2: OR all selectors to produce the key-found boolean
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_array_out_boolean, mem_ptr->selectors_contiguous,
      mem_ptr->at_least_one_true_buffer, bsks, ksks, num_entries);
}

template <typename Torus>
uint64_t scratch_cuda_kv_store_contains_key(
    CudaStreams streams, int_kv_store_contains_key_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_entries, uint32_t num_key_blocks,
    bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_kv_store_contains_key_buffer<Torus>(
      streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
      size_tracker);
  return size_tracker;
}
