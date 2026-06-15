#pragma once

#include "helper_profile.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/kv_store/kv_store.h"
#include "integer/kv_store/kv_store_utilities.h"
#include "integer/vector_find.cuh"

/// @brief Accumulates chunks of LWE blocks for multiple entries in a single
/// kernel.
///
/// Each CUDA block (in the y-dimension) handles one (entry, chunk) pair,
/// summing chunk_length adjacent LWE blocks element-wise into one output block.
///
/// @param output                Output buffer receiving one accumulated block
/// per
///                              (entry, chunk) pair
/// @param input                 Input LWE blocks in row-major layout (entries x
///                              blocks_per_entry)
/// @param lwe_dimension         LWE dimension (number of mask coefficients)
/// @param blocks_per_entry      Number of input LWE blocks per map entry
/// @param max_value             Maximum chunk length (accumulation width)
/// @param num_chunks_per_entry  Number of chunks each entry is split into
template <typename Torus>
__global__ void device_accumulate_all_blocks_batched(
    Torus *output, Torus const *input, uint32_t lwe_dimension,
    uint32_t blocks_per_entry, uint32_t max_value,
    uint32_t num_chunks_per_entry) {
  uint32_t lwe_idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (lwe_idx >= lwe_dimension + 1)
    return;

  uint32_t chunk_flat_idx = blockIdx.y;
  uint32_t entry_idx = chunk_flat_idx / num_chunks_per_entry;
  uint32_t chunk_idx = chunk_flat_idx % num_chunks_per_entry;

  uint32_t chunk_start = chunk_idx * max_value;
  uint32_t chunk_length = min(max_value, blocks_per_entry - chunk_start);

  uint32_t stride = lwe_dimension + 1;
  Torus const *base =
      &input[(entry_idx * blocks_per_entry + chunk_start) * stride];

  Torus sum = base[lwe_idx];
  for (uint32_t i = 1; i < chunk_length; i++) {
    sum += base[lwe_idx + i * stride];
  }

  output[chunk_flat_idx * stride + lwe_idx] = sum;
}

/// @brief Host wrapper launching device_accumulate_all_blocks_batched.
///
/// @param output                Output buffer receiving one accumulated block
/// per
///                              (entry, chunk) pair
/// @param input                 Input LWE blocks in row-major layout
/// @param lwe_dimension         LWE dimension (number of mask coefficients)
/// @param blocks_per_entry      Number of input LWE blocks per map entry
/// @param max_value             Maximum chunk length (accumulation width)
/// @param num_entries           Number of map entries being processed
/// @param num_chunks_per_entry  Number of chunks each entry is split into
template <typename Torus>
__host__ void host_accumulate_all_blocks_batched(
    cudaStream_t stream, uint32_t gpu_index, Torus *output, Torus const *input,
    uint32_t lwe_dimension, uint32_t blocks_per_entry, uint32_t max_value,
    uint32_t num_entries, uint32_t num_chunks_per_entry) {
  cuda_set_device(gpu_index);
  int num_blocks_x = 0, num_threads = 0;
  getNumBlocksAndThreads(lwe_dimension + 1, 512, num_blocks_x, num_threads);
  dim3 grid(num_blocks_x, num_entries * num_chunks_per_entry);
  device_accumulate_all_blocks_batched<Torus><<<grid, num_threads, 0, stream>>>(
      output, input, lwe_dimension, blocks_per_entry, max_value,
      num_chunks_per_entry);
  check_cuda_error(cudaGetLastError());
}

/// @brief Computes per-entry equality selectors using the small-map tree
/// algorithm.
///
/// Given one encrypted radix ciphertext (num_blocks blocks, each a digit in
/// [0, message_modulus)) and N cleartext candidates (the clear kv_store keys),
/// produces N encrypted booleans: selector_i = Enc(input == candidate_i).
///
/// Candidates live in h_decomposed_cleartexts, a flat array where candidate i
/// occupies [i*num_blocks .. (i+1)*num_blocks). N =
/// mem_ptr->num_possible_values.
///
/// A per-candidate approach costs N * num_blocks PBS. Since there are only
/// message_modulus possible digit values (typically 2 or 4), we instead
/// precompute all per-block comparisons in one batched PBS, then let each
/// candidate pick the results it needs via memcpy:
///
/// Step 1: One batched PBS builds a message_modulus x num_blocks grid:
///
///                       block 0    block 1    block 2
///                     +----------+----------+----------+
///     LUT for v=0     | b0==0?   | b1==0?   | b2==0?   |
///     LUT for v=1     | b0==1?   | b1==1?   | b2==1?   |
///     LUT for v=2     | b0==2?   | b1==2?   | b2==2?   |
///     LUT for v=3     | b0==3?   | b1==3?   | b2==3?   |
///                     +----------+----------+----------+
///     Flat: tmp_many_luts_output[v * num_blocks + j]
///
/// Step 2: For each candidate i with digits [d0, d1, ..], gather grid[dj][j]
///   for all j into a flat N*num_blocks buffer.
///
/// Step 3: AND-reduce across all candidates simultaneously using a batched
///   tree: at each level, accumulate chunks and apply one large batched PBS.
///   This replaces per-candidate AND-trees with 2 batched PBS calls (for
///   typical 2_2 params with 16-block keys).
///
/// This is the few-entries kv_store variant; see
/// KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES for when it is preferred over
/// vector_find's host_compute_eq_selectors_ct_vs_clears.
///
/// @param lwe_array_out_packed       Output ciphertext: N single-block boolean
///                                   selectors packed contiguously
/// @param lwe_array_in               Input encrypted radix key
/// @param num_blocks                 Number of radix blocks in the input key
/// @param h_decomposed_cleartexts    Host flat array of candidate digit values
///                                   (N * num_blocks)
/// @param mem_ptr                    Scratch buffer holding LUTs, gather maps,
///                                   and tree buffers
template <typename Torus>
__host__ void host_kv_store_compute_eq_selectors_small_map(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_packed,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_blocks,
    const uint64_t *h_decomposed_cleartexts,
    int_kv_store_eq_selectors_small_map_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  // num_blocks == 0 would yield an all-zero selector matrix instead of the
  // trivial all-match, so require at least one block (matching the vector_find
  // dispatch guard so both variants agree).
  GPU_ASSERT(num_blocks >= 1, "num_blocks must be at least 1 in "
                              "host_kv_store_compute_eq_selectors_small_map");

  uint32_t num_possible_values = mem_ptr->num_possible_values;
  uint32_t message_modulus = mem_ptr->params.message_modulus;
  uint32_t big_lwe_dimension = mem_ptr->params.big_lwe_dimension;

  // Step 1: Grid PBS — precompute all per-block equality indicators.
  // One batched PBS builds a message_modulus x num_blocks grid where
  // grid[v][j] = Enc(input_block_j == v).
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, &mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);

  // Step 2: Gather — for each candidate i, extract its comparison blocks
  // from the grid PBS output into a flat row-major buffer:
  //   batched[i * num_blocks + j] = grid[decomposed[i][j]][j]
  Torus *h_map = mem_ptr->h_map;
  uint32_t total_blocks = num_possible_values * num_blocks;
  for (uint32_t i = 0; i < num_possible_values; i++) {
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t block_value = h_decomposed_cleartexts[i * num_blocks + j];
      if (block_value >= message_modulus)
        PANIC("Cuda error: block value in compute_equality_selectors exceeds "
              "message modulus");
      h_map[i * num_blocks + j] = (Torus)block_value * num_blocks + j;
    }
  }
  cuda_memcpy_async_to_gpu(mem_ptr->d_map, h_map,
                           safe_mul_sizeof<Torus>(total_blocks),
                           streams.stream(0), streams.gpu_index(0));

  uint32_t lwe_size = mem_ptr->tmp_batched_comparisons.lwe_dimension + 1;
  align_with_indexes<Torus><<<total_blocks, 256, 0, streams.stream(0)>>>(
      (Torus *)mem_ptr->tmp_batched_comparisons.ptr,
      (Torus *)mem_ptr->tmp_many_luts_output.ptr, mem_ptr->d_map, lwe_size);
  check_cuda_error(cudaGetLastError());

  if (num_blocks == 1) {
    // Each candidate needs exactly one comparison block; no tree reduction.
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 0,
        num_possible_values, &mem_ptr->tmp_batched_comparisons, 0,
        num_possible_values);
    return;
  }

  // Step 3: Batched tree reduction — AND-reduce the per-entry comparison
  // blocks using host_accumulate_all_blocks_batched + is_max_value PBS.
  // The data is in row-major layout: entry_i occupies blocks
  // [i*num_blocks .. (i+1)*num_blocks).
  uint32_t max_value = mem_ptr->max_value;
  auto is_max_value_lut = mem_ptr->is_max_value_lut;
  auto tree_accumulator = mem_ptr->tree_accumulator;
  auto tree_pbs_output = mem_ptr->tree_pbs_output;

  Torus *current_input_ptr = (Torus *)mem_ptr->tmp_batched_comparisons.ptr;
  uint32_t blocks_per_entry = num_blocks;
  uint32_t level = 0;

  while (blocks_per_entry > 1) {
    uint32_t num_chunks = CEIL_DIV(blocks_per_entry, max_value);
    uint32_t total_chunks = num_possible_values * num_chunks;

    host_accumulate_all_blocks_batched<Torus>(
        streams.stream(0), streams.gpu_index(0), (Torus *)tree_accumulator->ptr,
        current_input_ptr, big_lwe_dimension, blocks_per_entry, max_value,
        num_possible_values, num_chunks);

    for (uint32_t flat = 0; flat < total_chunks; flat++) {
      uint32_t chunk = flat % num_chunks;
      uint32_t chunk_start = chunk * max_value;
      uint32_t chunk_len = std::min(max_value, blocks_per_entry - chunk_start);
      tree_accumulator->degrees[flat] = chunk_len;
      tree_accumulator->noise_levels[flat] = NoiseLevel::NOMINAL;
    }

    // Switch to this level's precomputed index buffer (slots baked at scratch
    // time): a small gpu-to-gpu copy plus broadcast, no per-level LUT regen.
    auto active =
        streams.active_gpu_subset(total_chunks, mem_ptr->params.pbs_type);
    is_max_value_lut->set_lut_indexes_and_broadcast_from_gpu(
        active, mem_ptr->d_level_lut_indexes[level], total_chunks);

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, tree_pbs_output, tree_accumulator, bsks, ksks,
        is_max_value_lut, total_chunks);

    current_input_ptr = (Torus *)tree_pbs_output->ptr;
    blocks_per_entry = num_chunks;
    level++;
  }

  CudaRadixCiphertextFFI *result_source =
      (blocks_per_entry == num_blocks) ? &mem_ptr->tmp_batched_comparisons
                                       : tree_pbs_output;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 0,
      num_possible_values, result_source, 0, num_possible_values);
}

/// @brief Dispatches equality-selector computation to the algorithm chosen at
/// scratch time.
///
/// Computes one encrypted boolean per stored key (input == key_i), delegating
/// to the small-map tree variant or the sequential-scan variant based on
/// KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES.
///
/// @param lwe_array_out_packed       Output ciphertext: one boolean per entry
/// @param lwe_array_in               Input encrypted radix key
/// @param num_blocks                 Number of radix blocks in the input key
/// @param h_decomposed_cleartexts    Host flat array of all candidate digit
///                                   values
/// @param mem_ptr                    Wrapper buffer selecting the active
///                                   algorithm
template <typename Torus>
__host__ void host_kv_store_compute_eq_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_packed,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_blocks,
    const uint64_t *h_decomposed_cleartexts,
    int_kv_store_eq_selectors_wrapper_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {
  if (mem_ptr->use_small_map) {
    host_kv_store_compute_eq_selectors_small_map<Torus>(
        streams, lwe_array_out_packed, lwe_array_in, num_blocks,
        h_decomposed_cleartexts, mem_ptr->small_map_buffer, bsks, ksks);
  } else {
    host_compute_eq_selectors_ct_vs_clears<Torus>(
        streams, lwe_array_out_packed, lwe_array_in, num_blocks,
        h_decomposed_cleartexts, mem_ptr->vector_find_buffer, bsks, ksks);
  }
}

/// @brief Retrieves the encrypted value for a key from an encrypted kv_store.
///
/// Compares the encrypted key against all stored clear keys. If a match
/// is found, the corresponding encrypted value is extracted; otherwise the
/// result is an encryption of zero. Does not leak which key was accessed.
///
/// @param lwe_array_out_result       Output ciphertext receiving the looked-up
///                                   value
/// @param lwe_array_out_boolean      Output single-block ciphertext: 1 if key
///                                   found, 0 otherwise
/// @param lwe_array_out_selectors    Output per-entry boolean selectors
/// @param lwe_array_in_encrypted_key Input encrypted key to look up
/// @param lwe_array_in_values        Input flat array of all stored encrypted
///                                   values
/// @param h_decomposed_clear_keys    Host-side clear keys decomposed into radix
///                                   blocks (num_entries * num_key_blocks)
/// @param mem_ptr                    Scratch buffer from
///                                   scratch_cuda_kv_store_get
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
  auto mem_zero_out_batch_buffer = mem_ptr->mem_zero_out_batch_buffer;
  auto one_hot_vector_predicate = mem_ptr->one_hot_vector_predicate;
  auto tmp_cmux_array = mem_ptr->tmp_cmux_array;
  auto message_modulus = mem_ptr->message_modulus;
  auto carry_modulus = mem_ptr->carry_modulus;

  cuda_set_device(streams.gpu_index(0));

  // Step 1: one encrypted boolean per stored key (input == key_i).
  PUSH_RANGE("get: equality selectors")
  host_kv_store_compute_eq_selectors<Torus>(
      streams, lwe_array_out_selectors, lwe_array_in_encrypted_key,
      num_key_blocks, h_decomposed_clear_keys, mem_ptr->mem_eq_selectors_buffer,
      bsks, ksks);
  POP_RANGE()

  // Step 2: one-hot vector, zeroing every value whose selector is 0 so only the
  // matched value (if any) survives.
  PUSH_RANGE("get: one-hot vector")
  auto lwe_one_hot_vector = tmp_cmux_array;
  host_zero_out_if_batch(streams, lwe_one_hot_vector, lwe_array_in_values,
                         lwe_array_out_selectors, mem_zero_out_batch_buffer,
                         one_hot_vector_predicate, bsks, ksks, num_entries,
                         num_value_blocks);
  POP_RANGE()

  // Step 3: Sum all elements in the vector
  PUSH_RANGE("get: binary tree sum")
  host_binary_tree_fold_sum_dispatch<Torus>(
      streams, lwe_array_out_result, lwe_one_hot_vector, num_entries,
      num_value_blocks, message_modulus, carry_modulus, bsks, ksks,
      mem_ptr->identity_lut);
  POP_RANGE()

  PUSH_RANGE("get: OR selectors")
  auto at_least_one_true_buffer = mem_ptr->at_least_one_true_buffer;
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_array_out_boolean, lwe_array_out_selectors,
      at_least_one_true_buffer, bsks, ksks, num_entries);
  POP_RANGE()
}

/// @brief Allocates the scratch buffer for kv_store get.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
///                           buffer
/// @param num_entries        Number of stored key-value pairs
/// @param num_key_blocks     Number of radix blocks per key
/// @param num_value_blocks   Number of radix blocks per value
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

/// @brief Updates the encrypted value for a key in an encrypted kv_store.
///
/// For each entry, if the stored clear key matches the query, the old
/// encrypted value is replaced with lwe_in_new_value; otherwise kept.
/// Does not leak which key was accessed or whether a match was found.
///
/// @param lwe_check_out_block          Output single-block ciphertext: 1 if key
///                                     found, 0 otherwise
/// @param lwe_array_out_values         Output flat array of stored encrypted
///                                     values (updated in place)
/// @param lwe_array_in_encrypted_key   Input encrypted key to match
/// @param lwe_array_in_values          Input flat array of current stored
///                                     encrypted values
/// @param lwe_in_new_value             Input encrypted replacement value
/// @param h_decomposed_clear_keys      Host-side clear keys decomposed into
///                                     radix blocks
/// @param mem_ptr                      Scratch buffer from
///                                     scratch_cuda_kv_store_update
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
  uint32_t total_value_blocks = static_cast<uint32_t>(safe_mul(
      static_cast<size_t>(num_entries), static_cast<size_t>(num_value_blocks)));

  GPU_ASSERT(
      lwe_array_out_values->num_radix_blocks >= total_value_blocks &&
          lwe_array_in_values->num_radix_blocks >= total_value_blocks,
      "Cuda error: output or input values radix ciphertext does not have "
      "enough blocks");

  GPU_ASSERT(
      lwe_in_new_value->num_radix_blocks >= num_value_blocks,
      "Cuda error: new_value radix ciphertext does not have enough blocks");

  cuda_set_device(streams.gpu_index(0));

  // Step 1: one encrypted boolean per stored key (input == key_i).
  PUSH_RANGE("update: equality selectors")
  host_kv_store_compute_eq_selectors<Torus>(
      streams, mem_ptr->selectors_contiguous, lwe_array_in_encrypted_key,
      num_key_blocks, h_decomposed_clear_keys, mem_eq_selectors_buffer, bsks,
      ksks);
  POP_RANGE()

  // Step 2: batched CMUX selecting new_value where selector==1, old otherwise.
  // The true branch (new_value) is replicated across all entries.
  PUSH_RANGE("update: batched cmux")
  host_cmux_batch<Torus, KSTorus>(
      streams, lwe_array_out_values, lwe_in_new_value, lwe_array_in_values,
      mem_ptr->selectors_contiguous, mem_ptr->cmux_batch_buffer, bsks, ksks,
      num_entries, num_value_blocks, true);
  POP_RANGE()

  // Step 3: OR all selectors to produce the key-found boolean
  PUSH_RANGE("update: OR selectors")
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_check_out_block, mem_ptr->selectors_contiguous,
      mem_ptr->at_least_one_true_buffer, bsks, ksks, num_entries);
  POP_RANGE()
}

/// @brief Allocates the scratch buffer for kv_store update.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
///                           buffer
/// @param num_entries        Number of stored key-value pairs
/// @param num_key_blocks     Number of radix blocks per key
/// @param num_value_blocks   Number of radix blocks per value
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

/// @brief Applies a conditional update to all entries using pre-computed
/// selectors.
///
/// For each entry, if the corresponding selector is 1, the old encrypted value
/// is replaced with lwe_in_new_value; otherwise the old value is kept. This is
/// the inner CMUX step shared by update and insert.
///
/// @param lwe_check_out_block       Output single-block ciphertext: 1 if at
///                                  least one selector was true
/// @param lwe_array_out_values      Output flat array of stored encrypted
/// values
///                                  (updated)
/// @param lwe_array_in_values       Input flat array of current stored
/// encrypted
///                                  values
/// @param lwe_in_new_value          Input encrypted replacement value
/// @param lwe_array_in_selectors    Input per-entry boolean selectors
///                                  (1 = replace, 0 = keep)
/// @param mem_ptr                   Scratch buffer from
///                                  scratch_cuda_kv_store_map
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

  GPU_ASSERT(
      lwe_array_out_values->num_radix_blocks >= total_value_blocks &&
          lwe_array_in_values->num_radix_blocks >= total_value_blocks,
      "Cuda error: output or input values radix ciphertext does not have "
      "enough blocks");

  GPU_ASSERT(
      lwe_in_new_value->num_radix_blocks >= num_value_blocks,
      "Cuda error: new_value radix ciphertext does not have enough blocks");

  GPU_ASSERT(
      lwe_array_in_selectors->num_radix_blocks >= num_entries,
      "Cuda error: selectors radix ciphertext does not have enough blocks");

  cuda_set_device(streams.gpu_index(0));

  // Batched CMUX selecting new_value where selector==1, old otherwise. The true
  // branch (new_value) is replicated across all entries.
  PUSH_RANGE("map: batched cmux")
  host_cmux_batch<Torus, KSTorus>(
      streams, lwe_array_out_values, lwe_in_new_value, lwe_array_in_values,
      lwe_array_in_selectors, mem_ptr->cmux_batch_buffer, bsks, ksks,
      num_entries, num_value_blocks, true);
  POP_RANGE()

  // OR all selectors to produce the key-found boolean
  PUSH_RANGE("map: OR selectors")
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_check_out_block, lwe_array_in_selectors,
      mem_ptr->at_least_one_true_buffer, bsks, ksks, num_entries);
  POP_RANGE()
}

/// @brief Allocates the scratch buffer for kv_store map.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
///                           buffer
/// @param num_entries        Number of stored key-value pairs
/// @param num_value_blocks   Number of radix blocks per value
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

/// @brief Checks whether a clear key exists in the encrypted kv_store.
///
/// Compares the encrypted key against all stored clear keys and OR-reduces
/// the per-entry booleans into a single key-found flag. Does not leak which
/// key was queried.
///
/// @param lwe_array_out_boolean      Output single-block ciphertext: 1 if key
///                                   found, 0 otherwise
/// @param lwe_array_in_encrypted_key Input encrypted key to look up
/// @param h_decomposed_clear_keys    Host-side clear keys decomposed into radix
///                                   blocks
/// @param mem_ptr                    Scratch buffer from
///                                   scratch_cuda_kv_store_contains_key
template <typename Torus, typename KSTorus>
__host__ void host_kv_store_contains_key(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    const uint64_t *h_decomposed_clear_keys,
    int_kv_store_contains_key_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks) {

  auto num_entries = mem_ptr->num_entries;
  auto num_key_blocks = mem_ptr->num_key_blocks;

  cuda_set_device(streams.gpu_index(0));

  // Step 1: one encrypted boolean per stored key (input == key_i).
  PUSH_RANGE("contains_key: equality selectors")
  host_kv_store_compute_eq_selectors<Torus>(
      streams, mem_ptr->selectors_contiguous, lwe_array_in_encrypted_key,
      num_key_blocks, h_decomposed_clear_keys, mem_ptr->mem_eq_selectors_buffer,
      bsks, ksks);
  POP_RANGE()

  // Step 2: OR all selectors to produce the key-found boolean
  PUSH_RANGE("contains_key: OR selectors")
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_array_out_boolean, mem_ptr->selectors_contiguous,
      mem_ptr->at_least_one_true_buffer, bsks, ksks, num_entries);
  POP_RANGE()
}

/// @brief Allocates the scratch buffer for kv_store contains_key.
///
/// @param mem_ptr            Output pointer receiving the allocated scratch
///                           buffer
/// @param num_entries        Number of stored keys
/// @param num_key_blocks     Number of radix blocks per key
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
