#ifndef CUDA_INTEGER_KV_STORE_UTILITIES_H
#define CUDA_INTEGER_KV_STORE_UTILITIES_H

#include "../comparison.h"
#include "../vector_find.h"
#include "integer/cmux.cuh"
#include "integer/radix_ciphertext.cuh"

/// Entry-count threshold for the equality-selector algorithm
constexpr uint32_t KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES = 256;

/// @brief GPU scratch buffer for the few-entries equality-selector algorithm.
///
/// Given one encrypted radix key and num_possible_values block-decomposed
/// clear keys, computes one encrypted boolean per clear key via a grid PBS
/// followed by a batched tree AND-reduction.
///
/// @tparam Torus  Unsigned integer type representing a ciphertext torus element
template <typename Torus> struct int_kv_store_eq_selectors_small_map_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// PBS LUT stride in torus elements, derived from ciphertext modulus
  uint32_t lut_stride;

  /// Number of cleartext key candidates (entries in the map)
  uint32_t num_possible_values;

  // Grid PBS
  /// Per-digit equality LUTs (one per message_modulus value)
  int_radix_lut<Torus> *comparison_luts;
  /// Grid PBS output: message_modulus x num_blocks equality indicators
  CudaRadixCiphertextFFI tmp_many_luts_output;

  /// Gathered per-candidate comparison blocks
  CudaRadixCiphertextFFI tmp_batched_comparisons;
  /// Device gather-index buffer for align_with_indexes
  Torus *d_map;
  /// Host gather-index buffer, copied to d_map before each use
  Torus *h_map;

  // Tree reduction
  /// Accumulator for tree-level block sums (null for single-block keys)
  CudaRadixCiphertextFFI *tree_accumulator;
  /// PBS output at each tree level (null for single-block keys)
  CudaRadixCiphertextFFI *tree_pbs_output;
  /// LUTs for the is-max-value check at each tree level
  int_radix_lut<Torus> *is_max_value_lut;
  /// Maximum sum before a PBS round: (msg*carry - 1) / (msg - 1)
  uint32_t max_value;
  /// Number of chunks per entry at the first tree level
  uint32_t max_chunks;

  // Per-level precomputed LUT-index buffers for the tree reduction.
  /// Depth of the AND-reduction tree (0 for single-block keys)
  uint32_t num_tree_levels;
  /// Device LUT-index arrays, one per tree level
  Torus **d_level_lut_indexes;

  /// @brief Allocates GPU buffers for the small-map equality-selector
  /// algorithm.
  ///
  /// @param num_possible_values  Number of cleartext key candidates
  /// @param num_blocks           Number of radix blocks per key
  int_kv_store_eq_selectors_small_map_buffer(CudaStreams streams,
                                             int_radix_params params,
                                             uint32_t num_possible_values,
                                             uint32_t num_blocks,
                                             bool allocate_gpu_memory,
                                             uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_possible_values = num_possible_values;

    uint32_t ciphertext_modulus = params.message_modulus * params.carry_modulus;
    uint32_t box_size = params.polynomial_size / ciphertext_modulus;
    lut_stride = (ciphertext_modulus / params.message_modulus) * box_size;

    // Grid PBS LUTs: one per possible block value
    this->comparison_luts = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, params.message_modulus,
        allocate_gpu_memory, size_tracker);

    std::vector<std::function<Torus(Torus)>> fs;
    fs.reserve(params.message_modulus);
    for (uint32_t i = 0; i < params.message_modulus; i++) {
      fs.push_back([i](Torus x) -> Torus { return (x == i); });
    }

    this->comparison_luts->generate_and_broadcast_many_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {fs},
        LUT_0_FOR_ALL_BLOCKS);
    fs.clear();

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_many_luts_output,
        params.message_modulus * num_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    // Gather buffer: row-major layout [entry_0_blk_0, entry_0_blk_1, ...]
    uint64_t total_blocks64 = (uint64_t)num_possible_values * num_blocks;
    GPU_ASSERT(total_blocks64 <= UINT32_MAX,
               "num_possible_values * num_blocks must fit in uint32_t");
    uint32_t total_blocks = (uint32_t)total_blocks64;

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_batched_comparisons,
        total_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->h_map = new Torus[total_blocks];
    this->d_map = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(total_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);

    // Tree reduction
    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    this->max_value = (total_modulus - 1) / (params.message_modulus - 1);
    this->max_chunks =
        (num_blocks > 1) ? CEIL_DIV(num_blocks, this->max_value) : 1;

    // A single-block key needs no AND-reduction: each candidate's one
    // comparison block already is its selector. Leave the tree resources null
    // and skip their allocation.
    if (num_blocks == 1) {
      this->tree_accumulator = nullptr;
      this->tree_pbs_output = nullptr;
      this->is_max_value_lut = nullptr;
      this->num_tree_levels = 0;
      this->d_level_lut_indexes = nullptr;
    } else {
      uint32_t acc_blocks = num_possible_values * this->max_chunks;
      uint32_t max_value = this->max_value;

      this->tree_accumulator = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), this->tree_accumulator,
          acc_blocks, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);

      this->tree_pbs_output = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), this->tree_pbs_output,
          acc_blocks, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);

      std::vector<uint32_t> level_num_chunks;
      std::vector<uint32_t> level_last_chunk_length;
      {
        uint32_t blocks_per_entry = num_blocks;
        while (blocks_per_entry > 1) {
          uint32_t num_chunks = CEIL_DIV(blocks_per_entry, max_value);
          uint32_t last_chunk_length =
              blocks_per_entry - (num_chunks - 1) * max_value;
          level_num_chunks.push_back(num_chunks);
          level_last_chunk_length.push_back(last_chunk_length);
          blocks_per_entry = num_chunks;
        }
      }
      this->num_tree_levels = static_cast<uint32_t>(level_num_chunks.size());

      uint32_t num_luts = 1 + this->num_tree_levels;
      this->is_max_value_lut =
          new int_radix_lut<Torus>(streams, params, num_luts, acc_blocks,
                                   allocate_gpu_memory, size_tracker);

      std::vector<uint32_t> lut_ids;
      std::vector<std::function<Torus(Torus)>> lut_fns;
      lut_ids.reserve(num_luts);
      lut_fns.reserve(num_luts);
      lut_ids.push_back(0);
      lut_fns.push_back(
          [max_value](Torus x) -> Torus { return x == max_value; });
      for (uint32_t L = 0; L < this->num_tree_levels; L++) {
        uint32_t lcl = level_last_chunk_length[L];
        lut_ids.push_back(L + 1);
        lut_fns.push_back([lcl](Torus x) -> Torus { return x == lcl; });
      }

      auto lut_active = streams.active_gpu_subset(acc_blocks, params.pbs_type);
      this->is_max_value_lut->generate_and_broadcast_lut(
          lut_active, lut_ids, lut_fns, LUT_0_FOR_ALL_BLOCKS);

      // Precompute one device lut-index buffer per level. For a block at flat
      // index idx in [0, total_chunks): the last chunk of each entry
      // ((idx % num_chunks) == num_chunks - 1) uses this level's slot (L + 1)
      // when last_chunk_length != max_value; every other block uses slot 0.
      this->d_level_lut_indexes = new Torus *[this->num_tree_levels];
      Torus *h_level_indexes = new Torus[acc_blocks];
      for (uint32_t L = 0; L < this->num_tree_levels; L++) {
        uint32_t num_chunks = level_num_chunks[L];
        uint32_t total_chunks = num_possible_values * num_chunks;
        bool special = (level_last_chunk_length[L] != max_value);
        for (uint32_t idx = 0; idx < acc_blocks; idx++) {
          if (special && idx < total_chunks &&
              (idx % num_chunks) == num_chunks - 1) {
            h_level_indexes[idx] = static_cast<Torus>(L + 1);
          } else {
            h_level_indexes[idx] = 0;
          }
        }
        this->d_level_lut_indexes[L] =
            (Torus *)cuda_malloc_with_size_tracking_async(
                safe_mul_sizeof<Torus>(acc_blocks), streams.stream(0),
                streams.gpu_index(0), size_tracker, allocate_gpu_memory);
        if (allocate_gpu_memory) {
          cuda_memcpy_async_to_gpu(this->d_level_lut_indexes[L],
                                   h_level_indexes,
                                   safe_mul_sizeof<Torus>(acc_blocks),
                                   streams.stream(0), streams.gpu_index(0));
        }
      }
      cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
      delete[] h_level_indexes;
    }
  }

  void release(CudaStreams streams) {
    this->comparison_luts->release(streams);
    delete this->comparison_luts;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_many_luts_output,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_batched_comparisons,
                                   this->allocate_gpu_memory);

    if (this->tree_accumulator != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tree_accumulator,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tree_pbs_output,
                                     this->allocate_gpu_memory);
      this->is_max_value_lut->release(streams);
      delete this->is_max_value_lut;
      for (uint32_t L = 0; L < this->num_tree_levels; L++) {
        cuda_drop_async(this->d_level_lut_indexes[L], streams.stream(0),
                        streams.gpu_index(0));
      }
      delete[] this->d_level_lut_indexes;
    }

    cuda_drop_async(this->d_map, streams.stream(0), streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    if (this->tree_accumulator != nullptr) {
      delete this->tree_accumulator;
      delete this->tree_pbs_output;
    }
    delete[] this->h_map;
  }
};

/// @brief Wrapper selecting the equality-selector algorithm by entry count.
///
/// Holds whichever equality-selector buffer the entry count selects, so a
/// single allocation matches the algorithm host_kv_store_compute_eq_selectors
/// will run. Exactly one of the two pointers is non-null, decided by
/// num_entries against KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES.
///
/// @tparam Torus  Unsigned integer type representing a ciphertext torus element
template <typename Torus> struct int_kv_store_eq_selectors_wrapper_buffer {
  /// True when the tree variant is selected
  bool use_small_map;
  /// Tree-based buffer for few entries (non-null when use_small_map)
  int_kv_store_eq_selectors_small_map_buffer<Torus> *small_map_buffer;
  /// Sequential-scan buffer for many entries (non-null when !use_small_map)
  int_eq_selectors_ct_vs_clears_buffer<Torus> *vector_find_buffer;

  /// @brief Allocates the appropriate equality-selector sub-buffer.
  ///
  /// @param num_entries    Number of stored keys in the map
  /// @param num_key_blocks Number of radix blocks per key
  int_kv_store_eq_selectors_wrapper_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_entries,
      uint32_t num_key_blocks, bool allocate_gpu_memory, uint64_t &size_tracker)
      : small_map_buffer(nullptr), vector_find_buffer(nullptr) {
    this->use_small_map =
        num_entries <= KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES;
    if (this->use_small_map) {
      this->small_map_buffer =
          new int_kv_store_eq_selectors_small_map_buffer<Torus>(
              streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
              size_tracker);
      this->vector_find_buffer = nullptr;
    } else {
      this->vector_find_buffer =
          new int_eq_selectors_ct_vs_clears_buffer<Torus>(
              streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
              size_tracker);
      this->small_map_buffer = nullptr;
    }
  }

  void release(CudaStreams streams) {
    if (this->small_map_buffer) {
      this->small_map_buffer->release(streams);
      delete this->small_map_buffer;
    }
    if (this->vector_find_buffer) {
      this->vector_find_buffer->release(streams);
      delete this->vector_find_buffer;
    }
  }
};

/// @brief GPU scratch buffer for homomorphic kv_store get (value lookup by
/// key).
///
/// Preallocates all intermediate buffers needed to look up an encrypted value
/// by comparing an encrypted key against all stored clear keys, zero-out
/// non-matching entries, and sum the survivors.
///
/// @tparam Torus  Unsigned integer type representing a ciphertext torus element
template <typename Torus> struct int_kv_store_get_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// Number of stored key-value pairs
  uint32_t num_entries;
  /// Number of radix blocks per key
  uint32_t num_key_blocks;
  /// Number of radix blocks per value
  uint32_t num_value_blocks;

  /// Message modulus from radix parameters
  Torus message_modulus;
  /// Carry modulus from radix parameters
  Torus carry_modulus;

  /// Equality-selector sub-buffer (one boolean per entry)
  int_kv_store_eq_selectors_wrapper_buffer<Torus> *mem_eq_selectors_buffer;

  /// Batch zero-out buffer for the one-hot vector step
  int_zero_out_if_batch_buffer<Torus> *mem_zero_out_batch_buffer;
  /// Bivariate LUT: keep block if selector is nonzero, else zero
  int_radix_lut<Torus> *one_hot_vector_predicate;
  /// Scratch ciphertext for the one-hot vector
  CudaRadixCiphertextFFI *tmp_cmux_array;
  /// Identity LUT for carry propagation during the sum step
  int_radix_lut<Torus> *identity_lut;

  /// OR-reduction scratch producing the key-found boolean
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  /// @brief Allocates GPU buffers required for kv_store get.
  ///
  /// @param num_entries      Number of stored key-value pairs
  /// @param num_key_blocks   Number of radix blocks per key
  /// @param num_value_blocks Number of radix blocks per value
  int_kv_store_get_buffer(CudaStreams streams, int_radix_params params,
                          uint32_t num_entries, uint32_t num_key_blocks,
                          uint32_t num_value_blocks, bool allocate_gpu_memory,
                          uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        num_entries(num_entries), num_key_blocks(num_key_blocks),
        num_value_blocks(num_value_blocks) {

    this->message_modulus = params.message_modulus;
    this->carry_modulus = params.carry_modulus;

    uint32_t total_value_blocks =
        static_cast<uint32_t>(safe_mul(static_cast<size_t>(num_entries),
                                       static_cast<size_t>(num_value_blocks)));

    this->mem_eq_selectors_buffer =
        new int_kv_store_eq_selectors_wrapper_buffer<Torus>(
            streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
            size_tracker);

    this->mem_zero_out_batch_buffer = new int_zero_out_if_batch_buffer<Torus>(
        streams, params, num_entries, num_value_blocks, allocate_gpu_memory,
        size_tracker);

    auto zero_out_predicate_lut_f = [](Torus block, Torus condition) -> Torus {
      if (condition == 0)
        return 0;
      else
        return block;
    };

    this->one_hot_vector_predicate =
        new int_radix_lut<Torus>(streams, params, 1, total_value_blocks,
                                 allocate_gpu_memory, size_tracker);

    auto active_streams =
        streams.active_gpu_subset(total_value_blocks, params.pbs_type);
    this->one_hot_vector_predicate->generate_and_broadcast_bivariate_lut(
        active_streams, {0}, {zero_out_predicate_lut_f}, LUT_0_FOR_ALL_BLOCKS);

    this->tmp_cmux_array = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_cmux_array,
        total_value_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint32_t max_entries_after_pbs_round = kv_sum_pbs_round_survivors(
        num_entries, params.message_modulus, params.carry_modulus);
    uint32_t pbs_batch_blocks = static_cast<uint32_t>(
        safe_mul(static_cast<size_t>(max_entries_after_pbs_round),
                 static_cast<size_t>(num_value_blocks)));

    std::function<Torus(Torus)> identity_fn = [](Torus x) -> Torus {
      return x;
    };
    this->identity_lut =
        new int_radix_lut<Torus>(streams, params, 1, pbs_batch_blocks,
                                 allocate_gpu_memory, size_tracker);
    this->identity_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(pbs_batch_blocks, params.pbs_type), {0},
        {identity_fn}, LUT_0_FOR_ALL_BLOCKS);

    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_entries, false, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->at_least_one_true_buffer->release(streams);
    delete this->at_least_one_true_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_cmux_array,
                                   this->allocate_gpu_memory);

    this->one_hot_vector_predicate->release(streams);
    delete this->one_hot_vector_predicate;

    this->mem_zero_out_batch_buffer->release(streams);
    delete this->mem_zero_out_batch_buffer;

    this->identity_lut->release(streams);
    delete this->identity_lut;

    this->mem_eq_selectors_buffer->release(streams);
    delete this->mem_eq_selectors_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete this->tmp_cmux_array;
  }
};

/// @brief GPU scratch buffer for homomorphic kv_store update (conditional value
/// replacement).
///
/// Preallocates buffers for comparing an encrypted key against all stored
/// clear keys and replacing the matched entry's encrypted value with a new
/// one via batched CMUX.
///
/// @tparam Torus  Unsigned integer type representing a ciphertext torus element
template <typename Torus> struct int_kv_store_update_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  /// Number of stored key-value pairs
  uint32_t num_entries;
  /// Number of radix blocks per key
  uint32_t num_key_blocks;
  /// Number of radix blocks per value
  uint32_t num_value_blocks;

  /// Message modulus from radix parameters
  Torus message_modulus;
  /// Carry modulus from radix parameters
  Torus carry_modulus;

  /// Batched CMUX buffer for conditional value replacement
  int_cmux_batch_buffer<Torus> *cmux_batch_buffer;

  /// Equality-selector sub-buffer (one boolean per entry)
  int_kv_store_eq_selectors_wrapper_buffer<Torus> *mem_eq_selectors_buffer;

  /// Contiguous buffer for selectors, one boolean per entry
  CudaRadixCiphertextFFI *selectors_contiguous;

  /// OR-reduction scratch producing the key-found boolean
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  /// @brief Allocates GPU buffers required for kv_store update.
  ///
  /// @param num_entries      Number of stored key-value pairs
  /// @param num_key_blocks   Number of radix blocks per key
  /// @param num_value_blocks Number of radix blocks per value
  int_kv_store_update_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t num_entries, uint32_t num_key_blocks,
                             uint32_t num_value_blocks,
                             bool allocate_gpu_memory, uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        gpu_memory_allocated(allocate_gpu_memory), num_entries(num_entries),
        num_key_blocks(num_key_blocks), num_value_blocks(num_value_blocks) {

    this->message_modulus = params.message_modulus;
    this->carry_modulus = params.carry_modulus;

    // Equality selectors
    this->mem_eq_selectors_buffer =
        new int_kv_store_eq_selectors_wrapper_buffer<Torus>(
            streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
            size_tracker);

    this->selectors_contiguous = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->selectors_contiguous,
        num_entries, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    auto condition_is_one = [](Torus x) -> Torus { return x == 1; };
    size_tracker += scratch_cuda_cmux_batch<Torus>(
        streams, &this->cmux_batch_buffer, condition_is_one, num_entries,
        num_value_blocks, params, allocate_gpu_memory);

    // OR all selectors to produce a key-found boolean
    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_entries, false, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->at_least_one_true_buffer->release(streams);
    delete this->at_least_one_true_buffer;

    this->cmux_batch_buffer->release(streams);
    delete this->cmux_batch_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->selectors_contiguous,
                                   this->gpu_memory_allocated);

    this->mem_eq_selectors_buffer->release(streams);
    delete this->mem_eq_selectors_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete this->selectors_contiguous;
  }
};

/// @brief GPU scratch buffer for homomorphic kv_store map (selector-driven
/// conditional update).
///
/// Preallocates buffers for the inner CMUX step shared by update and insert:
/// given pre-computed selectors (one boolean per entry), replace matched
/// entries' values with a new one. Does not compute equality selectors itself.
///
/// @tparam Torus  Unsigned integer type representing a ciphertext torus element
template <typename Torus> struct int_kv_store_map_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  /// Number of stored key-value pairs
  uint32_t num_entries;
  /// Number of radix blocks per value
  uint32_t num_value_blocks;

  /// Message modulus from radix parameters
  Torus message_modulus;
  /// Carry modulus from radix parameters
  Torus carry_modulus;

  /// Batched CMUX buffer for conditional value replacement
  int_cmux_batch_buffer<Torus> *cmux_batch_buffer;

  /// OR-reduction scratch producing the key-found boolean
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  /// @brief Allocates GPU buffers required for kv_store map.
  ///
  /// @param num_entries      Number of stored key-value pairs
  /// @param num_value_blocks Number of radix blocks per value
  int_kv_store_map_buffer(CudaStreams streams, int_radix_params params,
                          uint32_t num_entries, uint32_t num_value_blocks,
                          bool allocate_gpu_memory, uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        gpu_memory_allocated(allocate_gpu_memory), num_entries(num_entries),
        num_value_blocks(num_value_blocks) {

    this->message_modulus = params.message_modulus;
    this->carry_modulus = params.carry_modulus;

    // Parallel CMUXes
    auto predicate_lut_f = [](Torus x) -> Torus { return x == 1; };
    size_tracker += scratch_cuda_cmux_batch<Torus>(
        streams, &this->cmux_batch_buffer, predicate_lut_f, num_entries,
        num_value_blocks, params, allocate_gpu_memory);

    // OR all selectors to produce a key-found boolean
    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_entries, false, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->at_least_one_true_buffer->release(streams);
    delete this->at_least_one_true_buffer;

    this->cmux_batch_buffer->release(streams);
    delete this->cmux_batch_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/// @brief GPU scratch buffer for homomorphic kv_store contains_key (key
/// existence check).
///
/// Preallocates buffers for comparing an encrypted key against all stored
/// clear keys and OR-reducing the per-entry booleans into a single
/// key-found flag.
///
/// @tparam Torus  Unsigned integer type representing a ciphertext torus element
template <typename Torus> struct int_kv_store_contains_key_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  /// Number of stored keys
  uint32_t num_entries;
  /// Number of radix blocks per key
  uint32_t num_key_blocks;

  /// Message modulus from radix parameters
  Torus message_modulus;
  /// Carry modulus from radix parameters
  Torus carry_modulus;

  /// Equality-selector sub-buffer (one boolean per entry)
  int_kv_store_eq_selectors_wrapper_buffer<Torus> *mem_eq_selectors_buffer;

  /// Contiguous buffer for selectors, one boolean per entry
  CudaRadixCiphertextFFI *selectors_contiguous;

  /// OR-reduction scratch producing the key-found boolean
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  /// @brief Allocates GPU buffers required for kv_store contains_key.
  ///
  /// @param num_entries    Number of stored keys
  /// @param num_key_blocks Number of radix blocks per key
  int_kv_store_contains_key_buffer(CudaStreams streams, int_radix_params params,
                                   uint32_t num_entries,
                                   uint32_t num_key_blocks,
                                   bool allocate_gpu_memory,
                                   uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        gpu_memory_allocated(allocate_gpu_memory), num_entries(num_entries),
        num_key_blocks(num_key_blocks) {

    this->message_modulus = params.message_modulus;
    this->carry_modulus = params.carry_modulus;

    this->mem_eq_selectors_buffer =
        new int_kv_store_eq_selectors_wrapper_buffer<Torus>(
            streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
            size_tracker);

    this->selectors_contiguous = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->selectors_contiguous,
        num_entries, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_entries, false, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->at_least_one_true_buffer->release(streams);
    delete this->at_least_one_true_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->selectors_contiguous,
                                   this->gpu_memory_allocated);

    this->mem_eq_selectors_buffer->release(streams);
    delete this->mem_eq_selectors_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete this->selectors_contiguous;
  }
};

#endif // CUDA_INTEGER_KV_STORE_UTILITIES_H
