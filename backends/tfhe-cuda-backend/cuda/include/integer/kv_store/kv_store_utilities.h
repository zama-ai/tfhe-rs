#ifndef CUDA_INTEGER_KV_STORE_UTILITIES_H
#define CUDA_INTEGER_KV_STORE_UTILITIES_H

#include "../comparison.h"
#include "../vector_find.h"
#include "integer/cmux.cuh"
#include "integer/radix_ciphertext.cuh"

// Threshold on the entry count that selects which equality-selector algorithm
// kv_store uses. On H100 (u64 keys, classical params) the small-map tree
// variant is 28-39% faster at 16-64 entries, the two are within ~3% at 256,
// and the vector_find sequential variant pulls ~9% ahead at 1024. The same
// crossover holds under multi-bit params. The small-map variant wins on PBS
// depth (2 levels vs ~3 sequential rounds); the vector_find variant wins on
// total PBS count once a single batch saturates the GPU. num_entries strictly
// greater than this uses vector_find's host_compute_eq_selectors_ct_vs_clears;
// otherwise the small-map tree variant below is used. The scratch-time buffer
// choice and the runtime dispatch both read this constant so they cannot drift.
constexpr uint32_t KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES = 256;

// kv_store-specific equality-selector buffer for the few-entries case.
//
// Given one encrypted radix key and the num_possible_values block-decomposed
// clear keys, computes one encrypted boolean per clear key (input == key_i).
// It precomputes all per-block comparisons in one batched grid PBS, gathers
// each key's comparison blocks, then AND-reduces every key in parallel with a
// batched tree: at each level it accumulates chunks of size max_value and
// applies one large is_max_value PBS, so a multi-block key reduces in
// ceil(log_max_value(num_key_blocks)) batched PBS rounds (2 for typical 2_2
// params with 16-block keys) instead of one sequential round per chunk.
template <typename Torus> struct int_kv_store_eq_selectors_small_map_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t lut_stride;

  uint32_t num_possible_values;

  // Grid PBS resources (shared step 1)
  int_radix_lut<Torus> *comparison_luts;
  CudaRadixCiphertextFFI tmp_many_luts_output;

  // Gather resources (step 2: align_with_indexes)
  CudaRadixCiphertextFFI tmp_batched_comparisons;
  Torus *d_map;
  Torus *h_map;

  // Tree reduction resources (step 3: host_accumulate_all_blocks_batched + PBS)
  CudaRadixCiphertextFFI *tree_accumulator;
  CudaRadixCiphertextFFI *tree_pbs_output;
  int_radix_lut<Torus> *is_max_value_lut;
  uint32_t max_value;
  uint32_t max_chunks;

  // Per-level precomputed LUT-index buffers for the tree reduction (PM2).
  //
  // The AND-reduction at each tree level packs each entry's blocks into chunks
  // of size max_value and applies an is_max LUT, except for the (possibly
  // shorter) last chunk of every entry, which needs an is_equal_to_last LUT
  // keyed on last_chunk_length. last_chunk_length is a deterministic function
  // of num_blocks and max_value, so the whole level schedule is known at
  // scratch time. We bake every distinct is_equal_to_last function into its own
  // slot of is_max_value_lut (slot 0 stays is_max) and precompute one device
  // lut-index buffer per level. At runtime the loop only switches indexes
  // (a small gpu-to-gpu copy + broadcast) instead of regenerating the LUT
  // polynomial on the host and broadcasting it, then resetting, every level.
  uint32_t num_tree_levels;
  Torus **d_level_lut_indexes;

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

    std::vector<std::function<Torus(Torus)>> fns;
    fns.reserve(params.message_modulus);
    for (uint32_t i = 0; i < params.message_modulus; i++) {
      fns.push_back([i](Torus x) -> Torus { return (x == i); });
    }

    this->comparison_luts->generate_and_broadcast_many_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {fns},
        LUT_0_FOR_ALL_BLOCKS);
    fns.clear();

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_many_luts_output,
        params.message_modulus * num_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    // Gather buffer: row-major layout [entry_0_blk_0, entry_0_blk_1, ...]
    uint64_t total_blocks64 = (uint64_t)num_possible_values * num_blocks;
    PANIC_IF_FALSE(total_blocks64 <= UINT32_MAX,
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

    // Tree reduction resources
    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    this->max_value = (total_modulus - 1) / (params.message_modulus - 1);
    this->max_chunks =
        (num_blocks > 1) ? CEIL_DIV(num_blocks, this->max_value) : 1;

    if (num_blocks > 1) {
      uint32_t acc_blocks = num_possible_values * this->max_chunks;
      uint32_t mv = this->max_value;

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

      // Replay the reduction schedule to learn how many levels there are and,
      // per level, num_chunks / last_chunk_length. This mirrors the runtime
      // loop in host_kv_store_compute_eq_selectors_small_map exactly.
      std::vector<uint32_t> level_num_chunks;
      std::vector<uint32_t> level_last_chunk_length;
      {
        uint32_t blocks_per_entry = num_blocks;
        while (blocks_per_entry > 1) {
          uint32_t num_chunks = CEIL_DIV(blocks_per_entry, mv);
          uint32_t last_chunk_length = blocks_per_entry - (num_chunks - 1) * mv;
          level_num_chunks.push_back(num_chunks);
          level_last_chunk_length.push_back(last_chunk_length);
          blocks_per_entry = num_chunks;
        }
      }
      this->num_tree_levels = static_cast<uint32_t>(level_num_chunks.size());

      // Slot 0 is is_max; each level gets its own slot holding the
      // x == last_chunk_length function for that level. A slot whose function
      // is identical to is_max is harmless because its level's index buffer is
      // all zeros, so we keep one slot per level for a uniform mapping.
      uint32_t num_luts = 1 + this->num_tree_levels;
      this->is_max_value_lut =
          new int_radix_lut<Torus>(streams, params, num_luts, acc_blocks,
                                   allocate_gpu_memory, size_tracker);

      std::vector<uint32_t> lut_ids;
      std::vector<std::function<Torus(Torus)>> lut_fns;
      lut_ids.reserve(num_luts);
      lut_fns.reserve(num_luts);
      lut_ids.push_back(0);
      lut_fns.push_back([mv](Torus x) -> Torus { return x == mv; });
      for (uint32_t L = 0; L < this->num_tree_levels; L++) {
        uint32_t lcl = level_last_chunk_length[L];
        lut_ids.push_back(L + 1);
        lut_fns.push_back([lcl](Torus x) -> Torus { return x == lcl; });
      }

      auto lut_active = streams.active_gpu_subset(acc_blocks, params.pbs_type);
      // LUT_0_FOR_ALL_BLOCKS only sets default indexes; the real per-level
      // index buffers are precomputed below and switched in at runtime.
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
        bool special = (level_last_chunk_length[L] != mv);
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
    } else {
      this->tree_accumulator = nullptr;
      this->tree_pbs_output = nullptr;
      this->is_max_value_lut = nullptr;
      this->num_tree_levels = 0;
      this->d_level_lut_indexes = nullptr;
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

    if (this->tree_accumulator) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tree_accumulator,
                                     this->allocate_gpu_memory);
      delete this->tree_accumulator;
    }
    if (this->tree_pbs_output) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tree_pbs_output,
                                     this->allocate_gpu_memory);
      delete this->tree_pbs_output;
    }
    if (this->is_max_value_lut) {
      this->is_max_value_lut->release(streams);
      delete this->is_max_value_lut;
    }
    if (this->d_level_lut_indexes) {
      for (uint32_t L = 0; L < this->num_tree_levels; L++) {
        cuda_drop_async(this->d_level_lut_indexes[L], streams.stream(0),
                        streams.gpu_index(0));
      }
      delete[] this->d_level_lut_indexes;
    }

    cuda_drop_async(this->d_map, streams.stream(0), streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete[] this->h_map;
  }
};

// Holds whichever equality-selector buffer the entry count selects, so a single
// allocation matches the algorithm host_kv_store_compute_eq_selectors will run.
// Exactly one of the two pointers is non-null, decided by num_entries against
// KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES.
template <typename Torus> struct int_kv_store_eq_selectors_buffer {
  bool use_small_map;
  int_kv_store_eq_selectors_small_map_buffer<Torus> *small_map_buffer;
  int_eq_selectors_ct_vs_clears_buffer<Torus> *vector_find_buffer;

  int_kv_store_eq_selectors_buffer(CudaStreams streams, int_radix_params params,
                                   uint32_t num_entries,
                                   uint32_t num_key_blocks,
                                   bool allocate_gpu_memory,
                                   uint64_t &size_tracker)
      : small_map_buffer(nullptr), vector_find_buffer(nullptr) {
    this->use_small_map =
        num_entries <= KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES;
    if (this->use_small_map) {
      this->small_map_buffer =
          new int_kv_store_eq_selectors_small_map_buffer<Torus>(
              streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
              size_tracker);
    } else {
      this->vector_find_buffer =
          new int_eq_selectors_ct_vs_clears_buffer<Torus>(
              streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
              size_tracker);
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

template <typename Torus> struct int_kv_store_get_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_entries;
  uint32_t num_key_blocks;
  uint32_t num_value_blocks;

  Torus message_modulus;
  Torus carry_modulus;

  // Step 1: equality selectors (one encrypted boolean per entry)
  int_kv_store_eq_selectors_buffer<Torus> *mem_eq_selectors_buffer;

  // Step 2: one-hot vector generated via conditional zero-out
  int_zero_out_if_batch_buffer<Torus> *mem_zero_out_batch_buffer;
  // Bivariate LUT: preserves block when selector != 0, zeros it otherwise
  int_radix_lut<Torus> *one_hot_vector_predicate;
  // Scratch for one-hot vector (consumed in-place by step 3 binary tree sum)
  CudaRadixCiphertextFFI *tmp_cmux_array;
  // Step 3: Sum all elements in the vector (value-block-count dependent)
  // Uses the fast pairwise binary-tree-fold kernel
  int_radix_lut<Torus> *identity_lut;

  // Step 4: OR all selectors into a single boolean (this is the key-found flag)
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

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

    // Step 1: equality selectors (operates on key blocks)
    this->mem_eq_selectors_buffer = new int_kv_store_eq_selectors_buffer<Torus>(
        streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
        size_tracker);

    // Step 2: one-hot vector via conditional zero-out (operates on value
    // blocks)
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

    // Step 3: binary tree sum of the one-hot vector into a single entry
    this->tmp_cmux_array = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_cmux_array,
        total_value_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    // Step 3: identity LUT for binary tree fold sum. The largest identity PBS
    // batch is the first round's survivor count, since the per-round survivor
    // count shrinks monotonically. kv_sum_pbs_round_survivors is the single
    // source of truth shared with the host loop in host_binary_tree_fold_sum so
    // the batch sizing and the schedule cannot drift.
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

    // Step 4: OR all selectors to produce a key-found boolean
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
    delete this->tmp_cmux_array;

    this->one_hot_vector_predicate->release(streams);
    delete this->one_hot_vector_predicate;

    this->mem_zero_out_batch_buffer->release(streams);
    delete this->mem_zero_out_batch_buffer;

    this->identity_lut->release(streams);
    delete this->identity_lut;

    this->mem_eq_selectors_buffer->release(streams);
    delete this->mem_eq_selectors_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_kv_store_update_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  uint32_t num_entries;
  uint32_t num_key_blocks;
  uint32_t num_value_blocks;

  Torus message_modulus;
  Torus carry_modulus;

  int_cmux_batch_buffer<Torus> *cmux_batch_buffer;

  int_kv_store_eq_selectors_buffer<Torus> *mem_eq_selectors_buffer;

  // Contiguous buffer for selectors (num_entries blocks), sliced per entry
  CudaRadixCiphertextFFI *selectors_contiguous;
  CudaRadixCiphertextFFI *selectors_list;

  // OR-reduction scratch for key-found boolean
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  int_kv_store_update_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t num_entries, uint32_t num_key_blocks,
                             uint32_t num_value_blocks,
                             bool allocate_gpu_memory, uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        gpu_memory_allocated(allocate_gpu_memory), num_entries(num_entries),
        num_key_blocks(num_key_blocks), num_value_blocks(num_value_blocks) {

    this->message_modulus = params.message_modulus;
    this->carry_modulus = params.carry_modulus;

    // Equality selectors (operates on key blocks)
    this->mem_eq_selectors_buffer = new int_kv_store_eq_selectors_buffer<Torus>(
        streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
        size_tracker);

    this->selectors_contiguous = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->selectors_contiguous,
        num_entries, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->selectors_list = new CudaRadixCiphertextFFI[num_entries];
    for (uint32_t i = 0; i < num_entries; i++) {
      as_radix_ciphertext_slice<Torus>(&selectors_list[i], selectors_contiguous,
                                       i, i + 1);
    }

    // Parallel CMUXes (operates on value blocks)
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

    delete[] this->selectors_list;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->selectors_contiguous,
                                   this->gpu_memory_allocated);
    delete this->selectors_contiguous;

    this->mem_eq_selectors_buffer->release(streams);
    delete this->mem_eq_selectors_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_kv_store_map_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  uint32_t num_entries;
  uint32_t num_value_blocks;

  Torus message_modulus;
  Torus carry_modulus;

  int_cmux_batch_buffer<Torus> *cmux_batch_buffer;

  // OR-reduction scratch for key-found boolean
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  int_kv_store_map_buffer(CudaStreams streams, int_radix_params params,
                          uint32_t num_entries, uint32_t num_value_blocks,
                          bool allocate_gpu_memory, uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        gpu_memory_allocated(allocate_gpu_memory), num_entries(num_entries),
        num_value_blocks(num_value_blocks) {

    this->message_modulus = params.message_modulus;
    this->carry_modulus = params.carry_modulus;

    // Parallel CMUXes (operates on value blocks)
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

template <typename Torus> struct int_kv_store_contains_key_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  uint32_t num_entries;
  uint32_t num_key_blocks;

  Torus message_modulus;
  Torus carry_modulus;

  int_kv_store_eq_selectors_buffer<Torus> *mem_eq_selectors_buffer;

  // Contiguous buffer for selectors (num_entries blocks), sliced per entry
  CudaRadixCiphertextFFI *selectors_contiguous;
  CudaRadixCiphertextFFI *selectors_list;

  // OR-reduction scratch for key-found boolean
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

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

    this->mem_eq_selectors_buffer = new int_kv_store_eq_selectors_buffer<Torus>(
        streams, params, num_entries, num_key_blocks, allocate_gpu_memory,
        size_tracker);

    this->selectors_contiguous = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->selectors_contiguous,
        num_entries, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->selectors_list = new CudaRadixCiphertextFFI[num_entries];
    for (uint32_t i = 0; i < num_entries; i++) {
      as_radix_ciphertext_slice<Torus>(&selectors_list[i], selectors_contiguous,
                                       i, i + 1);
    }

    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_entries, false, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->at_least_one_true_buffer->release(streams);
    delete this->at_least_one_true_buffer;

    delete[] this->selectors_list;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->selectors_contiguous,
                                   this->gpu_memory_allocated);
    delete this->selectors_contiguous;

    this->mem_eq_selectors_buffer->release(streams);
    delete this->mem_eq_selectors_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

#endif // CUDA_INTEGER_KV_STORE_UTILITIES_H
