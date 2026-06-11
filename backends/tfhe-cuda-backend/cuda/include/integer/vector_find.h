#pragma once
#include "cast.h"
#include "helper_multi_gpu.h"
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"
#include <functional>
#include <vector>

template <typename Torus> struct int_equality_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t lut_stride;

  uint32_t num_possible_values;
  int_radix_lut<Torus> *comparison_luts;
  CudaRadixCiphertextFFI *tmp_many_luts_output;

  // Batched tree reduction: instead of per-entry AND-trees on separate streams,
  // gather all entries' comparison blocks and reduce level-by-level with large
  // batched PBS calls.
  CudaRadixCiphertextFFI *batched_comparisons;
  CudaRadixCiphertextFFI *tree_accumulator;
  CudaRadixCiphertextFFI *tree_pbs_output;
  int_radix_lut<Torus> *is_max_value_lut;
  Torus *preallocated_h_lut;
  uint32_t max_value;
  uint32_t max_chunks;

  int_equality_selectors_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_possible_values,
                                uint32_t num_blocks, bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_possible_values = num_possible_values;

    auto active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    uint32_t ciphertext_modulus = params.message_modulus * params.carry_modulus;
    uint32_t box_size = params.polynomial_size / ciphertext_modulus;
    lut_stride = (ciphertext_modulus / params.message_modulus) * box_size;

    this->comparison_luts = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, params.message_modulus,
        allocate_gpu_memory, size_tracker);

    std::vector<std::function<Torus(Torus)>> fns;
    fns.reserve(params.message_modulus);
    for (uint32_t i = 0; i < params.message_modulus; i++) {
      fns.push_back([i](Torus x) -> Torus { return (x == i); });
    }

    this->comparison_luts->generate_and_broadcast_many_lut(
        active_streams, {0}, {fns}, LUT_0_FOR_ALL_BLOCKS);
    fns.clear();

    this->tmp_many_luts_output = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_many_luts_output,
        params.message_modulus * num_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    this->max_value = (total_modulus - 1) / (params.message_modulus - 1);
    this->max_chunks =
        (num_blocks > 1) ? CEIL_DIV(num_blocks, this->max_value) : 1;

    this->batched_comparisons = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->batched_comparisons,
        num_possible_values * std::max(num_blocks, 1u),
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    if (num_blocks > 1) {
      uint32_t acc_blocks = num_possible_values * this->max_chunks;

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

      this->is_max_value_lut = new int_radix_lut<Torus>(
          streams, params, 2, acc_blocks, allocate_gpu_memory, size_tracker);

      uint32_t mv = this->max_value;
      auto is_max_fn = [mv](Torus x) -> Torus { return x == mv; };
      auto lut_active = streams.active_gpu_subset(acc_blocks, params.pbs_type);
      this->is_max_value_lut->generate_and_broadcast_lut(
          lut_active, {0}, {is_max_fn}, LUT_0_FOR_ALL_BLOCKS);

      this->preallocated_h_lut = (Torus *)malloc(safe_mul_sizeof<Torus>(
          params.glwe_dimension + 1, params.polynomial_size));
    } else {
      this->tree_accumulator = nullptr;
      this->tree_pbs_output = nullptr;
      this->is_max_value_lut = nullptr;
      this->preallocated_h_lut = nullptr;
    }
  }

  void release(CudaStreams streams) {
    this->comparison_luts->release(streams);
    delete this->comparison_luts;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_many_luts_output,
                                   this->allocate_gpu_memory);
    delete this->tmp_many_luts_output;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->batched_comparisons,
                                   this->allocate_gpu_memory);
    delete this->batched_comparisons;

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
    free(this->preallocated_h_lut);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_eq_selectors_ct_vs_clears_buffer {
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
  Torus *preallocated_h_lut;
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

  int_eq_selectors_ct_vs_clears_buffer(CudaStreams streams,
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
      // loop in host_compute_eq_selectors_ct_vs_clears exactly.
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

      this->preallocated_h_lut = (Torus *)malloc(safe_mul_sizeof<Torus>(
          params.glwe_dimension + 1, params.polynomial_size));
    } else {
      this->tree_accumulator = nullptr;
      this->tree_pbs_output = nullptr;
      this->is_max_value_lut = nullptr;
      this->preallocated_h_lut = nullptr;
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
    free(this->preallocated_h_lut);

    cuda_drop_async(this->d_map, streams.stream(0), streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete[] this->h_map;
  }
};

template <typename Torus> struct int_eq_selectors_cts_vs_ct_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t num_inputs;
  uint32_t num_blocks;
  uint32_t chunk_size;
  uint32_t max_degree;

  uint32_t num_luts_needed;

  int_radix_lut<Torus> *equality_lut;

  CudaRadixCiphertextFFI packed_accumulator;
  CudaRadixCiphertextFFI packed_current_block;
  CudaRadixCiphertextFFI packed_value_block;

  std::vector<int_radix_lut<Torus> *> luts_eq;

  Torus **h_input_ptrs;
  Torus **d_input_ptrs;

  int_eq_selectors_cts_vs_ct_buffer(CudaStreams streams,
                                    int_radix_params params,
                                    uint32_t num_inputs, uint32_t num_blocks,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;
    this->num_blocks = num_blocks;

    this->max_degree = params.max_degree();

    constexpr uint32_t TARGET_PBS_BATCH = 2048;
    uint32_t target_chunk = std::max(1u, TARGET_PBS_BATCH / num_blocks);
    this->chunk_size = std::max(1u, std::min(num_inputs, target_chunk));

    uint32_t biv_batch = this->chunk_size * num_blocks;
    uint32_t red_batch = this->chunk_size;

    auto eq_fn = [](Torus x, Torus y) -> Torus { return (x == y) ? 1 : 0; };

    this->equality_lut = new int_radix_lut<Torus>(
        streams, params, 1, biv_batch, allocate_gpu_memory, size_tracker);
    this->equality_lut->generate_and_broadcast_bivariate_lut(
        streams.active_gpu_subset(biv_batch, params.pbs_type), {0}, {eq_fn},
        LUT_0_FOR_ALL_BLOCKS);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_accumulator,
        red_batch, params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_current_block,
        biv_batch, params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_value_block,
        biv_batch, params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->num_luts_needed = std::min(this->max_degree, num_blocks);
    this->luts_eq.assign(this->num_luts_needed + 1, nullptr);
    for (uint32_t k = 2; k <= this->num_luts_needed; k++) {
      auto f_eq_k = [k](Torus x) -> Torus { return (x == k) ? 1 : 0; };
      this->luts_eq[k] = new int_radix_lut<Torus>(
          streams, params, 1, red_batch, allocate_gpu_memory, size_tracker);
      this->luts_eq[k]->generate_and_broadcast_lut(
          streams.active_gpu_subset(red_batch, params.pbs_type), {0}, {f_eq_k},
          LUT_0_FOR_ALL_BLOCKS);
    }

    this->h_input_ptrs = (Torus **)malloc(safe_mul_sizeof<Torus *>(num_inputs));
    this->d_input_ptrs = (Torus **)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus *>(num_inputs), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->equality_lut->release(streams);
    delete this->equality_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_accumulator,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_current_block,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_value_block,
                                   this->allocate_gpu_memory);

    for (uint32_t k = 2; k <= this->num_luts_needed; k++) {
      this->luts_eq[k]->release(streams);
      delete this->luts_eq[k];
    }

    cuda_drop_async(this->d_input_ptrs, streams.stream(0),
                    streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(this->h_input_ptrs);
  }
};

template <typename Torus> struct int_possible_results_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t max_packed_value;
  uint32_t max_luts_per_call;
  uint32_t num_lut_accumulators;
  uint32_t lut_stride;
  uint32_t num_possible_values;
  uint32_t num_blocks;

  int_radix_lut<Torus> *batched_accumulators_lut;

  CudaRadixCiphertextFFI tmp_batched_selectors;
  CudaRadixCiphertextFFI tmp_many_luts_output;

  Torus *d_dst_ptrs;
  Torus *h_dst_ptrs;
  uint32_t *d_src_idx;
  uint32_t *h_src_idx;

  int_possible_results_buffer(CudaStreams streams, int_radix_params params,
                              uint32_t num_blocks, uint32_t num_possible_values,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_possible_values = num_possible_values;
    this->num_blocks = num_blocks;

    this->max_packed_value = params.message_modulus * params.message_modulus;
    uint32_t total_luts_needed = this->max_packed_value;

    uint32_t ciphertext_modulus = params.message_modulus * params.carry_modulus;
    uint32_t box_size = params.polynomial_size / ciphertext_modulus;

    this->max_luts_per_call = (ciphertext_modulus) / 2;
    if (this->max_luts_per_call == 0) {
      this->max_luts_per_call = 1;
    }

    this->lut_stride =
        (ciphertext_modulus / this->max_luts_per_call) * box_size;
    this->num_lut_accumulators = CEIL_DIV(total_luts_needed, max_luts_per_call);

    uint64_t total_lut_blocks_u64 =
        (uint64_t)num_lut_accumulators * num_possible_values;
    PANIC_IF_FALSE(total_lut_blocks_u64 <= UINT32_MAX,
                   "num_lut_accumulators * num_possible_values must fit in "
                   "uint32_t");
    uint32_t total_lut_blocks = (uint32_t)total_lut_blocks_u64;

    this->batched_accumulators_lut = new int_radix_lut<Torus>(
        streams, params, num_lut_accumulators, total_lut_blocks,
        max_luts_per_call, allocate_gpu_memory, size_tracker);

    std::vector<std::vector<std::function<Torus(Torus)>>> all_fns;
    std::vector<uint32_t> lut_generation_indices(num_lut_accumulators);
    all_fns.reserve(num_lut_accumulators);
    for (uint32_t k = 0; k < num_lut_accumulators; k++) {
      std::vector<std::function<Torus(Torus)>> current_fns;
      current_fns.reserve(max_luts_per_call);
      for (uint32_t j = 0; j < max_luts_per_call; j++) {
        uint32_t c = k * max_luts_per_call + j;
        if (c < total_luts_needed) {
          current_fns.push_back([c](Torus x) -> Torus { return (x == 1) * c; });
        } else {
          current_fns.push_back([](Torus) -> Torus { return 0; });
        }
      }
      all_fns.push_back(std::move(current_fns));
      lut_generation_indices[k] = k;
    }

    auto lut_active_streams =
        streams.active_gpu_subset(total_lut_blocks, params.pbs_type);

    auto idx_gen = [num_possible_values](Torus *idx, uint32_t count) {
      for (uint32_t b = 0; b < count; b++) {
        idx[b] = b / num_possible_values;
      }
    };
    this->batched_accumulators_lut->generate_and_broadcast_many_lut(
        lut_active_streams, lut_generation_indices, all_fns, idx_gen);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_batched_selectors,
        total_lut_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint64_t many_luts_out_u64 = (uint64_t)total_lut_blocks * max_luts_per_call;
    PANIC_IF_FALSE(many_luts_out_u64 <= UINT32_MAX,
                   "total_lut_blocks * max_luts_per_call must fit in uint32_t");
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_many_luts_output,
        (uint32_t)many_luts_out_u64, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint64_t total_scatter_indices_u64 =
        (uint64_t)num_possible_values * num_blocks;
    PANIC_IF_FALSE(total_scatter_indices_u64 <= UINT32_MAX,
                   "num_possible_values * num_blocks must fit in uint32_t");
    uint32_t total_scatter_indices = (uint32_t)total_scatter_indices_u64;
    this->h_dst_ptrs =
        (Torus *)malloc(safe_mul_sizeof<Torus *>(num_possible_values));
    this->h_src_idx = new uint32_t[total_scatter_indices];
    this->d_dst_ptrs = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus *>(num_possible_values), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    this->d_src_idx = (uint32_t *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<uint32_t>(total_scatter_indices), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->batched_accumulators_lut->release(streams);
    delete this->batched_accumulators_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_batched_selectors,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_many_luts_output,
                                   this->allocate_gpu_memory);

    cuda_drop_async(this->d_dst_ptrs, streams.stream(0), streams.gpu_index(0));
    cuda_drop_async(this->d_src_idx, streams.stream(0), streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(this->h_dst_ptrs);
    delete[] this->h_src_idx;
  }
};

template <typename Torus> struct int_aggregate_one_hot_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t chunk_size;

  int_radix_lut<Torus> *identity_lut;
  int_radix_lut<Torus> *batched_identity_lut;

  int_radix_lut<Torus> *message_extract_lut;
  int_radix_lut<Torus> *carry_extract_lut;

  CudaRadixCiphertextFFI packed_partial_temp_vectors;
  CudaRadixCiphertextFFI tree_reduction_buf;

  CudaRadixCiphertextFFI message_ct;
  CudaRadixCiphertextFFI carry_ct;

  Torus **h_input_ptrs;
  Torus **d_input_ptrs;
  uint32_t num_input_ciphertexts_capacity;

  int_aggregate_one_hot_buffer(CudaStreams streams, int_radix_params params,
                               uint32_t num_blocks, uint32_t num_matches,
                               bool allocate_gpu_memory,
                               uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_input_ciphertexts_capacity = num_matches;

    this->chunk_size = params.max_degree();

    std::function<Torus(Torus)> id_fn = [](Torus x) -> Torus { return x; };

    this->identity_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    this->identity_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {id_fn},
        LUT_0_FOR_ALL_BLOCKS);

    uint64_t batched_blocks_u64 = (uint64_t)num_matches * num_blocks;
    PANIC_IF_FALSE(batched_blocks_u64 <= UINT32_MAX,
                   "num_matches * num_blocks must fit in uint32_t");
    uint32_t batched_blocks = (uint32_t)batched_blocks_u64;

    this->batched_identity_lut = new int_radix_lut<Torus>(
        streams, params, 1, batched_blocks, allocate_gpu_memory, size_tracker);
    this->batched_identity_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(batched_blocks, params.pbs_type), {0},
        {id_fn}, LUT_0_FOR_ALL_BLOCKS);

    std::function<Torus(Torus)> msg_fn = [params](Torus x) -> Torus {
      return (x % params.message_modulus) % params.message_modulus;
    };
    std::function<Torus(Torus)> carry_fn = [params](Torus x) -> Torus {
      return x / params.message_modulus;
    };

    this->message_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    this->message_extract_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {msg_fn},
        LUT_0_FOR_ALL_BLOCKS);

    this->carry_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    this->carry_extract_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {carry_fn},
        LUT_0_FOR_ALL_BLOCKS);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        &this->packed_partial_temp_vectors, batched_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tree_reduction_buf,
        batched_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->message_ct, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->carry_ct, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->h_input_ptrs =
        (Torus **)malloc(safe_mul_sizeof<Torus *>(num_matches));
    this->d_input_ptrs = (Torus **)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus *>(num_matches), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->identity_lut->release(streams);
    delete this->identity_lut;

    this->batched_identity_lut->release(streams);
    delete this->batched_identity_lut;

    this->message_extract_lut->release(streams);
    delete this->message_extract_lut;
    this->carry_extract_lut->release(streams);
    delete this->carry_extract_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_partial_temp_vectors,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tree_reduction_buf,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->message_ct,
                                   this->allocate_gpu_memory);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->carry_ct, this->allocate_gpu_memory);

    cuda_drop_async(this->d_input_ptrs, streams.stream(0),
                    streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(this->h_input_ptrs);
  }
};

template <typename Torus> struct int_binary_tree_sum_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t chunk_size;

  int_radix_lut<Torus> *batched_identity_lut;

  CudaRadixCiphertextFFI packed_partial_temp_vectors;
  CudaRadixCiphertextFFI tree_reduction_buf;

  uint32_t num_input_ciphertexts;

  int_binary_tree_sum_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t num_blocks,
                             uint32_t num_input_ciphertexts,
                             bool allocate_gpu_memory, uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        chunk_size(params.max_degree()),
        num_input_ciphertexts(num_input_ciphertexts) {

    std::function<Torus(Torus)> id_fn = [](Torus x) -> Torus { return x; };

    uint64_t batched_blocks_u64 = (uint64_t)num_input_ciphertexts * num_blocks;
    PANIC_IF_FALSE(batched_blocks_u64 <= UINT32_MAX,
                   "num_input_ciphertexts * num_blocks must fit in uint32_t");
    uint32_t batched_blocks = (uint32_t)batched_blocks_u64;

    this->batched_identity_lut = new int_radix_lut<Torus>(
        streams, params, 1, batched_blocks, allocate_gpu_memory, size_tracker);
    this->batched_identity_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(batched_blocks, params.pbs_type), {0},
        {id_fn}, LUT_0_FOR_ALL_BLOCKS);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        &this->packed_partial_temp_vectors, batched_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tree_reduction_buf,
        batched_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->batched_identity_lut->release(streams);
    delete this->batched_identity_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_partial_temp_vectors,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tree_reduction_buf,
                                   this->allocate_gpu_memory);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_match_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_matches;
  uint32_t num_input_blocks;
  uint32_t num_output_packed_blocks;
  bool max_output_is_zero;

  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_selectors_buffer;
  int_possible_results_buffer<Torus> *possible_results_buffer;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buffer;
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  CudaRadixCiphertextFFI packed_selectors_ct;
  std::vector<CudaRadixCiphertextFFI> possible_results_list;

  int_unchecked_match_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t num_matches, uint32_t num_input_blocks,
                             uint32_t num_output_packed_blocks,
                             bool max_output_is_zero, bool allocate_gpu_memory,
                             uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_matches = num_matches;
    this->num_input_blocks = num_input_blocks;
    this->num_output_packed_blocks = num_output_packed_blocks;
    this->max_output_is_zero = max_output_is_zero;

    this->eq_selectors_buffer = new int_eq_selectors_ct_vs_clears_buffer<Torus>(
        streams, params, num_matches, num_input_blocks, allocate_gpu_memory,
        size_tracker);

    this->possible_results_buffer = new int_possible_results_buffer<Torus>(
        streams, params, num_output_packed_blocks, num_matches,
        allocate_gpu_memory, size_tracker);

    if (!max_output_is_zero) {
      this->aggregate_buffer = new int_aggregate_one_hot_buffer<Torus>(
          streams, params, num_output_packed_blocks, num_matches,
          allocate_gpu_memory, size_tracker);
    }

    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_matches, false, allocate_gpu_memory,
        size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors_ct,
        num_matches, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->possible_results_list.resize(num_matches);
    if (!max_output_is_zero) {
      for (uint32_t i = 0; i < num_matches; i++) {
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            &this->possible_results_list[i], num_output_packed_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      }
    }
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buffer->release(streams);
    delete this->eq_selectors_buffer;

    this->possible_results_buffer->release(streams);
    delete this->possible_results_buffer;

    if (!max_output_is_zero) {
      this->aggregate_buffer->release(streams);
      delete this->aggregate_buffer;
    }

    this->at_least_one_true_buffer->release(streams);
    delete this->at_least_one_true_buffer;

    if (!max_output_is_zero) {
      for (uint32_t i = 0; i < num_matches; i++) {
        release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                       &this->possible_results_list[i],
                                       this->allocate_gpu_memory);
      }
    }

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors_ct,
                                   this->allocate_gpu_memory);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_match_value_or_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t num_matches;
  uint32_t num_input_blocks;
  uint32_t num_match_packed_blocks;
  uint32_t num_final_blocks;
  bool max_output_is_zero;

  int_unchecked_match_buffer<Torus> *match_buffer;
  int_cmux_buffer<Torus> *cmux_buffer;

  CudaRadixCiphertextFFI tmp_match_result;
  CudaRadixCiphertextFFI tmp_match_bool;
  CudaRadixCiphertextFFI tmp_or_value;

  Torus *d_or_value;

  int_unchecked_match_value_or_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_matches,
      uint32_t num_input_blocks, uint32_t num_match_packed_blocks,
      uint32_t num_final_blocks, bool max_output_is_zero,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_matches = num_matches;
    this->num_input_blocks = num_input_blocks;
    this->num_match_packed_blocks = num_match_packed_blocks;
    this->num_final_blocks = num_final_blocks;
    this->max_output_is_zero = max_output_is_zero;

    this->match_buffer = new int_unchecked_match_buffer<Torus>(
        streams, params, num_matches, num_input_blocks, num_match_packed_blocks,
        max_output_is_zero, allocate_gpu_memory, size_tracker);

    this->cmux_buffer = new int_cmux_buffer<Torus>(
        streams, [](Torus x) -> Torus { return x == 1; }, params,
        num_final_blocks, allocate_gpu_memory, size_tracker);

    this->d_or_value = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_final_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_match_result,
        num_final_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_match_bool, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_or_value,
        num_final_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->match_buffer->release(streams);
    delete this->match_buffer;

    this->cmux_buffer->release(streams);
    delete this->cmux_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_match_result,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_match_bool,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_or_value,
                                   this->allocate_gpu_memory);

    cuda_drop_async(this->d_or_value, streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI packed_selectors;
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;

  int_unchecked_contains_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_inputs, uint32_t num_blocks,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->eq_selectors_buf = new int_eq_selectors_cts_vs_ct_buffer<Torus>(
        streams, params, num_inputs, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       &this->packed_selectors, i, i + 1);
    }
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors,
                                   this->allocate_gpu_memory);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI packed_selectors;
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  CudaRadixCiphertextFFI tmp_clear_val;
  Torus *d_clear_val;

  int_unchecked_contains_clear_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->eq_selectors_buf = new int_eq_selectors_cts_vs_ct_buffer<Torus>(
        streams, params, num_inputs, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       &this->packed_selectors, i, i + 1);
    }

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_clear_val,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->d_clear_val = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors,
                                   this->allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_clear_val,
                                   this->allocate_gpu_memory);

    cuda_drop_async(this->d_clear_val, streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_is_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_clears;

  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_buffer;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI packed_selectors;

  int_unchecked_is_in_clears_buffer(CudaStreams streams,
                                    int_radix_params params,
                                    uint32_t num_clears, uint32_t num_blocks,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_clears = num_clears;

    this->eq_buffer = new int_eq_selectors_ct_vs_clears_buffer<Torus>(
        streams, params, num_clears, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_clears, false,
                                         allocate_gpu_memory, size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors,
        num_clears, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->eq_buffer->release(streams);
    delete this->eq_buffer;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors,
                                   this->allocate_gpu_memory);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_final_index_from_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI packed_selectors;
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  std::vector<CudaRadixCiphertextFFI> possible_results_ct_list;

  uint64_t *h_indices;

  int_final_index_from_selectors_buffer(CudaStreams streams,
                                        int_radix_params params,
                                        uint32_t num_inputs,
                                        uint32_t num_blocks_index,
                                        bool allocate_gpu_memory,
                                        uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       &this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }

    uint32_t num_bits_in_message = log2_int(params.message_modulus);
    uint32_t bits_per_packed_block = 2 * num_bits_in_message;

    h_indices = new uint64_t[safe_mul((size_t)num_inputs, (size_t)packed_len)];
    for (uint32_t i = 0; i < num_inputs; i++) {
      uint64_t val = i;
      for (uint32_t b = 0; b < packed_len; b++) {
        uint64_t mask = (1ULL << bits_per_packed_block) - 1;
        uint64_t block_val = (val >> (b * bits_per_packed_block)) & mask;
        h_indices[i * packed_len + b] = block_val;
      }
    }
  }

  void release(CudaStreams streams) {
    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors,
                                   this->allocate_gpu_memory);

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_index_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_clears;

  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_selectors_buf;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  int_unchecked_index_in_clears_buffer(CudaStreams streams,
                                       int_radix_params params,
                                       uint32_t num_clears, uint32_t num_blocks,
                                       uint32_t num_blocks_index,
                                       bool allocate_gpu_memory,
                                       uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_clears = num_clears;

    this->eq_selectors_buf = new int_eq_selectors_ct_vs_clears_buffer<Torus>(
        streams, params, num_clears, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_clears, num_blocks_index, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_first_index_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_unique;

  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_selectors_buf;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI packed_selectors;
  std::vector<CudaRadixCiphertextFFI> possible_results_ct_list;

  int_unchecked_first_index_in_clears_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_unique,
      uint32_t num_blocks, uint32_t num_blocks_index, bool allocate_gpu_memory,
      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_unique = num_unique;

    this->eq_selectors_buf = new int_eq_selectors_ct_vs_clears_buffer<Torus>(
        streams, params, num_unique, num_blocks, allocate_gpu_memory,
        size_tracker);

    uint32_t packed_len = (num_blocks_index + 1) / 2;
    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_unique, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_unique, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_unique, false,
                                         allocate_gpu_memory, size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors,
        num_unique, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->possible_results_ct_list.resize(num_unique);
    for (uint32_t i = 0; i < num_unique; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors,
                                   this->allocate_gpu_memory);

    for (uint32_t i = 0; i < num_unique; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_first_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI packed_selectors;
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  std::vector<CudaRadixCiphertextFFI> possible_results_ct_list;
  CudaRadixCiphertextFFI tmp_clear_val;
  Torus *d_clear_val;
  uint64_t *h_indices;

  int_radix_lut<Torus> *prefix_sum_lut;
  int_radix_lut<Torus> *cleanup_lut;

  int_unchecked_first_index_of_clear_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_inputs,
      uint32_t num_blocks, uint32_t num_blocks_index, bool allocate_gpu_memory,
      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->eq_selectors_buf = new int_eq_selectors_cts_vs_ct_buffer<Torus>(
        streams, params, num_inputs, num_blocks, allocate_gpu_memory,
        size_tracker);

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       &this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_clear_val,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->d_clear_val = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);

    h_indices = nullptr;
    if (allocate_gpu_memory) {
      uint32_t num_bits_in_message = log2_int(params.message_modulus);
      uint32_t bits_per_packed_block = 2 * num_bits_in_message;

      h_indices =
          new uint64_t[safe_mul((size_t)num_inputs, (size_t)packed_len)];
      for (uint32_t i = 0; i < num_inputs; i++) {
        uint64_t val = i;
        for (uint32_t b = 0; b < packed_len; b++) {
          uint64_t mask = (1ULL << bits_per_packed_block) - 1;
          uint64_t block_val = (val >> (b * bits_per_packed_block)) & mask;
          h_indices[i * packed_len + b] = block_val;
        }
      }
    }

    const Torus ALREADY_SEEN = 2;
    auto prefix_sum_fn = [ALREADY_SEEN](Torus current,
                                        Torus previous) -> Torus {
      if (previous == 1 || previous == ALREADY_SEEN) {
        return ALREADY_SEEN;
      }
      return current;
    };
    this->prefix_sum_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_inputs, allocate_gpu_memory, size_tracker);

    this->prefix_sum_lut->generate_and_broadcast_bivariate_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {prefix_sum_fn}, LUT_0_FOR_ALL_BLOCKS);

    auto cleanup_fn = [ALREADY_SEEN, params](Torus x) -> Torus {
      Torus val = x % params.message_modulus;
      if (val == ALREADY_SEEN)
        return 0;
      return val;
    };
    this->cleanup_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_inputs, allocate_gpu_memory, size_tracker);
    this->cleanup_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {cleanup_fn}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    this->prefix_sum_lut->release(streams);
    delete this->prefix_sum_lut;

    this->cleanup_lut->release(streams);
    delete this->cleanup_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors,
                                   this->allocate_gpu_memory);

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_clear_val,
                                   this->allocate_gpu_memory);

    cuda_drop_async(this->d_clear_val, streams.stream(0), streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_first_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI packed_selectors;
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  std::vector<CudaRadixCiphertextFFI> possible_results_ct_list;
  uint64_t *h_indices;

  int_radix_lut<Torus> *prefix_sum_lut;
  int_radix_lut<Torus> *cleanup_lut;

  int_unchecked_first_index_of_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->eq_selectors_buf = new int_eq_selectors_cts_vs_ct_buffer<Torus>(
        streams, params, num_inputs, num_blocks, allocate_gpu_memory,
        size_tracker);

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       &this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list.resize(num_inputs);
    for (uint32_t i = 0; i < num_inputs; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }

    h_indices = nullptr;
    if (allocate_gpu_memory) {
      uint32_t num_bits_in_message = log2_int(params.message_modulus);
      uint32_t bits_per_packed_block = 2 * num_bits_in_message;

      h_indices =
          new uint64_t[safe_mul((size_t)num_inputs, (size_t)packed_len)];
      for (uint32_t i = 0; i < num_inputs; i++) {
        uint64_t val = i;
        for (uint32_t b = 0; b < packed_len; b++) {
          uint64_t mask = (1ULL << bits_per_packed_block) - 1;
          uint64_t block_val = (val >> (b * bits_per_packed_block)) & mask;
          h_indices[i * packed_len + b] = block_val;
        }
      }
    }

    const Torus ALREADY_SEEN = 2;
    auto prefix_sum_fn = [ALREADY_SEEN](Torus current,
                                        Torus previous) -> Torus {
      if (previous == 1 || previous == ALREADY_SEEN) {
        return ALREADY_SEEN;
      }
      return current;
    };
    this->prefix_sum_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_inputs, allocate_gpu_memory, size_tracker);

    this->prefix_sum_lut->generate_and_broadcast_bivariate_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {prefix_sum_fn}, LUT_0_FOR_ALL_BLOCKS);

    auto cleanup_fn = [ALREADY_SEEN, params](Torus x) -> Torus {
      Torus val = x % params.message_modulus;
      if (val == ALREADY_SEEN)
        return 0;
      return val;
    };
    this->cleanup_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_inputs, allocate_gpu_memory, size_tracker);
    this->cleanup_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {cleanup_fn}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    this->prefix_sum_lut->release(streams);
    delete this->prefix_sum_lut;

    this->cleanup_lut->release(streams);
    delete this->cleanup_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_selectors,
                                   this->allocate_gpu_memory);

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  int_unchecked_index_of_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_inputs, uint32_t num_blocks,
                                uint32_t num_blocks_index,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->eq_selectors_buf = new int_eq_selectors_cts_vs_ct_buffer<Torus>(
        streams, params, num_inputs, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_inputs, num_blocks_index, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  CudaRadixCiphertextFFI tmp_clear_val;
  Torus *d_clear_val;

  int_unchecked_index_of_clear_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->eq_selectors_buf = new int_eq_selectors_cts_vs_ct_buffer<Torus>(
        streams, params, num_inputs, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_inputs, num_blocks_index, allocate_gpu_memory,
        size_tracker);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_clear_val,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->d_clear_val = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_clear_val,
                                   this->allocate_gpu_memory);

    cuda_drop_async(this->d_clear_val, streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
