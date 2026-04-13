#pragma once
#include "cast.h"
#include "helper_multi_gpu.h"
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"
#include <functional>
#include <vector>

/**
 * @brief Generates the one-hot equality mask of an encrypted value against a
 * set of clear values.
 *
 * @details
 * The absence of conditional branching forces an exhaustive approach: the input
 * is compared to all clear candidates simultaneously, producing a one-hot
 * vector (all 0s with a single 1 at the matching index).
 */
template <typename Torus> struct int_eq_selectors_ct_vs_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// Address step between two packed LUTs.
  uint32_t lut_stride;

  /// How many clear candidates we test at once, also the mask length.
  uint32_t num_possible_values;
  /// Block-matches we may sum per LUT input before a refresh is needed.
  uint32_t max_degree;
  /// How many per-degree equality LUTs we actually build and use.
  uint32_t num_luts_needed;

  /// Many-LUT turning each input block into its equality profile.
  int_radix_lut<Torus> *comparison_luts;
  /// Raw equality profiles straight from the many-LUT, before gathering.
  CudaRadixCiphertextFFI tmp_many_luts_output;
  /// Equality cells regrouped one column per candidate, ready to AND.
  CudaRadixCiphertextFFI tmp_batched_comparisons;
  /// Collects the surviving boolean per candidate after the AND.
  CudaRadixCiphertextFFI packed_accumulator;

  /// Gather map on device, fed straight to the align kernel.
  Torus *d_map;
  /// Gather map: for each candidate block, which equality cell to read.
  Torus *h_map;

  /// Per-degree LUTs that AND a packed sum of block-matches.
  std::vector<int_radix_lut<Torus> *> luts_eq;

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

    uint64_t total_blocks = (uint64_t)num_possible_values * num_blocks;
    PANIC_IF_FALSE(total_blocks <= UINT32_MAX,
                   "num_possible_values * num_blocks must fit in uint32_t");

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_batched_comparisons,
        (uint32_t)total_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->packed_accumulator,
        num_possible_values, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->max_degree = params.max_degree();
    this->num_luts_needed = std::min(this->max_degree, num_blocks);
    this->luts_eq.assign(this->num_luts_needed + 1, nullptr);
    for (uint32_t k = 2; k <= this->num_luts_needed; k++) {
      auto f_eq_k = [k](Torus x) -> Torus { return (x == k) ? 1 : 0; };
      this->luts_eq[k] =
          new int_radix_lut<Torus>(streams, params, 1, num_possible_values,
                                   allocate_gpu_memory, size_tracker);
      this->luts_eq[k]->generate_and_broadcast_lut(
          streams.active_gpu_subset(num_possible_values, params.pbs_type), {0},
          {f_eq_k}, LUT_0_FOR_ALL_BLOCKS);
    }

    this->h_map = new Torus[total_blocks];
    this->d_map = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(total_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
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

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->packed_accumulator,
                                   this->allocate_gpu_memory);

    for (uint32_t k = 2; k <= this->num_luts_needed; k++) {
      this->luts_eq[k]->release(streams);
      delete this->luts_eq[k];
    }

    cuda_drop_async(this->d_map, streams.stream(0), streams.gpu_index(0));
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete[] this->h_map;
  }
};

/**
 * @brief Generates a one-hot equality mask between an encrypted list and an
 * encrypted target.
 *
 * @details
 * Uses bivariate LUTs to compare list blocks to the target. The resulting
 * mask highlights the position of the encrypted target within the list.
 */
template <typename Torus> struct int_eq_selectors_cts_vs_ct_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  /// How many encrypted values in the list we compare to the target.
  uint32_t num_inputs;
  /// Radix-block width of each value (u64 in 2_2 params is 32 blocks).
  uint32_t num_blocks;
  /// How many inputs we feed through one bivariate PBS at a time.
  uint32_t chunk_size;
  /// Block-matches we may sum per LUT input before a refresh is needed.
  uint32_t max_degree;

  /// How many per-degree equality LUTs we actually build and use.
  uint32_t num_luts_needed;

  /// Bivariate LUT testing one input block against the target block.
  int_radix_lut<Torus> *equality_lut;

  /// Collects the surviving boolean per input after the AND.
  CudaRadixCiphertextFFI packed_accumulator;
  /// Holds the list blocks of the current chunk, first PBS operand.
  CudaRadixCiphertextFFI packed_current_block;
  /// Holds the target blocks duplicated per input, second PBS operand.
  CudaRadixCiphertextFFI packed_value_block;

  /// Per-degree LUTs that AND a packed sum of block-matches.
  std::vector<int_radix_lut<Torus> *> luts_eq;

  /// Host list of pointers to each input, gathered before the device copy.
  Torus **h_input_ptrs;
  /// Device copy of the per-input pointers the packing kernel reads.
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

/**
 * @brief Materializes potential output values based on the one-hot selector
 * vector.
 *
 * @details
 * Multiplies each boolean selector from the one-hot mask (e.g. [0, 0, 1, 0]) by
 * its corresponding candidate value, yielding a sparse array where only the
 * matched value remains intact and the rest are zeroed out.
 */
template <typename Torus> struct int_possible_results_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  /// Largest value one accumulator LUT can emit, capping how we split them.
  uint32_t max_packed_value;
  /// How many candidate-value LUTs one many-LUT PBS can evaluate at once.
  uint32_t max_luts_per_call;
  /// How many many-LUT passes it takes to cover the whole value range.
  uint32_t num_lut_accumulators;
  /// Address step between two packed LUTs inside a polynomial.
  uint32_t lut_stride;
  /// How many candidate values the selector can pick from.
  uint32_t num_possible_values;
  /// Radix-block width of each value we materialize.
  uint32_t num_blocks;

  /// Many-LUT that maps each selector boolean to its candidate value.
  int_radix_lut<Torus> *batched_accumulators_lut;

  /// The selector mask broadcast once per accumulator pass, PBS input.
  CudaRadixCiphertextFFI tmp_batched_selectors;
  /// Materialized values fresh out of the many-LUT, awaiting the scatter.
  CudaRadixCiphertextFFI tmp_many_luts_output;

  /// Device pointers telling the scatter where each value must land.
  Torus *d_dst_ptrs;
  /// Host-built destination pointers, copied to the device before scatter.
  Torus *h_dst_ptrs;
  /// Device source index per block, picking which LUT output to keep.
  uint32_t *d_src_idx;
  /// Host-built source indices selecting each value's correct LUT output.
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

/**
 * @brief Merges the selected candidates into a single encrypted result.
 *
 * @details
 * Aggregates a sparse array of mostly zeros (e.g. [0, 0, TargetValue, 0, 0]) by
 * summing all elements. To avoid noise explosion from linear addition, it uses
 * a binary reduction tree with identity LUTs to safely collapse the array.
 */
template <typename Torus> struct int_aggregate_one_hot_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many ciphertexts one reduction-tree level sums before a refresh.
  uint32_t chunk_size;

  /// Identity PBS that refreshes noise on a single ciphertext.
  int_radix_lut<Torus> *identity_lut;
  /// Identity PBS refreshing a whole tree level at once.
  int_radix_lut<Torus> *batched_identity_lut;

  /// Pulls the low digit out of a packed block during the final unpack.
  int_radix_lut<Torus> *message_extract_lut;
  /// Pulls the high digit out of a packed block during the final unpack.
  int_radix_lut<Torus> *carry_extract_lut;

  /// Holds one tree level's partial sums, source of the next level.
  CudaRadixCiphertextFFI packed_partial_temp_vectors;
  /// Holds the next tree level's sums, swapped with the source each round.
  CudaRadixCiphertextFFI tree_reduction_buf;

  /// Low digits after unpacking, interleaved into the final result.
  CudaRadixCiphertextFFI message_ct;
  /// High digits after unpacking, interleaved into the final result.
  CudaRadixCiphertextFFI carry_ct;

  /// Host list of pointers to each candidate, gathered before the copy.
  Torus **h_input_ptrs;
  /// Device copy of the per-candidate pointers the sum kernel reads.
  Torus **d_input_ptrs;
  /// Largest candidate count the pointer arrays were sized for.
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

/**
 * @brief Orchestrates the match operation: a clear switch-case mapped onto
 * encrypted data.
 */
template <typename Torus> struct int_unchecked_match_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many match cases (clear keys) the table maps from.
  uint32_t num_matches;
  /// Radix-block width of the key we look up.
  uint32_t num_input_blocks;
  /// Packed-block width of each case's output value.
  uint32_t num_output_packed_blocks;
  /// All outputs zero, so we skip aggregation and only emit the flag.
  bool max_output_is_zero;

  /// Builds the one-hot mask of the key against the clear cases.
  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_selectors_buffer;
  /// Turns the mask into each case's output value.
  int_possible_results_buffer<Torus> *possible_results_buffer;
  /// Sums the masked outputs down to the single matched value.
  int_aggregate_one_hot_buffer<Torus> *aggregate_buffer;
  /// OR-reduces the mask to tell whether any case matched.
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  /// The one-hot mask, one boolean per case packed together.
  CudaRadixCiphertextFFI packed_selectors_ct;
  /// Each case's output value, masked, awaiting the aggregation sum.
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

/**
 * @brief Orchestrates a match with a default fallback.
 */
template <typename Torus> struct int_unchecked_match_value_or_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  /// How many match cases (clear keys) the table maps from.
  uint32_t num_matches;
  /// Radix-block width of the key we look up.
  uint32_t num_input_blocks;
  /// Packed-block width of the match result before the CMUX.
  uint32_t num_match_packed_blocks;
  /// Radix-block width of the final result and the fallback value.
  uint32_t num_final_blocks;
  /// All match outputs zero, so the inner match skips aggregation.
  bool max_output_is_zero;

  /// Runs the table lookup and reports whether it matched.
  int_unchecked_match_buffer<Torus> *match_buffer;
  /// Picks the match result when found, else the fallback value.
  int_cmux_buffer<Torus> *cmux_buffer;

  /// The looked-up value, one CMUX input.
  CudaRadixCiphertextFFI tmp_match_result;
  /// The match flag steering the CMUX.
  CudaRadixCiphertextFFI tmp_match_bool;
  /// The clear fallback re-encrypted trivially, the other CMUX input.
  CudaRadixCiphertextFFI tmp_or_value;

  /// Device copy of the fallback digits before trivial encryption.
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

/**
 * @brief Orchestrates the contains operation over an encrypted list against an
 * encrypted needle (presence check, no index extracted).
 */
template <typename Torus> struct int_unchecked_contains_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many encrypted values we search through.
  uint32_t num_inputs;

  /// Builds the one-hot mask of the list against the encrypted needle.
  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  /// OR-reduces the mask to tell whether anything matched.
  int_comparison_buffer<Torus> *reduction_buffer;

  /// The one-hot mask, one boolean per list element packed together.
  CudaRadixCiphertextFFI packed_selectors;
  /// Per-element single-block views into the packed mask.
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

/**
 * @brief Orchestrates the contains operation over an encrypted list against a
 * clear needle.
 */
template <typename Torus> struct int_unchecked_contains_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many encrypted values we search through.
  uint32_t num_inputs;

  /// Builds the one-hot mask of the list against the needle.
  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  /// OR-reduces the mask to tell whether anything matched.
  int_comparison_buffer<Torus> *reduction_buffer;

  /// The one-hot mask, one boolean per list element packed together.
  CudaRadixCiphertextFFI packed_selectors;
  /// Per-element single-block views into the packed mask.
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  /// The clear needle re-encrypted trivially so it can feed the PBS.
  CudaRadixCiphertextFFI tmp_clear_val;
  /// Device copy of the clear needle digits before trivial encryption.
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

/**
 * @brief Checks whether an encrypted value exists in a clear set.
 */
template <typename Torus> struct int_unchecked_is_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many clear candidates we test against.
  uint32_t num_clears;

  /// Builds the one-hot mask of the input against the clear set.
  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_buffer;
  /// OR-reduces the mask to tell whether anything matched.
  int_comparison_buffer<Torus> *reduction_buffer;

  /// The one-hot mask, one boolean per clear value packed together.
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

/**
 * @brief Transforms a one-hot selector vector into the encrypted index of the
 * found element.
 */
template <typename Torus> struct int_final_index_from_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many selector slots feed the index computation.
  uint32_t num_inputs;

  /// Turns the mask into the candidate index values to aggregate.
  int_possible_results_buffer<Torus> *possible_results_buf;
  /// Sums the masked indices down to the single position.
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  /// OR-reduces the mask to tell whether anything matched.
  int_comparison_buffer<Torus> *reduction_buf;

  /// The one-hot mask, one boolean per slot packed together.
  CudaRadixCiphertextFFI packed_selectors;
  /// Per-slot single-block views into the packed mask.
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  /// One materialized index per slot, masked, before the aggregation.
  std::vector<CudaRadixCiphertextFFI> possible_results_ct_list;

  /// Clear index per slot, multiplied in so a match becomes a position.
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

/**
 * @brief Orchestrates the index-of operation locating an encrypted target in a
 * list of clear values.
 */
template <typename Torus> struct int_unchecked_index_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many clear candidates we test against.
  uint32_t num_clears;

  /// Builds the one-hot mask of the input against the clear set.
  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_selectors_buf;
  /// Turns the one-hot mask into the encrypted position of the match.
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

/**
 * @brief Orchestrates finding the first occurrence in a clear list.
 */
template <typename Torus> struct int_unchecked_first_index_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many distinct clear values we search for.
  uint32_t num_unique;

  /// Builds the one-hot mask of the input against the clear set.
  int_eq_selectors_ct_vs_clears_buffer<Torus> *eq_selectors_buf;
  /// Turns the mask into the candidate index values to aggregate.
  int_possible_results_buffer<Torus> *possible_results_buf;
  /// Sums the masked indices down to the single position.
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  /// OR-reduces the mask to tell whether anything matched.
  int_comparison_buffer<Torus> *reduction_buf;

  /// The one-hot mask, one boolean per clear value packed together.
  CudaRadixCiphertextFFI packed_selectors;
  /// One materialized index per value, masked, before the aggregation.
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

/**
 * @brief Orchestrates finding the first occurrence of a clear needle in an
 * encrypted list.
 */
template <typename Torus> struct int_unchecked_first_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many encrypted values we search through.
  uint32_t num_inputs;

  /// Builds the one-hot mask of the list against the needle.
  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  /// Turns the trimmed mask into the candidate index values.
  int_possible_results_buffer<Torus> *possible_results_buf;
  /// Sums the masked index down to the single position.
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  /// OR-reduces the mask to tell whether anything matched.
  int_comparison_buffer<Torus> *reduction_buf;

  /// The one-hot mask, later trimmed to keep only the first match.
  CudaRadixCiphertextFFI packed_selectors;
  /// Per-element single-block views into the packed mask.
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  /// One materialized index per element, masked, before the aggregation.
  std::vector<CudaRadixCiphertextFFI> possible_results_ct_list;
  /// The clear needle re-encrypted trivially so it can feed the PBS.
  CudaRadixCiphertextFFI tmp_clear_val;
  /// Device copy of the clear needle digits before trivial encryption.
  Torus *d_clear_val;
  /// Clear index per element, multiplied in so a match becomes a position.
  uint64_t *h_indices;

  /// Bivariate scan LUT that keeps only the first 1 in the mask.
  int_radix_lut<Torus> *prefix_sum_lut;
  /// Wipes the already-seen markers the scan leaves behind.
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

/**
 * @brief Orchestrates finding the first occurrence of an encrypted needle in an
 * encrypted list.
 */
template <typename Torus> struct int_unchecked_first_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many encrypted values we search through.
  uint32_t num_inputs;

  /// Builds the one-hot mask of the list against the encrypted needle.
  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  /// Turns the trimmed mask into the candidate index values.
  int_possible_results_buffer<Torus> *possible_results_buf;
  /// Sums the masked index down to the single position.
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  /// OR-reduces the mask to tell whether anything matched.
  int_comparison_buffer<Torus> *reduction_buf;

  /// The one-hot mask, later trimmed to keep only the first match.
  CudaRadixCiphertextFFI packed_selectors;
  /// Per-element single-block views into the packed mask.
  std::vector<CudaRadixCiphertextFFI> unpacked_selectors;
  /// One materialized index per element, masked, before the aggregation.
  std::vector<CudaRadixCiphertextFFI> possible_results_ct_list;
  /// Clear index per element, multiplied in so a match becomes a position.
  uint64_t *h_indices;

  /// Bivariate scan LUT that keeps only the first 1 in the mask.
  int_radix_lut<Torus> *prefix_sum_lut;
  /// Wipes the already-seen markers the scan leaves behind.
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

/**
 * @brief Orchestrates the index-of operation locating an encrypted target in an
 * encrypted list.
 */
template <typename Torus> struct int_unchecked_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many encrypted values we search through.
  uint32_t num_inputs;

  /// Builds the one-hot mask of the list against the encrypted needle.
  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  /// Turns the one-hot mask into the encrypted position of the match.
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

/**
 * @brief Orchestrates the index-of operation locating a clear target in an
 * encrypted list.
 */
template <typename Torus> struct int_unchecked_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// How many encrypted values we search through.
  uint32_t num_inputs;

  /// Builds the one-hot mask of the list against the needle.
  int_eq_selectors_cts_vs_ct_buffer<Torus> *eq_selectors_buf;
  /// Turns the one-hot mask into the encrypted position of the match.
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  /// The clear needle re-encrypted trivially so it can feed the PBS.
  CudaRadixCiphertextFFI tmp_clear_val;
  /// Device copy of the clear needle digits before trivial encryption.
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
