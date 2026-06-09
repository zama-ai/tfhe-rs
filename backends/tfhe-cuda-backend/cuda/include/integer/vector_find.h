#pragma once
#include "helper_multi_gpu.h"
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"
#include <functional>
#include <vector>

// If we use more than 5 streams the result is incorrect
const uint32_t MAX_STREAMS_FOR_VECTOR_FIND = 5;

template <typename Torus> struct int_equality_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t lut_stride;

  uint32_t num_possible_values;
  int_radix_lut<Torus> *comparison_luts;
  CudaRadixCiphertextFFI *tmp_many_luts_output;

  CudaStreams active_streams;
  CudaRadixCiphertextFFI *tmp_batched_block_comparisons;
  CudaRadixCiphertextFFI *tmp_batched_out;
  CudaRadixCiphertextFFI *tmp_batched_accumulated;

  int_radix_lut<Torus> *batched_is_max_value;
  Torus *preallocated_h_lut;

  uint32_t *d_map;
  uint32_t *h_map;

  bool is_aliased;

  int_equality_selectors_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_possible_values,
                                uint32_t num_blocks, bool allocate_gpu_memory,
                                uint64_t &size_tracker,
                                CudaRadixCiphertextFFI *arena = nullptr,
                                uint32_t *arena_offset = nullptr) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_possible_values = num_possible_values;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->is_aliased = (arena != nullptr && arena_offset != nullptr);

    auto alloc_or_alias = [&](CudaRadixCiphertextFFI *ct,
                              uint32_t num_blocks_to_alloc, uint32_t lwe_dim) {
      if (this->is_aliased) {
        as_radix_ciphertext_slice<Torus>(ct, arena, *arena_offset,
                                         *arena_offset + num_blocks_to_alloc);
        *arena_offset += num_blocks_to_alloc;
      } else {
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), ct, num_blocks_to_alloc,
            lwe_dim, size_tracker, allocate_gpu_memory);
      }
    };

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
    alloc_or_alias(this->tmp_many_luts_output,
                   params.message_modulus * num_blocks,
                   params.big_lwe_dimension);

    uint32_t total_batched_blocks = num_possible_values * num_blocks;
    this->tmp_batched_block_comparisons = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_batched_block_comparisons, total_batched_blocks,
                   params.big_lwe_dimension);

    Torus total_modulus = params.message_modulus * params.carry_modulus;
    uint32_t max_value = (total_modulus - 1) / (params.message_modulus - 1);
    uint32_t max_chunks_per_group = (num_blocks + max_value - 1) / max_value;
    uint32_t total_max_chunks = num_possible_values * max_chunks_per_group;

    this->tmp_batched_out = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_batched_out, total_batched_blocks,
                   params.big_lwe_dimension);

    this->tmp_batched_accumulated = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_batched_accumulated, total_max_chunks,
                   params.big_lwe_dimension);

    this->batched_is_max_value =
        new int_radix_lut<Torus>(streams, params, 2, total_max_chunks,
                                 allocate_gpu_memory, size_tracker);

    auto is_max_value_f = [max_value](Torus x) -> Torus {
      return x == max_value;
    };

    auto lut_active_streams =
        streams.active_gpu_subset(total_max_chunks, params.pbs_type);
    this->batched_is_max_value->generate_and_broadcast_lut(
        lut_active_streams, {0}, {is_max_value_f}, LUT_0_FOR_ALL_BLOCKS);

    this->preallocated_h_lut = (Torus *)malloc(
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus));

    uint32_t total_blocks = num_possible_values * num_blocks;
    this->h_map = new uint32_t[total_blocks];
    this->d_map = (uint32_t *)cuda_malloc_with_size_tracking_async(
        total_blocks * sizeof(uint32_t), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->comparison_luts->release(streams);
    delete this->comparison_luts;

    if (!this->is_aliased) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_many_luts_output,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_batched_block_comparisons,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_batched_out,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_batched_accumulated,
                                     this->allocate_gpu_memory);
    }
    delete this->tmp_many_luts_output;
    delete this->tmp_batched_block_comparisons;
    delete this->tmp_batched_out;
    delete this->tmp_batched_accumulated;

    this->batched_is_max_value->release(streams);
    delete this->batched_is_max_value;

    free(this->preallocated_h_lut);

    delete[] this->h_map;
    cuda_drop_async(this->d_map, streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_possible_results_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t max_packed_value;
  uint32_t max_luts_per_call;
  uint32_t num_lut_accumulators;
  uint32_t lut_stride;

  int_radix_lut<Torus> *batched_accumulators_lut;

  CudaRadixCiphertextFFI *tmp_batched_selectors;
  CudaRadixCiphertextFFI *tmp_many_luts_output;

  Torus **d_dst_ptrs;
  uint32_t *d_src_idx;
  Torus **h_dst_ptrs;
  uint32_t *h_src_idx;

  bool is_aliased;

  int_possible_results_buffer(CudaStreams streams, int_radix_params params,
                              uint32_t num_blocks, uint32_t num_possible_values,
                              bool allocate_gpu_memory, uint64_t &size_tracker,
                              CudaRadixCiphertextFFI *arena = nullptr,
                              uint32_t *arena_offset = nullptr) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->is_aliased = (arena != nullptr && arena_offset != nullptr);

    auto alloc_or_alias = [&](CudaRadixCiphertextFFI *ct,
                              uint32_t num_blocks_to_alloc, uint32_t lwe_dim) {
      if (this->is_aliased) {
        as_radix_ciphertext_slice<Torus>(ct, arena, *arena_offset,
                                         *arena_offset + num_blocks_to_alloc);
        *arena_offset += num_blocks_to_alloc;
      } else {
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), ct, num_blocks_to_alloc,
            lwe_dim, size_tracker, allocate_gpu_memory);
      }
    };

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

    this->batched_accumulators_lut = new int_radix_lut<Torus>(
        streams, params, num_lut_accumulators,
        num_lut_accumulators * num_possible_values, max_luts_per_call,
        allocate_gpu_memory, size_tracker);

    std::vector<std::vector<std::function<Torus(Torus)>>> all_fns;
    std::vector<uint32_t> lut_generation_indices(num_lut_accumulators);

    uint32_t lut_value_start = 0;
    for (uint32_t i = 0; i < num_lut_accumulators; i++) {
      std::vector<std::function<Torus(Torus)>> current_fns;
      for (uint32_t j = 0; j < max_luts_per_call; j++) {
        uint32_t c = lut_value_start + j;
        if (c < total_luts_needed) {
          current_fns.push_back([c](Torus x) -> Torus { return (x == 1) * c; });
        } else {
          current_fns.push_back([](Torus x) -> Torus { return 0; });
        }
      }
      all_fns.push_back(current_fns);
      lut_generation_indices[i] = i;
      lut_value_start += max_luts_per_call;
    }

    auto lut_active_streams = streams.active_gpu_subset(
        num_lut_accumulators * num_possible_values, params.pbs_type);

    // Indexes are set explicitly below (custom accumulator->value mapping),
    // so generate with all-zero indexes here.
    this->batched_accumulators_lut->generate_and_broadcast_many_lut(
        lut_active_streams, lut_generation_indices, all_fns,
        LUT_0_FOR_ALL_BLOCKS);

    all_fns.clear();

    Torus *h_lut_indexes = this->batched_accumulators_lut->h_lut_indexes;
    for (uint32_t i = 0; i < num_lut_accumulators; i++) {
      for (uint32_t v = 0; v < num_possible_values; v++) {
        h_lut_indexes[i * num_possible_values + v] = i;
      }
    }

    if (allocate_gpu_memory) {
      cuda_memcpy_async_to_gpu(
          this->batched_accumulators_lut->get_lut_indexes(0, 0), h_lut_indexes,
          num_lut_accumulators * num_possible_values * sizeof(Torus),
          streams.stream(0), streams.gpu_index(0));
      this->batched_accumulators_lut->broadcast_lut(lut_active_streams, false);
    }

    this->tmp_batched_selectors = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_batched_selectors,
                   num_lut_accumulators * num_possible_values,
                   params.big_lwe_dimension);

    this->tmp_many_luts_output = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_many_luts_output,
                   num_lut_accumulators * num_possible_values *
                       max_luts_per_call,
                   params.big_lwe_dimension);

    uint32_t total_blocks = num_possible_values * num_blocks;
    this->h_dst_ptrs = new Torus *[num_possible_values];
    this->h_src_idx = new uint32_t[total_blocks];
    this->d_dst_ptrs = (Torus **)cuda_malloc_with_size_tracking_async(
        num_possible_values * sizeof(Torus *), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    this->d_src_idx = (uint32_t *)cuda_malloc_with_size_tracking_async(
        total_blocks * sizeof(uint32_t), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->batched_accumulators_lut->release(streams);
    delete this->batched_accumulators_lut;

    if (!this->is_aliased) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_batched_selectors,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_many_luts_output,
                                     this->allocate_gpu_memory);
    }
    delete this->tmp_batched_selectors;
    delete this->tmp_many_luts_output;

    delete[] this->h_dst_ptrs;
    delete[] this->h_src_idx;
    cuda_drop_async(this->d_dst_ptrs, streams.stream(0), streams.gpu_index(0));
    cuda_drop_async(this->d_src_idx, streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_aggregate_one_hot_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t chunk_size;

  int_radix_lut<Torus> *identity_lut;
  int_radix_lut<Torus> *message_extract_lut;
  int_radix_lut<Torus> *carry_extract_lut;

  CudaRadixCiphertextFFI *tmp_out;
  CudaRadixCiphertextFFI *tmp_accumulated;
  CudaRadixCiphertextFFI *tmp_batched_input;

  CudaRadixCiphertextFFI *message_ct;
  CudaRadixCiphertextFFI *carry_ct;

  const Torus **d_src_ptrs;
  const Torus **h_src_ptrs;

  bool is_aliased;

  int_aggregate_one_hot_buffer(CudaStreams streams, int_radix_params params,
                               uint32_t num_blocks, uint32_t num_matches,
                               bool allocate_gpu_memory, uint64_t &size_tracker,
                               CudaRadixCiphertextFFI *arena = nullptr,
                               uint32_t *arena_offset = nullptr) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->is_aliased = (arena != nullptr && arena_offset != nullptr);

    auto alloc_or_alias = [&](CudaRadixCiphertextFFI *ct,
                              uint32_t num_blocks_to_alloc, uint32_t lwe_dim) {
      if (this->is_aliased) {
        as_radix_ciphertext_slice<Torus>(ct, arena, *arena_offset,
                                         *arena_offset + num_blocks_to_alloc);
        *arena_offset += num_blocks_to_alloc;
      } else {
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), ct, num_blocks_to_alloc,
            lwe_dim, size_tracker, allocate_gpu_memory);
      }
    };

    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    this->chunk_size = (total_modulus - 1) / (params.message_modulus - 1);

    uint32_t max_chunks = (num_matches + chunk_size - 1) / chunk_size;
    if (max_chunks == 0)
      max_chunks = 1;
    uint32_t max_lut_blocks = max_chunks * num_blocks;

    this->identity_lut = new int_radix_lut<Torus>(
        streams, params, 1, max_lut_blocks, allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> id_fn = [](Torus x) -> Torus { return x; };
    this->identity_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(max_lut_blocks, params.pbs_type), {0},
        {id_fn}, LUT_0_FOR_ALL_BLOCKS);

    this->message_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> msg_fn = [params](Torus x) -> Torus {
      return (x % params.message_modulus) % params.message_modulus;
    };
    this->message_extract_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {msg_fn},
        LUT_0_FOR_ALL_BLOCKS);

    this->carry_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> carry_fn = [params](Torus x) -> Torus {
      return x / params.message_modulus;
    };
    this->carry_extract_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {carry_fn},
        LUT_0_FOR_ALL_BLOCKS);

    uint32_t max_items = num_matches == 0 ? 1 : num_matches;

    this->tmp_out = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_out, max_items * num_blocks,
                   params.big_lwe_dimension);

    this->tmp_accumulated = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_accumulated, max_chunks * num_blocks,
                   params.big_lwe_dimension);

    this->tmp_batched_input = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->tmp_batched_input, max_chunks * num_blocks,
                   params.big_lwe_dimension);

    this->message_ct = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->message_ct, num_blocks, params.big_lwe_dimension);

    this->carry_ct = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->carry_ct, num_blocks, params.big_lwe_dimension);

    this->h_src_ptrs = new const Torus *[max_items];
    this->d_src_ptrs = (const Torus **)cuda_malloc_with_size_tracking_async(
        max_items * sizeof(const Torus *), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->identity_lut->release(streams);
    delete this->identity_lut;

    this->message_extract_lut->release(streams);
    delete this->message_extract_lut;

    this->carry_extract_lut->release(streams);
    delete this->carry_extract_lut;

    if (!this->is_aliased) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_out, this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_accumulated,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_batched_input,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->message_ct,
                                     this->allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->carry_ct, this->allocate_gpu_memory);
    }
    delete this->tmp_out;
    delete this->tmp_accumulated;
    delete this->tmp_batched_input;
    delete this->message_ct;
    delete this->carry_ct;

    delete[] this->h_src_ptrs;
    if (this->allocate_gpu_memory) {
      cuda_drop_async(this->d_src_ptrs, streams.stream(0),
                      streams.gpu_index(0));
    }

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

  int_equality_selectors_buffer<Torus> *eq_selectors_buffer;
  int_possible_results_buffer<Torus> *possible_results_buffer;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buffer;
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  CudaRadixCiphertextFFI *selectors_list;
  CudaRadixCiphertextFFI *packed_selectors_ct;
  CudaRadixCiphertextFFI *possible_results_list;

  bool is_aliased;

  int_unchecked_match_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t num_matches, uint32_t num_input_blocks,
                             uint32_t num_output_packed_blocks,
                             bool max_output_is_zero, bool allocate_gpu_memory,
                             uint64_t &size_tracker,
                             CudaRadixCiphertextFFI *arena = nullptr,
                             uint32_t *arena_offset = nullptr) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_matches = num_matches;
    this->num_input_blocks = num_input_blocks;
    this->num_output_packed_blocks = num_output_packed_blocks;
    this->max_output_is_zero = max_output_is_zero;
    this->is_aliased = (arena != nullptr && arena_offset != nullptr);

    auto alloc_or_alias = [&](CudaRadixCiphertextFFI *ct,
                              uint32_t num_blocks_to_alloc, uint32_t lwe_dim) {
      if (this->is_aliased) {
        as_radix_ciphertext_slice<Torus>(ct, arena, *arena_offset,
                                         *arena_offset + num_blocks_to_alloc);
        *arena_offset += num_blocks_to_alloc;
      } else {
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), ct, num_blocks_to_alloc,
            lwe_dim, size_tracker, allocate_gpu_memory);
      }
    };

    this->eq_selectors_buffer = new int_equality_selectors_buffer<Torus>(
        streams, params, num_matches, num_input_blocks, allocate_gpu_memory,
        size_tracker, arena, arena_offset);

    this->possible_results_buffer = new int_possible_results_buffer<Torus>(
        streams, params, num_output_packed_blocks, num_matches,
        allocate_gpu_memory, size_tracker, arena, arena_offset);

    if (!max_output_is_zero) {
      this->aggregate_buffer = new int_aggregate_one_hot_buffer<Torus>(
          streams, params, num_output_packed_blocks, num_matches,
          allocate_gpu_memory, size_tracker, arena, arena_offset);
    }

    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_matches, false, allocate_gpu_memory,
        size_tracker);

    this->packed_selectors_ct = new CudaRadixCiphertextFFI;
    alloc_or_alias(this->packed_selectors_ct, num_matches,
                   params.big_lwe_dimension);

    this->selectors_list = new CudaRadixCiphertextFFI[num_matches];
    this->possible_results_list = new CudaRadixCiphertextFFI[num_matches];

    for (uint32_t i = 0; i < num_matches; i++) {
      as_radix_ciphertext_slice<Torus>(&this->selectors_list[i],
                                       this->packed_selectors_ct, i, i + 1);

      if (!max_output_is_zero) {
        alloc_or_alias(&this->possible_results_list[i],
                       num_output_packed_blocks, params.big_lwe_dimension);
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

    for (uint32_t i = 0; i < num_matches; i++) {
      if (!max_output_is_zero) {
        if (!this->is_aliased) {
          release_radix_ciphertext_async(
              streams.stream(0), streams.gpu_index(0),
              &this->possible_results_list[i], this->allocate_gpu_memory);
        }
      }
    }

    if (!this->is_aliased) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->packed_selectors_ct,
                                     this->allocate_gpu_memory);
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] this->selectors_list;
    delete[] this->possible_results_list;
    delete this->packed_selectors_ct;
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

  CudaRadixCiphertextFFI *tmp_match_result;
  CudaRadixCiphertextFFI *tmp_match_bool;
  CudaRadixCiphertextFFI *tmp_or_value;

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

    this->tmp_match_result = new CudaRadixCiphertextFFI;
    this->tmp_match_bool = new CudaRadixCiphertextFFI;
    this->tmp_or_value = new CudaRadixCiphertextFFI;

    this->d_or_value = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_final_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_match_result,
        num_final_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_match_bool, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_or_value,
        num_final_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->match_buffer->release(streams);
    delete this->match_buffer;

    this->cmux_buffer->release(streams);
    delete this->cmux_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_match_result,
                                   this->allocate_gpu_memory);
    delete this->tmp_match_result;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_match_bool,
                                   this->allocate_gpu_memory);
    delete this->tmp_match_bool;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_or_value,
                                   this->allocate_gpu_memory);
    delete this->tmp_or_value;

    cuda_drop_async(this->d_or_value, streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_selectors;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_contains_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_inputs, uint32_t num_blocks,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *tmp_clear_val;
  Torus *d_clear_val;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_contains_clear_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->tmp_clear_val = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_clear_val,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->d_clear_val = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_clear_val,
                                   this->allocate_gpu_memory);
    delete this->tmp_clear_val;

    cuda_drop_async(this->d_clear_val, streams.stream(0), streams.gpu_index(0));

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_is_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_clears;

  int_equality_selectors_buffer<Torus> *eq_buffer;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;

  int_unchecked_is_in_clears_buffer(CudaStreams streams,
                                    int_radix_params params,
                                    uint32_t num_clears, uint32_t num_blocks,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_clears = num_clears;

    this->eq_buffer = new int_equality_selectors_buffer<Torus>(
        streams, params, num_clears, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_clears, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_clears, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_clears];

    for (uint32_t i = 0; i < num_clears; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }
  }

  void release(CudaStreams streams) {
    this->eq_buffer->release(streams);
    delete this->eq_buffer;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

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

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;

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

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_inputs];
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
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_index_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_clears;

  int_equality_selectors_buffer<Torus> *eq_selectors_buf;
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

    this->eq_selectors_buf = new int_equality_selectors_buffer<Torus>(
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

  int_equality_selectors_buffer<Torus> *eq_selectors_buf;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;

  int_unchecked_first_index_in_clears_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_unique,
      uint32_t num_blocks, uint32_t num_blocks_index, bool allocate_gpu_memory,
      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_unique = num_unique;

    this->eq_selectors_buf = new int_equality_selectors_buffer<Torus>(
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

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_unique, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_unique];
    for (uint32_t i = 0; i < num_unique; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_unique];
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
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_unique; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_first_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;
  CudaRadixCiphertextFFI *tmp_clear_val;
  Torus *d_clear_val;
  uint64_t *h_indices;

  int_radix_lut<Torus> *prefix_sum_lut;
  int_radix_lut<Torus> *cleanup_lut;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_first_index_of_clear_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_inputs,
      uint32_t num_blocks, uint32_t num_blocks_index, bool allocate_gpu_memory,
      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }

    this->tmp_clear_val = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_clear_val,
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
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

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
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_clear_val,
                                   this->allocate_gpu_memory);
    delete this->tmp_clear_val;

    cuda_drop_async(this->d_clear_val, streams.stream(0), streams.gpu_index(0));

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_first_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;
  uint64_t *h_indices;

  int_radix_lut<Torus> *prefix_sum_lut;
  int_radix_lut<Torus> *cleanup_lut;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_first_index_of_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_inputs];
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
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

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
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_index_of_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_inputs, uint32_t num_blocks,
                                uint32_t num_blocks_index,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_inputs, num_blocks_index, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_index_of_clear_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_inputs, num_blocks_index, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
