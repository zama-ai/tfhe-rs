#ifndef CUDA_INTEGER_KV_STORE_UTILITIES_H
#define CUDA_INTEGER_KV_STORE_UTILITIES_H

#include "../cmux.h"
#include "../comparison.h"
#include "../vector_find.h"
#include "integer/radix_ciphertext.cuh"

template <typename Torus> struct int_kv_store_get_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_entries;
  uint32_t num_key_blocks;
  uint32_t num_value_blocks;

  Torus message_modulus;
  Torus carry_modulus;

  // Step 1: equality selectors (one encrypted boolean per entry)
  int_eq_selectors_ct_vs_clears_buffer<Torus> *mem_eq_selectors_buffer;

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
    this->mem_eq_selectors_buffer =
        new int_eq_selectors_ct_vs_clears_buffer<Torus>(
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

  int_eq_selectors_ct_vs_clears_buffer<Torus> *mem_eq_selectors_buffer;

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
    this->mem_eq_selectors_buffer =
        new int_eq_selectors_ct_vs_clears_buffer<Torus>(
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
    this->cmux_batch_buffer = new int_cmux_batch_buffer<Torus>(
        streams, condition_is_one, params, num_entries, num_value_blocks,
        allocate_gpu_memory, size_tracker);

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
    this->cmux_batch_buffer = new int_cmux_batch_buffer<Torus>(
        streams, predicate_lut_f, params, num_entries, num_value_blocks,
        allocate_gpu_memory, size_tracker);

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

  int_eq_selectors_ct_vs_clears_buffer<Torus> *mem_eq_selectors_buffer;

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

    this->mem_eq_selectors_buffer =
        new int_eq_selectors_ct_vs_clears_buffer<Torus>(
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
