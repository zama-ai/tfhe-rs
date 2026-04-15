#pragma once
#include "checked_arithmetic.h"
#include "comparison.h"
#include "integer_utilities.h"

template <typename Torus> struct int_bitonic_sort_buffer {
  int_radix_params params;
  uint32_t max_num_pairs;
  uint32_t num_radix_blocks;

  int_comparison_buffer<Torus> *comparison_mem;
  CudaRadixCiphertextFFI *comparison_results;

  // Unsigned compare path: K*N packed, K*N/2 diffs, K*N/2 tree scratch (x, y).
  CudaRadixCiphertextFFI *batch_cmp_packed;
  CudaRadixCiphertextFFI *batch_cmp_comparisons;
  CudaRadixCiphertextFFI *batch_cmp_tree_x;
  CudaRadixCiphertextFFI *batch_cmp_tree_y;

  int_radix_lut<Torus> *batch_identity_lut;
  int_radix_lut<Torus> *batch_is_non_zero_lut;
  int_radix_lut<Torus> *batch_inner_tree_leaf_lut;
  int_radix_lut<Torus> *batch_last_tree_leaf_lut;
  Torus *preallocated_h_lut;

  // Batched cmux: 4KN = [true-side (2KN)] [false-side (2KN)]; condition
  // broadcast per block.
  CudaRadixCiphertextFFI *batch_buffer_in;
  CudaRadixCiphertextFFI *batch_buffer_out;
  CudaRadixCiphertextFFI *batch_condition;

  int_radix_lut<Torus> *batch_predicate_lut;
  int_radix_lut<Torus> *batch_message_extract_lut;

  bool is_signed;
  bool gpu_memory_allocated;

  int_bitonic_sort_buffer(CudaStreams streams, int_radix_params params,
                          uint32_t num_radix_blocks, uint32_t num_values,
                          bool is_signed, bool allocate_gpu_memory,
                          uint64_t &size_tracker) {
    this->params = params;
    this->is_signed = is_signed;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->num_radix_blocks = num_radix_blocks;
    this->max_num_pairs = num_values / 2;

    uint32_t K = max_num_pairs;
    uint32_t N = num_radix_blocks;
    uint32_t packed_per_pair = N / 2;
    uint32_t total_bivariate_blocks = 4 * K * N;
    uint32_t total_result_blocks = 2 * K * N;

    comparison_mem = new int_comparison_buffer<Torus>(
        streams, COMPARISON_TYPE::GT, params, num_radix_blocks, is_signed,
        allocate_gpu_memory, size_tracker);

    comparison_results = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), comparison_results, K,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    batch_cmp_packed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_cmp_packed, K * N,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    batch_cmp_comparisons = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_cmp_comparisons,
        K * packed_per_pair, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    batch_cmp_tree_x = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_cmp_tree_x,
        K * packed_per_pair, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    batch_cmp_tree_y = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_cmp_tree_y,
        K * packed_per_pair, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    Torus total_modulus = params.message_modulus * params.carry_modulus;

    batch_identity_lut = new int_radix_lut<Torus>(
        streams, params, 1, K * N, allocate_gpu_memory, size_tracker);
    auto active_id = streams.active_gpu_subset(K * N, params.pbs_type);
    batch_identity_lut->generate_and_broadcast_lut(
        active_id, {0}, {[](Torus x) -> Torus { return x; }},
        LUT_0_FOR_ALL_BLOCKS);

    batch_is_non_zero_lut =
        new int_radix_lut<Torus>(streams, params, 1, K * packed_per_pair,
                                 allocate_gpu_memory, size_tracker);
    auto active_nz =
        streams.active_gpu_subset(K * packed_per_pair, params.pbs_type);
    batch_is_non_zero_lut->generate_and_broadcast_lut(
        active_nz, {0}, {[total_modulus](Torus x) -> Torus {
          return (x % total_modulus) != 0;
        }},
        LUT_0_FOR_ALL_BLOCKS);

    batch_inner_tree_leaf_lut =
        new int_radix_lut<Torus>(streams, params, 1, K * packed_per_pair,
                                 allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus, Torus)> block_selector_f =
        [](Torus msb, Torus lsb) -> Torus {
      return (msb == IS_EQUAL) ? lsb : msb;
    };
    batch_inner_tree_leaf_lut->generate_and_broadcast_bivariate_lut(
        active_nz, {0}, {block_selector_f}, LUT_0_FOR_ALL_BLOCKS);

    batch_last_tree_leaf_lut = new int_radix_lut<Torus>(
        streams, params, 1, K, allocate_gpu_memory, size_tracker);

    preallocated_h_lut = (Torus *)malloc(safe_mul_sizeof<Torus>(
        params.glwe_dimension + 1, params.polynomial_size));

    batch_buffer_in = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_buffer_in,
        total_bivariate_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    batch_buffer_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_buffer_out,
        total_bivariate_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    batch_condition = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_condition,
        total_bivariate_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    // Pick true/false branch where cond == IS_SUPERIOR: LUT 0 zeros false-side,
    // LUT 1 zeros true-side; the two halves are summed after the PBS.
    batch_predicate_lut =
        new int_radix_lut<Torus>(streams, params, 2, total_bivariate_blocks,
                                 allocate_gpu_memory, size_tracker);

    auto pred_f = [](Torus x) -> Torus { return x == IS_SUPERIOR; };
    auto active_pred =
        streams.active_gpu_subset(total_bivariate_blocks, params.pbs_type);
    batch_predicate_lut->generate_and_broadcast_bivariate_lut(
        active_pred, {0, 1},
        {[pred_f](Torus b, Torus c) -> Torus { return pred_f(c) ? b : 0; },
         [pred_f](Torus b, Torus c) -> Torus { return pred_f(c) ? 0 : b; }},
        [total_result_blocks](Torus *idx, uint32_t) {
          for (uint32_t i = 0; i < 2 * total_result_blocks; i++)
            idx[i] = (i < total_result_blocks) ? 0 : 1;
        });

    batch_message_extract_lut =
        new int_radix_lut<Torus>(streams, params, 1, total_result_blocks,
                                 allocate_gpu_memory, size_tracker);
    auto active_msg =
        streams.active_gpu_subset(total_result_blocks, params.pbs_type);
    batch_message_extract_lut->generate_and_broadcast_lut(
        active_msg, {0},
        {[params](Torus x) -> Torus { return x % params.message_modulus; }},
        LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    comparison_mem->release(streams);
    delete comparison_mem;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   comparison_results, gpu_memory_allocated);
    delete comparison_results;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_cmp_packed, gpu_memory_allocated);
    delete batch_cmp_packed;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_cmp_comparisons, gpu_memory_allocated);
    delete batch_cmp_comparisons;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_cmp_tree_x, gpu_memory_allocated);
    delete batch_cmp_tree_x;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_cmp_tree_y, gpu_memory_allocated);
    delete batch_cmp_tree_y;

    batch_identity_lut->release(streams);
    delete batch_identity_lut;
    batch_is_non_zero_lut->release(streams);
    delete batch_is_non_zero_lut;
    batch_inner_tree_leaf_lut->release(streams);
    delete batch_inner_tree_leaf_lut;
    batch_last_tree_leaf_lut->release(streams);
    delete batch_last_tree_leaf_lut;
    free(preallocated_h_lut);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_buffer_in, gpu_memory_allocated);
    delete batch_buffer_in;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_buffer_out, gpu_memory_allocated);
    delete batch_buffer_out;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_condition, gpu_memory_allocated);
    delete batch_condition;

    batch_predicate_lut->release(streams);
    delete batch_predicate_lut;
    batch_message_extract_lut->release(streams);
    delete batch_message_extract_lut;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
