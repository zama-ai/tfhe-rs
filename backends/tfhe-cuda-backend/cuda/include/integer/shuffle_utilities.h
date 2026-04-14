#pragma once
#include "checked_arithmetic.h"
#include "comparison.h"
#include "integer_utilities.h"
#include "oprf.h"

// Per-half-step scratch for the bitonic sort on K = num_values/2 pairs of
// N-block radix integers: per-pair compare scratch and the 4*K*N batched
// cmux buffers with their LUTs.
// Attributes:
// - params: shared radix parameters
// - max_num_pairs, num_radix_blocks: K and N
// - comparison_mem, comparison_results: per-pair compare scratch and K signs
// - batch_cmp_*, batch_*_lut, preallocated_h_lut: legacy batched compare
//   path, now unused
// - batch_buffer_in / batch_buffer_out / batch_condition: 4*K*N cmux buffers
// - batch_predicate_lut, batch_message_extract_lut: cmux predicate and final
//   message-extract LUTs
// - is_signed, gpu_memory_allocated: compare-path selector and ownership flag
//
template <typename Torus> struct int_bitonic_sort_buffer {
  int_radix_params params;
  uint32_t max_num_pairs;
  uint32_t num_radix_blocks;

  int_comparison_buffer<Torus> *comparison_mem;
  CudaRadixCiphertextFFI *comparison_results;

  CudaRadixCiphertextFFI *batch_cmp_packed;
  CudaRadixCiphertextFFI *batch_cmp_comparisons;
  CudaRadixCiphertextFFI *batch_cmp_tree_x;
  CudaRadixCiphertextFFI *batch_cmp_tree_y;

  int_radix_lut<Torus> *batch_identity_lut;
  int_radix_lut<Torus> *batch_is_non_zero_lut;
  int_radix_lut<Torus> *batch_inner_tree_leaf_lut;
  int_radix_lut<Torus> *batch_last_tree_leaf_lut;
  Torus *preallocated_h_lut;

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

// Pairs two int_bitonic_sort_buffer instances (keys and data) so the compare
// and cmux phases reuse the same primitives, plus padding scratch for the
// (key=MAX, data=0) sentinels when num_values is not a power of 2.
// Attributes:
// - params: shared radix parameters
// - keys_buffer, data_buffer: per-array sort scratch
// - real_num_values, padded_num_values, needs_pad: original and padded sizes
// - key_num_blocks, key_num_blocks_padded, data_num_blocks: block counts
// - padded_keys_storage / _views / _ptrs: per-call padded keys storage
// - sentinel_data_storage / _views, padded_data_ptrs: sentinel data and the
//   spliced (real ptrs then sentinel views) pointer array
// - h_max_scalar, d_max_scalar: host / device scalar arrays used to
//   materialize trivial-MAX sentinel keys
// - gpu_memory_allocated: ownership flag
//
template <typename Torus> struct int_bitonic_shuffle_buffer {
  int_radix_params params;
  int_bitonic_sort_buffer<Torus> *keys_buffer;
  int_bitonic_sort_buffer<Torus> *data_buffer;
  bool gpu_memory_allocated;

  uint32_t real_num_values;
  uint32_t padded_num_values;
  uint32_t key_num_blocks;
  uint32_t key_num_blocks_padded;
  uint32_t data_num_blocks;
  bool needs_pad;

  CudaRadixCiphertextFFI *padded_keys_storage;
  CudaRadixCiphertextFFI *padded_keys_views;
  CudaRadixCiphertextFFI **padded_keys_ptrs;

  CudaRadixCiphertextFFI *sentinel_data_storage;
  CudaRadixCiphertextFFI *sentinel_data_views;
  CudaRadixCiphertextFFI **padded_data_ptrs;

  Torus *h_max_scalar;
  Torus *d_max_scalar;

  int_bitonic_shuffle_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t key_num_blocks, uint32_t data_num_blocks,
                             uint32_t num_values, bool data_is_signed,
                             bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->real_num_values = num_values;
    this->key_num_blocks = key_num_blocks;
    this->data_num_blocks = data_num_blocks;
    this->needs_pad = (num_values & (num_values - 1)) != 0;

    uint32_t on = 1;
    while (on < num_values)
      on <<= 1;
    this->padded_num_values = needs_pad ? on : num_values;
    this->key_num_blocks_padded =
        needs_pad ? ((key_num_blocks / 2) + 1) * 2 : key_num_blocks;

    this->keys_buffer = new int_bitonic_sort_buffer<Torus>(
        streams, params, key_num_blocks_padded, padded_num_values,
        /*is_signed=*/false, allocate_gpu_memory, size_tracker);
    this->data_buffer = new int_bitonic_sort_buffer<Torus>(
        streams, params, data_num_blocks, padded_num_values, data_is_signed,
        allocate_gpu_memory, size_tracker);

    if (!needs_pad) {
      padded_keys_storage = nullptr;
      padded_keys_views = nullptr;
      padded_keys_ptrs = nullptr;
      sentinel_data_storage = nullptr;
      sentinel_data_views = nullptr;
      padded_data_ptrs = nullptr;
      h_max_scalar = nullptr;
      d_max_scalar = nullptr;
      return;
    }

    padded_keys_storage = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), padded_keys_storage,
        padded_num_values * key_num_blocks_padded, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    padded_keys_views = new CudaRadixCiphertextFFI[padded_num_values];
    padded_keys_ptrs = new CudaRadixCiphertextFFI *[padded_num_values];
    for (uint32_t i = 0; i < padded_num_values; i++) {
      as_radix_ciphertext_slice<Torus>(
          &padded_keys_views[i], padded_keys_storage, i * key_num_blocks_padded,
          (i + 1) * key_num_blocks_padded);
      padded_keys_ptrs[i] = &padded_keys_views[i];
    }

    uint32_t num_sentinels = padded_num_values - real_num_values;
    sentinel_data_storage = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), sentinel_data_storage,
        num_sentinels * data_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    sentinel_data_views = new CudaRadixCiphertextFFI[num_sentinels];
    for (uint32_t i = 0; i < num_sentinels; i++) {
      as_radix_ciphertext_slice<Torus>(
          &sentinel_data_views[i], sentinel_data_storage, i * data_num_blocks,
          (i + 1) * data_num_blocks);
    }

    padded_data_ptrs = new CudaRadixCiphertextFFI *[padded_num_values];
    for (uint32_t i = 0; i < num_sentinels; i++) {
      padded_data_ptrs[real_num_values + i] = &sentinel_data_views[i];
    }

    h_max_scalar = (Torus *)calloc(key_num_blocks_padded, sizeof(Torus));
    if (h_max_scalar == nullptr)
      PANIC("Cuda error: failed to allocate host max scalar buffer");
    Torus max_block = static_cast<Torus>(params.message_modulus) - 1;
    for (uint32_t i = 0; i < key_num_blocks_padded; i++)
      h_max_scalar[i] = max_block;

    d_max_scalar = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(key_num_blocks_padded), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    if (allocate_gpu_memory) {
      cuda_memcpy_async_to_gpu(d_max_scalar, h_max_scalar,
                               safe_mul_sizeof<Torus>(key_num_blocks_padded),
                               streams.stream(0), streams.gpu_index(0));
    }
  }

  void release(CudaStreams streams) {
    keys_buffer->release(streams);
    delete keys_buffer;
    data_buffer->release(streams);
    delete data_buffer;

    if (!needs_pad)
      return;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   padded_keys_storage, gpu_memory_allocated);
    delete padded_keys_storage;
    delete[] padded_keys_views;
    delete[] padded_keys_ptrs;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   sentinel_data_storage, gpu_memory_allocated);
    delete sentinel_data_storage;
    delete[] sentinel_data_views;
    delete[] padded_data_ptrs;

    free(h_max_scalar);
    if (gpu_memory_allocated) {
      cuda_drop_async(d_max_scalar, streams.stream(0), streams.gpu_index(0));
    }
  }
};

// Bundles a shared OPRF memory, a bitonic_shuffle scratch, and per-value key
// storage so the OPRF + sort composition runs in a single backend call.
// Attributes:
// - params: shared radix parameters
// - num_values, key_num_blocks: vector length and per-key block count
// - oprf_memory: shared OPRF state (one PBS round per key block)
// - shuffle_buffer: int_bitonic_shuffle_buffer driving the actual sort
// - keys_storage / keys_views / keys_ptrs: backing storage and per-key views
//   for the OPRF output keys
// - gpu_memory_allocated: ownership flag
//
template <typename Torus> struct int_oprf_bitonic_shuffle_buffer {
  int_radix_params params;
  uint32_t num_values;
  uint32_t key_num_blocks;

  int_grouped_oprf_memory<Torus> *oprf_memory;
  int_bitonic_shuffle_buffer<Torus> *shuffle_buffer;

  CudaRadixCiphertextFFI *keys_storage;
  CudaRadixCiphertextFFI *keys_views;
  CudaRadixCiphertextFFI **keys_ptrs;

  bool gpu_memory_allocated;

  int_oprf_bitonic_shuffle_buffer(CudaStreams streams, int_radix_params params,
                                  uint32_t key_num_blocks,
                                  uint32_t data_num_blocks, uint32_t num_values,
                                  bool data_is_signed, bool allocate_gpu_memory,
                                  uint64_t &size_tracker) {
    this->params = params;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->num_values = num_values;
    this->key_num_blocks = key_num_blocks;

    uint64_t message_bits_per_block =
        (uint64_t)std::log2(params.message_modulus);
    uint32_t total_oprf_blocks = num_values * key_num_blocks;
    uint64_t total_random_bits =
        (uint64_t)total_oprf_blocks * message_bits_per_block;

    this->oprf_memory = new int_grouped_oprf_memory<Torus>(
        streams, params, total_oprf_blocks, (uint32_t)message_bits_per_block,
        total_random_bits, allocate_gpu_memory, size_tracker);

    this->shuffle_buffer = new int_bitonic_shuffle_buffer<Torus>(
        streams, params, key_num_blocks, data_num_blocks, num_values,
        data_is_signed, allocate_gpu_memory, size_tracker);

    this->keys_storage = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->keys_storage,
        num_values * key_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->keys_views = new CudaRadixCiphertextFFI[num_values];
    this->keys_ptrs = new CudaRadixCiphertextFFI *[num_values];
    for (uint32_t i = 0; i < num_values; i++) {
      as_radix_ciphertext_slice<Torus>(&this->keys_views[i], this->keys_storage,
                                       i * key_num_blocks,
                                       (i + 1) * key_num_blocks);
      this->keys_ptrs[i] = &this->keys_views[i];
    }
  }

  void release(CudaStreams streams) {
    oprf_memory->release(streams);
    delete oprf_memory;
    shuffle_buffer->release(streams);
    delete shuffle_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   keys_storage, gpu_memory_allocated);
    delete keys_storage;
    delete[] keys_views;
    delete[] keys_ptrs;
  }
};
