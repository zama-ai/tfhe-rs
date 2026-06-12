#pragma once
#include "checked_arithmetic.h"
#include "comparison.h"
#include "integer_utilities.h"
#include "oprf.h"

// Packs ciphertexts to evaluate multiple block comparisons in fewer PBS.
template <typename Torus> struct int_batched_compare_buffer {
  int_radix_params params;
  uint32_t key_num_blocks;
  uint32_t packed_per_pair;
  bool gpu_memory_allocated;

  CudaRadixCiphertextFFI *lhs_data;
  CudaRadixCiphertextFFI *rhs_data;

  CudaRadixCiphertextFFI *tmp_packed;
  CudaRadixCiphertextFFI *comparisons;
  CudaRadixCiphertextFFI *tree_x;
  CudaRadixCiphertextFFI *tree_y;
  CudaRadixCiphertextFFI *comparison_results;

  int_radix_lut<Torus> *identity_lut;
  int_radix_lut<Torus> *is_non_zero_lut;
  int_radix_lut<Torus> *tree_inner_lut;
  int_radix_lut<Torus> *tree_last_lut;

  int_batched_compare_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t max_num_pairs, uint32_t key_num_blocks,
                             bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->key_num_blocks = key_num_blocks;
    this->gpu_memory_allocated = allocate_gpu_memory;

    if (params.carry_modulus < params.message_modulus || key_num_blocks < 3 ||
        max_num_pairs == 0)
      PANIC("Cuda error: int_batched_compare_buffer invariant violated "
            "(carry >= message, key_num_blocks >= 3, max_num_pairs > 0)");

    uint32_t M = (key_num_blocks + 1u) / 2u;
    this->packed_per_pair = M;
    uint32_t K = max_num_pairs;
    uint32_t tree_first_blocks = K * ((M + 1u) / 2u);

    lhs_data = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lhs_data, K * key_num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    rhs_data = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), rhs_data, K * key_num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tmp_packed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_packed, 2 * K * M,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    comparisons = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), comparisons, K * M,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tree_x = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tree_x, K * M,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    tree_y = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tree_y, K * M,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    comparison_results = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), comparison_results, K,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    auto identity_f = [](Torus x) -> Torus { return x; };
    auto is_non_zero_f = [total_modulus](Torus x) -> Torus {
      return (x % total_modulus) != 0;
    };
    auto num_bits_in_message =
        static_cast<Torus>(log2_int(params.message_modulus));
    auto msg_mod = static_cast<Torus>(params.message_modulus);
    auto block_selector_f = [](Torus msb, Torus lsb) -> Torus {
      return (msb == IS_EQUAL) ? lsb : msb;
    };
    auto last_leaf_f = [block_selector_f, num_bits_in_message,
                        msg_mod](Torus x) -> Torus {
      Torus msb = (x >> num_bits_in_message) & (msg_mod - 1);
      Torus lsb = x & (msg_mod - 1);
      return block_selector_f(msb, lsb);
    };

    identity_lut = new int_radix_lut<Torus>(streams, params, 1, 2 * K * M,
                                            allocate_gpu_memory, size_tracker);
    auto active_id = streams.active_gpu_subset(2 * K * M, params.pbs_type);
    identity_lut->generate_and_broadcast_lut(active_id, {0}, {identity_f},
                                             LUT_0_FOR_ALL_BLOCKS);

    is_non_zero_lut = new int_radix_lut<Torus>(
        streams, params, 1, K * M, allocate_gpu_memory, size_tracker);
    auto active_nz = streams.active_gpu_subset(K * M, params.pbs_type);
    is_non_zero_lut->generate_and_broadcast_lut(active_nz, {0}, {is_non_zero_f},
                                                LUT_0_FOR_ALL_BLOCKS);

    uint32_t tree_inner_blocks = tree_first_blocks > 0 ? tree_first_blocks : K;
    tree_inner_lut =
        new int_radix_lut<Torus>(streams, params, 1, tree_inner_blocks,
                                 allocate_gpu_memory, size_tracker);
    auto active_inner =
        streams.active_gpu_subset(tree_inner_blocks, params.pbs_type);
    tree_inner_lut->generate_and_broadcast_bivariate_lut(
        active_inner, {0}, {block_selector_f}, LUT_0_FOR_ALL_BLOCKS);

    tree_last_lut = new int_radix_lut<Torus>(streams, params, 1, K,
                                             allocate_gpu_memory, size_tracker);
    auto active_last = streams.active_gpu_subset(K, params.pbs_type);
    tree_last_lut->generate_and_broadcast_lut(active_last, {0}, {last_leaf_f},
                                              LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   lhs_data, gpu_memory_allocated);
    delete lhs_data;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   rhs_data, gpu_memory_allocated);
    delete rhs_data;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_packed, gpu_memory_allocated);
    delete tmp_packed;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   comparisons, gpu_memory_allocated);
    delete comparisons;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tree_x, gpu_memory_allocated);
    delete tree_x;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tree_y, gpu_memory_allocated);
    delete tree_y;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   comparison_results, gpu_memory_allocated);
    delete comparison_results;
    identity_lut->release(streams);
    delete identity_lut;
    is_non_zero_lut->release(streams);
    delete is_non_zero_lut;
    tree_inner_lut->release(streams);
    delete tree_inner_lut;
    tree_last_lut->release(streams);
    delete tree_last_lut;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

// Preallocates buffers to conditionally swap both keys and data
// simultaneously.
template <typename Torus> struct int_fused_cmux_buffer {
  int_radix_params params;
  uint32_t key_num_blocks;
  uint32_t data_num_blocks;
  bool gpu_memory_allocated;

  CudaRadixCiphertextFFI *batch_buffer_in;
  CudaRadixCiphertextFFI *batch_buffer_out;
  CudaRadixCiphertextFFI *batch_condition;

  int_radix_lut<Torus> *predicate_lut;
  int_radix_lut<Torus> *extract_lut;

  int_fused_cmux_buffer(CudaStreams streams, int_radix_params params,
                        uint32_t num_pairs, uint32_t key_num_blocks,
                        uint32_t data_num_blocks, bool allocate_gpu_memory,
                        uint64_t &size_tracker) {
    this->params = params;
    this->key_num_blocks = key_num_blocks;
    this->data_num_blocks = data_num_blocks;
    this->gpu_memory_allocated = allocate_gpu_memory;

    uint32_t K = num_pairs;
    uint32_t per_branch_blocks = 2 * K * (key_num_blocks + data_num_blocks);
    uint32_t total_bivariate = 2 * per_branch_blocks;

    batch_buffer_in = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_buffer_in,
        total_bivariate, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    batch_buffer_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_buffer_out,
        total_bivariate, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    batch_condition = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batch_condition,
        total_bivariate, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    predicate_lut = new int_radix_lut<Torus>(
        streams, params, 2, total_bivariate, allocate_gpu_memory, size_tracker);
    auto pred_f = [](Torus x) -> Torus { return x == IS_SUPERIOR; };
    auto active_pred =
        streams.active_gpu_subset(total_bivariate, params.pbs_type);
    predicate_lut->generate_and_broadcast_bivariate_lut(
        active_pred, {0, 1},
        {[pred_f](Torus b, Torus c) -> Torus { return pred_f(c) ? b : 0; },
         [pred_f](Torus b, Torus c) -> Torus { return pred_f(c) ? 0 : b; }},
        [per_branch_blocks](Torus *idx, uint32_t) {
          for (uint32_t i = 0; i < 2 * per_branch_blocks; i++)
            idx[i] = (i < per_branch_blocks) ? 0 : 1;
        });

    extract_lut =
        new int_radix_lut<Torus>(streams, params, 1, per_branch_blocks,
                                 allocate_gpu_memory, size_tracker);
    auto active_msg =
        streams.active_gpu_subset(per_branch_blocks, params.pbs_type);
    extract_lut->generate_and_broadcast_lut(
        active_msg, {0},
        {[params](Torus x) -> Torus { return x % params.message_modulus; }},
        LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_buffer_in, gpu_memory_allocated);
    delete batch_buffer_in;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_buffer_out, gpu_memory_allocated);
    delete batch_buffer_out;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   batch_condition, gpu_memory_allocated);
    delete batch_condition;
    predicate_lut->release(streams);
    delete predicate_lut;
    extract_lut->release(streams);
    delete extract_lut;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

// Top-level state. Also handles dummy-element padding for array sizes that
// aren't a power of two.
template <typename Torus> struct int_bitonic_shuffle_buffer {
  int_radix_params params;
  int_batched_compare_buffer<Torus> *batched_compare;
  int_fused_cmux_buffer<Torus> *fused_cmux;
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
                             uint32_t num_values, bool allocate_gpu_memory,
                             uint64_t &size_tracker) {
    this->params = params;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->real_num_values = num_values;
    this->key_num_blocks = key_num_blocks;
    this->data_num_blocks = data_num_blocks;

    bool needs_pad_n = (num_values & (num_values - 1)) != 0;

    uint32_t on = 1;
    while (on < num_values)
      on <<= 1;
    this->padded_num_values = needs_pad_n ? on : num_values;

    uint32_t k_min = needs_pad_n ? (key_num_blocks + 1) : key_num_blocks;
    if (k_min < 3)
      k_min = 3;
    this->key_num_blocks_padded = k_min;
    this->needs_pad = needs_pad_n || (key_num_blocks_padded != key_num_blocks);

    this->batched_compare = new int_batched_compare_buffer<Torus>(
        streams, params, padded_num_values / 2, key_num_blocks_padded,
        allocate_gpu_memory, size_tracker);
    this->fused_cmux = new int_fused_cmux_buffer<Torus>(
        streams, params, padded_num_values / 2, key_num_blocks_padded,
        data_num_blocks, allocate_gpu_memory, size_tracker);

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
    if (num_sentinels > 0) {
      sentinel_data_storage = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), sentinel_data_storage,
          num_sentinels * data_num_blocks, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);

      sentinel_data_views = new CudaRadixCiphertextFFI[num_sentinels];
      for (uint32_t i = 0; i < num_sentinels; i++) {
        as_radix_ciphertext_slice<Torus>(
            &sentinel_data_views[i], sentinel_data_storage, i * data_num_blocks,
            (i + 1) * data_num_blocks);
      }
    } else {
      sentinel_data_storage = nullptr;
      sentinel_data_views = nullptr;
    }

    padded_data_ptrs = new CudaRadixCiphertextFFI *[padded_num_values];
    for (uint32_t i = 0; i < num_sentinels; i++) {
      padded_data_ptrs[real_num_values + i] = &sentinel_data_views[i];
    }

    h_max_scalar = (Torus *)calloc(key_num_blocks_padded, sizeof(Torus));
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
    batched_compare->release(streams);
    delete batched_compare;
    fused_cmux->release(streams);
    delete fused_cmux;

    if (!needs_pad)
      return;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   padded_keys_storage, gpu_memory_allocated);
    delete padded_keys_storage;
    delete[] padded_keys_views;
    delete[] padded_keys_ptrs;

    if (sentinel_data_storage != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     sentinel_data_storage,
                                     gpu_memory_allocated);
      delete sentinel_data_storage;
      delete[] sentinel_data_views;
    }
    delete[] padded_data_ptrs;

    free(h_max_scalar);
    if (gpu_memory_allocated) {
      cuda_drop_async(d_max_scalar, streams.stream(0), streams.gpu_index(0));
    }
  }
};

// Bundles OPRF state with the shuffle buffer to generate random sorting keys.
template <typename Torus> struct int_oprf_bitonic_shuffle_buffer {
  int_radix_params params;
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
                                  bool allocate_gpu_memory,
                                  uint64_t &size_tracker) {
    this->params = params;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->key_num_blocks = key_num_blocks;

    uint64_t message_bits_per_block = log2_int(params.message_modulus);
    uint32_t total_oprf_blocks = num_values * key_num_blocks;
    uint64_t total_random_bits =
        (uint64_t)total_oprf_blocks * message_bits_per_block;

    this->oprf_memory = new int_grouped_oprf_memory<Torus>(
        streams, params, total_oprf_blocks, (uint32_t)message_bits_per_block,
        total_random_bits, allocate_gpu_memory, size_tracker);

    this->shuffle_buffer = new int_bitonic_shuffle_buffer<Torus>(
        streams, params, key_num_blocks, data_num_blocks, num_values,
        allocate_gpu_memory, size_tracker);

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
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
