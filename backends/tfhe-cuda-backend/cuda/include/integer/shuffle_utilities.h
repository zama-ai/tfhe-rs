#pragma once
#include "checked_arithmetic.h"
#include "comparison.h"
#include "integer_utilities.h"
#include "oprf.h"

/// @brief Forward declaration of the re-randomization scratch buffer.
template <typename Torus> struct int_rerand_mem;

/**
 * @brief Scratch buffer for batched encrypted key comparisons. Holds
 * contiguous lhs/rhs key blocks for all pairs, intermediate packing and
 * tree-reduction buffers, and the precomputed LUTs needed by
 * bitonic_sort_compare_phase_batched.
 */
template <typename Torus> struct int_batched_compare_buffer {
  int_radix_params params;
  /// @brief Number of radix blocks per key; must be >= 3.
  uint32_t key_num_blocks;
  /// @brief Number of packed blocks per key after pair-packing:
  /// ceil(key_num_blocks/2).
  uint32_t packed_per_pair;
  bool gpu_memory_allocated;

  /// @brief Contiguous buffer of all K lhs keys (keys[i], the lower-index
  /// element
  ///        of each pair): K * key_num_blocks blocks.
  CudaRadixCiphertextFFI *lhs_data;
  /// @brief Contiguous buffer of all K rhs keys (keys[i ^
  /// bitonic_subsequence_stride],
  ///        the higher-index element of each pair): K * key_num_blocks blocks.
  CudaRadixCiphertextFFI *rhs_data;

  /// @brief Temporary buffer for pair-packed lhs and rhs blocks: 2 * K *
  /// packed_per_pair blocks.
  CudaRadixCiphertextFFI *tmp_packed;
  /// @brief Per-block comparison verdicts after is_non_zero PBS: K *
  /// packed_per_pair blocks.
  CudaRadixCiphertextFFI *comparisons;
  /// @brief Tree reduction working buffer, current level.
  CudaRadixCiphertextFFI *tree_x;
  /// @brief Tree reduction working buffer, next level.
  CudaRadixCiphertextFFI *tree_y;
  /// @brief Final EQ or IS_SUPERIOR verdict per pair: K blocks.
  CudaRadixCiphertextFFI *comparison_results;

  /// @brief Identity LUT used to refresh noise on packed blocks before
  /// subtraction.
  int_radix_lut<Torus> *identity_lut;
  /// @brief Univariate LUT mapping any non-zero value to 1, zero to 0.
  int_radix_lut<Torus> *is_non_zero_lut;
  /// @brief Bivariate LUT implementing block_selector for inner tree levels:
  ///        returns IS_SUPERIOR if either packed verdict is not EQ.
  int_radix_lut<Torus> *is_any_not_equal_lut;
  /// @brief Univariate variant of is_any_not_equal_lut operating on a
  /// pre-packed
  ///        value; used at the final tree step to save one PBS.
  int_radix_lut<Torus> *is_any_not_equal_packed_lut;

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
    is_any_not_equal_lut =
        new int_radix_lut<Torus>(streams, params, 1, tree_inner_blocks,
                                 allocate_gpu_memory, size_tracker);
    auto active_inner =
        streams.active_gpu_subset(tree_inner_blocks, params.pbs_type);
    is_any_not_equal_lut->generate_and_broadcast_bivariate_lut(
        active_inner, {0}, {block_selector_f}, LUT_0_FOR_ALL_BLOCKS);

    is_any_not_equal_packed_lut = new int_radix_lut<Torus>(
        streams, params, 1, K, allocate_gpu_memory, size_tracker);
    auto active_last = streams.active_gpu_subset(K, params.pbs_type);
    is_any_not_equal_packed_lut->generate_and_broadcast_lut(
        active_last, {0}, {last_leaf_f}, LUT_0_FOR_ALL_BLOCKS);
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
    is_any_not_equal_lut->release(streams);
    delete is_any_not_equal_lut;
    is_any_not_equal_packed_lut->release(streams);
    delete is_any_not_equal_packed_lut;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * @brief Scratch buffer to conditionally swap both keys and data
 * simultaneously.
 */
template <typename Torus> struct int_fused_cmux_buffer {
  int_radix_params params;
  /// @brief Number of radix blocks per key.
  uint32_t key_num_blocks;
  /// @brief Number of radix blocks per data element.
  uint32_t data_num_blocks;
  bool gpu_memory_allocated;

  /// @brief Input buffer holding both branches in layout
  ///        [ keys_is_superior | data_is_superior | keys_is_equal |
  ///        data_is_equal ].
  CudaRadixCiphertextFFI *batch_buffer_in;
  /// @brief Output buffer after the bivariate predicate PBS; same layout as
  /// batch_buffer_in.
  CudaRadixCiphertextFFI *batch_buffer_out;
  /// @brief Comparison result (EQ or IS_SUPERIOR) broadcast across all blocks
  /// of each pair.
  CudaRadixCiphertextFFI *batch_condition;

  /// @brief Bivariate LUT that zeros the losing branch per block: passes b if
  ///        cond == IS_SUPERIOR (is_superior half) or cond != IS_SUPERIOR
  ///        (is_equal half).
  int_radix_lut<Torus> *predicate_lut;
  /// @brief Univariate LUT for message extraction (x -> x % message_modulus)
  /// applied
  ///        after adding the two halves to re-bootstrap before the next
  ///        substep.
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

/**
 * @brief Top-level scratch buffer for the bitonic shuffle. Owns the
 * compare and CMUX sub-buffers, and handles padding of the input array
 * to the next power of two with sentinel keys (MAX_VALUE) and zero data.
 */
template <typename Torus> struct int_bitonic_shuffle_buffer {
  int_radix_params params;
  /// @brief Sub-buffer for the batched key comparison phase.
  int_batched_compare_buffer<Torus> *batched_compare;
  /// @brief Sub-buffer for the fused CMUX phase.
  int_fused_cmux_buffer<Torus> *fused_cmux;
  bool gpu_memory_allocated;

  /// @brief Original number of values before padding.
  uint32_t real_num_values;
  /// @brief Number of values after padding to the next power of two.
  uint32_t padded_num_values;
  /// @brief Number of radix blocks per key as provided by the caller.
  uint32_t key_num_blocks;
  /// @brief key_num_blocks raised to at least 3, ensuring packed_per_pair >= 2
  ///        as required by the final tree reduction step.
  uint32_t key_num_blocks_padded;
  /// @brief Number of radix blocks per data element.
  uint32_t data_num_blocks;
  /// @brief True when padding or block-count adjustment is needed.
  bool needs_pad;

  /// @brief Flat storage for all padded keys: padded_num_values *
  /// key_num_blocks_padded blocks.
  CudaRadixCiphertextFFI *padded_keys_storage;
  /// @brief Per-element views into padded_keys_storage.
  CudaRadixCiphertextFFI *padded_keys_views;
  /// @brief Pointer array into padded_keys_views passed to the sort.
  CudaRadixCiphertextFFI **padded_keys_ptrs;

  /// @brief Flat storage for sentinel (zero) data elements filling the padding
  /// slots.
  CudaRadixCiphertextFFI *sentinel_data_storage;
  /// @brief Per-element views into sentinel_data_storage.
  CudaRadixCiphertextFFI *sentinel_data_views;
  /// @brief Unified data pointer array combining real data and sentinel
  /// pointers.
  CudaRadixCiphertextFFI **padded_data_ptrs;

  /// @brief Host-side maximum key scalar used to initialise sentinel keys.
  Torus *h_max_scalar;
  /// @brief Device-side maximum key scalar used to initialise sentinel keys.
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
    // Pad to 3 minimum since the tree-reduction needs at least two blocks
    // for the final layer of the tree (hardcoded final layer with dedicated
    // LUT)
    if (k_min < 3)
      k_min = 3;
    this->key_num_blocks_padded = k_min;
    this->needs_pad = needs_pad_n || (key_num_blocks_padded != key_num_blocks);

    GPU_ASSERT(padded_num_values >= 2,
               "In bitonic shuffle: padded_num_values / 2 must be at least 1");
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

    if (gpu_memory_allocated) {
      cuda_drop_async(d_max_scalar, streams.stream(0), streams.gpu_index(0));
    }
    streams.synchronize();
    free(h_max_scalar);
  }
};

/**
 * @brief Top-level scratch buffer for the OPRF-keyed bitonic shuffle. Generates
 * fresh encrypted random keys via OPRF, then delegates to
 * int_bitonic_shuffle_buffer to sort the data values by those keys.
 */
template <typename Torus> struct int_oprf_bitonic_shuffle_buffer {
  int_radix_params params;
  /// @brief Number of radix blocks per OPRF-generated key.
  uint32_t key_num_blocks;
  /// @brief Number of data elements to shuffle.
  uint32_t num_values;

  /// @brief OPRF scratch memory used to produce the random sorting keys.
  int_grouped_oprf_memory<Torus> *oprf_memory;
  /// @brief Underlying bitonic shuffle buffer that sorts data by the OPRF keys.
  int_bitonic_shuffle_buffer<Torus> *shuffle_buffer;
  /// @brief Optional re-randomization scratch for sort keys.
  int_rerand_mem<Torus> *rerand_memory;

  /// @brief Flat storage for all num_values OPRF-generated keys: num_values *
  /// key_num_blocks blocks.
  CudaRadixCiphertextFFI *keys_storage;
  /// @brief Per-element views into keys_storage.
  CudaRadixCiphertextFFI *keys_views;
  /// @brief Pointer array into keys_views passed to host_bitonic_shuffle as the
  /// key array.
  CudaRadixCiphertextFFI **keys_ptrs;

  bool gpu_memory_allocated;

  /// @brief Returns true when re-randomization of sort keys is enabled.
  bool applies_rerand() const { return rerand_memory != nullptr; }

  int_oprf_bitonic_shuffle_buffer(CudaStreams streams, int_radix_params params,
                                  uint32_t key_num_blocks,
                                  uint32_t data_num_blocks, uint32_t num_values,
                                  bool allocate_gpu_memory,
                                  uint64_t &size_tracker) {
    this->params = params;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->key_num_blocks = key_num_blocks;
    this->num_values = num_values;
    this->rerand_memory = nullptr;

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

  /// @brief Overloaded constructor that also allocates re-randomization scratch
  ///        for the OPRF-generated sort keys.
  ///
  /// @param rerand_params      Radix params for the re-randomization key.
  /// @param rerand_mode        Re-randomization mode (with or without KS).
  int_oprf_bitonic_shuffle_buffer(CudaStreams streams, int_radix_params params,
                                  int_radix_params rerand_params,
                                  uint32_t key_num_blocks,
                                  uint32_t data_num_blocks, uint32_t num_values,
                                  RERAND_MODE rerand_mode,
                                  bool allocate_gpu_memory,
                                  uint64_t &size_tracker)
      : int_oprf_bitonic_shuffle_buffer(streams, params, key_num_blocks,
                                        data_num_blocks, num_values,
                                        allocate_gpu_memory, size_tracker) {
    this->rerand_memory = new int_rerand_mem<Torus>(
        streams, rerand_params, num_values * key_num_blocks, rerand_mode,
        allocate_gpu_memory, size_tracker);
  }

  void release(CudaStreams streams) {
    if (this->applies_rerand()) {
      rerand_memory->release(streams);
      delete rerand_memory;
    }
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
