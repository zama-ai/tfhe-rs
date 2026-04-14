#ifndef TFHE_RS_SHUFFLE_CUH
#define TFHE_RS_SHUFFLE_CUH

#include "integer/comparison.cuh"
#include "integer/oprf.cuh"
#include "integer/shuffle_utilities.h"
#include "linearalgebra/addition.cuh"
#include "radix_ciphertext.cuh"

// Reduces K groups of M sign blocks {INF=0, EQ=1, SUP=2} to one merged sign
// per group via pairwise (msb == EQ ? lsb : msb), then sign_handler_f.
// Unused: pack_blocks pairs cross group boundaries when M is odd.
// Inputs
// - input: K * blocks_per_group sign blocks, K contiguous groups
// - K, blocks_per_group: group count and per-group sign block count
// - sign_handler_f: post-merge transform applied per group
// Operation
// merged[g] = sign_handler_f(reduce((a, b) -> (b == EQ ? a : b), input[g, :]))
// Outputs
// - output: K merged sign blocks, one per group
//
template <typename Torus, typename KSTorus>
__host__ void batched_tree_sign_reduction(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI *input, uint32_t K, uint32_t blocks_per_group,
    int_bitonic_sort_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, std::function<Torus(Torus)> sign_handler_f) {

  auto params = mem_ptr->params;
  auto message_modulus = params.message_modulus;
  auto x = mem_ptr->batch_cmp_tree_x;
  auto y = mem_ptr->batch_cmp_tree_y;
  uint32_t total_blocks = K * blocks_per_group;

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), x, 0, total_blocks, input, 0,
      total_blocks);

  while (blocks_per_group > 2) {
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), y, x,
                       total_blocks, message_modulus);
    total_blocks >>= 1;
    blocks_per_group >>= 1;
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, x, y, bsks, ksks, mem_ptr->batch_inner_tree_leaf_lut,
        total_blocks);
  }

  auto last_lut = mem_ptr->batch_last_tree_leaf_lut;
  auto num_bits = log2_int(message_modulus);
  std::function<Torus(Torus)> f;

  if (blocks_per_group == 2) {
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), y, x,
                       total_blocks, message_modulus);
    total_blocks >>= 1;
    f = [sign_handler_f, num_bits, message_modulus](Torus x) -> Torus {
      Torus msb = (x >> num_bits) & (message_modulus - 1);
      Torus lsb = x & (message_modulus - 1);
      return sign_handler_f((msb == IS_EQUAL) ? lsb : msb);
    };
  } else {
    y = x;
    f = sign_handler_f;
  }

  auto active = streams.active_gpu_subset(total_blocks, params.pbs_type);
  last_lut->generate_and_broadcast_lut(active, {0}, {f}, LUT_0_FOR_ALL_BLOCKS,
                                       true, {mem_ptr->preallocated_h_lut});
  integer_radix_apply_univariate_lookup_table<Torus>(streams, output, y, bsks,
                                                     ksks, last_lut, K);
}

// Compares K pairs (values[i], values[i ^ j_param]) blockwise as unsigned
// radix: pack -> identity PBS -> raw subtract -> is_non_zero+1 -> tree reduce.
// Unused: relies on batched_tree_sign_reduction which mishandles odd M.
// Inputs
// - values: pointer array of length num_values
// - k_param, j_param: bitonic stage parameters; only pairs with l > i counted
// Operation
// for each pair K: pack(values[i]) - pack(values[l]); LUT to {INF, EQ, SUP};
// per-pair tree reduction yields one sign block per pair.
// Outputs
// - mem_ptr->comparison_results[0..K): one sign block per pair
//
template <typename Torus, typename KSTorus>
__host__ void host_batched_unsigned_comparison(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    uint32_t k_param, uint32_t j_param, int_bitonic_sort_buffer<Torus> *mem_ptr,
    void *const *bsks, KSTorus *const *ksks) {

  auto N = mem_ptr->num_radix_blocks;
  auto params = mem_ptr->params;
  auto message_modulus = params.message_modulus;
  auto big_lwe_dimension = params.big_lwe_dimension;
  uint32_t packed_per_pair = N / 2;
  uint32_t half = mem_ptr->max_num_pairs * packed_per_pair;

  uint32_t K = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;

    CudaRadixCiphertextFFI lp;
    as_radix_ciphertext_slice<Torus>(&lp, mem_ptr->batch_cmp_packed,
                                     K * packed_per_pair,
                                     (K + 1) * packed_per_pair);
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), &lp, values[i],
                       N, message_modulus);

    CudaRadixCiphertextFFI rp;
    as_radix_ciphertext_slice<Torus>(&rp, mem_ptr->batch_cmp_packed,
                                     half + K * packed_per_pair,
                                     half + (K + 1) * packed_per_pair);
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), &rp, values[l],
                       N, message_modulus);
    K++;
  }

  uint32_t total_packed = K * packed_per_pair;

  CudaRadixCiphertextFFI packed_view;
  as_radix_ciphertext_slice<Torus>(&packed_view, mem_ptr->batch_cmp_packed, 0,
                                   2 * total_packed);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &packed_view, &packed_view, bsks, ksks,
      mem_ptr->batch_identity_lut, 2 * total_packed);

  CudaRadixCiphertextFFI left_half, right_half, cmp_view;
  as_radix_ciphertext_slice<Torus>(&left_half, mem_ptr->batch_cmp_packed, 0,
                                   total_packed);
  as_radix_ciphertext_slice<Torus>(&right_half, mem_ptr->batch_cmp_packed, half,
                                   half + total_packed);
  as_radix_ciphertext_slice<Torus>(&cmp_view, mem_ptr->batch_cmp_comparisons, 0,
                                   total_packed);

  host_subtraction<Torus>(
      streams.stream(0), streams.gpu_index(0),
      static_cast<Torus *>(cmp_view.ptr), static_cast<Torus *>(left_half.ptr),
      static_cast<Torus *>(right_half.ptr), big_lwe_dimension, total_packed);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &cmp_view, &cmp_view, bsks, ksks, mem_ptr->batch_is_non_zero_lut,
      total_packed);
  host_add_scalar_one_inplace<Torus>(streams, &cmp_view, message_modulus,
                                     params.carry_modulus);

  std::function<Torus(Torus)> identity_f = [](Torus x) -> Torus { return x; };
  batched_tree_sign_reduction<Torus>(streams, mem_ptr->comparison_results,
                                     &cmp_view, K, packed_per_pair, mem_ptr,
                                     bsks, ksks, identity_f);
}

// Compares the K pairs (values[i], values[i ^ j_param]) selected by one
// bitonic sub-step and writes one sign block per pair. Goes through
// host_difference_check, which handles odd per-pair block counts.
// Inputs
// - values: pointer array of length num_values
// - k_param, j_param: bitonic stage parameters; only pairs with l > i counted
// Operation
// for each pair pair_idx in iteration order:
//   sign = compare(values[i], values[l]) in {INF=0, EQ=1, SUP=2}
//   mem_ptr->comparison_results[pair_idx] <- sign
// Outputs
// - mem_ptr->comparison_results[0..K): one sign block per pair
//
template <typename Torus, typename KSTorus>
__host__ void host_bitonic_sort_compare_phase(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    uint32_t k_param, uint32_t j_param, int_bitonic_sort_buffer<Torus> *mem_ptr,
    void *const *bsks, KSTorus *const *ksks) {

  auto N = mem_ptr->num_radix_blocks;
  auto cmp_mem = mem_ptr->comparison_mem;
  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;
    host_difference_check<Torus>(streams, cmp_mem->tmp_lwe_array_out, values[i],
                                 values[l], cmp_mem, cmp_mem->identity_lut_f,
                                 bsks, ksks, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->comparison_results,
        pair_idx, pair_idx + 1, cmp_mem->tmp_lwe_array_out, 0, 1);
    pair_idx++;
  }
}

// Gathers per-pair (min, max) candidates into the cmux input buffer (true
// side for the swap branch, false side for the no-swap branch) and broadcasts
// each pair's sign block into the bivariate-LUT condition slots.
// Inputs
// - values: pointer array of length num_values
// - k_param, j_param: bitonic stage parameters; ascending = (i & k_param) == 0
// - direction: 0 flips ascending, 1 keeps it
// Operation
// for each pair (i, l = i ^ j_param) with l > i:
//   true_side  = ascending ? (values[l], values[i]) : (values[i], values[l])
//   false_side = ascending ? (values[i], values[l]) : (values[l], values[i])
// Outputs
// - K_out: number of pairs visited (= num_values / 2 for the bitonic network)
// - half_out: K * blocks_per_pair (offset between true and false halves)
//
template <typename Torus>
__host__ void host_bitonic_sort_gather_cmux_batch(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    uint32_t k_param, uint32_t j_param, int32_t direction,
    int_bitonic_sort_buffer<Torus> *mem_ptr, uint32_t &K_out,
    uint32_t &half_out) {

  auto N = mem_ptr->num_radix_blocks;
  uint32_t blocks_per_pair = 2 * N;

  uint32_t K = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    if ((i ^ j_param) > i)
      K++;
  }
  uint32_t half = K * blocks_per_pair;

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;

    bool ascending = ((i & k_param) == 0);
    if (direction == 0)
      ascending = !ascending;

    uint32_t base = pair_idx * blocks_per_pair;
    CudaRadixCiphertextFFI *min_t = ascending ? values[l] : values[i];
    CudaRadixCiphertextFFI *max_t = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *min_f = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *max_f = ascending ? values[l] : values[i];

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in, base,
        base + N, min_t, 0, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in,
        base + N, base + blocks_per_pair, max_t, 0, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in,
        half + base, half + base + N, min_f, 0, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in,
        half + base + N, half + base + blocks_per_pair, max_f, 0, N);
    for (uint32_t b = 0; b < blocks_per_pair; b++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->batch_condition,
          base + b, base + b + 1, mem_ptr->comparison_results, pair_idx,
          pair_idx + 1);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->batch_condition,
          half + base + b, half + base + b + 1, mem_ptr->comparison_results,
          pair_idx, pair_idx + 1);
    }
    pair_idx++;
  }

  K_out = K;
  half_out = half;
}

// Runs the bivariate cmux PBS on the gathered batch, sums the true and false
// halves, message-extracts the result, and scatters back to values[i] and
// values[l]. Counterpart to host_bitonic_sort_gather_cmux_batch.
// Inputs
// - K, half: as returned by the gather phase
// - j_param: bitonic stage parameter (same as gather)
// Operation
// PBS LUT_0/LUT_1 with predicate (c == SUP) zero out the unselected branch;
// host_addition collapses true_half + false_half into the chosen blocks;
// message_extract LUT cleans the message; then per-pair scatter writes
// extract_out[base..base+N) -> values[i] and extract_out[base+N..) ->
// values[l]. Outputs
// - values[i], values[l] updated in place for every pair
//
template <typename Torus, typename KSTorus>
__host__ void host_bitonic_sort_apply_cmux_batch(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    uint32_t j_param, uint32_t K, uint32_t half,
    int_bitonic_sort_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks) {

  auto N = mem_ptr->num_radix_blocks;
  auto params = mem_ptr->params;
  uint32_t blocks_per_pair = 2 * N;
  uint32_t total_bivariate = 2 * half;

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, mem_ptr->batch_buffer_out, mem_ptr->batch_buffer_in,
      mem_ptr->batch_condition, bsks, ksks, mem_ptr->batch_predicate_lut,
      total_bivariate, params.message_modulus);

  CudaRadixCiphertextFFI true_half, false_half;
  as_radix_ciphertext_slice<Torus>(&true_half, mem_ptr->batch_buffer_out, 0,
                                   half);
  as_radix_ciphertext_slice<Torus>(&false_half, mem_ptr->batch_buffer_out, half,
                                   total_bivariate);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &true_half,
                       &true_half, &false_half, half, params.message_modulus,
                       params.carry_modulus);

  CudaRadixCiphertextFFI extract_out;
  as_radix_ciphertext_slice<Torus>(&extract_out, mem_ptr->batch_buffer_out, 0,
                                   half);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &extract_out, &true_half, bsks, ksks,
      mem_ptr->batch_message_extract_lut, half);

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;
    uint32_t base = pair_idx * blocks_per_pair;
    copy_radix_ciphertext_slice_async<Torus>(streams.stream(0),
                                             streams.gpu_index(0), values[i], 0,
                                             N, &extract_out, base, base + N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), values[l], 0, N, &extract_out,
        base + N, base + blocks_per_pair);
    pair_idx++;
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_bitonic_shuffle(
    CudaStreams streams, int_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_radix_blocks, uint32_t data_num_radix_blocks,
    uint32_t num_values, int_radix_params params, bool data_is_signed,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_bitonic_shuffle_buffer<Torus>(
      streams, params, key_num_radix_blocks, data_num_radix_blocks, num_values,
      data_is_signed, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

// One sub-step of the bitonic network: compares keys and applies the same
// per-pair condition to swap both keys and data. Mirrors comparison_results
// from keys_buffer to data_buffer so the two cmux passes share signs.
// Inputs
// - keys, values: parallel pointer arrays, num_values entries each
// - k_param, j_param: bitonic stage parameters
// - direction: 0 flips ascending sub-arrays
// Operation
// compare_phase(keys) -> condition;
// gather + apply cmux on keys; copy condition into data_buffer;
// gather + apply cmux on values with the same condition.
// Outputs
// - keys[], values[] updated in place
//
template <typename Torus, typename KSTorus>
__host__ void
host_bitonic_shuffle_substep(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                             CudaRadixCiphertextFFI **values,
                             uint32_t num_values, uint32_t k_param,
                             uint32_t j_param, int32_t direction,
                             int_bitonic_shuffle_buffer<Torus> *mem_ptr,
                             void *const *bsks, KSTorus *const *ksks) {

  auto key_buf = mem_ptr->keys_buffer;
  auto data_buf = mem_ptr->data_buffer;

  host_bitonic_sort_compare_phase<Torus>(streams, keys, num_values, k_param,
                                         j_param, key_buf, bsks, ksks);

  uint32_t K_keys, half_keys;
  host_bitonic_sort_gather_cmux_batch<Torus>(streams, keys, num_values, k_param,
                                             j_param, direction, key_buf,
                                             K_keys, half_keys);
  host_bitonic_sort_apply_cmux_batch<Torus>(streams, keys, num_values, j_param,
                                            K_keys, half_keys, key_buf, bsks,
                                            ksks);

  uint32_t K_pairs = num_values / 2;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), data_buf->comparison_results, 0,
      K_pairs, key_buf->comparison_results, 0, K_pairs);

  uint32_t K_data, half_data;
  host_bitonic_sort_gather_cmux_batch<Torus>(streams, values, num_values,
                                             k_param, j_param, direction,
                                             data_buf, K_data, half_data);
  host_bitonic_sort_apply_cmux_batch<Torus>(streams, values, num_values,
                                            j_param, K_data, half_data,
                                            data_buf, bsks, ksks);
}

// When num_values is not a power of 2, materializes the padded keys and data
// pointer arrays held by mem_ptr; otherwise aliases the caller arrays in
// *eff_*. Sentinel keys are all-MAX so they sort to the tail.
// Inputs
// - keys, values, num_values: caller arrays
// Operation
// real keys i in [0, num_values): copy first K0 blocks, zero MSB extension.
// sentinel keys i in [num_values, padded_num_values): all blocks set to MAX.
// real data ptrs aliased; sentinel data slots zeroed.
// Outputs
// - *eff_keys, *eff_values, *eff_num_values: views fed to the bitonic network
//
template <typename Torus>
__host__ void host_bitonic_shuffle_setup_padded(
    CudaStreams streams, CudaRadixCiphertextFFI **keys,
    CudaRadixCiphertextFFI **values, uint32_t num_values,
    int_bitonic_shuffle_buffer<Torus> *mem_ptr,
    CudaRadixCiphertextFFI ***eff_keys, CudaRadixCiphertextFFI ***eff_values,
    uint32_t *eff_num_values) {

  if (!mem_ptr->needs_pad) {
    *eff_keys = keys;
    *eff_values = values;
    *eff_num_values = num_values;
    return;
  }

  uint32_t Kp = mem_ptr->key_num_blocks_padded;
  uint32_t K0 = mem_ptr->key_num_blocks;
  uint32_t padded_n = mem_ptr->padded_num_values;
  uint32_t data_n_blocks = mem_ptr->data_num_blocks;

  for (uint32_t i = 0; i < num_values; i++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &mem_ptr->padded_keys_views[i],
        0, K0, keys[i], 0, K0);
    if (Kp > K0) {
      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &mem_ptr->padded_keys_views[i], K0, Kp);
    }
  }

  for (uint32_t i = num_values; i < padded_n; i++) {
    set_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &mem_ptr->padded_keys_views[i],
        mem_ptr->d_max_scalar, mem_ptr->h_max_scalar, Kp,
        mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);
  }

  for (uint32_t i = 0; i < num_values; i++)
    mem_ptr->padded_data_ptrs[i] = values[i];

  for (uint32_t i = 0; i < padded_n - num_values; i++) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        &mem_ptr->sentinel_data_views[i], 0, data_n_blocks);
  }

  *eff_keys = mem_ptr->padded_keys_ptrs;
  *eff_values = mem_ptr->padded_data_ptrs;
  *eff_num_values = padded_n;
}

// Sorts (keys, values) ascending by keys via a bitonic network. When
// num_values is not a power of 2, runs the network on a padded vector with
// (key=MAX, data=0) sentinels; padding is implicitly dropped on return.
// Inputs
// - keys, values: parallel pointer arrays of length num_values
// Operation
// for k = 2..eff_n in powers of 2, for j = k/2..1 in powers of 2:
//   substep(eff_keys, eff_values, eff_n, k, j, direction = 1)
// Outputs
// - values[] permuted to match keys[] sorted ascending in place
//
template <typename Torus, typename KSTorus>
__host__ void
host_bitonic_shuffle(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                     CudaRadixCiphertextFFI **values, uint32_t num_values,
                     int_bitonic_shuffle_buffer<Torus> *mem_ptr,
                     void *const *bsks, KSTorus *const *ksks) {

  CudaRadixCiphertextFFI **eff_keys;
  CudaRadixCiphertextFFI **eff_values;
  uint32_t eff_n;
  host_bitonic_shuffle_setup_padded<Torus>(streams, keys, values, num_values,
                                           mem_ptr, &eff_keys, &eff_values,
                                           &eff_n);

  for (uint32_t k = 2; k <= eff_n; k <<= 1)
    for (uint32_t j = k >> 1; j > 0; j >>= 1)
      host_bitonic_shuffle_substep<Torus>(streams, eff_keys, eff_values, eff_n,
                                          k, j, 1, mem_ptr, bsks, ksks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_oprf_bitonic_shuffle(
    CudaStreams streams, int_oprf_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_blocks, uint32_t data_num_blocks, uint32_t num_values,
    int_radix_params params, bool data_is_signed, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_oprf_bitonic_shuffle_buffer<Torus>(
      streams, params, key_num_blocks, data_num_blocks, num_values,
      data_is_signed, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

// Generates one OPRF-derived random key per value, then runs a bitonic
// shuffle keyed by those random keys. The result is a uniformly random
// permutation that does not reveal the keys server-side.
// Inputs
// - values: pointer array of length num_values
// - seeded_lwe_input: num_values * key_num_blocks LWEs, one block of seed
//   material per key block, laid out contiguously
// Operation
// keys[i] <- OPRF(seeded_lwe_input[i, :]); host_bitonic_shuffle(keys, values).
// Outputs
// - values[] permuted in place
//
template <typename Torus, typename KSTorus>
__host__ void
host_oprf_bitonic_shuffle(CudaStreams streams, CudaRadixCiphertextFFI **values,
                          uint32_t num_values, const Torus *seeded_lwe_input,
                          int_oprf_bitonic_shuffle_buffer<Torus> *mem_ptr,
                          void *const *bsks, KSTorus *const *ksks) {

  uint32_t key_num_blocks = mem_ptr->key_num_blocks;

  host_integer_grouped_oprf<Torus>(
      streams, mem_ptr->keys_storage, seeded_lwe_input,
      num_values * key_num_blocks, mem_ptr->oprf_memory, bsks);

  host_bitonic_shuffle<Torus>(streams, mem_ptr->keys_ptrs, values, num_values,
                              mem_ptr->shuffle_buffer, bsks, ksks);
}

#endif
