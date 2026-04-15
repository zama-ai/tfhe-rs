#ifndef TFHE_RS_SHUFFLE_CUH
#define TFHE_RS_SHUFFLE_CUH

#include "integer/comparison.cuh"
#include "integer/shuffle_utilities.h"
#include "linearalgebra/addition.cuh"
#include "radix_ciphertext.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_bitonic_sort(
    CudaStreams streams, int_bitonic_sort_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, uint32_t num_values, int_radix_params params,
    bool is_signed, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_bitonic_sort_buffer<Torus>(
      streams, params, num_radix_blocks, num_values, is_signed,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

// Reduce K groups of M sign blocks {INF=0, EQ=1, SUP=2} to K final signs by
// pairwise merge (msb == EQ ? lsb : msb), then apply sign_handler_f.
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

  // Inner levels: K*M -> K*2.
  while (blocks_per_group > 2) {
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), y, x,
                       total_blocks, message_modulus);
    total_blocks >>= 1;
    blocks_per_group >>= 1;
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, x, y, bsks, ksks, mem_ptr->batch_inner_tree_leaf_lut,
        total_blocks);
  }

  // Last level: merge the final pair (if any) and apply sign_handler_f.
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

// Batched unsigned comparison for all K pairs selected by j_param in one
// sub-step: pack -> identity PBS -> subtract -> is_non_zero+1 -> tree reduce.
// Result: K sign blocks in mem_ptr->comparison_results.
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

  // Gather + pack each pair (values[i], values[l]) into left/right halves.
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

  // Identity PBS to clean noise after packing.
  CudaRadixCiphertextFFI packed_view;
  as_radix_ciphertext_slice<Torus>(&packed_view, mem_ptr->batch_cmp_packed, 0,
                                   2 * total_packed);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &packed_view, &packed_view, bsks, ksks,
      mem_ptr->batch_identity_lut, 2 * total_packed);

  // Raw LWE subtract: cmp = left - right.
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

  // Map diff to {0=INF, 1=EQ, 2=SUP} via is_non_zero + scalar one.
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

// Phase 1 of a sub-step: produce K comparison signs. Batched when unsigned,
// sequential host_difference_check fallback when signed.
template <typename Torus, typename KSTorus>
__host__ void host_bitonic_sort_compare_phase(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    uint32_t k_param, uint32_t j_param, int_bitonic_sort_buffer<Torus> *mem_ptr,
    void *const *bsks, KSTorus *const *ksks) {

  auto N = mem_ptr->num_radix_blocks;

  if (!mem_ptr->is_signed) {
    host_batched_unsigned_comparison<Torus>(
        streams, values, num_values, k_param, j_param, mem_ptr, bsks, ksks);
  } else {
    auto cmp_mem = mem_ptr->comparison_mem;
    uint32_t pair_idx = 0;
    for (uint32_t i = 0; i < num_values; i++) {
      uint32_t l = i ^ j_param;
      if (l <= i)
        continue;
      host_difference_check<Torus>(streams, cmp_mem->tmp_lwe_array_out,
                                   values[i], values[l], cmp_mem,
                                   cmp_mem->identity_lut_f, bsks, ksks, N);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->comparison_results,
          pair_idx, pair_idx + 1, cmp_mem->tmp_lwe_array_out, 0, 1);
      pair_idx++;
    }
  }
}

// Phase 2a: for each compare-and-swap pair, copy (min, max) candidates into
// batch_buffer_in (2N blocks per pair on each side) and broadcast the pair's
// sign into batch_condition. Returns K (number of pairs) and half (= K * 2N).
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

    // Ascending iff bit k_param of i is zero, flip when sorting descending.
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

// Phase 2b: run the cmux PBS, sum the selected halves, msg-extract, and
// scatter results back into values[].
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

  // Sum the two halves: one side holds the selected value, the other is zero.
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

// One sub-step of the bitonic network for fixed (k_param, j_param).
template <typename Torus, typename KSTorus>
__host__ void
host_bitonic_sort_substep(CudaStreams streams, CudaRadixCiphertextFFI **values,
                          uint32_t num_values, uint32_t k_param,
                          uint32_t j_param, int32_t direction,
                          int_bitonic_sort_buffer<Torus> *mem_ptr,
                          void *const *bsks, KSTorus *const *ksks) {

  host_bitonic_sort_compare_phase<Torus>(streams, values, num_values, k_param,
                                         j_param, mem_ptr, bsks, ksks);

  uint32_t K, half;
  host_bitonic_sort_gather_cmux_batch<Torus>(streams, values, num_values,
                                             k_param, j_param, direction,
                                             mem_ptr, K, half);

  host_bitonic_sort_apply_cmux_batch<Torus>(
      streams, values, num_values, j_param, K, half, mem_ptr, bsks, ksks);
}

template <typename Torus, typename KSTorus>
__host__ void
host_bitonic_sort(CudaStreams streams, CudaRadixCiphertextFFI **values,
                  uint32_t num_values, int_bitonic_sort_buffer<Torus> *mem_ptr,
                  void *const *bsks, KSTorus *const *ksks, int32_t direction) {

  for (uint32_t k = 2; k <= num_values; k <<= 1)
    for (uint32_t j = k >> 1; j > 0; j >>= 1)
      host_bitonic_sort_substep<Torus>(streams, values, num_values, k, j,
                                       direction, mem_ptr, bsks, ksks);
}

#endif
