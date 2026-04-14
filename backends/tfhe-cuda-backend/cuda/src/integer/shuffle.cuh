#ifndef TFHE_RS_SHUFFLE_CUH
#define TFHE_RS_SHUFFLE_CUH

#include "integer/oprf.cuh"
#include "integer/shuffle_utilities.h"
#include "linearalgebra/addition.cuh"
#include "radix_ciphertext.cuh"

// Pair-packs adjacent blocks within each row. Used at both ends of the
// batched compare: to pack keys before the subtract, and the last two
// verdicts before the final LUT.
//
//   row_in : [b0][b1][b2][b3] ... [b_{M-1}]            M blocks
//   row_out: [b0 + f*b1][b2 + f*b3] ... [b_{2k} + f*b_{2k+1}]
//
// If M is odd, the orphan b_{M-1} is copied verbatim into the last slot:
//   row_out: [...][b_{M-3} + f*b_{M-2}][b_{M-1}]
//
template <typename Torus>
__global__ void pair_pack_per_row_kernel(Torus *out, Torus const *in,
                                         uint32_t lwe_dim, uint32_t num_rows,
                                         uint32_t partial_M, uint32_t factor) {
  uint32_t tid = threadIdx.x + blockIdx.x * blockDim.x;
  uint32_t lwe_size = lwe_dim + 1;
  if (tid >= lwe_size)
    return;

  uint32_t full_pairs = partial_M / 2;
  uint32_t out_M = (partial_M + 1) / 2;

  for (uint32_t p = 0; p < num_rows; p++) {
    Torus const *row_in = in + (size_t)p * partial_M * lwe_size;
    Torus *row_out = out + (size_t)p * out_M * lwe_size;

    for (uint32_t b = 0; b < full_pairs; b++) {
      Torus lsb = row_in[(2 * b) * lwe_size + tid];
      Torus msb = row_in[(2 * b + 1) * lwe_size + tid];
      row_out[b * lwe_size + tid] = lsb + factor * msb;
    }

    if (partial_M & 1u) {
      Torus orphan = row_in[(partial_M - 1) * lwe_size + tid];
      row_out[full_pairs * lwe_size + tid] = orphan;
    }
  }
}

template <typename Torus>
__host__ void pair_pack_per_row(cudaStream_t stream, uint32_t gpu_index,
                                CudaRadixCiphertextFFI *lwe_array_out,
                                CudaRadixCiphertextFFI const *lwe_array_in,
                                uint32_t num_rows, uint32_t partial_M,
                                uint32_t factor, uint32_t message_modulus,
                                uint32_t carry_modulus) {
  if (num_rows == 0 || partial_M == 0)
    return;
  if (lwe_array_in->lwe_dimension != lwe_array_out->lwe_dimension)
    PANIC("Cuda error: pair_pack_per_row requires matching lwe_dimension on "
          "input and output")
  uint32_t out_M = (partial_M + 1u) / 2u;
  if (lwe_array_in->num_radix_blocks < num_rows * partial_M)
    PANIC("Cuda error: pair_pack_per_row input does not have enough blocks")
  if (lwe_array_out->num_radix_blocks < num_rows * out_M)
    PANIC("Cuda error: pair_pack_per_row output does not have enough blocks")
  uint32_t lwe_size = lwe_array_in->lwe_dimension + 1;
  cuda_set_device(gpu_index);
  int blocks = 0, threads = 0;
  getNumBlocksAndThreads(lwe_size, 1024, blocks, threads);
  pair_pack_per_row_kernel<Torus><<<blocks, threads, 0, stream>>>(
      (Torus *)lwe_array_out->ptr, (Torus const *)lwe_array_in->ptr,
      lwe_array_in->lwe_dimension, num_rows, partial_M, factor);
  check_cuda_error(cudaGetLastError());

  uint32_t full_pairs = partial_M / 2;
  for (uint32_t p = 0; p < num_rows; p++) {
    uint32_t in_off = p * partial_M;
    uint32_t out_off = p * out_M;
    for (uint32_t b = 0; b < full_pairs; b++) {
      uint64_t deg_lsb = lwe_array_in->degrees[in_off + 2 * b];
      uint64_t deg_msb = lwe_array_in->degrees[in_off + 2 * b + 1];
      uint64_t noise_lsb = lwe_array_in->noise_levels[in_off + 2 * b];
      uint64_t noise_msb = lwe_array_in->noise_levels[in_off + 2 * b + 1];
      lwe_array_out->degrees[out_off + b] = deg_lsb + factor * deg_msb;
      lwe_array_out->noise_levels[out_off + b] = noise_lsb + factor * noise_msb;
      CHECK_NOISE_LEVEL(lwe_array_out->noise_levels[out_off + b],
                        message_modulus, carry_modulus);
    }
    if (partial_M & 1u) {
      uint32_t orphan_in = in_off + partial_M - 1;
      uint32_t orphan_out = out_off + full_pairs;
      lwe_array_out->degrees[orphan_out] = lwe_array_in->degrees[orphan_in];
      lwe_array_out->noise_levels[orphan_out] =
          lwe_array_in->noise_levels[orphan_in];
      CHECK_NOISE_LEVEL(lwe_array_out->noise_levels[orphan_out],
                        message_modulus, carry_modulus);
    }
  }
}

// Like pair_pack_per_row, but for one level of the tree reduction that
// collapses M per-block verdicts into a single verdict per pair.
// On an odd orphan v_{M-1}, packs (msb = orphan, lsb = trivial EQ) so the next
// block_selector LUT preserves the orphan's verdict:
//   row_out: [...][EQ + f * v_{M-1}]
//
template <typename Torus>
__global__ void
tree_merge_pack_per_row_kernel(Torus *out, Torus const *in, uint32_t lwe_dim,
                               uint32_t num_rows, uint32_t partial_M,
                               uint32_t factor, uint64_t eq_delta) {
  uint32_t tid = threadIdx.x + blockIdx.x * blockDim.x;
  uint32_t lwe_size = lwe_dim + 1;
  if (tid >= lwe_size)
    return;

  uint32_t full_pairs = partial_M / 2;
  uint32_t out_M = (partial_M + 1) / 2;

  for (uint32_t p = 0; p < num_rows; p++) {
    Torus const *row_in = in + (size_t)p * partial_M * lwe_size;
    Torus *row_out = out + (size_t)p * out_M * lwe_size;

    for (uint32_t b = 0; b < full_pairs; b++) {
      Torus lsb = row_in[(2 * b) * lwe_size + tid];
      Torus msb = row_in[(2 * b + 1) * lwe_size + tid];
      row_out[b * lwe_size + tid] = lsb + factor * msb;
    }

    if (partial_M & 1u) {
      Torus orphan = row_in[(partial_M - 1) * lwe_size + tid];
      Torus shadow = (tid == lwe_dim) ? (Torus)eq_delta : (Torus)0;
      row_out[full_pairs * lwe_size + tid] = shadow + factor * orphan;
    }
  }
}

template <typename Torus>
__host__ void
tree_merge_pack_per_row(cudaStream_t stream, uint32_t gpu_index,
                        CudaRadixCiphertextFFI *lwe_array_out,
                        CudaRadixCiphertextFFI const *lwe_array_in,
                        uint32_t num_rows, uint32_t partial_M, uint32_t factor,
                        uint32_t message_modulus, uint32_t carry_modulus) {
  if (num_rows == 0 || partial_M == 0)
    return;
  if (lwe_array_in->lwe_dimension != lwe_array_out->lwe_dimension)
    PANIC("Cuda error: tree_merge_pack_per_row requires matching "
          "lwe_dimension on input and output")
  if (message_modulus == 0 || carry_modulus == 0)
    PANIC("Cuda error: tree_merge_pack_per_row requires "
          "message_modulus > 0 and carry_modulus > 0")
  uint32_t out_M = (partial_M + 1u) / 2u;
  if (lwe_array_in->num_radix_blocks < num_rows * partial_M)
    PANIC("Cuda error: tree_merge_pack_per_row input does not have enough "
          "blocks")
  if (lwe_array_out->num_radix_blocks < num_rows * out_M)
    PANIC("Cuda error: tree_merge_pack_per_row output does not have enough "
          "blocks")
  uint64_t total = (uint64_t)message_modulus * carry_modulus;
  if (factor != message_modulus)
    PANIC("Cuda error: tree_merge_pack_per_row expects factor == "
          "message_modulus")
  if (1u + factor * 2u >= total)
    PANIC("Cuda error: tree_merge_pack_per_row EQ-shadow packed value "
          "would overflow message+carry space")
  uint32_t lwe_size = lwe_array_in->lwe_dimension + 1;
  uint64_t eq_delta = ((uint64_t)1 << 63) / total;
  cuda_set_device(gpu_index);
  int blocks = 0, threads = 0;
  getNumBlocksAndThreads(lwe_size, 1024, blocks, threads);
  tree_merge_pack_per_row_kernel<Torus><<<blocks, threads, 0, stream>>>(
      (Torus *)lwe_array_out->ptr, (Torus const *)lwe_array_in->ptr,
      lwe_array_in->lwe_dimension, num_rows, partial_M, factor, eq_delta);
  check_cuda_error(cudaGetLastError());

  uint32_t full_pairs = partial_M / 2;
  for (uint32_t p = 0; p < num_rows; p++) {
    uint32_t in_off = p * partial_M;
    uint32_t out_off = p * out_M;
    for (uint32_t b = 0; b < full_pairs; b++) {
      uint64_t deg_lsb = lwe_array_in->degrees[in_off + 2 * b];
      uint64_t deg_msb = lwe_array_in->degrees[in_off + 2 * b + 1];
      uint64_t noise_lsb = lwe_array_in->noise_levels[in_off + 2 * b];
      uint64_t noise_msb = lwe_array_in->noise_levels[in_off + 2 * b + 1];
      lwe_array_out->degrees[out_off + b] = deg_lsb + factor * deg_msb;
      lwe_array_out->noise_levels[out_off + b] = noise_lsb + factor * noise_msb;
      CHECK_NOISE_LEVEL(lwe_array_out->noise_levels[out_off + b],
                        message_modulus, carry_modulus);
    }
    if (partial_M & 1u) {
      uint32_t orphan_in = in_off + partial_M - 1;
      uint32_t orphan_out = out_off + full_pairs;
      lwe_array_out->degrees[orphan_out] =
          1u + factor * lwe_array_in->degrees[orphan_in];
      lwe_array_out->noise_levels[orphan_out] =
          factor * lwe_array_in->noise_levels[orphan_in];
      CHECK_NOISE_LEVEL(lwe_array_out->noise_levels[orphan_out],
                        message_modulus, carry_modulus);
    }
  }
}

template <typename Torus>
__global__ void tile_pair_signs_across_blocks_kernel(
    Torus *batch_condition_ptr, uint32_t chunk_start_block,
    const Torus *comparison_results_ptr, uint32_t lwe_size,
    uint32_t blocks_per_pair) {
  uint32_t pair_idx = blockIdx.x;
  uint32_t block_in_pair = blockIdx.y;
  uint32_t dst_block =
      chunk_start_block + pair_idx * blocks_per_pair + block_in_pair;

  const Torus *src = comparison_results_ptr + pair_idx * lwe_size;
  Torus *dst = batch_condition_ptr + dst_block * lwe_size;

  for (uint32_t i = threadIdx.x; i < lwe_size; i += blockDim.x) {
    dst[i] = src[i];
  }
}

// A subfunction that writes num_pairs * blocks_per_pair consecutive blocks
// of batch_condition from chunk_start_block,
// replicating each pair's single-block sign
// ({INF, EQ, SUP}) across its blocks_per_pair slots.
//
template <typename Torus>
__host__ void
tile_pair_signs_across_blocks(cudaStream_t stream,
                              CudaRadixCiphertextFFI *batch_condition,
                              uint32_t chunk_start_block,
                              const CudaRadixCiphertextFFI *comparison_results,
                              uint32_t num_pairs, uint32_t blocks_per_pair) {
  if (blocks_per_pair == 0 || num_pairs == 0)
    return;
  if (batch_condition->lwe_dimension != comparison_results->lwe_dimension)
    PANIC("Cuda error: tile_pair_signs_across_blocks requires matching "
          "lwe_dimension on batch_condition and comparison_results")
  if (comparison_results->num_radix_blocks < num_pairs)
    PANIC("Cuda error: tile_pair_signs_across_blocks comparison_results has "
          "fewer than num_pairs blocks")
  if (chunk_start_block + num_pairs * blocks_per_pair >
      batch_condition->num_radix_blocks)
    PANIC("Cuda error: tile_pair_signs_across_blocks write would overflow "
          "batch_condition")
  uint32_t lwe_size = batch_condition->lwe_dimension + 1;
  uint32_t threads_per_block = lwe_size < 256u ? lwe_size : 256u;

  dim3 grid(num_pairs, blocks_per_pair, 1);
  tile_pair_signs_across_blocks_kernel<Torus>
      <<<grid, threads_per_block, 0, stream>>>(
          (Torus *)batch_condition->ptr, chunk_start_block,
          (const Torus *)comparison_results->ptr, lwe_size, blocks_per_pair);
  check_cuda_error(cudaGetLastError());

  for (uint32_t p = 0; p < num_pairs; p++) {
    uint64_t deg = comparison_results->degrees[p];
    uint64_t noise = comparison_results->noise_levels[p];
    for (uint32_t b = 0; b < blocks_per_pair; b++) {
      uint32_t pos = chunk_start_block + p * blocks_per_pair + b;
      batch_condition->degrees[pos] = deg;
      batch_condition->noise_levels[pos] = noise;
    }
  }
}

// Step 1 of a bitonic substep, batched across all K = num_values/2 pairs of
// this layer. Pseudocode:
//
//   for each i with (i ^ j_param) > i:
//     l = i ^ j_param
//     sign[pair] = FHE_compare(keys[i], keys[l])   // -> {INF=0, EQ=1, SUP=2}
//
// To avoid one PBS per radix block, pairs of radix blocks are packed
// together, the difference is computed in the LWE domain, and a tree
// reduction collapses the M packed signals down to a single block per
// pair carrying the final {INF=0, EQ=1, SUP=2} encoding the CMUX LUT
// expects.
//
template <typename Torus, typename KSTorus>
__host__ void bitonic_sort_compare_phase_batched(
    CudaStreams streams, CudaRadixCiphertextFFI **keys, uint32_t num_values,
    uint32_t j_param, int_batched_compare_buffer<Torus> *batched_buf,
    void *const *bsks, KSTorus *const *ksks) {

  auto params = batched_buf->params;
  uint32_t N = batched_buf->key_num_blocks;
  uint32_t M = batched_buf->packed_per_pair;
  uint32_t K = num_values / 2;
  uint32_t msg_mod = params.message_modulus;
  uint32_t big_lwe_dim = params.big_lwe_dimension;

  if (num_values < 2 || (num_values & 1u) != 0)
    PANIC("Cuda error: bitonic_sort_compare_phase_batched requires "
          "num_values >= 2 and even")
  if (j_param == 0 || j_param >= num_values)
    PANIC("Cuda error: bitonic_sort_compare_phase_batched requires "
          "0 < j_param < num_values")
  if (M < 2)
    PANIC("Cuda error: bitonic_sort_compare_phase_batched requires "
          "packed_per_pair >= 2 (key_num_blocks >= 3)")

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batched_buf->lhs_data,
        pair_idx * N, (pair_idx + 1) * N, keys[i], 0, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batched_buf->rhs_data,
        pair_idx * N, (pair_idx + 1) * N, keys[l], 0, N);
    pair_idx++;
  }

  CudaRadixCiphertextFFI lhs_packed_view, rhs_packed_view;
  as_radix_ciphertext_slice<Torus>(&lhs_packed_view, batched_buf->tmp_packed, 0,
                                   K * M);
  as_radix_ciphertext_slice<Torus>(&rhs_packed_view, batched_buf->tmp_packed,
                                   K * M, 2 * K * M);
  pair_pack_per_row<Torus>(streams.stream(0), streams.gpu_index(0),
                           &lhs_packed_view, batched_buf->lhs_data, K, N,
                           msg_mod, params.message_modulus,
                           params.carry_modulus);
  pair_pack_per_row<Torus>(streams.stream(0), streams.gpu_index(0),
                           &rhs_packed_view, batched_buf->rhs_data, K, N,
                           msg_mod, params.message_modulus,
                           params.carry_modulus);

  CudaRadixCiphertextFFI tmp_packed_view;
  as_radix_ciphertext_slice<Torus>(&tmp_packed_view, batched_buf->tmp_packed, 0,
                                   2 * K * M);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &tmp_packed_view, &tmp_packed_view, bsks, ksks,
      batched_buf->identity_lut, 2 * K * M);

  host_subtraction<Torus>(streams.stream(0), streams.gpu_index(0),
                          (Torus *)batched_buf->comparisons->ptr,
                          (Torus *)lhs_packed_view.ptr,
                          (Torus *)rhs_packed_view.ptr, big_lwe_dim, K * M);

  CudaRadixCiphertextFFI comparisons_view;
  as_radix_ciphertext_slice<Torus>(&comparisons_view, batched_buf->comparisons,
                                   0, K * M);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &comparisons_view, &comparisons_view, bsks, ksks,
      batched_buf->is_non_zero_lut, K * M);
  host_add_scalar_one_inplace<Torus>(
      streams, &comparisons_view, params.message_modulus, params.carry_modulus);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), batched_buf->tree_x, 0, K * M,
      batched_buf->comparisons, 0, K * M);

  uint32_t partial_M = M;
  while (partial_M > 2) {
    uint32_t next_M = (partial_M + 1u) / 2u;
    CudaRadixCiphertextFFI tx_view, ty_view;
    as_radix_ciphertext_slice<Torus>(&tx_view, batched_buf->tree_x, 0,
                                     K * partial_M);
    as_radix_ciphertext_slice<Torus>(&ty_view, batched_buf->tree_y, 0,
                                     K * next_M);
    tree_merge_pack_per_row<Torus>(
        streams.stream(0), streams.gpu_index(0), &ty_view, &tx_view, K,
        partial_M, msg_mod, params.message_modulus, params.carry_modulus);
    CudaRadixCiphertextFFI tx_next_view;
    as_radix_ciphertext_slice<Torus>(&tx_next_view, batched_buf->tree_x, 0,
                                     K * next_M);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &tx_next_view, &ty_view, bsks, ksks,
        batched_buf->tree_inner_lut, K * next_M);
    partial_M = next_M;
  }

  CudaRadixCiphertextFFI tx_final, ty_final;
  as_radix_ciphertext_slice<Torus>(&tx_final, batched_buf->tree_x, 0, K * 2);
  as_radix_ciphertext_slice<Torus>(&ty_final, batched_buf->tree_y, 0, K);
  pair_pack_per_row<Torus>(streams.stream(0), streams.gpu_index(0), &ty_final,
                           &tx_final, K, 2, msg_mod, params.message_modulus,
                           params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, batched_buf->comparison_results, &ty_final, bsks, ksks,
      batched_buf->tree_last_lut, K);
}

// Steps 2 and 3 of a bitonic substep, gather/prep phase. Pseudocode:
//
//   should_swap = ascending ? (sign == SUP) : (sign != SUP)
//   (keys[i], keys[l]) = CMUX(should_swap,
//                             (keys[l], keys[i]),   // swapped
//                             (keys[i], keys[l]))   // unchanged
//   (data[i], data[l]) = CMUX(should_swap,
//                             (data[l], data[i]),
//                             (data[i], data[l]))
//
// should_swap is never materialized, the ascending/descending choice is
// baked into which operand becomes the CMUX "true" branch. Operands are
// laid out as
//   [ keys_true | data_true | keys_false | data_false ]
// in batch_buffer_in, and the sign is broadcast across all blocks so the
// next phase needs a single bivariate PBS over the whole buffer.
//
template <typename Torus>
__host__ void
gather_cmux_inputs_batched(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                           CudaRadixCiphertextFFI **values, uint32_t num_values,
                           uint32_t k_param, uint32_t j_param,
                           int_batched_compare_buffer<Torus> *batched_buf,
                           int_fused_cmux_buffer<Torus> *fused_buf) {

  uint32_t K = num_values / 2;
  uint32_t N_key = fused_buf->key_num_blocks;
  uint32_t N_data = fused_buf->data_num_blocks;

  uint32_t keys_true_off = 0;
  uint32_t data_true_off = 2 * K * N_key;
  uint32_t per_branch = 2 * K * (N_key + N_data);
  uint32_t keys_false_off = per_branch;
  uint32_t data_false_off = per_branch + 2 * K * N_key;

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;

    bool ascending = ((i & k_param) == 0);

    CudaRadixCiphertextFFI *min_t_keys = ascending ? keys[l] : keys[i];
    CudaRadixCiphertextFFI *max_t_keys = ascending ? keys[i] : keys[l];
    CudaRadixCiphertextFFI *min_f_keys = ascending ? keys[i] : keys[l];
    CudaRadixCiphertextFFI *max_f_keys = ascending ? keys[l] : keys[i];

    CudaRadixCiphertextFFI *min_t_data = ascending ? values[l] : values[i];
    CudaRadixCiphertextFFI *max_t_data = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *min_f_data = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *max_f_data = ascending ? values[l] : values[i];

    uint32_t k_off_t = keys_true_off + pair_idx * 2 * N_key;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        k_off_t, k_off_t + N_key, min_t_keys, 0, N_key);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        k_off_t + N_key, k_off_t + 2 * N_key, max_t_keys, 0, N_key);

    uint32_t k_off_f = keys_false_off + pair_idx * 2 * N_key;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        k_off_f, k_off_f + N_key, min_f_keys, 0, N_key);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        k_off_f + N_key, k_off_f + 2 * N_key, max_f_keys, 0, N_key);

    uint32_t d_off_t = data_true_off + pair_idx * 2 * N_data;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        d_off_t, d_off_t + N_data, min_t_data, 0, N_data);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        d_off_t + N_data, d_off_t + 2 * N_data, max_t_data, 0, N_data);

    uint32_t d_off_f = data_false_off + pair_idx * 2 * N_data;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        d_off_f, d_off_f + N_data, min_f_data, 0, N_data);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        d_off_f + N_data, d_off_f + 2 * N_data, max_f_data, 0, N_data);

    pair_idx++;
  }

  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, keys_true_off,
      batched_buf->comparison_results, K, 2 * N_key);
  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, data_true_off,
      batched_buf->comparison_results, K, 2 * N_data);
  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, keys_false_off,
      batched_buf->comparison_results, K, 2 * N_key);
  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, data_false_off,
      batched_buf->comparison_results, K, 2 * N_data);
}

// CMUX core, applied to the fused keys+data buffer produced by
// gather_cmux_inputs_batched. Pseudocode:
//
//   out_true  = bivariate_PBS(true_val,  cond,
//                   LUT: (b, c) -> b if c == SUP else 0)
//   out_false = bivariate_PBS(false_val, cond,
//                   LUT: (b, c) -> b if c != SUP else 0)
//   result    = HE_add(out_true, out_false)
//   result    = message_extract(result)              // clean up noise
//
// The two LUTs are bundled in predicate_lut and selected per block, so
// one kernel call handles both branches x (keys + data) x all K pairs.
// The two halves are then added, re-extracted for noise, and scattered
// back into keys[]/values[].
//
template <typename Torus, typename KSTorus>
__host__ void
apply_cmux_batched(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                   CudaRadixCiphertextFFI **values, uint32_t num_values,
                   uint32_t j_param, int_fused_cmux_buffer<Torus> *fused_buf,
                   void *const *bsks, KSTorus *const *ksks) {

  auto params = fused_buf->params;
  uint32_t K = num_values / 2;
  uint32_t N_key = fused_buf->key_num_blocks;
  uint32_t N_data = fused_buf->data_num_blocks;
  uint32_t per_branch = 2 * K * (N_key + N_data);
  uint32_t total_bivariate = 2 * per_branch;

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, fused_buf->batch_buffer_out, fused_buf->batch_buffer_in,
      fused_buf->batch_condition, bsks, ksks, fused_buf->predicate_lut,
      total_bivariate, params.message_modulus);

  CudaRadixCiphertextFFI true_half, false_half;
  as_radix_ciphertext_slice<Torus>(&true_half, fused_buf->batch_buffer_out, 0,
                                   per_branch);
  as_radix_ciphertext_slice<Torus>(&false_half, fused_buf->batch_buffer_out,
                                   per_branch, total_bivariate);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &true_half,
                       &true_half, &false_half, per_branch,
                       params.message_modulus, params.carry_modulus);

  CudaRadixCiphertextFFI extract_out;
  as_radix_ciphertext_slice<Torus>(&extract_out, fused_buf->batch_buffer_out, 0,
                                   per_branch);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &extract_out, &true_half, bsks, ksks, fused_buf->extract_lut,
      per_branch);

  uint32_t keys_zone = 2 * K * N_key;

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;

    uint32_t k_pair_off = pair_idx * 2 * N_key;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), keys[i], 0, N_key,
        &extract_out, k_pair_off, k_pair_off + N_key);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), keys[l], 0, N_key,
        &extract_out, k_pair_off + N_key, k_pair_off + 2 * N_key);

    uint32_t d_pair_off = keys_zone + pair_idx * 2 * N_data;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), values[i], 0, N_data,
        &extract_out, d_pair_off, d_pair_off + N_data);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), values[l], 0, N_data,
        &extract_out, d_pair_off + N_data, d_pair_off + 2 * N_data);

    pair_idx++;
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_bitonic_shuffle(
    CudaStreams streams, int_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_radix_blocks, uint32_t data_num_radix_blocks,
    uint32_t num_values, int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_bitonic_shuffle_buffer<Torus>(
      streams, params, key_num_radix_blocks, data_num_radix_blocks, num_values,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

// One full layer of the bitonic butterfly network. Pseudocode:
//
//   for each i with (i ^ j_param) > i:
//     l = i ^ j_param
//     ascending   = ((i & k_param) == 0)
//     sign        = FHE_compare(keys[i], keys[l])    // {INF, EQ, SUP}
//     should_swap = ascending ? (sign == SUP) : (sign != SUP)
//     (keys[i], keys[l]) = CMUX(should_swap, swapped, unchanged)
//     (data[i], data[l]) = CMUX(should_swap, swapped, unchanged)
//
template <typename Torus, typename KSTorus>
__host__ void
bitonic_shuffle_substep(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                        CudaRadixCiphertextFFI **values, uint32_t num_values,
                        uint32_t k_param, uint32_t j_param,
                        int_bitonic_shuffle_buffer<Torus> *mem_ptr,
                        void *const *bsks, KSTorus *const *ksks) {

  auto batched_buf = mem_ptr->batched_compare;
  auto fused_buf = mem_ptr->fused_cmux;

  bitonic_sort_compare_phase_batched<Torus>(streams, keys, num_values, j_param,
                                            batched_buf, bsks, ksks);
  gather_cmux_inputs_batched<Torus>(streams, keys, values, num_values, k_param,
                                    j_param, batched_buf, fused_buf);
  apply_cmux_batched<Torus>(streams, keys, values, num_values, j_param,
                            fused_buf, bsks, ksks);
}

// Padding step. Pseudocode:
//
//   padded_n = next_power_of_2(n)
//   for i in [n, padded_n):
//     keys[i] = MAX_VALUE   // sentinel: always sorts to the end
//     data[i] = 0
//
template <typename Torus>
__host__ void bitonic_shuffle_setup_padded(
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

// Bitonic shuffle / sort-by-key entry point. High-level pseudocode:
//
//   pad keys/data to next_power_of_2(n) with sentinels (+INF, 0)
//
//   for k = 2, 4, 8, ... while k <= padded_n:
//     for j = k/2, k/4, ... while j >= 1:
//       bitonic_substep(keys, data, padded_n, k, j)
//   return keys[0..n], data[0..n]   // drop sentinels
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
  bitonic_shuffle_setup_padded<Torus>(streams, keys, values, num_values,
                                      mem_ptr, &eff_keys, &eff_values, &eff_n);

  for (uint32_t k = 2; k <= eff_n; k <<= 1)
    for (uint32_t j = k >> 1; j > 0; j >>= 1)
      bitonic_shuffle_substep<Torus>(streams, eff_keys, eff_values, eff_n, k, j,
                                     mem_ptr, bsks, ksks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_oprf_bitonic_shuffle(
    CudaStreams streams, int_oprf_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_blocks, uint32_t data_num_blocks, uint32_t num_values,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_oprf_bitonic_shuffle_buffer<Torus>(
      streams, params, key_num_blocks, data_num_blocks, num_values,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

// Oblivious shuffle entry point: derives random keys via OPRF from a seed,
// then uses bitonic sort to permute the data.
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
