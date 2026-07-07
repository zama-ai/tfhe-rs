#ifndef TFHE_RS_SHUFFLE_CUH
#define TFHE_RS_SHUFFLE_CUH

#include "integer/oprf.cuh"
#include "integer/rerand.cuh"
#include "integer/shuffle_utilities.h"
#include "radix_ciphertext.cuh"

/**
 * @brief GPU kernel that pair-packs adjacent blocks within each row as
 * lsb + factor * msb, halving the block count per row.
 *
 * Input  row: [b0][b1]...[b_{N-1}]  where N = n_blocks_per_row
 * Output row: [b0+f*b1][b2+f*b3]...; when N is odd the orphan is packed as
 * orphan_body_sentinel + orphan_factor * orphan, where orphan_body_sentinel
 * is injected only into the body coefficient (tid == lwe_dim).
 *
 * @param lwe_2d_array_out     Output LWE coefficient buffer.
 * @param lwe_2d_array_in      Input LWE coefficient buffer.
 * @param lwe_dim              LWE dimension; coefficients per block =
 *                             lwe_dim + 1.
 * @param num_rows             Number of rows to process.
 * @param n_blocks_per_row     Number of input blocks per row.
 * @param factor               Packing scale applied to paired MSB blocks.
 * @param orphan_factor        Scale applied to the orphan block (1 = copy
 *                             verbatim; factor = treat as MSB).
 * @param orphan_body_sentinel Constant injected at the body coefficient of
 *                             the orphan output (0 or some Torus-encoded value
 * : clear_value * delta).
 */
template <typename Torus>
__global__ void pack_bivariate_adjacent_blocks_kernel(
    Torus *lwe_2d_array_out, Torus const *lwe_2d_array_in, uint32_t lwe_dim,
    uint32_t num_rows, uint32_t n_blocks_per_row, uint32_t factor,
    uint32_t orphan_factor, uint64_t orphan_body_sentinel) {
  uint32_t tid = threadIdx.x + blockIdx.x * blockDim.x;
  uint32_t lwe_size = lwe_dim + 1;
  if (tid >= lwe_size)
    return;

  uint32_t full_pairs = n_blocks_per_row / 2;
  uint32_t out_n = (n_blocks_per_row + 1) / 2;

  for (uint32_t p = 0; p < num_rows; p++) {
    Torus const *row_in =
        lwe_2d_array_in + (size_t)p * n_blocks_per_row * lwe_size;
    Torus *row_out = lwe_2d_array_out + (size_t)p * out_n * lwe_size;

    for (uint32_t b = 0; b < full_pairs; b++) {
      Torus lsb = row_in[(2 * b) * lwe_size + tid];
      Torus msb = row_in[(2 * b + 1) * lwe_size + tid];
      row_out[b * lwe_size + tid] = lsb + factor * msb;
    }

    if (n_blocks_per_row & 1u) {
      Torus orphan = row_in[(n_blocks_per_row - 1) * lwe_size + tid];
      Torus sentinel =
          (tid == lwe_dim) ? (Torus)orphan_body_sentinel : (Torus)0;
      row_out[full_pairs * lwe_size + tid] = sentinel + orphan_factor * orphan;
    }
  }
}

/**
 * @brief Pair-packs adjacent blocks within each row of a 2-D radix-ciphertext
 * array as lsb + factor * msb, halving the block count per row.
 *
 * When n_blocks_per_row is odd the orphan block is packed as
 * orphan_body_sentinel + orphan_factor * orphan, where orphan_body_sentinel
 * is only injected at the body coefficient.
 * Pass orphan_factor = 1 and orphan_clear_value = 0 to copy the orphan
 * verbatim into the LSB. Or use orphan_factor = message_modulus and
 * orphan_clear_value = some plaintext value to pack the orphan as an MSB
 * with that plaintext encoded as LSB.
 *
 * @param lwe_array_out       Output; must hold at least
 *                            num_rows * ceil(n_blocks_per_row / 2) blocks.
 * @param lwe_array_in        Input; must hold at least
 *                            num_rows * n_blocks_per_row blocks.
 * @param num_rows            Number of rows to process.
 * @param n_blocks_per_row    Number of input blocks per row.
 * @param factor              Packing scale applied to paired MSB blocks.
 * @param orphan_factor       Scale applied to the orphan block.
 * @param orphan_clear_value  Plaintext value encoded into the orphan LSB
 *                            body coefficient (0 = no sentinel).
 */
template <typename Torus>
__host__ void host_pack_bivariate_adjacent_blocks(
    cudaStream_t stream, uint32_t gpu_index,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_rows,
    uint32_t n_blocks_per_row, uint32_t factor, uint32_t orphan_factor,
    uint32_t orphan_clear_value, uint32_t message_modulus,
    uint32_t carry_modulus) {
  if (num_rows == 0 || n_blocks_per_row == 0)
    return;
  if (lwe_array_in->lwe_dimension != lwe_array_out->lwe_dimension)
    PANIC("Cuda error: host_pack_bivariate_adjacent_blocks requires matching "
          "lwe_dimension on input and output")
  uint32_t out_n = (n_blocks_per_row + 1u) / 2u;
  if (lwe_array_in->num_radix_blocks < num_rows * n_blocks_per_row)
    PANIC("Cuda error: host_pack_bivariate_adjacent_blocks input does not "
          "have enough blocks")
  if (lwe_array_out->num_radix_blocks < num_rows * out_n)
    PANIC("Cuda error: host_pack_bivariate_adjacent_blocks output does not "
          "have enough blocks")
  uint64_t delta = ((uint64_t)1 << (sizeof(Torus) * 8 - 1)) /
                   ((uint64_t)message_modulus * carry_modulus);
  uint64_t orphan_body_sentinel = (uint64_t)orphan_clear_value * delta;
  uint32_t lwe_size = lwe_array_in->lwe_dimension + 1;
  cuda_set_device(gpu_index);
  int blocks = 0, threads = 0;
  getNumBlocksAndThreads(lwe_size, 1024, blocks, threads);
  pack_bivariate_adjacent_blocks_kernel<Torus><<<blocks, threads, 0, stream>>>(
      (Torus *)lwe_array_out->ptr, (Torus const *)lwe_array_in->ptr,
      lwe_array_in->lwe_dimension, num_rows, n_blocks_per_row, factor,
      orphan_factor, orphan_body_sentinel);
  check_cuda_error(cudaGetLastError());

  uint32_t full_pairs = n_blocks_per_row / 2;
  uint64_t orphan_lsb_degree = orphan_clear_value;
  for (uint32_t p = 0; p < num_rows; p++) {
    uint32_t in_off = p * n_blocks_per_row;
    uint32_t out_off = p * out_n;
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
    if (n_blocks_per_row & 1u) {
      uint32_t orphan_in_idx = in_off + n_blocks_per_row - 1;
      uint32_t orphan_out_idx = out_off + full_pairs;
      lwe_array_out->degrees[orphan_out_idx] =
          orphan_lsb_degree +
          orphan_factor * lwe_array_in->degrees[orphan_in_idx];
      lwe_array_out->noise_levels[orphan_out_idx] =
          orphan_factor * lwe_array_in->noise_levels[orphan_in_idx];
      CHECK_NOISE_LEVEL(lwe_array_out->noise_levels[orphan_out_idx],
                        message_modulus, carry_modulus);
    }
  }
}

/**
 * @brief GPU kernel that replicates each pair's single-block comparison result
 * into blocks_per_pair consecutive slots in batch_condition_ptr.
 *
 * @param batch_condition_ptr    Output LWE buffer; must have room for at least
 *                               chunk_start_block + num_pairs*blocks_per_pair
 *                               blocks (num_pairs inferred from gridDim.x).
 * @param chunk_start_block      First block index in batch_condition_ptr to
 *                               write.
 * @param comparison_results_ptr Input buffer; one block per pair.
 * @param lwe_size               LWE dimension + 1 (coefficients per block).
 * @param blocks_per_pair        Number of output blocks to fill per pair.
 */
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

/**
 * @brief Replicates each pair's single-block comparison result
 * ({IS_INFERIOR, IS_EQUAL, IS_SUPERIOR}) into blocks_per_pair consecutive
 * slots of batch_condition starting at chunk_start_block.
 *
 * @param batch_condition   Output radix-ciphertext; must have room for at least
 *                          chunk_start_block + num_pairs*blocks_per_pair
 * blocks.
 * @param chunk_start_block First block index in batch_condition to write.
 * @param comparison_results Input radix-ciphertext; one block per pair.
 * @param num_pairs         Number of key pairs whose results are tiled.
 * @param blocks_per_pair   Number of output blocks filled per pair.
 */
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

/**
 * @brief Computes the comparison result for all num_values/2 key pairs in a
 * single batched pass. Keys are first copied to a single contiguous memory
 * buffer to allow batched comparison. Elements at indexes i are simultaneously
 * compared with elements at indexes i ^ bitonic_subsequence_stride.
 *
 * To perform the batched comparison, each key's N radix blocks are
 * pair-packed into M = ceil(N/2) blocks, subtracted in the LWE domain, then
 * collapsed via a tree reduction to a single EQ or IS_SUPERIOR verdict per
 * pair. Results are written to batched_buf->comparison_results.
 *
 * @param keys                       Array of pointers to key ciphertexts.
 * @param num_values                 Total number of elements; must be even.
 * @param bitonic_subsequence_stride Defines which pairs are compared:
 *                                   element i is compared with i ^
 * bitonic_subsequence_stride.
 * @param batched_buf                Scratch buffer; comparison_results field
 *                                   holds the output after this call.
 */
template <typename Torus, typename KSTorus>
__host__ void bitonic_sort_compare_phase_batched(
    CudaStreams streams, CudaRadixCiphertextFFI **keys, uint32_t num_values,
    uint32_t bitonic_subsequence_stride,
    int_batched_compare_buffer<Torus> *batched_buf, void *const *bsks,
    KSTorus *const *ksks) {

  auto params = batched_buf->params;
  uint32_t blocks_per_key = batched_buf->key_num_blocks;
  uint32_t packed_blocks_per_key = batched_buf->packed_per_pair;
  uint32_t num_pairs = num_values / 2;
  uint32_t message_modulus = params.message_modulus;
  uint32_t big_lwe_dim = params.big_lwe_dimension;

  if (num_values < 2 || (num_values & 1u) != 0)
    PANIC("Cuda error: bitonic_sort_compare_phase_batched requires "
          "num_values >= 2 and even")
  if (bitonic_subsequence_stride == 0 ||
      bitonic_subsequence_stride >= num_values)
    PANIC("Cuda error: bitonic_sort_compare_phase_batched requires "
          "0 < bitonic_subsequence_stride < num_values")
  if (packed_blocks_per_key < 2)
    PANIC("Cuda error: bitonic_sort_compare_phase_batched requires "
          "packed_per_pair >= 2 (key_num_blocks >= 3)")

  // Gather all num_pairs lhs and rhs key blocks into contiguous buffers for
  // batched processing.
  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ bitonic_subsequence_stride;
    if (l <= i)
      continue;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batched_buf->lhs_data,
        pair_idx * blocks_per_key, (pair_idx + 1) * blocks_per_key, keys[i], 0,
        blocks_per_key);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), batched_buf->rhs_data,
        pair_idx * blocks_per_key, (pair_idx + 1) * blocks_per_key, keys[l], 0,
        blocks_per_key);
    pair_idx++;
  }

  // Pair-pack each key's blocks_per_key blocks into packed_blocks_per_key =
  // ceil(blocks_per_key/2) blocks: lsb + message_modulus * msb.
  CudaRadixCiphertextFFI lhs_packed_view, rhs_packed_view;
  as_radix_ciphertext_slice<Torus>(&lhs_packed_view, batched_buf->tmp_packed, 0,
                                   num_pairs * packed_blocks_per_key);
  as_radix_ciphertext_slice<Torus>(&rhs_packed_view, batched_buf->tmp_packed,
                                   num_pairs * packed_blocks_per_key,
                                   2 * num_pairs * packed_blocks_per_key);
  host_pack_bivariate_adjacent_blocks<Torus>(
      streams.stream(0), streams.gpu_index(0), &lhs_packed_view,
      batched_buf->lhs_data, num_pairs, blocks_per_key, message_modulus,
      /*orphan_factor=*/1, /*orphan_clear_value=*/0, params.message_modulus,
      params.carry_modulus);
  host_pack_bivariate_adjacent_blocks<Torus>(
      streams.stream(0), streams.gpu_index(0), &rhs_packed_view,
      batched_buf->rhs_data, num_pairs, blocks_per_key, message_modulus,
      /*orphan_factor=*/1, /*orphan_clear_value=*/0, params.message_modulus,
      params.carry_modulus);

  // Refresh noise on all packed blocks via identity PBS before subtraction.
  CudaRadixCiphertextFFI tmp_packed_view;
  as_radix_ciphertext_slice<Torus>(&tmp_packed_view, batched_buf->tmp_packed, 0,
                                   2 * num_pairs * packed_blocks_per_key);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &tmp_packed_view, &tmp_packed_view, bsks, ksks,
      batched_buf->identity_lut, 2 * num_pairs * packed_blocks_per_key);

  // Subtract lhs - rhs block-wise in the LWE domain; result is 0 iff blocks are
  // equal. This subtraction is levelled and may overflow into the padding bit.
  host_subtraction<Torus>(streams.stream(0), streams.gpu_index(0),
                          batched_buf->comparisons, &lhs_packed_view,
                          &rhs_packed_view, num_pairs * packed_blocks_per_key,
                          params.message_modulus, params.carry_modulus);

  CudaRadixCiphertextFFI comparisons_view;
  as_radix_ciphertext_slice<Torus>(&comparisons_view, batched_buf->comparisons,
                                   0, num_pairs * packed_blocks_per_key);
  // Map each diff block to 0 (equal) or 1 (different) via is_non_zero PBS.
  // Note that is_non_zero_lut relies on negacyclic behavior of the PBS
  //  when lhs - rhs < 0, the padding bit is set which makes the PBS
  // output -LUT[(lhs - rhs) % 16 == 0]
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &comparisons_view, &comparisons_view, bsks, ksks,
      batched_buf->is_non_zero_lut, num_pairs * packed_blocks_per_key);
  // Shift {-1=lhs_is_inferior, 0=equal, 1=lhs_is_superior} to {0, 1, 2} as
  // expected by the tree reduction and CMUX LUTs, where EQ=1 is the
  // pass-through value.
  host_add_scalar_one_inplace<Torus>(
      streams, &comparisons_view, params.message_modulus, params.carry_modulus);

  // Initialize the tree reduction with the per-block verdicts.
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), batched_buf->tree_x, 0,
      num_pairs * packed_blocks_per_key, batched_buf->comparisons, 0,
      num_pairs * packed_blocks_per_key);

  // Collapse per-block verdicts down to 2 via repeated pack + is_any_not_equal
  // PBS.
  uint32_t remaining_packed_blocks = packed_blocks_per_key;
  while (remaining_packed_blocks > 2) {
    uint32_t next_remaining_packed_blocks = (remaining_packed_blocks + 1u) / 2u;
    CudaRadixCiphertextFFI tx_view, ty_view;
    as_radix_ciphertext_slice<Torus>(&tx_view, batched_buf->tree_x, 0,
                                     num_pairs * remaining_packed_blocks);
    as_radix_ciphertext_slice<Torus>(&ty_view, batched_buf->tree_y, 0,
                                     num_pairs * next_remaining_packed_blocks);
    // Pack adjacent verdict pairs into one block per pair, injecting an EQ
    // sentinel into any orphan slot.
    host_pack_bivariate_adjacent_blocks<Torus>(
        streams.stream(0), streams.gpu_index(0), &ty_view, &tx_view, num_pairs,
        remaining_packed_blocks, message_modulus,
        /*orphan_factor=*/message_modulus, /*orphan_clear_value=*/IS_EQUAL,
        params.message_modulus, params.carry_modulus);
    CudaRadixCiphertextFFI tx_next_view;
    as_radix_ciphertext_slice<Torus>(&tx_next_view, batched_buf->tree_x, 0,
                                     num_pairs * next_remaining_packed_blocks);
    // PBS: propagate IS_SUPERIOR or IS_INFERIOR if any block in the pair was
    // not equal.
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &tx_next_view, &ty_view, bsks, ksks,
        batched_buf->is_any_not_equal_lut,
        num_pairs * next_remaining_packed_blocks);
    remaining_packed_blocks = next_remaining_packed_blocks;
  }

  // Pack the last 2 verdicts per pair, then apply is_any_not_equal_packed_lut —
  // a univariate PBS equivalent to is_any_not_equal_lut operating on the
  // pre-packed value — to produce one final EQ or IS_SUPERIOR verdict per pair,
  // written to comparison_results.
  CudaRadixCiphertextFFI tx_final, ty_final;
  as_radix_ciphertext_slice<Torus>(&tx_final, batched_buf->tree_x, 0,
                                   num_pairs * 2);
  as_radix_ciphertext_slice<Torus>(&ty_final, batched_buf->tree_y, 0,
                                   num_pairs);
  host_pack_bivariate_adjacent_blocks<Torus>(
      streams.stream(0), streams.gpu_index(0), &ty_final, &tx_final, num_pairs,
      2, message_modulus, /*orphan_factor=*/1, /*orphan_clear_value=*/0,
      params.message_modulus, params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, batched_buf->comparison_results, &ty_final, bsks, ksks,
      batched_buf->is_any_not_equal_packed_lut, num_pairs);
}

/**
 * @brief Prepares the fused CMUX input buffer for all num_values/2 pairs by
 * gathering key and data ciphertexts into the contiguous layout
 * [ keys_is_superior | data_is_superior | keys_is_equal | data_is_equal ]
 * in batch_buffer_in, and broadcasting each pair's comparison result across
 * all its blocks into batch_condition. The IS_SUPERIOR/IS_EQUAL branch
 * assignment encodes the ascending or descending swap direction without
 * materializing should_swap.
 *
 * @param keys                         Array of pointers to key ciphertexts.
 * @param values                       Array of pointers to data ciphertexts.
 * @param num_values                   Total number of elements; must be even.
 * @param bitonic_subsequence_length_k Controls ascending/descending direction
 *                                     per element.
 * @param bitonic_subsequence_stride   Defines which pairs are gathered:
 *                                     element i is paired with i ^
 * bitonic_subsequence_stride.
 * @param batched_buf                  Provides comparison_results (EQ or
 *                                     IS_SUPERIOR per pair) from the compare
 * phase.
 * @param fused_buf                    Receives the gathered inputs in
 *                                     batch_buffer_in and the broadcasted signs
 *                                     in batch_condition.
 */
template <typename Torus>
__host__ void
gather_cmux_inputs_batched(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                           CudaRadixCiphertextFFI **values, uint32_t num_values,
                           uint32_t bitonic_subsequence_length_k,
                           uint32_t bitonic_subsequence_stride,
                           int_batched_compare_buffer<Torus> *batched_buf,
                           int_fused_cmux_buffer<Torus> *fused_buf) {

  uint32_t num_pairs = num_values / 2;
  uint32_t blocks_per_key = fused_buf->key_num_blocks;
  uint32_t blocks_per_data = fused_buf->data_num_blocks;

  uint32_t keys_sup_branch_start = 0;
  uint32_t data_sup_branch_start = 2 * num_pairs * blocks_per_key;
  uint32_t blocks_per_branch =
      2 * num_pairs * (blocks_per_key + blocks_per_data);
  uint32_t keys_eq_branch_start = blocks_per_branch;
  uint32_t data_eq_branch_start =
      blocks_per_branch + 2 * num_pairs * blocks_per_key;

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ bitonic_subsequence_stride;
    if (l <= i)
      continue;

    // The ascending/descending pattern repeats every 2k elements — e.g. for k=4
    // elements 0-3 are sorted ascending, 4-7 descending, 8-11 ascending, etc.
    bool ascending =
        (i % (2 * bitonic_subsequence_length_k)) < bitonic_subsequence_length_k;

    CudaRadixCiphertextFFI *sup_key_at_i = ascending ? keys[l] : keys[i];
    CudaRadixCiphertextFFI *sup_key_at_l = ascending ? keys[i] : keys[l];
    CudaRadixCiphertextFFI *eq_key_at_i = ascending ? keys[i] : keys[l];
    CudaRadixCiphertextFFI *eq_key_at_l = ascending ? keys[l] : keys[i];

    CudaRadixCiphertextFFI *sup_data_at_i = ascending ? values[l] : values[i];
    CudaRadixCiphertextFFI *sup_data_at_l = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *eq_data_at_i = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *eq_data_at_l = ascending ? values[l] : values[i];

    uint32_t key_sup_pair_start =
        keys_sup_branch_start + pair_idx * 2 * blocks_per_key;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        key_sup_pair_start, key_sup_pair_start + blocks_per_key, sup_key_at_i,
        0, blocks_per_key);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        key_sup_pair_start + blocks_per_key,
        key_sup_pair_start + 2 * blocks_per_key, sup_key_at_l, 0,
        blocks_per_key);

    uint32_t key_eq_pair_start =
        keys_eq_branch_start + pair_idx * 2 * blocks_per_key;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        key_eq_pair_start, key_eq_pair_start + blocks_per_key, eq_key_at_i, 0,
        blocks_per_key);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        key_eq_pair_start + blocks_per_key,
        key_eq_pair_start + 2 * blocks_per_key, eq_key_at_l, 0, blocks_per_key);

    uint32_t data_sup_pair_start =
        data_sup_branch_start + pair_idx * 2 * blocks_per_data;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        data_sup_pair_start, data_sup_pair_start + blocks_per_data,
        sup_data_at_i, 0, blocks_per_data);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        data_sup_pair_start + blocks_per_data,
        data_sup_pair_start + 2 * blocks_per_data, sup_data_at_l, 0,
        blocks_per_data);

    uint32_t data_eq_pair_start =
        data_eq_branch_start + pair_idx * 2 * blocks_per_data;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        data_eq_pair_start, data_eq_pair_start + blocks_per_data, eq_data_at_i,
        0, blocks_per_data);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), fused_buf->batch_buffer_in,
        data_eq_pair_start + blocks_per_data,
        data_eq_pair_start + 2 * blocks_per_data, eq_data_at_l, 0,
        blocks_per_data);

    pair_idx++;
  }

  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, keys_sup_branch_start,
      batched_buf->comparison_results, num_pairs, 2 * blocks_per_key);
  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, data_sup_branch_start,
      batched_buf->comparison_results, num_pairs, 2 * blocks_per_data);
  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, keys_eq_branch_start,
      batched_buf->comparison_results, num_pairs, 2 * blocks_per_key);
  tile_pair_signs_across_blocks<Torus>(
      streams.stream(0), fused_buf->batch_condition, data_eq_branch_start,
      batched_buf->comparison_results, num_pairs, 2 * blocks_per_data);
}

/**
 * @brief Applies the batched fused CMUX over the buffer prepared by
 * gather_cmux_inputs_batched, conditionally swapping keys and data for all
 * num_values/2 pairs in a single bivariate PBS.
 *
 * The two branches (IS_SUPERIOR and IS_EQUAL) are zeroed out selectively by
 * predicate_lut, added together, and re-extracted for noise. Results are
 * scattered back into keys[] and values[].
 *
 * Pseudocode:
 *   out_is_superior = bivariate_PBS(is_superior_val, cond,
 *                         LUT: (b, c) -> b if c == SUP else 0)
 *   out_is_equal    = bivariate_PBS(is_equal_val,    cond,
 *                         LUT: (b, c) -> b if c != SUP else 0)
 *   result          = message_extract(HE_add(out_is_superior, out_is_equal))
 *
 * @param keys                       Array of pointers to key ciphertexts,
 * modified in place.
 * @param values                     Array of pointers to data ciphertexts,
 * modified in place.
 * @param num_values                 Total number of elements; must be even.
 * @param bitonic_subsequence_stride Defines which pairs are scattered back:
 *                                   element i is paired with i ^
 * bitonic_subsequence_stride.
 * @param fused_buf                  Holds the prepared batch_buffer_in and
 * batch_condition from gather_cmux_inputs_batched.
 */
template <typename Torus, typename KSTorus>
__host__ void
apply_cmux_batched(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                   CudaRadixCiphertextFFI **values, uint32_t num_values,
                   uint32_t bitonic_subsequence_stride,
                   int_fused_cmux_buffer<Torus> *fused_buf, void *const *bsks,
                   KSTorus *const *ksks) {

  auto params = fused_buf->params;
  uint32_t num_pairs = num_values / 2;
  uint32_t blocks_per_key = fused_buf->key_num_blocks;
  uint32_t blocks_per_data = fused_buf->data_num_blocks;
  uint32_t blocks_per_branch =
      2 * num_pairs * (blocks_per_key + blocks_per_data);
  uint32_t total_bivariate = 2 * blocks_per_branch;

  // Apply predicate_lut: zeros out the losing branch of each block.
  // IS_SUPERIOR blocks survive in is_superior_half; IS_EQUAL blocks survive in
  // is_equal_half.
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, fused_buf->batch_buffer_out, fused_buf->batch_buffer_in,
      fused_buf->batch_condition, bsks, ksks, fused_buf->predicate_lut,
      total_bivariate, params.message_modulus);

  // Add the two halves: exactly one is non-zero per block, so the sum is the
  // result.
  CudaRadixCiphertextFFI is_superior_half, is_equal_half;
  as_radix_ciphertext_slice<Torus>(
      &is_superior_half, fused_buf->batch_buffer_out, 0, blocks_per_branch);
  as_radix_ciphertext_slice<Torus>(&is_equal_half, fused_buf->batch_buffer_out,
                                   blocks_per_branch, total_bivariate);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                       &is_superior_half, &is_superior_half, &is_equal_half,
                       blocks_per_branch, params.message_modulus,
                       params.carry_modulus);

  // Re-bootstrap via message extraction: for intermediate substeps, the next
  // substep's pair-packing amplifies noise by (1 + msg_mod) before the identity
  // PBS can refresh it, so the addition noise must be cleaned here to stay
  // within budget. For the final substep, this ensures the outputs are clean
  // for the caller.
  CudaRadixCiphertextFFI extract_out;
  as_radix_ciphertext_slice<Torus>(&extract_out, fused_buf->batch_buffer_out, 0,
                                   blocks_per_branch);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &extract_out, &is_superior_half, bsks, ksks,
      fused_buf->extract_lut, blocks_per_branch);

  // Scatter results back into keys[] and values[].
  uint32_t keys_zone = 2 * num_pairs * blocks_per_key;

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ bitonic_subsequence_stride;
    if (l <= i)
      continue;

    uint32_t key_pair_start = pair_idx * 2 * blocks_per_key;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), keys[i], 0, blocks_per_key,
        &extract_out, key_pair_start, key_pair_start + blocks_per_key);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), keys[l], 0, blocks_per_key,
        &extract_out, key_pair_start + blocks_per_key,
        key_pair_start + 2 * blocks_per_key);

    uint32_t data_pair_start = keys_zone + pair_idx * 2 * blocks_per_data;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), values[i], 0, blocks_per_data,
        &extract_out, data_pair_start, data_pair_start + blocks_per_data);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), values[l], 0, blocks_per_data,
        &extract_out, data_pair_start + blocks_per_data,
        data_pair_start + 2 * blocks_per_data);

    pair_idx++;
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_bitonic_shuffle_async(
    CudaStreams streams, int_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_radix_blocks, uint32_t data_num_radix_blocks,
    uint32_t num_values, int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_bitonic_shuffle_buffer<Torus>(
      streams, params, key_num_radix_blocks, data_num_radix_blocks, num_values,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/**
 * @brief Executes one compare-and-swap substep of the bitonic network over
 * encrypted key and data vectors of radix-ciphertexts. All num_values/2 key
 * comparisons are batched into a single compare phase. Then all keys and
 * values, forming num_values/2 pairs each, are conditionally swapped in a
 * single batched CMUX phase.
 *
 * @param keys                         Array of pointers to key ciphertexts,
 * modified in place.
 * @param values                       Array of pointers to data ciphertexts,
 * modified in place.
 * @param num_values                   Total number of elements; must be a power
 * of two.
 * @param bitonic_subsequence_length_k Outer loop variable of the bitonic
 * network; controls the ascending/descending pattern across elements.
 * @param bitonic_subsequence_stride   Inner loop variable; element at index i
 * is compared and swapped with element at index i ^ bitonic_subsequence_stride.
 * @param mem_ptr                      Pre-allocated scratch buffer for
 * intermediate results.
 */
template <typename Torus, typename KSTorus>
__host__ void
bitonic_shuffle_substep(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                        CudaRadixCiphertextFFI **values, uint32_t num_values,
                        uint32_t bitonic_subsequence_length_k,
                        uint32_t bitonic_subsequence_stride,
                        int_bitonic_shuffle_buffer<Torus> *mem_ptr,
                        void *const *bsks, KSTorus *const *ksks) {

  auto batched_buf = mem_ptr->batched_compare;
  auto fused_buf = mem_ptr->fused_cmux;

  bitonic_sort_compare_phase_batched<Torus>(streams, keys, num_values,
                                            bitonic_subsequence_stride,
                                            batched_buf, bsks, ksks);
  gather_cmux_inputs_batched<Torus>(
      streams, keys, values, num_values, bitonic_subsequence_length_k,
      bitonic_subsequence_stride, batched_buf, fused_buf);
  apply_cmux_batched<Torus>(streams, keys, values, num_values,
                            bitonic_subsequence_stride, fused_buf, bsks, ksks);
}

/**
 * @brief Pads keys and values to the next power of two required by the bitonic
 * sort, filling sentinel slots with MAX_VALUE keys and zero data.
 * If no padding is needed the output pointers alias the inputs directly.
 *
 * Pseudocode:
 *   padded_n = next_power_of_2(n)
 *   for i in [n, padded_n): keys[i] = MAX_VALUE; data[i] = 0
 *
 * @param keys           Array of num_values pointers to key radix-ciphertexts.
 * @param values         Array of num_values pointers to data radix-ciphertexts.
 * @param num_values     Number of real key-value pairs.
 * @param eff_keys       Output: pointer to the (possibly padded) key array.
 * @param eff_values     Output: pointer to the (possibly padded) value array.
 * @param eff_num_values Output: effective count, padded to a power of two.
 */
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

/**
 * @brief Sorts encrypted key-value radix-ciphertext pairs in-place using a
 * bitonic sorting network. Keys and values are reordered together.
 *
 * Keys/data are padded to next_power_of_2(num_values) with sentinel slots
 * (MAX_VALUE keys, zero data), the sort runs, then sentinels are discarded.
 *
 * @param keys       Array of num_values pointers to key radix-ciphertexts.
 * @param values     Array of num_values pointers to data radix-ciphertexts.
 * @param num_values Number of key-value pairs.
 */
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
__host__ uint64_t scratch_cuda_integer_oprf_bitonic_shuffle_async(
    CudaStreams streams, int_oprf_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_blocks, uint32_t data_num_blocks, uint32_t num_values,
    int_radix_params params, bool apply_rerand, int_radix_params rerand_params,
    RERAND_MODE rerand_mode, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  if (apply_rerand) {
    *mem_ptr = new int_oprf_bitonic_shuffle_buffer<Torus>(
        streams, params, rerand_params, key_num_blocks, data_num_blocks,
        num_values, rerand_mode, allocate_gpu_memory, size_tracker);
  } else {
    *mem_ptr = new int_oprf_bitonic_shuffle_buffer<Torus>(
        streams, params, key_num_blocks, data_num_blocks, num_values,
        allocate_gpu_memory, size_tracker);
  }
  return size_tracker;
}

/**
 * @brief Shuffles encrypted radix-ciphertexts in-place by deriving random
 * keys via OPRF from a seed, then sorting by those keys with a bitonic network.
 *
 * @param values           Array of num_values pointers to data
 * radix-ciphertexts.
 * @param num_values       Number of values to shuffle.
 * @param seeded_lwe_input Seeded LWE ciphertext used as OPRF input.
 * @param lwe_flattened_encryptions_of_zero_compact_array_in Flattened compact
 * array of encryptions of zero used for re-randomization.
 * @param rerand_ksks      Array of re-randomization keyswitch key pointers, one
 * per GPU.
 * @param oprf_bsks        Array of OPRF bootstrapping key pointers, one per
 * GPU.
 */
template <typename Torus, typename KSTorus>
__host__ void host_oprf_bitonic_shuffle(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    const Torus *seeded_lwe_input,
    const Torus *lwe_flattened_encryptions_of_zero_compact_array_in,
    Torus *const *rerand_ksks, int_oprf_bitonic_shuffle_buffer<Torus> *mem_ptr,
    void *const *oprf_bsks, void *const *bsks, KSTorus *const *ksks) {

  uint32_t key_num_blocks = mem_ptr->key_num_blocks;

  host_integer_grouped_oprf<Torus>(
      streams, mem_ptr->keys_storage, seeded_lwe_input,
      num_values * key_num_blocks, mem_ptr->oprf_memory, oprf_bsks);

  if (mem_ptr->applies_rerand()) {
    auto *rerand_mem = mem_ptr->rerand_memory;
    auto *keys_ptr = static_cast<Torus *>(mem_ptr->keys_storage->ptr);

    host_rerand_inplace_dispatch<Torus>(
        streams, keys_ptr, lwe_flattened_encryptions_of_zero_compact_array_in,
        rerand_ksks, rerand_mem);
  }

  host_bitonic_shuffle<Torus>(streams, mem_ptr->keys_ptrs, values, num_values,
                              mem_ptr->shuffle_buffer, bsks, ksks);
}

#endif
