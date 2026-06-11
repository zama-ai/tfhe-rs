#pragma once

#include "integer/cast.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/vector_find.h"

// Accumulates chunks of LWE blocks for multiple entries in a single kernel.
// Each CUDA block (in the y-dimension) handles one (entry, chunk) pair,
// summing chunk_length adjacent LWE blocks element-wise into one output block.
template <typename Torus>
__global__ void device_accumulate_all_blocks_batched(
    Torus *output, Torus const *input, uint32_t lwe_dimension,
    uint32_t blocks_per_entry, uint32_t max_value,
    uint32_t num_chunks_per_entry) {
  uint32_t lwe_idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (lwe_idx >= lwe_dimension + 1)
    return;

  uint32_t chunk_flat_idx = blockIdx.y;
  uint32_t entry_idx = chunk_flat_idx / num_chunks_per_entry;
  uint32_t chunk_idx = chunk_flat_idx % num_chunks_per_entry;

  uint32_t chunk_start = chunk_idx * max_value;
  uint32_t chunk_length = min(max_value, blocks_per_entry - chunk_start);

  uint32_t stride = lwe_dimension + 1;
  Torus const *base =
      &input[(entry_idx * blocks_per_entry + chunk_start) * stride];

  Torus sum = base[lwe_idx];
  for (uint32_t i = 1; i < chunk_length; i++) {
    sum += base[lwe_idx + i * stride];
  }

  output[chunk_flat_idx * stride + lwe_idx] = sum;
}

template <typename Torus>
__host__ void host_accumulate_all_blocks_batched(
    cudaStream_t stream, uint32_t gpu_index, Torus *output, Torus const *input,
    uint32_t lwe_dimension, uint32_t blocks_per_entry, uint32_t max_value,
    uint32_t num_entries, uint32_t num_chunks_per_entry) {
  cuda_set_device(gpu_index);
  int num_blocks_x = 0, num_threads = 0;
  getNumBlocksAndThreads(lwe_dimension + 1, 512, num_blocks_x, num_threads);
  dim3 grid(num_blocks_x, num_entries * num_chunks_per_entry);
  device_accumulate_all_blocks_batched<Torus><<<grid, num_threads, 0, stream>>>(
      output, input, lwe_dimension, blocks_per_entry, max_value,
      num_chunks_per_entry);
  check_cuda_error(cudaGetLastError());
}

// Given one encrypted radix ciphertext (num_blocks blocks, each a digit in
// [0, message_modulus)) and N cleartext candidates (e.g. KV-store keys),
// produces N encrypted booleans: selector_i = Enc(input == candidate_i).
//
// Uses a batched tree reduction: precompute all per-block comparisons in one
// batched PBS, gather each candidate's results, then AND-reduce with
// host_accumulate_all_blocks_batched + is_max_value PBS.
template <typename Torus>
__host__ void host_compute_equality_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_blocks,
    const uint64_t *h_decomposed_cleartexts,
    int_equality_selectors_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  uint32_t num_possible_values = mem_ptr->num_possible_values;
  uint32_t message_modulus = mem_ptr->params.message_modulus;
  uint32_t carry_modulus = mem_ptr->params.carry_modulus;
  auto big_lwe_dimension = mem_ptr->params.big_lwe_dimension;

  // Step 1: Grid PBS — constant cost regardless of N
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);

  if (num_blocks == 0) {
    for (uint32_t i = 0; i < num_possible_values; i++) {
      set_single_scalar_trivial_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[i], 1,
          message_modulus, carry_modulus);
    }
    return;
  }

  // Step 2: Gather comparison blocks for all candidates into a flat buffer.
  auto batched = mem_ptr->batched_comparisons;
  for (uint32_t i = 0; i < num_possible_values; i++) {
    const uint64_t *current_clear_blocks =
        &h_decomposed_cleartexts[i * num_blocks];

    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t block_value = current_clear_blocks[j];

      if (block_value >= message_modulus) {
        PANIC("Cuda error: block value in compute_equality_selectors "
              "exceeds message modulus");
      }

      uint32_t src_idx = (uint32_t)block_value * num_blocks + j;
      uint32_t dst_idx = i * num_blocks + j;

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), batched, dst_idx,
          dst_idx + 1, mem_ptr->tmp_many_luts_output, src_idx, src_idx + 1);
    }
  }

  if (num_blocks == 1) {
    for (uint32_t i = 0; i < num_possible_values; i++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[i], 0, 1,
          batched, i, i + 1);
    }
    reset_radix_ciphertext_blocks(&lwe_array_out_list[0], 1);
    return;
  }

  // Step 3: Batched tree reduction.
  uint32_t max_value = mem_ptr->max_value;
  auto is_max_value_lut = mem_ptr->is_max_value_lut;
  auto tree_accumulator = mem_ptr->tree_accumulator;
  auto tree_pbs_output = mem_ptr->tree_pbs_output;

  Torus *current_input_ptr = (Torus *)batched->ptr;
  uint32_t blocks_per_entry = num_blocks;

  while (blocks_per_entry > 1) {
    uint32_t num_chunks = CEIL_DIV(blocks_per_entry, max_value);
    uint32_t total_chunks = num_possible_values * num_chunks;
    uint32_t last_chunk_length =
        blocks_per_entry - (num_chunks - 1) * max_value;

    host_accumulate_all_blocks_batched<Torus>(
        streams.stream(0), streams.gpu_index(0), (Torus *)tree_accumulator->ptr,
        current_input_ptr, big_lwe_dimension, blocks_per_entry, max_value,
        num_possible_values, num_chunks);

    if (last_chunk_length != max_value) {
      auto is_equal_to_last_f = [last_chunk_length](Torus x) -> Torus {
        return x == last_chunk_length;
      };

      uint32_t lut_num_blocks = is_max_value_lut->num_blocks;
      auto index_gen = [num_chunks, total_chunks,
                        lut_num_blocks](Torus *h_lut_indexes, uint32_t) {
        for (uint32_t idx = 0; idx < lut_num_blocks; idx++) {
          if (idx < total_chunks && (idx % num_chunks) == num_chunks - 1) {
            h_lut_indexes[idx] = 1;
          } else {
            h_lut_indexes[idx] = 0;
          }
        }
      };

      auto active =
          streams.active_gpu_subset(total_chunks, mem_ptr->params.pbs_type);
      is_max_value_lut->generate_and_broadcast_lut(
          active, {1}, {is_equal_to_last_f}, index_gen, true,
          {mem_ptr->preallocated_h_lut});
    }

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, tree_pbs_output, tree_accumulator, bsks, ksks,
        is_max_value_lut, total_chunks);

    if (last_chunk_length != max_value) {
      auto active = streams.active_gpu_subset(is_max_value_lut->num_blocks,
                                              mem_ptr->params.pbs_type);
      is_max_value_lut->set_lut_indexes_and_broadcast_constant(active, 0);
    }

    current_input_ptr = (Torus *)tree_pbs_output->ptr;
    blocks_per_entry = num_chunks;
  }

  // Step 4: Scatter single-block results to per-entry outputs
  CudaRadixCiphertextFFI *result_source =
      (blocks_per_entry == num_blocks) ? batched : tree_pbs_output;
  for (uint32_t i = 0; i < num_possible_values; i++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[i], 0, 1,
        result_source, i, i + 1);
  }
}

// gridDim.x == current_chunk_size, gridDim.y == num_blocks.
template <typename T>
__global__ void
pack_chunk_eq_pairs_kernel(T *packed_current, T *packed_value,
                           T *const *src_ptrs, T const *value_ptr,
                           uint32_t input_offset, uint32_t current_chunk_size,
                           uint32_t num_blocks, uint32_t lwe_size) {
  uint32_t c = blockIdx.x;
  uint32_t j = blockIdx.y;

  uint32_t dst = j * current_chunk_size + c;
  T *out_cur = packed_current + (size_t)dst * lwe_size;
  T *out_val = packed_value + (size_t)dst * lwe_size;

  const T *src_input = src_ptrs[input_offset + c] + (size_t)j * lwe_size;
  const T *src_value = value_ptr + (size_t)j * lwe_size;

  for (uint32_t tid = threadIdx.x; tid < lwe_size; tid += blockDim.x) {
    out_cur[tid] = src_input[tid];
    out_val[tid] = src_value[tid];
  }
}

// Formats memory for a batched bivariate PBS (comparing N ciphertexts to 1
// target).
//
// Memory layout:
// inputs (chunk) : [ In 0 ] [ In 1 ] ... [ In N ]
// value          : [ Target ]
//
// Result:
// packed_current : [ In 0 ]   [ In 1 ]   ... [ In N ]
//                    vs         vs             vs
// packed_value   : [ Target ] [ Target ] ... [ Target ]
//
//   packed_current     [out]: Contiguous buffer of N input ciphertexts
//   packed_value       [out]: Target value duplicated N times
//   d_src_ptrs         [in] : Device pointers to the inputs
//   inputs             [in] : N input ciphertexts (for metadata)
//   value              [in] : Single target ciphertext
//   input_offset       [in] : Starting index in the inputs array
//   current_chunk_size [in] : Number of ciphertexts in this chunk
//   num_blocks         [in] : Radix blocks per ciphertext (64 bits or 32
//   bits...)
template <typename T>
__host__ void host_pack_chunk_eq_pairs(
    cudaStream_t stream, uint32_t gpu_index,
    CudaRadixCiphertextFFI *packed_current,
    CudaRadixCiphertextFFI *packed_value, T *const *d_src_ptrs,
    CudaRadixCiphertextFFI const *inputs, CudaRadixCiphertextFFI const *value,
    uint32_t input_offset, uint32_t current_chunk_size, uint32_t num_blocks) {
  if (current_chunk_size == 0 || num_blocks == 0)
    return;
  if (packed_current->lwe_dimension != value->lwe_dimension ||
      packed_value->lwe_dimension != value->lwe_dimension)
    PANIC("Cuda error: packed buffers and value must share the same "
          "lwe_dimension")
  if (packed_current->num_radix_blocks < current_chunk_size * num_blocks ||
      packed_value->num_radix_blocks < current_chunk_size * num_blocks)
    PANIC("Cuda error: packed buffers do not have enough blocks for "
          "current_chunk_size * num_blocks")
  if (value->num_radix_blocks < num_blocks)
    PANIC("Cuda error: value does not have enough blocks")
  for (uint32_t c = 0; c < current_chunk_size; c++) {
    if (inputs[input_offset + c].lwe_dimension != value->lwe_dimension)
      PANIC("Cuda error: input and value lwe dimensions must match")
    if (inputs[input_offset + c].num_radix_blocks < num_blocks)
      PANIC("Cuda error: an input has fewer blocks than num_blocks")
  }
  cuda_set_device(gpu_index);
  uint32_t lwe_size = packed_current->lwe_dimension + 1;
  dim3 grid(current_chunk_size, num_blocks, 1);
  pack_chunk_eq_pairs_kernel<T><<<grid, 256, 0, stream>>>(
      (T *)packed_current->ptr, (T *)packed_value->ptr, d_src_ptrs,
      (T const *)value->ptr, input_offset, current_chunk_size, num_blocks,
      lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t j = 0; j < num_blocks; j++) {
    for (uint32_t c = 0; c < current_chunk_size; c++) {
      uint32_t dst = j * current_chunk_size + c;
      packed_current->degrees[dst] = inputs[input_offset + c].degrees[j];
      packed_current->noise_levels[dst] =
          inputs[input_offset + c].noise_levels[j];
      packed_value->degrees[dst] = value->degrees[j];
      packed_value->noise_levels[dst] = value->noise_levels[j];
    }
  }
}

template <typename Torus>
__host__ void
host_binary_tree_sum(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
                     CudaRadixCiphertextFFI const *lwe_array_in,
                     uint32_t num_input_ciphertexts, uint32_t num_blocks,
                     int_binary_tree_sum_buffer<Torus> *mem_ptr,
                     void *const *bsks, Torus *const *ksks) {

  int_radix_params params = mem_ptr->params;
  uint32_t chunk_size = mem_ptr->chunk_size;
  uint32_t message_modulus = params.message_modulus;
  uint32_t carry_modulus = params.carry_modulus;

  if (num_input_ciphertexts == 0)
    PANIC("Cuda error: binary tree sum called with zero inputs")
  if (num_input_ciphertexts > mem_ptr->num_input_ciphertexts)
    PANIC("Cuda error: num_input_ciphertexts exceeds capacity used at scratch")

  CudaRadixCiphertextFFI *src_buf = &mem_ptr->packed_partial_temp_vectors;
  CudaRadixCiphertextFFI *dst_buf = &mem_ptr->tree_reduction_buf;

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     src_buf, lwe_array_in);

  uint32_t num_pending = num_input_ciphertexts;
  while (num_pending > 1) {
    uint32_t remaining = CEIL_DIV(num_pending, chunk_size);

    host_lwe_flat_array_2d_sum_rows<Torus>(
        streams.stream(0), streams.gpu_index(0), dst_buf, src_buf, chunk_size,
        num_pending, remaining, num_blocks, message_modulus, carry_modulus);

    CudaRadixCiphertextFFI level_slice;
    as_radix_ciphertext_slice<Torus>(&level_slice, dst_buf, 0,
                                     remaining * num_blocks);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &level_slice, &level_slice, bsks, ksks,
        mem_ptr->batched_identity_lut, remaining * num_blocks);

    std::swap(src_buf, dst_buf);
    num_pending = remaining;
  }

  // After the ping-pong loop the aggregated result always resides in src_buf
  // For the single-chunk case the loop never runs, thus we need to copy it into
  // the caller output instead.
  CudaRadixCiphertextFFI final_sum;
  as_radix_ciphertext_slice<Torus>(&final_sum, src_buf, 0, num_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out, 0, num_blocks,
      &final_sum, 0, num_blocks);
}

template <typename Torus>
__global__ void
scatter_to_ptr_array_kernel(Torus *const *dst_ptr_array,
                            const Torus *src_batched, uint32_t num_blocks,
                            const uint32_t *src_offsets, uint32_t lwe_size) {
  uint32_t out_idx = blockIdx.x / num_blocks;
  uint32_t blk_in_out = blockIdx.x % num_blocks;

  Torus *dst = dst_ptr_array[out_idx];
  Torus *dst_ptr = dst + (size_t)blk_in_out * lwe_size;
  const Torus *src_ptr =
      src_batched + (size_t)src_offsets[blockIdx.x] * lwe_size;

  for (uint32_t tid = threadIdx.x; tid < lwe_size; tid += blockDim.x) {
    dst_ptr[tid] = src_ptr[tid];
  }
}

/*
Copies radix-ciphertexts from a contiguous buffer of radix-ciphertexts to a
list of independently allocated radix-ciphertexts. It performs the inverse
operation of `align_with_indexes`. It allows re-ordering the input
radix-ciphertexts through the offsets argument.
A single CUDA kernel performs the copy.

Args:
- stream, gpu_index: GPU index and its associated stream that performs the
  copy. This is a single GPU function
- dst_list: the CPU-side list of independently allocated
  CudaRadixCiphertextFFI.
- d_dst_ptrs: GPU copy of the CPU-side pointer list to the
  CudaRadixCiphertextFFI LWE arrays.
- src: a CudaRadixCiphertextFFI containing num_outputs * num_blocks blocks that
  will be scattered to the destination CudaRadixCiphertextFFI.
- d_src_offsets: output radix-ciphertext k is set to src[offsets[k]]. This
  allows re-ordering.
- h_src_offsets: cpu copy of the offsets (indexes), used for noise tracking
- num_outputs: number of input and output radix-ciphertexts
- num_blocks: number of blocks in each radix-ciphertext
*/
template <typename Torus>
__host__ void host_scatter_to_ptr_array(
    cudaStream_t stream, uint32_t gpu_index,
    std::vector<CudaRadixCiphertextFFI> &dst_list, Torus *const *d_dst_ptrs,
    CudaRadixCiphertextFFI const *src, const uint32_t *d_src_offsets,
    const uint32_t *h_src_offsets, uint32_t num_outputs, uint32_t num_blocks) {
  if (num_outputs == 0 || num_blocks == 0)
    return;
  for (uint32_t i = 0; i < num_outputs; i++) {
    if (dst_list[i].lwe_dimension != src->lwe_dimension)
      PANIC("Cuda error: dst and src lwe dimensions must match")
    if (dst_list[i].num_radix_blocks < num_blocks)
      PANIC("Cuda error: a destination has fewer blocks than num_blocks")
  }
  for (uint32_t k = 0; k < num_outputs * num_blocks; k++) {
    if (h_src_offsets[k] >= src->num_radix_blocks)
      PANIC("Cuda error: src offset is out of range")
  }
  cuda_set_device(gpu_index);
  uint32_t lwe_size = src->lwe_dimension + 1;
  uint32_t grid = num_outputs * num_blocks;
  scatter_to_ptr_array_kernel<Torus><<<grid, 256, 0, stream>>>(
      d_dst_ptrs, (Torus const *)src->ptr, num_blocks, d_src_offsets, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t i = 0; i < num_outputs; i++) {
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint32_t off = h_src_offsets[i * num_blocks + j];
      dst_list[i].degrees[j] = src->degrees[off];
      dst_list[i].noise_levels[j] = src->noise_levels[off];
    }
  }
}

// AND-reduces a block-wise equality matrix across its rows.
//
// Memory layout and reduction logic:
// - The input selectors is treated as a flat 2D matrix of shape:
//   (num_blocks rows) x (num_columns columns).
//   Each column corresponds to a specific candidate/input, and each row
//   corresponds to a radix block.
// - The function sums the rows column-by-column and applies a LUT to check if
//   the sum equals the expected number of blocks (evaluating a logical AND).
//
// Output:
// - The accumulator output is a 1D vector of num_columns single-block LWEs.
// - Each single-block LWE contains a boolean (1 or 0) indicating if the full
//   multi-block equality holds for that specific column.
template <typename Torus>
__host__ void host_and_reduce_selector_matrix(
    CudaStreams streams, CudaRadixCiphertextFFI *accumulator,
    CudaRadixCiphertextFFI const *selectors,
    const std::vector<int_radix_lut<Torus> *> &luts_eq,
    uint32_t num_luts_needed, uint32_t num_columns, uint32_t num_blocks,
    uint32_t max_degree, uint32_t message_modulus, uint32_t carry_modulus,
    void *const *bsks, Torus *const *ksks) {

  CudaRadixCiphertextFFI acc_slice;
  as_radix_ciphertext_slice<Torus>(&acc_slice, accumulator, 0, num_columns);

  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &acc_slice, 0, num_columns);

  uint32_t take = 0;
  for (uint32_t row = 0; row < num_blocks; row += take) {
    bool first = (row == 0);
    uint32_t cap = first ? max_degree : (max_degree - 1);
    take = std::min(cap, num_blocks - row);
    uint32_t items_in_acc = (first ? 0u : 1u) + take;

    host_lwe_flat_array_2d_accumulate_rows<Torus>(
        streams.stream(0), streams.gpu_index(0), &acc_slice, selectors, row,
        take, num_columns, message_modulus, carry_modulus);

    if (items_in_acc >= 2) {
      PANIC_IF_FALSE(items_in_acc <= num_luts_needed,
                     "items_in_acc out of luts_eq bounds");
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, &acc_slice, &acc_slice, bsks, ksks, luts_eq[items_in_acc],
          num_columns);
    }
  }
}

/*
Computes an indicator (boolean) vector of LWEs, representing whether the input
radix-ciphertext is equal to any of a list of scalars.

Args:
- streams: the set of streams that can be used for this operation, supporting
  multi-GPU
- lwe_array_out_packed: a flat list of LWEs containing 0 or 1 depending on
  whether lwe_array_in equals each clear value
- lwe_array_in: input ciphertext that is matched with each clear value
- num_blocks: blocks in the ciphertext and in the decomposed clear values
- h_decomposed_cleartexts: CPU flat array of the decomposed clear values
- bsks, ksks: keys
*/
// Given one encrypted radix ciphertext (num_blocks blocks, each a digit in
// [0, message_modulus)) and N cleartext candidates (e.g. KV-store keys),
// produces N encrypted booleans: selector_i = Enc(input == candidate_i).
//
// Candidates live in h_decomposed_cleartexts, a flat array where candidate i
// occupies [i*num_blocks .. (i+1)*num_blocks). N =
// mem_ptr->num_possible_values.
//
// A per-candidate approach costs N * num_blocks PBS. Since there are only
// message_modulus possible digit values (typically 2 or 4), we instead
// precompute all per-block comparisons in one batched PBS, then let each
// candidate pick the results it needs via memcpy:
//
// Step 1 — One batched PBS builds a message_modulus x num_blocks grid:
//
//                       block 0    block 1    block 2
//                     ┌──────────┬──────────┬──────────┐
//     LUT for v=0     │ b0==0?   │ b1==0?   │ b2==0?   │
//     LUT for v=1     │ b0==1?   │ b1==1?   │ b2==1?   │
//     LUT for v=2     │ b0==2?   │ b1==2?   │ b2==2?   │
//     LUT for v=3     │ b0==3?   │ b1==3?   │ b2==3?   │
//                     └──────────┴──────────┴──────────┘
//     Flat: tmp_many_luts_output[v * num_blocks + j]
//
// Step 2 — For each candidate i with digits [d0, d1, ..], gather grid[dj][j]
//   for all j into a flat N*num_blocks buffer.
//
// Step 3 — AND-reduce across all candidates simultaneously using a batched
//   tree: at each level, accumulate chunks and apply one large batched PBS.
//   This replaces per-candidate AND-trees with 2 batched PBS calls (for
//   typical 2_2 params with 16-block keys).
//
// Cost: message_modulus * num_blocks PBS (grid, constant)
//     + sum_levels(N * chunks_at_level) PBS (batched tree)
template <typename Torus>
__host__ void host_compute_eq_selectors_ct_vs_clears(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_packed,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_blocks,
    const uint64_t *h_decomposed_cleartexts,
    int_eq_selectors_ct_vs_clears_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  uint32_t num_possible_values = mem_ptr->num_possible_values;
  uint32_t message_modulus = mem_ptr->params.message_modulus;
  uint32_t carry_modulus = mem_ptr->params.carry_modulus;
  uint32_t big_lwe_dimension = mem_ptr->params.big_lwe_dimension;

  // Step 1: Grid PBS — precompute all per-block equality indicators.
  // One batched PBS builds a message_modulus x num_blocks grid where
  // grid[v][j] = Enc(input_block_j == v).
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, &mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);

  if (num_blocks == 0) {
    for (uint32_t i = 0; i < num_possible_values; i++) {
      set_single_scalar_trivial_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 1,
          message_modulus, carry_modulus);
    }
    return;
  }

  // Step 2: Gather — for each candidate i, extract its comparison blocks
  // from the grid PBS output into a flat row-major buffer:
  //   batched[i * num_blocks + j] = grid[decomposed[i][j]][j]
  Torus *h_map = mem_ptr->h_map;
  uint32_t total_blocks = num_possible_values * num_blocks;
  for (uint32_t i = 0; i < num_possible_values; i++) {
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t block_value = h_decomposed_cleartexts[i * num_blocks + j];
      if (block_value >= message_modulus)
        PANIC("Cuda error: block value in compute_equality_selectors exceeds "
              "message modulus");
      h_map[i * num_blocks + j] = (Torus)block_value * num_blocks + j;
    }
  }
  cuda_memcpy_async_to_gpu(mem_ptr->d_map, h_map,
                           safe_mul_sizeof<Torus>(total_blocks),
                           streams.stream(0), streams.gpu_index(0));

  uint32_t lwe_size = mem_ptr->tmp_batched_comparisons.lwe_dimension + 1;
  align_with_indexes<Torus><<<total_blocks, 256, 0, streams.stream(0)>>>(
      (Torus *)mem_ptr->tmp_batched_comparisons.ptr,
      (Torus *)mem_ptr->tmp_many_luts_output.ptr, mem_ptr->d_map, lwe_size);
  check_cuda_error(cudaGetLastError());

  if (num_blocks == 1) {
    // Each candidate needs exactly one comparison block; no tree reduction.
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 0,
        num_possible_values, &mem_ptr->tmp_batched_comparisons, 0,
        num_possible_values);
    return;
  }

  // Step 3: Batched tree reduction — AND-reduce the per-entry comparison
  // blocks using host_accumulate_all_blocks_batched + is_max_value PBS.
  // The data is in row-major layout: entry_i occupies blocks
  // [i*num_blocks .. (i+1)*num_blocks).
  uint32_t max_value = mem_ptr->max_value;
  auto is_max_value_lut = mem_ptr->is_max_value_lut;
  auto tree_accumulator = mem_ptr->tree_accumulator;
  auto tree_pbs_output = mem_ptr->tree_pbs_output;

  Torus *current_input_ptr = (Torus *)mem_ptr->tmp_batched_comparisons.ptr;
  uint32_t blocks_per_entry = num_blocks;
  uint32_t level = 0;

  while (blocks_per_entry > 1) {
    uint32_t num_chunks = CEIL_DIV(blocks_per_entry, max_value);
    uint32_t total_chunks = num_possible_values * num_chunks;

    host_accumulate_all_blocks_batched<Torus>(
        streams.stream(0), streams.gpu_index(0), (Torus *)tree_accumulator->ptr,
        current_input_ptr, big_lwe_dimension, blocks_per_entry, max_value,
        num_possible_values, num_chunks);

    // Update metadata for tree_accumulator
    for (uint32_t flat = 0; flat < total_chunks; flat++) {
      uint32_t entry = flat / num_chunks;
      uint32_t chunk = flat % num_chunks;
      uint32_t chunk_start = chunk * max_value;
      uint32_t chunk_len = std::min(max_value, blocks_per_entry - chunk_start);
      tree_accumulator->degrees[flat] = chunk_len;
      tree_accumulator->noise_levels[flat] = NoiseLevel::NOMINAL;
    }

    // Switch to this level's precomputed lut-index buffer (PM2). The is_max LUT
    // (slot 0) and the per-level is_equal_to_last LUT (slot level+1) are baked
    // in at scratch time, so we only do a small gpu-to-gpu index copy and
    // broadcast instead of regenerating the LUT polynomial on the host and
    // resetting indexes every level.
    auto active =
        streams.active_gpu_subset(total_chunks, mem_ptr->params.pbs_type);
    is_max_value_lut->set_lut_indexes_and_broadcast_from_gpu(
        active, mem_ptr->d_level_lut_indexes[level], total_chunks);

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, tree_pbs_output, tree_accumulator, bsks, ksks,
        is_max_value_lut, total_chunks);

    current_input_ptr = (Torus *)tree_pbs_output->ptr;
    blocks_per_entry = num_chunks;
    level++;
  }

  // Step 4: Copy single-block results to output
  CudaRadixCiphertextFFI *result_source =
      (blocks_per_entry == num_blocks) ? &mem_ptr->tmp_batched_comparisons
                                       : tree_pbs_output;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 0,
      num_possible_values, result_source, 0, num_possible_values);
}

/*
Computes an indicator (boolean) vector of LWEs, representing whether the input
list of radix-ciphertext is equal to the target value that is searched for.

Args:
- streams: the set of streams that can be used for this operation, supporting
  multi-GPU
- lwe_array_out_list: boolean list, the i-th cell indicating whether value
  matches the i-th input
- inputs: list of radix-ciphertext to be searched
- value: radix-ciphertext that is searched for in the list
- num_inputs: number of values in the search list of radix-ciphertext
- num_blocks: number of blocks in the radix-ciphertexts used
- bsks, ksks: keys
*/
template <typename Torus>
__host__ void host_compute_eq_selectors_cts_vs_ct(
    CudaStreams streams,
    std::vector<CudaRadixCiphertextFFI> &lwe_array_out_list,
    CudaRadixCiphertextFFI const *inputs, CudaRadixCiphertextFFI const *value,
    uint32_t num_inputs, uint32_t num_blocks,
    int_eq_selectors_cts_vs_ct_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  PANIC_IF_FALSE(num_inputs <= mem_ptr->num_inputs,
                 "num_inputs exceeds the capacity reserved at scratch time");

  uint32_t message_modulus = mem_ptr->params.message_modulus;
  uint32_t carry_modulus = mem_ptr->params.carry_modulus;
  uint32_t max_degree = mem_ptr->max_degree;
  uint32_t chunk_size = mem_ptr->chunk_size;

  Torus **h_input_ptrs = mem_ptr->h_input_ptrs;
  for (uint32_t k = 0; k < num_inputs; k++) {
    h_input_ptrs[k] = (Torus *)inputs[k].ptr;
  }
  cuda_memcpy_async_to_gpu(mem_ptr->d_input_ptrs, mem_ptr->h_input_ptrs,
                           safe_mul_sizeof<Torus *>(num_inputs),
                           streams.stream(0), streams.gpu_index(0));

  for (uint32_t base = 0; base < num_inputs; base += chunk_size) {
    uint32_t current_chunk_size = std::min(chunk_size, num_inputs - base);

    // Cache the chunk of the input radix-ciphertext list in a temporary buffer.
    // Also duplicate the searched-for value radix-ct blocks in a manner in
    // which the bivariate PBS can pack pairs of (inputs[i][k], value[k])
    // for-each i in [0..num_inputs], for-each k in [0..num_blocks]
    host_pack_chunk_eq_pairs<Torus>(
        streams.stream(0), streams.gpu_index(0), &mem_ptr->packed_current_block,
        &mem_ptr->packed_value_block, mem_ptr->d_input_ptrs, inputs, value,
        base, current_chunk_size, num_blocks);

    // Compute an indicator value for each block of each input radix-ciphertext,
    // indicating whether the block is equal to the corresponding block in the
    // searched for radix-ciphertext value
    uint32_t total = current_chunk_size * num_blocks;
    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &mem_ptr->packed_current_block, &mem_ptr->packed_current_block,
        &mem_ptr->packed_value_block, bsks, ksks, mem_ptr->equality_lut, total,
        message_modulus);

    // The indicator boolean values produced by the LUT are interpreted as a 2d
    // array of num_blocks (rows) x num_inputs (cols). And-reduce the array to
    // determine which inputs match the searched-for value. This produces a 1d
    // vector of booleans
    host_and_reduce_selector_matrix<Torus>(
        streams, &mem_ptr->packed_accumulator, &mem_ptr->packed_current_block,
        mem_ptr->luts_eq, mem_ptr->num_luts_needed, current_chunk_size,
        num_blocks, max_degree, message_modulus, carry_modulus, bsks, ksks);

    // Copy the booleans into individual output radix-ciphertexts which have a
    // single block
    for (uint32_t c = 0; c < current_chunk_size; c++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &lwe_array_out_list[base + c], 0, 1, &mem_ptr->packed_accumulator, c,
          c + 1);
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_compute_equality_selectors(
    CudaStreams streams, int_eq_selectors_ct_vs_clears_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_possible_values, uint32_t num_blocks,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_eq_selectors_ct_vs_clears_buffer<Torus>(
      streams, params, num_possible_values, num_blocks, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_create_possible_results(
    CudaStreams streams,
    std::vector<CudaRadixCiphertextFFI> &lwe_array_out_list,
    CudaRadixCiphertextFFI const *batched_selectors,
    uint32_t num_possible_values, const uint64_t *h_decomposed_cleartexts,
    uint32_t num_blocks, int_possible_results_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  uint32_t max_packed_value = mem_ptr->max_packed_value;
  uint32_t max_luts_per_call = mem_ptr->max_luts_per_call;
  uint32_t num_lut_accumulators = mem_ptr->num_lut_accumulators;
  uint32_t total_lut_inputs = num_lut_accumulators * num_possible_values;

  for (uint32_t k = 0; k < num_lut_accumulators; k++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        &mem_ptr->tmp_batched_selectors, k * num_possible_values,
        (k + 1) * num_possible_values, batched_selectors, 0,
        num_possible_values);
  }

  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, &mem_ptr->tmp_many_luts_output, &mem_ptr->tmp_batched_selectors,
      bsks, (Torus *const *)ksks, mem_ptr->batched_accumulators_lut,
      max_luts_per_call, mem_ptr->lut_stride);

  Torus **h_dst_ptrs = (Torus **)mem_ptr->h_dst_ptrs;
  for (uint32_t i = 0; i < num_possible_values; i++) {
    h_dst_ptrs[i] = (Torus *)lwe_array_out_list[i].ptr;
  }

  uint32_t *h_src_idx = mem_ptr->h_src_idx;
  for (uint32_t i = 0; i < num_possible_values; i++) {
    const uint64_t *current_clear_blocks =
        &h_decomposed_cleartexts[i * num_blocks];
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t packed_block_value = current_clear_blocks[j];
      if (packed_block_value >= max_packed_value)
        PANIC("Cuda error: block value in create_possible_results exceeds max "
              "packed value");

      auto k = (uint32_t)(packed_block_value / max_luts_per_call);
      auto lut_in_acc = (uint32_t)(packed_block_value % max_luts_per_call);
      h_src_idx[i * num_blocks + j] =
          lut_in_acc * total_lut_inputs + k * num_possible_values + i;
    }
  }

  cuda_memcpy_async_to_gpu(mem_ptr->d_dst_ptrs, mem_ptr->h_dst_ptrs,
                           safe_mul_sizeof<Torus *>(num_possible_values),
                           streams.stream(0), streams.gpu_index(0));
  cuda_memcpy_async_to_gpu(
      mem_ptr->d_src_idx, h_src_idx,
      safe_mul_sizeof<uint32_t>(num_possible_values * num_blocks),
      streams.stream(0), streams.gpu_index(0));

  host_scatter_to_ptr_array<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_list,
      (Torus *const *)mem_ptr->d_dst_ptrs, &mem_ptr->tmp_many_luts_output,
      mem_ptr->d_src_idx, h_src_idx, num_possible_values, num_blocks);
}

template <typename Torus>
uint64_t scratch_cuda_create_possible_results(
    CudaStreams streams, int_possible_results_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks, uint32_t num_possible_values,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_possible_results_buffer<Torus>(
      streams, params, num_blocks, num_possible_values, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

// Given N encrypted radix ciphertexts forming a one-hot vector (at most one
// non-zero entry), sum them into a single output ciphertext. Because the
// vector is one-hot, the sum recovers the value of the single non-zero entry.
//
// Plain LWE addition accumulates noise in the carry bits. After chunk_size
// additions the carry space is exhausted, so an identity PBS is applied after
// each chunk to refresh the ciphertext (extract message, reset carry to zero).
//
// The algorithm has three phases:
//
// Phase 1 — Parallel chunked accumulation (one CUDA stream per partition):
//
//   stream 0: inputs[0..k)         stream 1: inputs[k..2k)        ...
//   ┌──────────────────────┐       ┌──────────────────────┐
//   │ acc  = 0             │       │ acc  = 0             │
//   │ acc += input[0]      │       │ acc += input[k]      │
//   │ acc += input[1]      │       │ acc += input[k+1]    │
//   │ ...chunk_size adds...│       │ ...chunk_size adds...│
//   │ acc = PBS(acc)  ← refresh    │ acc = PBS(acc)       │
//   │ (repeat for next chunk)      │ (repeat)             │
//   └──────────────────────┘       └──────────────────────┘
//
// Phase 2 — Cross-stream merge: sum partial accumulators into stream 0's
//   result. num_streams must stay below the noise ceiling.
//
// Phase 3 — Message/carry extraction and interleaving:
//   The accumulated blocks use both message and carry space. Two parallel
//   PBS calls extract message bits and carry bits separately, then
//   interleave them into the output:
//
//     output[2i]   = message_extract(acc[i])
//     output[2i+1] = carry_extract(acc[i])
//
//   This unpacks each "packed" block into two standard blocks, so the
//   output has up to 2 * num_blocks radix blocks.
template <typename Torus>
__host__ void host_aggregate_one_hot_vector(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    const std::vector<CudaRadixCiphertextFFI> &lwe_array_in_list,
    uint32_t num_input_ciphertexts, uint32_t num_blocks,
    int_aggregate_one_hot_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  int_radix_params params = mem_ptr->params;
  uint32_t chunk_size = mem_ptr->chunk_size;
  uint32_t message_modulus = params.message_modulus;
  uint32_t carry_modulus = params.carry_modulus;

  if (num_input_ciphertexts == 0)
    PANIC("Cuda error: aggregate one-hot vector called with zero inputs")
  if (num_input_ciphertexts > mem_ptr->num_input_ciphertexts_capacity)
    PANIC("Cuda error: num_input_ciphertexts exceeds capacity used at scratch")

  uint32_t num_chunks = CEIL_DIV(num_input_ciphertexts, chunk_size);

  CudaRadixCiphertextFFI *src_buf = &mem_ptr->packed_partial_temp_vectors;
  CudaRadixCiphertextFFI *dst_buf = &mem_ptr->tree_reduction_buf;

  Torus **h_input_ptrs = mem_ptr->h_input_ptrs;
  for (uint32_t k = 0; k < num_input_ciphertexts; k++) {
    h_input_ptrs[k] = (Torus *)lwe_array_in_list[k].ptr;
  }
  cuda_memcpy_async_to_gpu(mem_ptr->d_input_ptrs, mem_ptr->h_input_ptrs,
                           safe_mul_sizeof<Torus *>(num_input_ciphertexts),
                           streams.stream(0), streams.gpu_index(0));

  host_lwe_array_2d_sum_rows<Torus>(
      streams.stream(0), streams.gpu_index(0), src_buf, mem_ptr->d_input_ptrs,
      lwe_array_in_list.data(), 0u, chunk_size, num_input_ciphertexts,
      num_chunks, num_blocks, message_modulus, carry_modulus);

  CudaRadixCiphertextFFI partials_slice;
  as_radix_ciphertext_slice<Torus>(&partials_slice, src_buf, 0,
                                   num_chunks * num_blocks);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &partials_slice, &partials_slice, bsks, ksks,
      mem_ptr->batched_identity_lut, num_chunks * num_blocks);

  uint32_t num_pending = num_chunks;
  while (num_pending > 1) {
    uint32_t groups = CEIL_DIV(num_pending, chunk_size);

    host_lwe_flat_array_2d_sum_rows<Torus>(
        streams.stream(0), streams.gpu_index(0), dst_buf, src_buf, chunk_size,
        num_pending, groups, num_blocks, message_modulus, carry_modulus);

    CudaRadixCiphertextFFI level_slice;
    as_radix_ciphertext_slice<Torus>(&level_slice, dst_buf, 0,
                                     groups * num_blocks);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &level_slice, &level_slice, bsks, ksks,
        mem_ptr->batched_identity_lut, groups * num_blocks);

    std::swap(src_buf, dst_buf);
    num_pending = groups;
  }

  CudaRadixCiphertextFFI final_agg;
  as_radix_ciphertext_slice<Torus>(&final_agg, src_buf, 0, num_blocks);

  // Unpack final_agg
  // Split them with two PBS
  // Toy example (message_modulus = 4): final_agg = [12, 9]
  //   = [0 + 3*4, 1 + 2*4]  ->  unpacks to logical [0, 3, 1, 2].
  //
  // message_extract_lut: x -> x % message_modulus  (low digit):  [0, 1]
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &mem_ptr->message_ct, &final_agg, bsks, ksks,
      mem_ptr->message_extract_lut, num_blocks);

  // carry_extract_lut: x -> x / message_modulus  (high digit): [3, 2]
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &mem_ptr->carry_ct, &final_agg, bsks, ksks,
      mem_ptr->carry_extract_lut, num_blocks);

  for (uint32_t index = 0; index < num_blocks; index++) {
    if (2 * index < lwe_array_out->num_radix_blocks) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index,
          2 * index + 1, &mem_ptr->message_ct, index, index + 1);
    }
    if (2 * index + 1 < lwe_array_out->num_radix_blocks) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index + 1,
          2 * index + 2, &mem_ptr->carry_ct, index, index + 1);
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_aggregate_one_hot_vector(
    CudaStreams streams, int_aggregate_one_hot_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks, uint32_t num_matches,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_aggregate_one_hot_buffer<Torus>(
      streams, params, num_blocks, num_matches, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_match_value(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_result,
    CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI const *lwe_array_in_ct,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    int_unchecked_match_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  // sel_i = (key == key_i) in {0,1},
  // toy example: [10] vs [1,2,5,10,20] -> [0,0,0,1,0]
  host_compute_eq_selectors_ct_vs_clears<Torus>(
      streams, &mem_ptr->packed_selectors_ct, lwe_array_in_ct,
      mem_ptr->num_input_blocks, h_match_inputs, mem_ptr->eq_selectors_buffer,
      bsks, ksks);

  // result_i = sel_i * value_i: [0,0,0,1,0] * [100,15,10,9,1] -> [0,0,0,9,0]
  if (!mem_ptr->max_output_is_zero) {
    host_create_possible_results<Torus>(
        streams, mem_ptr->possible_results_list, &mem_ptr->packed_selectors_ct,
        mem_ptr->num_matches, h_match_outputs,
        mem_ptr->num_output_packed_blocks, mem_ptr->possible_results_buffer,
        bsks, ksks);
  }

  // all values 0 => result is 0: skip aggregation, only emit the "found" flag
  if (mem_ptr->max_output_is_zero) {
    host_integer_is_at_least_one_comparisons_block_true<Torus>(
        streams, lwe_array_out_boolean, &mem_ptr->packed_selectors_ct,
        mem_ptr->at_least_one_true_buffer, bsks, (Torus **)ksks,
        mem_ptr->num_matches);
    return;
  }

  // sum the one-hot = read out the matched value: 0+0+0+9+0 -> 9
  host_aggregate_one_hot_vector<Torus>(
      streams, lwe_array_out_result, mem_ptr->possible_results_list,
      mem_ptr->num_matches, mem_ptr->num_output_packed_blocks,
      mem_ptr->aggregate_buffer, bsks, ksks);

  // "found" flag = OR of selectors: 0 | 0 | 0 | 1 | 0 -> 1
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_array_out_boolean, &mem_ptr->packed_selectors_ct,
      mem_ptr->at_least_one_true_buffer, bsks, (Torus **)ksks,
      mem_ptr->num_matches);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_match_value(
    CudaStreams streams, int_unchecked_match_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_output_packed_blocks, bool max_output_is_zero,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_match_buffer<Torus>(
      streams, params, num_matches, num_input_blocks, num_output_packed_blocks,
      max_output_is_zero, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_match_value_or(
    CudaStreams streams, int_unchecked_match_value_or_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_match_packed_blocks, uint32_t num_final_blocks,
    bool max_output_is_zero, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_match_value_or_buffer<Torus>(
      streams, params, num_matches, num_input_blocks, num_match_packed_blocks,
      num_final_blocks, max_output_is_zero, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_match_value_or(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_ct,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    const uint64_t *h_or_value,
    int_unchecked_match_value_or_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  host_unchecked_match_value<Torus>(streams, &mem_ptr->tmp_match_result,
                                    &mem_ptr->tmp_match_bool, lwe_array_in_ct,
                                    h_match_inputs, h_match_outputs,
                                    mem_ptr->match_buffer, bsks, ksks);

  cuda_memcpy_async_to_gpu(mem_ptr->d_or_value, h_or_value,
                           safe_mul_sizeof<Torus>(mem_ptr->num_final_blocks),
                           streams.stream(0), streams.gpu_index(0));

  set_trivial_radix_ciphertext_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &mem_ptr->tmp_or_value,
      mem_ptr->d_or_value, h_or_value, mem_ptr->num_final_blocks,
      mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

  host_cmux<Torus>(streams, lwe_array_out, &mem_ptr->tmp_match_bool,
                   &mem_ptr->tmp_match_result, &mem_ptr->tmp_or_value,
                   mem_ptr->cmux_buffer, bsks, (Torus **)ksks);
}

template <typename Torus>
uint64_t
scratch_cuda_unchecked_contains(CudaStreams streams,
                                int_unchecked_contains_buffer<Torus> **mem_ptr,
                                int_radix_params params, uint32_t num_inputs,
                                uint32_t num_blocks, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_contains_buffer<Torus>(
      streams, params, num_inputs, num_blocks, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void
host_unchecked_contains(CudaStreams streams, CudaRadixCiphertextFFI *output,
                        CudaRadixCiphertextFFI const *inputs,
                        CudaRadixCiphertextFFI const *value,
                        uint32_t num_inputs, uint32_t num_blocks,
                        int_unchecked_contains_buffer<Torus> *mem_ptr,
                        void *const *bsks, Torus *const *ksks) {

  host_compute_eq_selectors_cts_vs_ct<Torus>(
      streams, mem_ptr->unpacked_selectors, inputs, value, num_inputs,
      num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, &mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
      bsks, (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_contains_clear(
    CudaStreams streams, int_unchecked_contains_clear_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_contains_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_contains_clear(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *inputs, const uint64_t *h_clear_val,
    uint32_t num_inputs, uint32_t num_blocks,
    int_unchecked_contains_clear_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  cuda_memcpy_async_to_gpu(mem_ptr->d_clear_val, h_clear_val,
                           safe_mul_sizeof<Torus>(num_blocks),
                           streams.stream(0), streams.gpu_index(0));

  set_trivial_radix_ciphertext_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &mem_ptr->tmp_clear_val,
      mem_ptr->d_clear_val, h_clear_val, num_blocks,
      mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

  host_compute_eq_selectors_cts_vs_ct<Torus>(
      streams, mem_ptr->unpacked_selectors, inputs, &mem_ptr->tmp_clear_val,
      num_inputs, num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, &mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
      bsks, (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_is_in_clears(
    CudaStreams streams, int_unchecked_is_in_clears_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_clears, uint32_t num_blocks,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_is_in_clears_buffer<Torus>(
      streams, params, num_clears, num_blocks, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void
host_unchecked_is_in_clears(CudaStreams streams, CudaRadixCiphertextFFI *output,
                            CudaRadixCiphertextFFI const *input,
                            const uint64_t *h_cleartexts, uint32_t num_clears,
                            uint32_t num_blocks,
                            int_unchecked_is_in_clears_buffer<Torus> *mem_ptr,
                            void *const *bsks, Torus *const *ksks) {

  host_compute_eq_selectors_ct_vs_clears<Torus>(
      streams, &mem_ptr->packed_selectors, input, num_blocks, h_cleartexts,
      mem_ptr->eq_buffer, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, &mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
      bsks, (Torus **)ksks, num_clears);
}

template <typename Torus>
__host__ void host_compute_final_index_from_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct,
    CudaRadixCiphertextFFI const *packed_selectors, uint32_t num_inputs,
    uint32_t num_blocks_index,
    int_final_index_from_selectors_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, packed_selectors, num_inputs,
      mem_ptr->h_indices, packed_len, mem_ptr->possible_results_buf, bsks,
      ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_inputs,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, packed_selectors, mem_ptr->reduction_buf, bsks,
      (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_index_in_clears(
    CudaStreams streams, int_unchecked_index_in_clears_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_clears, uint32_t num_blocks,
    uint32_t num_blocks_index, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_in_clears_buffer<Torus>(
      streams, params, num_clears, num_blocks, num_blocks_index,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_index_in_clears(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *input,
    const uint64_t *h_cleartexts, uint32_t num_clears, uint32_t num_blocks,
    uint32_t num_blocks_index,
    int_unchecked_index_in_clears_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  host_compute_eq_selectors_ct_vs_clears<Torus>(
      streams, &mem_ptr->final_index_buf->packed_selectors, input, num_blocks,
      h_cleartexts, mem_ptr->eq_selectors_buf, bsks, ksks);

  host_compute_final_index_from_selectors<Torus>(
      streams, index_ct, match_ct, &mem_ptr->final_index_buf->packed_selectors,
      num_clears, num_blocks_index, mem_ptr->final_index_buf, bsks, ksks);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_first_index_in_clears(
    CudaStreams streams,
    int_unchecked_first_index_in_clears_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_unique, uint32_t num_blocks,
    uint32_t num_blocks_index, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_in_clears_buffer<Torus>(
      streams, params, num_unique, num_blocks, num_blocks_index,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_first_index_in_clears(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *input,
    const uint64_t *h_unique_values, const uint64_t *h_unique_indices,
    uint32_t num_unique, uint32_t num_blocks, uint32_t num_blocks_index,
    int_unchecked_first_index_in_clears_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  host_compute_eq_selectors_ct_vs_clears<Torus>(
      streams, &mem_ptr->packed_selectors, input, num_blocks, h_unique_values,
      mem_ptr->eq_selectors_buf, bsks, ksks);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, &mem_ptr->packed_selectors,
      num_unique, h_unique_indices, packed_len, mem_ptr->possible_results_buf,
      bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_unique,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, &mem_ptr->packed_selectors, mem_ptr->reduction_buf,
      bsks, (Torus **)ksks, num_unique);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_first_index_of_clear(
    CudaStreams streams,
    int_unchecked_first_index_of_clear_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_of_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_first_index_of_clear(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    const uint64_t *h_clear_val, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index,
    int_unchecked_first_index_of_clear_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  cuda_memcpy_async_to_gpu(mem_ptr->d_clear_val, h_clear_val,
                           safe_mul_sizeof<Torus>(num_blocks),
                           streams.stream(0), streams.gpu_index(0));

  set_trivial_radix_ciphertext_async<Torus>(
      streams.stream(0), streams.gpu_index(0), &mem_ptr->tmp_clear_val,
      mem_ptr->d_clear_val, h_clear_val, num_blocks,
      mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

  host_compute_eq_selectors_cts_vs_ct<Torus>(
      streams, mem_ptr->unpacked_selectors, inputs, &mem_ptr->tmp_clear_val,
      num_inputs, num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  for (uint32_t offset = 1; offset < num_inputs; offset <<= 1) {
    uint32_t count = num_inputs - offset;

    CudaRadixCiphertextFFI current_slice;
    as_radix_ciphertext_slice<Torus>(&current_slice, &mem_ptr->packed_selectors,
                                     offset, num_inputs);

    CudaRadixCiphertextFFI prev_slice;
    as_radix_ciphertext_slice<Torus>(&prev_slice, &mem_ptr->packed_selectors, 0,
                                     count);

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &current_slice, &current_slice, &prev_slice, bsks, ksks,
        mem_ptr->prefix_sum_lut, count, mem_ptr->params.message_modulus);
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &mem_ptr->packed_selectors, &mem_ptr->packed_selectors, bsks,
      ksks, mem_ptr->cleanup_lut, num_inputs);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, &mem_ptr->packed_selectors,
      num_inputs, (const uint64_t *)mem_ptr->h_indices, packed_len,
      mem_ptr->possible_results_buf, bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_inputs,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, &mem_ptr->packed_selectors, mem_ptr->reduction_buf,
      bsks, (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_first_index_of(
    CudaStreams streams, int_unchecked_first_index_of_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_of_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_first_index_of(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    CudaRadixCiphertextFFI const *value, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index,
    int_unchecked_first_index_of_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  host_compute_eq_selectors_cts_vs_ct<Torus>(
      streams, mem_ptr->unpacked_selectors, inputs, value, num_inputs,
      num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  for (uint32_t offset = 1; offset < num_inputs; offset <<= 1) {
    uint32_t count = num_inputs - offset;

    CudaRadixCiphertextFFI current_slice;
    as_radix_ciphertext_slice<Torus>(&current_slice, &mem_ptr->packed_selectors,
                                     offset, num_inputs);

    CudaRadixCiphertextFFI prev_slice;
    as_radix_ciphertext_slice<Torus>(&prev_slice, &mem_ptr->packed_selectors, 0,
                                     count);

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &current_slice, &current_slice, &prev_slice, bsks, ksks,
        mem_ptr->prefix_sum_lut, count, mem_ptr->params.message_modulus);
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &mem_ptr->packed_selectors, &mem_ptr->packed_selectors, bsks,
      ksks, mem_ptr->cleanup_lut, num_inputs);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, &mem_ptr->packed_selectors,
      num_inputs, (const uint64_t *)mem_ptr->h_indices, packed_len,
      mem_ptr->possible_results_buf, bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_inputs,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, &mem_ptr->packed_selectors, mem_ptr->reduction_buf,
      bsks, (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_index_of(
    CudaStreams streams, int_unchecked_index_of_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_of_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_index_of(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    CudaRadixCiphertextFFI const *value, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index,
    int_unchecked_index_of_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  host_compute_eq_selectors_cts_vs_ct<Torus>(
      streams, mem_ptr->final_index_buf->unpacked_selectors, inputs, value,
      num_inputs, num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  host_compute_final_index_from_selectors<Torus>(
      streams, index_ct, match_ct, &mem_ptr->final_index_buf->packed_selectors,
      num_inputs, num_blocks_index, mem_ptr->final_index_buf, bsks, ksks);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_index_of_clear(
    CudaStreams streams, int_unchecked_index_of_clear_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_of_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_index_of_clear(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    const uint64_t *h_clear_val, bool is_scalar_obviously_bigger,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    int_unchecked_index_of_clear_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  CudaRadixCiphertextFFI *packed_selectors =
      &mem_ptr->final_index_buf->packed_selectors;

  if (is_scalar_obviously_bigger) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), packed_selectors, 0,
        num_inputs);
  } else {
    cuda_memcpy_async_to_gpu(mem_ptr->d_clear_val, h_clear_val,
                             safe_mul_sizeof<Torus>(num_blocks),
                             streams.stream(0), streams.gpu_index(0));

    set_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &mem_ptr->tmp_clear_val,
        mem_ptr->d_clear_val, h_clear_val, num_blocks,
        mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

    host_compute_eq_selectors_cts_vs_ct<Torus>(
        streams, mem_ptr->final_index_buf->unpacked_selectors, inputs,
        &mem_ptr->tmp_clear_val, num_inputs, num_blocks,
        mem_ptr->eq_selectors_buf, bsks, ksks);
  }

  host_compute_final_index_from_selectors<Torus>(
      streams, index_ct, match_ct, packed_selectors, num_inputs,
      num_blocks_index, mem_ptr->final_index_buf, bsks, ksks);
}
