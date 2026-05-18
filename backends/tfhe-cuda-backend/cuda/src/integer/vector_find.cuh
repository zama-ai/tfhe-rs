#pragma once

#include "integer/cast.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/vector_find.h"

template <typename T>
__global__ void tree_sum_inputs_kernel(T *output, T *const *src_ptrs,
                                       uint32_t base_input, uint32_t chunk_size,
                                       uint32_t num_inputs_total,
                                       uint32_t num_blocks, uint32_t lwe_size) {
  uint32_t c = blockIdx.y;
  uint32_t j = blockIdx.x;

  uint32_t chunk_start = base_input + c * chunk_size;
  if (chunk_start >= num_inputs_total)
    return;
  uint32_t k_max = min(chunk_size, num_inputs_total - chunk_start);

  T *dst = output + ((size_t)c * num_blocks + j) * lwe_size;

  for (uint32_t tid = threadIdx.x; tid < lwe_size; tid += blockDim.x) {
    T s = 0;
    for (uint32_t kk = 0; kk < k_max; kk++) {
      const T *src = src_ptrs[chunk_start + kk] + (size_t)j * lwe_size;
      s += src[tid];
    }
    dst[tid] = s;
  }
}

// Sums consecutive chunks of input ciphertexts.
// Used to avoid multiples additions during tree reduction.
//
//                                blk 0    blk 1   ...   blk M-1
//                              ┌────────┬────────┬─────┬────────┐
//     inputs[base + 0]     =   │ b₀,₀   │ b₀,₁   │ ... │ b₀,M-1 │ ─┐
//                              ├────────┼────────┼─────┼────────┤  │
//     inputs[base + 1]     =   │ b₁,₀   │ b₁,₁   │ ... │ b₁,M-1 │  │ chunk c
//                              ├────────┼────────┼─────┼────────┤  │
//                       ...                                        │
//                              ├────────┼────────┼─────┼────────┤  │
// inputs[base + chunk-1]   =   │ bₙ,₀   │ bₙ,₁   │ ... │ bₙ,M-1 │ ─┘
//                              └───┬────┴────┬───┴─────┴────┬───┘
//                                  │ Σ       │ Σ            │ Σ
//                                  ▼         ▼              ▼
//                              ┌────────┬────────┬─────┬────────┐
//      output[chunk c]      =  │ out 0  │ out 1  │ ... │ out M-1│
//                              └────────┴────────┴─────┴────────┘
//                    (repeated for c = 0 .. num_chunks-1)
template <typename T>
__host__ void
host_tree_sum_inputs(cudaStream_t stream, uint32_t gpu_index,
                     CudaRadixCiphertextFFI *output, T *const *d_src_ptrs,
                     CudaRadixCiphertextFFI const *inputs, uint32_t base_input,
                     uint32_t chunk_size, uint32_t num_inputs_total,
                     uint32_t num_chunks, uint32_t num_blocks,
                     uint32_t message_modulus, uint32_t carry_modulus) {
  if (num_chunks == 0 || num_blocks == 0)
    return;
  if (chunk_size == 0)
    PANIC("Cuda error: chunk_size must be positive")
  if (base_input >= num_inputs_total)
    PANIC("Cuda error: base_input is out of range")
  if (output->num_radix_blocks < num_chunks * num_blocks)
    PANIC("Cuda error: output does not have enough blocks for "
          "num_chunks * num_blocks")
  uint32_t k_end =
      std::min(base_input + num_chunks * chunk_size, num_inputs_total);
  for (uint32_t k = base_input; k < k_end; k++) {
    if (inputs[k].lwe_dimension != output->lwe_dimension)
      PANIC("Cuda error: input and output lwe dimensions must match")
    if (inputs[k].num_radix_blocks < num_blocks)
      PANIC("Cuda error: an input has fewer blocks than num_blocks")
  }
  cuda_set_device(gpu_index);
  uint32_t lwe_size = output->lwe_dimension + 1;
  dim3 grid(num_blocks, num_chunks, 1);
  tree_sum_inputs_kernel<T><<<grid, 256, 0, stream>>>(
      (T *)output->ptr, d_src_ptrs, base_input, chunk_size, num_inputs_total,
      num_blocks, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t c = 0; c < num_chunks; c++) {
    uint32_t chunk_start = base_input + c * chunk_size;
    uint32_t chunk_end = std::min(chunk_start + chunk_size, num_inputs_total);
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t added_deg = 0;
      uint64_t added_noise = 0;
      for (uint32_t k = chunk_start; k < chunk_end; k++) {
        added_deg += inputs[k].degrees[j];
        added_noise += inputs[k].noise_levels[j];
      }
      output->degrees[c * num_blocks + j] = added_deg;
      output->noise_levels[c * num_blocks + j] = added_noise;
      CHECK_NOISE_LEVEL(output->noise_levels[c * num_blocks + j],
                        message_modulus, carry_modulus);
    }
  }
}

template <typename T>
__global__ void
pack_chunk_eq_pairs_kernel(T *packed_current, T *packed_value,
                           T *const *src_ptrs, T const *value_ptr,
                           uint32_t base_input, uint32_t current_chunk,
                           uint32_t num_blocks, uint32_t lwe_size) {
  uint32_t c = blockIdx.x;
  uint32_t j = blockIdx.y;
  if (c >= current_chunk)
    return;

  uint32_t dst = j * current_chunk + c;
  T *out_cur = packed_current + (size_t)dst * lwe_size;
  T *out_val = packed_value + (size_t)dst * lwe_size;

  const T *src_input = src_ptrs[base_input + c] + (size_t)j * lwe_size;
  const T *src_value = value_ptr + (size_t)j * lwe_size;

  for (uint32_t tid = threadIdx.x; tid < lwe_size; tid += blockDim.x) {
    out_cur[tid] = src_input[tid];
    out_val[tid] = src_value[tid];
  }
}

// Packs memory for batched bivariate PBS (comparing multiple inputs to 1
// target).
//
//   Buffer: packed_current (Inputs)        Buffer: packed_value (Target)
// ┌──────────────────────────────┐      ┌──────────────────────────────┐
// │ j=0: [In_0[0], In_1[0], ...] │ <--> │ j=0: [Val[0],  Val[0],  ...] │
// ├──────────────────────────────┤      ├──────────────────────────────┤
// │ j=1: [In_0[1], In_1[1], ...] │ <--> │ j=1: [Val[1],  Val[1],  ...] │
// ├──────────────────────────────┤      ├──────────────────────────────┤
// │ ...                          │      │ ...                          │
// └──────────────────────────────┘      └──────────────────────────────┘
//
// Pair (packed_current[k], packed_value[k]) feeds one slot of a batched
// bivariate PBS that computes the block-wise equality.
//
// Used to avoid to loop with host_equality_check
template <typename T>
__host__ void host_pack_chunk_eq_pairs(
    cudaStream_t stream, uint32_t gpu_index,
    CudaRadixCiphertextFFI *packed_current,
    CudaRadixCiphertextFFI *packed_value, T *const *d_src_ptrs,
    CudaRadixCiphertextFFI const *inputs, CudaRadixCiphertextFFI const *value,
    uint32_t base_input, uint32_t current_chunk, uint32_t num_blocks) {
  if (current_chunk == 0 || num_blocks == 0)
    return;
  if (packed_current->lwe_dimension != value->lwe_dimension ||
      packed_value->lwe_dimension != value->lwe_dimension)
    PANIC("Cuda error: packed buffers and value must share the same "
          "lwe_dimension")
  if (packed_current->num_radix_blocks < current_chunk * num_blocks ||
      packed_value->num_radix_blocks < current_chunk * num_blocks)
    PANIC("Cuda error: packed buffers do not have enough blocks for "
          "current_chunk * num_blocks")
  if (value->num_radix_blocks < num_blocks)
    PANIC("Cuda error: value does not have enough blocks")
  for (uint32_t c = 0; c < current_chunk; c++) {
    if (inputs[base_input + c].lwe_dimension != value->lwe_dimension)
      PANIC("Cuda error: input and value lwe dimensions must match")
    if (inputs[base_input + c].num_radix_blocks < num_blocks)
      PANIC("Cuda error: an input has fewer blocks than num_blocks")
  }
  cuda_set_device(gpu_index);
  uint32_t lwe_size = packed_current->lwe_dimension + 1;
  dim3 grid(current_chunk, num_blocks, 1);
  pack_chunk_eq_pairs_kernel<T><<<grid, 256, 0, stream>>>(
      (T *)packed_current->ptr, (T *)packed_value->ptr, d_src_ptrs,
      (T const *)value->ptr, base_input, current_chunk, num_blocks, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t j = 0; j < num_blocks; j++) {
    for (uint32_t c = 0; c < current_chunk; c++) {
      uint32_t dst = j * current_chunk + c;
      packed_current->degrees[dst] = inputs[base_input + c].degrees[j];
      packed_current->noise_levels[dst] =
          inputs[base_input + c].noise_levels[j];
      packed_value->degrees[dst] = value->degrees[j];
      packed_value->noise_levels[dst] = value->noise_levels[j];
    }
  }
}

template <typename T>
__global__ void tree_sum_step_kernel(T *dst, T const *src, uint32_t chunk_size,
                                     uint32_t num_pending, uint32_t num_blocks,
                                     uint32_t lwe_size) {
  uint32_t g = blockIdx.y;
  uint32_t j = blockIdx.x;

  uint32_t r_start = g * chunk_size;
  if (r_start >= num_pending)
    return;
  uint32_t r_end = min(r_start + chunk_size, num_pending);

  T *out = dst + ((size_t)g * num_blocks + j) * lwe_size;

  for (uint32_t tid = threadIdx.x; tid < lwe_size; tid += blockDim.x) {
    T s = 0;
    for (uint32_t r = r_start; r < r_end; r++) {
      const T *in = src + ((size_t)r * num_blocks + j) * lwe_size;
      s += in[tid];
    }
    out[tid] = s;
  }
}

// Sums chunks of rows into a single row.
// Used to avoid multiples additions during tree reduction.
template <typename T>
__host__ void host_tree_sum_step(cudaStream_t stream, uint32_t gpu_index,
                                 CudaRadixCiphertextFFI *dst,
                                 CudaRadixCiphertextFFI const *src,
                                 uint32_t chunk_size, uint32_t num_pending,
                                 uint32_t num_groups, uint32_t num_blocks,
                                 uint32_t message_modulus,
                                 uint32_t carry_modulus) {
  if (num_groups == 0 || num_blocks == 0)
    return;
  if (chunk_size == 0)
    PANIC("Cuda error: chunk_size must be positive")
  if (dst->lwe_dimension != src->lwe_dimension)
    PANIC("Cuda error: dst and src lwe dimensions must match")
  if (src->num_radix_blocks < num_pending * num_blocks)
    PANIC("Cuda error: src does not have enough blocks for "
          "num_pending * num_blocks")
  if (dst->num_radix_blocks < num_groups * num_blocks)
    PANIC("Cuda error: dst does not have enough blocks for "
          "num_groups * num_blocks")
  cuda_set_device(gpu_index);
  uint32_t lwe_size = dst->lwe_dimension + 1;
  dim3 grid(num_blocks, num_groups, 1);
  tree_sum_step_kernel<T>
      <<<grid, 256, 0, stream>>>((T *)dst->ptr, (T const *)src->ptr, chunk_size,
                                 num_pending, num_blocks, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t g = 0; g < num_groups; g++) {
    uint32_t r_start = g * chunk_size;
    uint32_t r_end = std::min(r_start + chunk_size, num_pending);
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t added_deg = 0;
      uint64_t added_noise = 0;
      for (uint32_t r = r_start; r < r_end; r++) {
        added_deg += src->degrees[r * num_blocks + j];
        added_noise += src->noise_levels[r * num_blocks + j];
      }
      dst->degrees[g * num_blocks + j] = added_deg;
      dst->noise_levels[g * num_blocks + j] = added_noise;
      CHECK_NOISE_LEVEL(dst->noise_levels[g * num_blocks + j], message_modulus,
                        carry_modulus);
    }
  }
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

// Dispatches blocks from a flat batched src to multiple output ciphertexts.
// used to replace multiples copies
template <typename Torus>
__host__ void host_scatter_to_ptr_array(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *dst_list,
    Torus *const *d_dst_ptrs, CudaRadixCiphertextFFI const *src,
    const uint32_t *d_src_offsets, const uint32_t *h_src_offsets,
    uint32_t num_outputs, uint32_t num_blocks) {
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

template <typename T>
__global__ void
n_ary_blockwise_addition(T *output, T const *input_base, uint32_t row_offset,
                         uint32_t row_count, uint32_t num_columns,
                         uint32_t lwe_size, uint32_t num_entries) {
  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    uint32_t col = index / lwe_size;
    uint32_t lane = index - col * lwe_size;
    T s = output[index];
    for (uint32_t r = 0; r < row_count; r++) {
      size_t src_idx =
          ((size_t)(row_offset + r) * num_columns + col) * lwe_size + lane;
      s += input_base[src_idx];
    }
    output[index] = s;
  }
}

// N-ary blockwise addition into an existing accumulator.
//
//                                      col 0    col 1   ...   col M-1
//                                    ┌────────┬────────┬─────┬────────┐
//                 in_{row_offset} =  │ b₀,₀   │ b₀,₁   │ ... │ b₀,M-1 │
//                                    ├────────┼────────┼─────┼────────┤
//             in_{row_offset + 1} =  │ b₁,₀   │ b₁,₁   │ ... │ b₁,M-1 │
//                                    ├────────┼────────┼─────┼────────┤
//                              ...   │  ...   │  ...   │     │  ...   │
//                                    ├────────┼────────┼─────┼────────┤
// in_{row_offset + row_count - 1} =  │ bₙ,₀   │ bₙ,₁   │ ... │ bₙ,M-1 │
//                                    └───┬────┴───┬────┴─────┴───┬────┘
//                                        │ Σ      │ Σ            │ Σ
//                                        ▼        ▼              ▼
//                                    ┌────────┬────────┬─────┬────────┐
//                          OUTPUT += │ out 0  │ out 1  │ ... │ out M-1│
//                                    └────────┴────────┴─────┴────────┘
template <typename T>
__host__ void host_n_ary_blockwise_addition(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input, uint32_t row_offset,
    uint32_t row_count, uint32_t num_columns, const uint32_t message_modulus,
    const uint32_t carry_modulus) {
  if (output->lwe_dimension != input->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions must be the same")
  if (output->num_radix_blocks < num_columns)
    PANIC("Cuda error: output must have at least num_columns blocks")
  if (input->num_radix_blocks < (row_offset + row_count) * num_columns)
    PANIC("Cuda error: input does not have enough blocks for the requested "
          "window")
  if (row_count > (message_modulus * carry_modulus - 1) / (message_modulus - 1))
    PANIC("Cuda error: row_count exceeds max_degree")

  cuda_set_device(gpu_index);
  int lwe_size = output->lwe_dimension + 1;
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_columns * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  n_ary_blockwise_addition<T><<<grid, thds, 0, stream>>>(
      static_cast<T *>(output->ptr), static_cast<const T *>(input->ptr),
      row_offset, row_count, num_columns, lwe_size, num_entries);
  check_cuda_error(cudaGetLastError());

  for (uint c = 0; c < num_columns; c++) {
    uint64_t added_deg = 0;
    uint64_t added_noise = 0;
    for (uint r = 0; r < row_count; r++) {
      uint32_t src_block = (row_offset + r) * num_columns + c;
      added_deg += input->degrees[src_block];
      added_noise += input->noise_levels[src_block];
    }
    output->degrees[c] += added_deg;
    output->noise_levels[c] += added_noise;
    CHECK_NOISE_LEVEL(output->noise_levels[c], message_modulus, carry_modulus);
  }
}

// and-reduce each row of an num_inputs * num_blocks selector matrix into 1 bit
// per row
template <typename Torus>
__host__ void host_and_reduce_selector_matrix(
    CudaStreams streams, CudaRadixCiphertextFFI *accumulator,
    CudaRadixCiphertextFFI const *selectors, int_radix_lut<Torus> **luts_eq,
    uint32_t num_columns, uint32_t num_blocks, uint32_t max_degree,
    uint32_t message_modulus, uint32_t carry_modulus, void *const *bsks,
    Torus *const *ksks) {

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

    host_n_ary_blockwise_addition<Torus>(
        streams.stream(0), streams.gpu_index(0), &acc_slice, selectors, row,
        take, num_columns, message_modulus, carry_modulus);

    if (items_in_acc >= 2) {
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, &acc_slice, &acc_slice, bsks, ksks, luts_eq[items_in_acc],
          num_columns);
    }
  }
}

// 1 ciphertext is compared to N clear values
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
  uint32_t max_degree = mem_ptr->max_degree;

  // For every input block, precompute all possible equality results using a
  // single batched PBS: one block in, message_modulus blocks out (one per
  // candidate digit).
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);

  // For each (candidate i, block j) pair, store the index inside the
  // many-LUT output that corresponds to the precomputed equality result
  // (x_j == h_decomposed_cleartexts[i][j])
  Torus *h_map = mem_ptr->h_map;
  uint32_t total_blocks = num_possible_values * num_blocks;
  for (uint32_t j = 0; j < num_blocks; j++) {
    for (uint32_t i = 0; i < num_possible_values; i++) {
      uint64_t block_value = h_decomposed_cleartexts[i * num_blocks + j];
      if (block_value >= message_modulus)
        PANIC("Cuda error: block value in compute_equality_selectors exceeds "
              "message modulus");
      h_map[j * num_possible_values + i] = (Torus)block_value * num_blocks + j;
    }
  }
  cuda_memcpy_async_to_gpu(mem_ptr->d_map, h_map,
                           safe_mul_sizeof<Torus>(total_blocks),
                           streams.stream(0), streams.gpu_index(0));

  uint32_t lwe_size = mem_ptr->tmp_batched_comparisons->lwe_dimension + 1;
  align_with_indexes<Torus><<<total_blocks, 256, 0, streams.stream(0)>>>(
      (Torus *)mem_ptr->tmp_batched_comparisons->ptr,
      (Torus *)mem_ptr->tmp_many_luts_output->ptr, mem_ptr->d_map, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t b = 0; b < total_blocks; b++) {
    mem_ptr->tmp_batched_comparisons->degrees[b] = 1;
    mem_ptr->tmp_batched_comparisons->noise_levels[b] = NoiseLevel::NOMINAL;
  }

  host_and_reduce_selector_matrix<Torus>(
      streams, mem_ptr->packed_accumulator, mem_ptr->tmp_batched_comparisons,
      mem_ptr->luts_eq, num_possible_values, num_blocks, max_degree,
      message_modulus, carry_modulus, bsks, ksks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 0,
      num_possible_values, mem_ptr->packed_accumulator, 0, num_possible_values);
}

// N ciphertexts are compared to 1 encrypted value
template <typename Torus>
__host__ void host_compute_eq_selectors_cts_vs_ct(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *inputs, CudaRadixCiphertextFFI const *value,
    uint32_t num_inputs, uint32_t num_blocks,
    int_eq_selectors_cts_vs_ct_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  uint32_t message_modulus = mem_ptr->params.message_modulus;
  uint32_t carry_modulus = mem_ptr->params.carry_modulus;
  uint32_t max_degree = mem_ptr->max_degree;
  uint32_t chunk_size = mem_ptr->chunk_size;

  for (uint32_t k = 0; k < num_inputs; k++) {
    mem_ptr->h_input_ptrs[k] = (Torus *)inputs[k].ptr;
  }
  cuda_memcpy_async_to_gpu(mem_ptr->d_input_ptrs, mem_ptr->h_input_ptrs,
                           safe_mul_sizeof<Torus *>(num_inputs),
                           streams.stream(0), streams.gpu_index(0));

  for (uint32_t base = 0; base < num_inputs; base += chunk_size) {
    uint32_t current_chunk = std::min(chunk_size, num_inputs - base);

    host_pack_chunk_eq_pairs<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->packed_current_block,
        mem_ptr->packed_value_block, mem_ptr->d_input_ptrs, inputs, value, base,
        current_chunk, num_blocks);

    uint32_t total = current_chunk * num_blocks;
    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, mem_ptr->packed_current_block, mem_ptr->packed_current_block,
        mem_ptr->packed_value_block, bsks, ksks, mem_ptr->equality_lut, total,
        message_modulus);

    host_and_reduce_selector_matrix<Torus>(
        streams, mem_ptr->packed_accumulator, mem_ptr->packed_current_block,
        mem_ptr->luts_eq, current_chunk, num_blocks, max_degree,
        message_modulus, carry_modulus, bsks, ksks);

    for (uint32_t c = 0; c < current_chunk; c++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &lwe_array_out_list[base + c], 0, 1, mem_ptr->packed_accumulator, c,
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
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
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
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_batched_selectors,
        k * num_possible_values, (k + 1) * num_possible_values,
        batched_selectors, 0, num_possible_values);
  }

  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_many_luts_output, mem_ptr->tmp_batched_selectors,
      bsks, (Torus *const *)ksks, mem_ptr->batched_accumulators_lut,
      max_luts_per_call, mem_ptr->lut_stride);

  Torus **h_dst_ptrs = mem_ptr->h_dst_ptrs;
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

      auto k = static_cast<uint32_t>(packed_block_value / max_luts_per_call);
      auto lut_in_acc =
          static_cast<uint32_t>(packed_block_value % max_luts_per_call);
      h_src_idx[i * num_blocks + j] =
          lut_in_acc * total_lut_inputs + k * num_possible_values + i;
    }
  }

  cuda_memcpy_async_to_gpu(mem_ptr->d_dst_ptrs, h_dst_ptrs,
                           safe_mul_sizeof<Torus *>(num_possible_values),
                           streams.stream(0), streams.gpu_index(0));
  cuda_memcpy_async_to_gpu(
      mem_ptr->d_src_idx, h_src_idx,
      safe_mul_sizeof<uint32_t>(num_possible_values * num_blocks),
      streams.stream(0), streams.gpu_index(0));

  host_scatter_to_ptr_array<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_list,
      mem_ptr->d_dst_ptrs, mem_ptr->tmp_many_luts_output, mem_ptr->d_src_idx,
      h_src_idx, num_possible_values, num_blocks);
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

template <typename Torus>
__host__ void host_aggregate_one_hot_vector(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_list,
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

  CudaRadixCiphertextFFI *src_buf = mem_ptr->packed_partial_temp_vectors;
  CudaRadixCiphertextFFI *dst_buf = mem_ptr->tree_reduction_buf;

  for (uint32_t k = 0; k < num_input_ciphertexts; k++) {
    mem_ptr->h_input_ptrs[k] = (Torus *)lwe_array_in_list[k].ptr;
  }
  cuda_memcpy_async_to_gpu(mem_ptr->d_input_ptrs, mem_ptr->h_input_ptrs,
                           safe_mul_sizeof<Torus *>(num_input_ciphertexts),
                           streams.stream(0), streams.gpu_index(0));

  host_tree_sum_inputs<Torus>(streams.stream(0), streams.gpu_index(0), src_buf,
                              mem_ptr->d_input_ptrs, lwe_array_in_list, 0u,
                              chunk_size, num_input_ciphertexts, num_chunks,
                              num_blocks, message_modulus, carry_modulus);

  CudaRadixCiphertextFFI partials_slice;
  as_radix_ciphertext_slice<Torus>(&partials_slice, src_buf, 0,
                                   num_chunks * num_blocks);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &partials_slice, &partials_slice, bsks, ksks,
      mem_ptr->batched_identity_lut, num_chunks * num_blocks);

  uint32_t num_pending = num_chunks;
  while (num_pending > 1) {
    uint32_t groups = CEIL_DIV(num_pending, chunk_size);

    host_tree_sum_step<Torus>(streams.stream(0), streams.gpu_index(0), dst_buf,
                              src_buf, chunk_size, num_pending, groups,
                              num_blocks, message_modulus, carry_modulus);

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

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->message_ct, &final_agg, bsks, ksks,
      mem_ptr->message_extract_lut, num_blocks);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->carry_ct, &final_agg, bsks, ksks,
      mem_ptr->carry_extract_lut, num_blocks);

  for (uint32_t index = 0; index < num_blocks; index++) {
    if (2 * index < lwe_array_out->num_radix_blocks) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index,
          2 * index + 1, mem_ptr->message_ct, index, index + 1);
    }
    if (2 * index + 1 < lwe_array_out->num_radix_blocks) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index + 1,
          2 * index + 2, mem_ptr->carry_ct, index, index + 1);
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

  host_compute_eq_selectors_ct_vs_clears<Torus>(
      streams, mem_ptr->packed_selectors_ct, lwe_array_in_ct,
      mem_ptr->num_input_blocks, h_match_inputs, mem_ptr->eq_selectors_buffer,
      bsks, ksks);

  if (!mem_ptr->max_output_is_zero) {
    host_create_possible_results<Torus>(
        streams, mem_ptr->possible_results_list, mem_ptr->packed_selectors_ct,
        mem_ptr->num_matches, h_match_outputs,
        mem_ptr->num_output_packed_blocks, mem_ptr->possible_results_buffer,
        bsks, ksks);
  }

  if (mem_ptr->max_output_is_zero) {
    host_integer_is_at_least_one_comparisons_block_true<Torus>(
        streams, lwe_array_out_boolean, mem_ptr->packed_selectors_ct,
        mem_ptr->at_least_one_true_buffer, bsks, (Torus **)ksks,
        mem_ptr->num_matches);
    return;
  }

  host_aggregate_one_hot_vector<Torus>(
      streams, lwe_array_out_result, mem_ptr->possible_results_list,
      mem_ptr->num_matches, mem_ptr->num_output_packed_blocks,
      mem_ptr->aggregate_buffer, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_array_out_boolean, mem_ptr->packed_selectors_ct,
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

  host_unchecked_match_value<Torus>(streams, mem_ptr->tmp_match_result,
                                    mem_ptr->tmp_match_bool, lwe_array_in_ct,
                                    h_match_inputs, h_match_outputs,
                                    mem_ptr->match_buffer, bsks, ksks);

  cuda_memcpy_async_to_gpu(mem_ptr->d_or_value, h_or_value,
                           safe_mul_sizeof<Torus>(mem_ptr->num_final_blocks),
                           streams.stream(0), streams.gpu_index(0));

  set_trivial_radix_ciphertext_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_or_value,
      mem_ptr->d_or_value, (Torus *)h_or_value, mem_ptr->num_final_blocks,
      mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

  host_cmux<Torus>(streams, lwe_array_out, mem_ptr->tmp_match_bool,
                   mem_ptr->tmp_match_result, mem_ptr->tmp_or_value,
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
      streams, output, mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
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
      streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_clear_val,
      mem_ptr->d_clear_val, (Torus *)h_clear_val, num_blocks,
      mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

  host_compute_eq_selectors_cts_vs_ct<Torus>(
      streams, mem_ptr->unpacked_selectors, inputs, mem_ptr->tmp_clear_val,
      num_inputs, num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
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
      streams, mem_ptr->packed_selectors, input, num_blocks, h_cleartexts,
      mem_ptr->eq_buffer, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
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
uint64_t scratch_cuda_compute_final_index_from_selectors(
    CudaStreams streams, int_final_index_from_selectors_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks_index,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_final_index_from_selectors_buffer<Torus>(
      streams, params, num_inputs, num_blocks_index, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
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
      streams, mem_ptr->final_index_buf->packed_selectors, input, num_blocks,
      h_cleartexts, mem_ptr->eq_selectors_buf, bsks, ksks);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->final_index_buf->possible_results_ct_list,
      mem_ptr->final_index_buf->packed_selectors, num_clears,
      mem_ptr->final_index_buf->h_indices, packed_len,
      mem_ptr->final_index_buf->possible_results_buf, bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->final_index_buf->possible_results_ct_list,
      num_clears, packed_len, mem_ptr->final_index_buf->aggregate_buf, bsks,
      ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->final_index_buf->packed_selectors,
      mem_ptr->final_index_buf->reduction_buf, bsks, (Torus **)ksks,
      num_clears);
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
      streams, mem_ptr->packed_selectors, input, num_blocks, h_unique_values,
      mem_ptr->eq_selectors_buf, bsks, ksks);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, mem_ptr->packed_selectors,
      num_unique, h_unique_indices, packed_len, mem_ptr->possible_results_buf,
      bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_unique,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->packed_selectors, mem_ptr->reduction_buf,
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
      streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_clear_val,
      mem_ptr->d_clear_val, (Torus *)h_clear_val, num_blocks,
      mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

  host_compute_eq_selectors_cts_vs_ct<Torus>(
      streams, mem_ptr->unpacked_selectors, inputs, mem_ptr->tmp_clear_val,
      num_inputs, num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  for (uint32_t offset = 1; offset < num_inputs; offset <<= 1) {
    uint32_t count = num_inputs - offset;

    CudaRadixCiphertextFFI current_slice;
    as_radix_ciphertext_slice<Torus>(&current_slice, mem_ptr->packed_selectors,
                                     offset, num_inputs);

    CudaRadixCiphertextFFI prev_slice;
    as_radix_ciphertext_slice<Torus>(&prev_slice, mem_ptr->packed_selectors, 0,
                                     count);

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &current_slice, &current_slice, &prev_slice, bsks, ksks,
        mem_ptr->prefix_sum_lut, count, mem_ptr->params.message_modulus);
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->packed_selectors, mem_ptr->packed_selectors, bsks, ksks,
      mem_ptr->cleanup_lut, num_inputs);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, mem_ptr->packed_selectors,
      num_inputs, (const uint64_t *)mem_ptr->h_indices, packed_len,
      mem_ptr->possible_results_buf, bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_inputs,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->packed_selectors, mem_ptr->reduction_buf,
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
    as_radix_ciphertext_slice<Torus>(&current_slice, mem_ptr->packed_selectors,
                                     offset, num_inputs);

    CudaRadixCiphertextFFI prev_slice;
    as_radix_ciphertext_slice<Torus>(&prev_slice, mem_ptr->packed_selectors, 0,
                                     count);

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &current_slice, &current_slice, &prev_slice, bsks, ksks,
        mem_ptr->prefix_sum_lut, count, mem_ptr->params.message_modulus);
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->packed_selectors, mem_ptr->packed_selectors, bsks, ksks,
      mem_ptr->cleanup_lut, num_inputs);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, mem_ptr->packed_selectors,
      num_inputs, (const uint64_t *)mem_ptr->h_indices, packed_len,
      mem_ptr->possible_results_buf, bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_inputs,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->packed_selectors, mem_ptr->reduction_buf,
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

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->final_index_buf->possible_results_ct_list,
      mem_ptr->final_index_buf->packed_selectors, num_inputs,
      (const uint64_t *)mem_ptr->final_index_buf->h_indices, packed_len,
      mem_ptr->final_index_buf->possible_results_buf, bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->final_index_buf->possible_results_ct_list,
      num_inputs, packed_len, mem_ptr->final_index_buf->aggregate_buf, bsks,
      ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->final_index_buf->packed_selectors,
      mem_ptr->final_index_buf->reduction_buf, bsks, (Torus **)ksks,
      num_inputs);
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
      mem_ptr->final_index_buf->packed_selectors;

  if (is_scalar_obviously_bigger) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), packed_selectors, 0,
        num_inputs);
  } else {
    cuda_memcpy_async_to_gpu(mem_ptr->d_clear_val, h_clear_val,
                             safe_mul_sizeof<Torus>(num_blocks),
                             streams.stream(0), streams.gpu_index(0));

    set_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_clear_val,
        mem_ptr->d_clear_val, (Torus *)h_clear_val, num_blocks,
        mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);

    host_compute_eq_selectors_cts_vs_ct<Torus>(
        streams, mem_ptr->final_index_buf->unpacked_selectors, inputs,
        mem_ptr->tmp_clear_val, num_inputs, num_blocks,
        mem_ptr->eq_selectors_buf, bsks, ksks);
  }

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->final_index_buf->possible_results_ct_list,
      mem_ptr->final_index_buf->packed_selectors, num_inputs,
      (const uint64_t *)mem_ptr->final_index_buf->h_indices, packed_len,
      mem_ptr->final_index_buf->possible_results_buf, bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->final_index_buf->possible_results_ct_list,
      num_inputs, packed_len, mem_ptr->final_index_buf->aggregate_buf, bsks,
      ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, packed_selectors,
      mem_ptr->final_index_buf->reduction_buf, bsks, (Torus **)ksks,
      num_inputs);
}
