#pragma once

#include "integer/cast.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/vector_find.h"

/**
 * @brief Packs a chunk of input ciphertexts and the searched value into the
 * paired layout consumed by the batched bivariate equality PBS.
 * Launched with gridDim.x == current_chunk_size and gridDim.y == num_blocks.
 *
 * @tparam T Word type of the LWE coefficients (torus element, usually
 * uint64_t).
 * @param packed_current Receives each input's blocks, the first operand of the
 * bivariate equality PBS.
 * @param packed_value Receives the target's blocks duplicated once per input,
 * the second PBS operand.
 * @param src_ptrs Per-input device pointers to the ciphertexts being searched.
 * @param value_ptr The single target ciphertext compared against every input.
 * @param input_offset Index of this chunk's first input within the full list.
 * @param current_chunk_size Number of inputs packed by this launch (grid.x).
 * @param num_blocks Radix-block width of the operands (grid.y, e.g. a u64 in
 * 2_2 params -> 32 blocks).
 * @param lwe_size Coefficients per LWE block (lwe_dimension + 1), copy stride.
 */
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

/**
 * @brief Formats memory for a batched bivariate PBS comparing N ciphertexts to
 * a single target value.
 *
 * Memory layout:
 *   inputs (chunk) : [ In 0 ] [ In 1 ] ... [ In N ]
 *   value          : [ Target ]
 * Result:
 *   packed_current : [ In 0 ]   [ In 1 ]   ... [ In N ]
 *   packed_value   : [ Target ] [ Target ] ... [ Target ]
 *
 * @tparam T Word type of the LWE coefficients (torus element, usually
 * uint64_t).
 * @param packed_current Output buffer of the N input ciphertexts.
 * @param packed_value Output buffer of the target value duplicated N times.
 * @param d_src_ptrs Device pointers to the inputs.
 * @param inputs Input ciphertexts (used for metadata).
 * @param value Single target ciphertext.
 * @param input_offset Starting index in the inputs array.
 * @param current_chunk_size Number of ciphertexts in this chunk.
 * @param num_blocks Radix-block width of the operands (e.g. a u64 in 2_2 params
 * -> 32 blocks).
 */
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

/**
 * @brief Scatters block-wise LWEs from a contiguous batched buffer into a list
 * of independently allocated destination ciphertexts.
 *
 * @param dst_ptr_array Per-output device pointers, receives the de-batched
 * blocks.
 * @param src_batched Contiguous buffer holding every output's blocks back to
 * back.
 * @param num_blocks Radix-block width of each output ciphertext.
 * @param src_offsets Per-block source index, letting outputs be reordered while
 * scattering.
 * @param lwe_size Coefficients per LWE block (lwe_dimension + 1), copy stride.
 */
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

/**
 * @brief Copies radix ciphertexts from a contiguous batched buffer to a list of
 * independently allocated radix ciphertexts.
 *
 * @details
 * Inverse operation of align_with_indexes. src holds num_outputs * num_blocks
 * blocks, and d_src_offsets says, for each destination block, which src
 * position to pull (e.g. num_outputs = 2, num_blocks = 2):
 *   d_src_offsets : [ 2, 0, 3, 1 ]   one entry per destination block
 *   src           : [ A ] [ B ] [ C ] [ D ]   positions 0  1  2  3
 *   dst_ptrs[0]   : [ C ] [ A ]   <- src positions [2, 0]
 *   dst_ptrs[1]   : [ D ] [ B ]   <- src positions [3, 1]
 *
 * @param dst_list CPU-side list of independently allocated ciphertexts.
 * @param d_dst_ptrs Device copy of the destination LWE-array pointer list.
 * @param src Source ciphertext of num_outputs * num_blocks blocks.
 * @param d_src_offsets Device offsets: output k is set to src[offsets[k]].
 * @param h_src_offsets Host copy of the offsets, used for noise tracking.
 * @param num_outputs Number of input and output radix ciphertexts.
 * @param num_blocks Radix-block width of each output ciphertext.
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

/**
 * @brief AND-reduces a block-wise equality matrix across its rows.
 *
 * The selectors are treated as a flat 2D matrix of shape (num_blocks rows) x
 * (num_columns columns), each column is a candidate/input and each row a radix
 * block. Rows are summed column-by-column and a LUT checks if the sum
 * equals the block count, yielding a per-column boolean (full multi-block
 * equality) in the accumulator.
 *
 * @param accumulator Output 1D vector of num_columns single-block booleans.
 * @param selectors Input flat equality matrix.
 * @param luts_eq Per-degree equality LUTs indexed by packing degree.
 * @param num_luts_needed Number of usable entries in luts_eq.
 * @param num_columns Number of candidates/inputs (matrix columns).
 * @param num_blocks Block width of each value (matrix rows).
 * @param max_degree Maximum number of blocks packable into one LUT input.
 */
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

/**
 * @brief Computes a boolean indicator vector marking if the input
 * radix ciphertext equals each of a list of clear scalars.
 *
 * @param lwe_array_out_packed Flat list of booleans: 1 where lwe_array_in
 * equals the corresponding clear value, 0 otherwise.
 * @param lwe_array_in Input ciphertext matched against each clear value.
 * @param h_decomposed_cleartexts Host flat array of decomposed clear values.
 * @param num_blocks Radix-block width of the input, and of each decomposed
 * clear value (e.g. a u64 in 2_2 params -> 32 blocks).
 */
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

  // For every block in the input radix ciphertext lwe_array_in, precompute
  // indicators of equality to all possible values of the block
  // (0..2**(message_modulus+carry_modulus)-1).
  // Using only num_blocks multi-variate PBS an indicator matrix is produced
  // where columns are one-hot vectors indicating the active value in the input
  // block.
  // The indicator matrix can be used to assess equality for ALL the clear
  // values to be matched
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, &mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);

  // Equality between the input radix-ciphertext and each decomposed clear value
  // is determined by inspecting the indicator matrix cells corresponding to the
  // decomposed clear value.
  // E.g. for clear value = 20, the decomposed clear value with 2_2 params is
  // [1, 1, 0]. Thus we extract the cells [indicator_matrix[0,1],
  // indicator_matrix[1,1], indicator_matrix[2,0]]. If all these cells are 1
  // then the input radix-ciphertext matched this clear value.
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

  // Extract the indicator booleans for each clear value to be matched and group
  // them in a flat contiguous 2d array of LWE in order, so that each column
  // contains the booleans corresponding to a single clear value. The 2d array
  // is of size num_blocks (rows) x num_clear_values (cols)
  uint32_t lwe_size = mem_ptr->tmp_batched_comparisons.lwe_dimension + 1;
  align_with_indexes<Torus><<<total_blocks, 256, 0, streams.stream(0)>>>(
      (Torus *)mem_ptr->tmp_batched_comparisons.ptr,
      (Torus *)mem_ptr->tmp_many_luts_output.ptr, mem_ptr->d_map, lwe_size);
  check_cuda_error(cudaGetLastError());

  // Reset the noise levels since this buffer can be reused and noise is checked
  // at the start of PBS
  for (uint32_t b = 0; b < total_blocks; b++) {
    mem_ptr->tmp_batched_comparisons.degrees[b] = 1;
    mem_ptr->tmp_batched_comparisons.noise_levels[b] = NoiseLevel::NOMINAL;
  }

  // And-reduce by rows the indicator 2d array. This produces a 1d vector of
  // booleans, each indicating if the input matches one of the clear values
  host_and_reduce_selector_matrix<Torus>(
      streams, &mem_ptr->packed_accumulator, &mem_ptr->tmp_batched_comparisons,
      mem_ptr->luts_eq, mem_ptr->num_luts_needed, num_possible_values,
      num_blocks, max_degree, message_modulus, carry_modulus, bsks, ksks);

  // Place the output booleans into the output LWE list
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 0,
      num_possible_values, &mem_ptr->packed_accumulator, 0,
      num_possible_values);
}

/**
 * @brief Computes a boolean indicator vector marking if each input
 * radix ciphertext in a list equals the searched-for value.
 *
 * @param lwe_array_out_list Boolean list, cell i indicates if value
 * matches input i.
 * @param inputs List of radix ciphertexts to be searched.
 * @param value Radix ciphertext searched for in the list.
 * @param num_inputs Number of ciphertexts in the search list.
 * @param num_blocks Radix-block width of the operands (e.g. a u64 in 2_2 params
 * -> 32 blocks).
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
    // indicating if the block is equal to the corresponding block in the
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

/**
 * @brief Materializes the selected candidate values using the one-hot selector
 * vector.
 *
 * @details
 * A many-LUT conditionally evaluates each candidate from its selector boolean,
 * scattering the results into a sparse array where only the matched value is
 * non-zero.
 *
 * @param lwe_array_out_list Output list, one materialized value per candidate.
 * @param batched_selectors The one-hot mask selecting which candidate to emit.
 * @param num_possible_values How many candidates the mask chooses among.
 * @param h_decomposed_cleartexts Host flat array of the decomposed candidate
 * values.
 * @param num_blocks Radix-block width of each produced value.
 */
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

/**
 * @brief Fuses the sparse array of selected candidates into a single encrypted
 * result via a binary reduction tree.
 *
 * @param lwe_array_out Output ciphertext receiving the aggregated result.
 * @param lwe_array_in_list Sparse list of candidate ciphertexts to sum.
 * @param num_input_ciphertexts How many sparse candidates feed the reduction
 * tree.
 * @param num_blocks Radix-block width of each candidate summed.
 */
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

/**
 * @brief Evaluates an input against a set of clear keys and returns the
 * corresponding clear output value.
 *
 * @param lwe_array_out_result Output ciphertext receiving the matched value.
 * @param lwe_array_out_boolean Output boolean: 1 if any case matched, else 0.
 * @param lwe_array_in_ct Encrypted input compared against the match keys.
 * @param h_match_inputs Host array of clear match keys.
 * @param h_match_outputs Host array of clear values, one per key.
 */
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

/**
 * @brief Executes a match operation with a fallback default value.
 */
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

/**
 * @brief Checks if an encrypted target is present in an encrypted list.
 *
 * @param output Output boolean: 1 if value is present in inputs, else 0.
 * @param inputs Encrypted list searched for the value.
 * @param value Encrypted needle searched for in the list.
 * @param num_inputs How many list elements we test for the needle.
 * @param num_blocks Radix-block width of the searched values (e.g. a u64 in 2_2
 * params -> 32 blocks).
 */
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

/**
 * @brief Checks if a clear target is present in an encrypted list.
 */
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

/**
 * @brief Checks if an encrypted input exists within a list of clear
 * values.
 */
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

/**
 * @brief Helper that converts a one-hot boolean selector vector into an
 * encrypted scalar index.
 */
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

/**
 * @brief Locates an encrypted target within a clear list and returns its
 * encrypted index.
 */
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

/**
 * @brief Locates the first occurrence of an encrypted target within a list of
 * clear values.
 */
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

/**
 * @brief Locates the first occurrence of a clear target within an encrypted
 * list.
 */
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

/**
 * @brief Locates the first occurrence of an encrypted target within an
 * encrypted list.
 */
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

/**
 * @brief Locates an encrypted target within an encrypted list and returns its
 * encrypted index.
 */
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

/**
 * @brief Locates a clear target within an encrypted list and returns its
 * encrypted index.
 */
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
