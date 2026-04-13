#pragma once

#include "integer/cast.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/vector_find.h"

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

template <typename Torus>
__host__ void host_compute_equality_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_packed,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_blocks,
    const uint64_t *h_decomposed_cleartexts,
    int_equality_selectors_buffer<Torus> *mem_ptr, void *const *bsks,
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

  CudaRadixCiphertextFFI col_slice;
  as_radix_ciphertext_slice<Torus>(&col_slice, mem_ptr->tmp_batched_comparisons,
                                   0, num_possible_values);
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->packed_accumulator, 0,
      num_possible_values, &col_slice, 0, num_possible_values);

  uint32_t items_in_acc = 1;
  for (uint32_t j = 1; j < num_blocks; j++) {
    as_radix_ciphertext_slice<Torus>(
        &col_slice, mem_ptr->tmp_batched_comparisons, j * num_possible_values,
        (j + 1) * num_possible_values);

    host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                         mem_ptr->packed_accumulator,
                         mem_ptr->packed_accumulator, &col_slice,
                         num_possible_values, message_modulus, carry_modulus);
    items_in_acc++;

    if (items_in_acc == max_degree || j == num_blocks - 1) {
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, mem_ptr->packed_accumulator, mem_ptr->packed_accumulator,
          bsks, ksks, mem_ptr->luts_eq[items_in_acc], num_possible_values);
      items_in_acc = 1;
    }
  }

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_out_packed, 0,
      num_possible_values, mem_ptr->packed_accumulator, 0, num_possible_values);
}

template <typename Torus>
__host__ void host_compute_equality_selectors_vs_ciphertext(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *inputs, CudaRadixCiphertextFFI const *value,
    uint32_t num_inputs, uint32_t num_blocks,
    int_equality_selectors_vs_ciphertext_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  uint32_t message_modulus = mem_ptr->params.message_modulus;
  uint32_t carry_modulus = mem_ptr->params.carry_modulus;
  uint32_t max_batch_size = mem_ptr->max_batch_size;
  uint32_t max_degree = mem_ptr->max_degree;

  for (uint32_t i = 0; i < num_inputs; i += max_batch_size) {
    uint32_t current_batch_size = std::min(max_batch_size, num_inputs - i);

    for (uint32_t c = 0; c < current_batch_size; c++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          mem_ptr->packed_current_block, c, c + 1, &inputs[i + c], 0, 1);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->packed_value_block,
          c, c + 1, value, 0, 1);
    }

    CudaRadixCiphertextFFI acc_slice, curr_slice, val_slice;
    as_radix_ciphertext_slice<Torus>(&acc_slice, mem_ptr->packed_accumulator, 0,
                                     current_batch_size);
    as_radix_ciphertext_slice<Torus>(&curr_slice, mem_ptr->packed_current_block,
                                     0, current_batch_size);
    as_radix_ciphertext_slice<Torus>(&val_slice, mem_ptr->packed_value_block, 0,
                                     current_batch_size);

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &acc_slice, &curr_slice, &val_slice, bsks, ksks,
        mem_ptr->equality_lut, current_batch_size, message_modulus);

    uint32_t items_in_acc = 1;
    for (uint32_t j = 1; j < num_blocks; j++) {
      for (uint32_t c = 0; c < current_batch_size; c++) {
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            mem_ptr->packed_current_block, c, c + 1, &inputs[i + c], j, j + 1);
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            mem_ptr->packed_value_block, c, c + 1, value, j, j + 1);
      }

      integer_radix_apply_bivariate_lookup_table<Torus>(
          streams, &curr_slice, &curr_slice, &val_slice, bsks, ksks,
          mem_ptr->equality_lut, current_batch_size, message_modulus);

      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &acc_slice,
                           &acc_slice, &curr_slice, current_batch_size,
                           message_modulus, carry_modulus);
      items_in_acc++;

      if (items_in_acc == max_degree || j == num_blocks - 1) {
        integer_radix_apply_univariate_lookup_table<Torus>(
            streams, &acc_slice, &acc_slice, bsks, ksks,
            mem_ptr->luts_eq[items_in_acc], current_batch_size);
        items_in_acc = 1;
      }
    }

    for (uint32_t c = 0; c < current_batch_size; c++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[i + c],
          0, 1, mem_ptr->packed_accumulator, c, c + 1);
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_compute_equality_selectors(
    CudaStreams streams, int_equality_selectors_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_possible_values, uint32_t num_blocks,
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_equality_selectors_buffer<Torus>(
      streams, params, num_possible_values, num_blocks, max_batch_size,
      allocate_gpu_memory, size_tracker);

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

  uint32_t lwe_size = lwe_array_out_list[0].lwe_dimension + 1;
  scatter_to_ptr_array_kernel<Torus>
      <<<num_possible_values * num_blocks, 256, 0, streams.stream(0)>>>(
          mem_ptr->d_dst_ptrs, (Torus *)mem_ptr->tmp_many_luts_output->ptr,
          num_blocks, mem_ptr->d_src_idx, lwe_size);
  check_cuda_error(cudaGetLastError());

  for (uint32_t i = 0; i < num_possible_values; i++) {
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t packed_block_value = h_decomposed_cleartexts[i * num_blocks + j];
      lwe_array_out_list[i].degrees[j] = packed_block_value;
      lwe_array_out_list[i].noise_levels[j] = NoiseLevel::NOMINAL;
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_create_possible_results(
    CudaStreams streams, int_possible_results_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks, uint32_t num_possible_values,
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_possible_results_buffer<Torus>(
      streams, params, num_blocks, num_possible_values, max_batch_size,
      allocate_gpu_memory, size_tracker);

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
  uint32_t max_batch_size = mem_ptr->max_batch_size;

  CudaRadixCiphertextFFI *final_agg = mem_ptr->final_aggregated_vector;
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), final_agg, 0, num_blocks);

  uint32_t num_chunks = CEIL_DIV(num_input_ciphertexts, chunk_size);
  uint32_t chunks_accumulated = 0;

  for (uint32_t chunk_idx = 0; chunk_idx < num_chunks;
       chunk_idx += max_batch_size) {
    uint32_t current_batch_size =
        std::min(max_batch_size, num_chunks - chunk_idx);

    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        mem_ptr->packed_partial_temp_vectors, 0, max_batch_size * num_blocks);

    for (uint32_t c = 0; c < current_batch_size; c++) {
      uint32_t current_chunk = chunk_idx + c;
      uint32_t chunk_start = current_chunk * chunk_size;
      uint32_t chunk_end =
          std::min(chunk_start + chunk_size, num_input_ciphertexts);

      CudaRadixCiphertextFFI current_temp;
      as_radix_ciphertext_slice<Torus>(&current_temp,
                                       mem_ptr->packed_partial_temp_vectors,
                                       c * num_blocks, (c + 1) * num_blocks);

      for (uint32_t k = chunk_start; k < chunk_end; k++) {
        host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                             &current_temp, &current_temp,
                             &lwe_array_in_list[k], num_blocks,
                             params.message_modulus, params.carry_modulus);
      }
    }

    CudaRadixCiphertextFFI current_packed_partial;
    as_radix_ciphertext_slice<Torus>(&current_packed_partial,
                                     mem_ptr->packed_partial_temp_vectors, 0,
                                     max_batch_size * num_blocks);

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &current_packed_partial, &current_packed_partial, bsks, ksks,
        mem_ptr->batched_identity_lut, max_batch_size * num_blocks);

    for (uint32_t c = 0; c < current_batch_size; c++) {
      CudaRadixCiphertextFFI current_temp;
      as_radix_ciphertext_slice<Torus>(&current_temp,
                                       mem_ptr->packed_partial_temp_vectors,
                                       c * num_blocks, (c + 1) * num_blocks);

      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), final_agg,
                           final_agg, &current_temp, num_blocks,
                           params.message_modulus, params.carry_modulus);

      chunks_accumulated++;
      if (chunks_accumulated >= mem_ptr->chunk_size - 1) {
        integer_radix_apply_univariate_lookup_table<Torus>(
            streams, final_agg, final_agg, bsks, ksks, mem_ptr->identity_lut,
            num_blocks);
        chunks_accumulated = 0;
      }
    }
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->message_ct, final_agg, bsks, ksks,
      mem_ptr->message_extract_lut, num_blocks);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->carry_ct, final_agg, bsks, ksks,
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
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_aggregate_one_hot_buffer<Torus>(
      streams, params, num_blocks, num_matches, max_batch_size,
      allocate_gpu_memory, size_tracker);

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

  host_compute_equality_selectors<Torus>(
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
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_match_buffer<Torus>(
      streams, params, num_matches, num_input_blocks, num_output_packed_blocks,
      max_output_is_zero, max_batch_size, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_match_value_or(
    CudaStreams streams, int_unchecked_match_value_or_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_match_packed_blocks, uint32_t num_final_blocks,
    bool max_output_is_zero, uint32_t max_batch_size,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_match_value_or_buffer<Torus>(
      streams, params, num_matches, num_input_blocks, num_match_packed_blocks,
      num_final_blocks, max_output_is_zero, max_batch_size, allocate_gpu_memory,
      size_tracker);

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
uint64_t scratch_cuda_unchecked_contains(
    CudaStreams streams, int_unchecked_contains_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_contains_buffer<Torus>(
      streams, params, num_inputs, num_blocks, max_batch_size,
      allocate_gpu_memory, size_tracker);

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

  host_compute_equality_selectors_vs_ciphertext<Torus>(
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
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_contains_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, max_batch_size,
      allocate_gpu_memory, size_tracker);

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

  host_compute_equality_selectors_vs_ciphertext<Torus>(
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
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_is_in_clears_buffer<Torus>(
      streams, params, num_clears, num_blocks, max_batch_size,
      allocate_gpu_memory, size_tracker);

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

  host_compute_equality_selectors<Torus>(streams, mem_ptr->packed_selectors,
                                         input, num_blocks, h_cleartexts,
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
    uint32_t max_batch_size, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_final_index_from_selectors_buffer<Torus>(
      streams, params, num_inputs, num_blocks_index, max_batch_size,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_index_in_clears(
    CudaStreams streams, int_unchecked_index_in_clears_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_clears, uint32_t num_blocks,
    uint32_t num_blocks_index, uint32_t max_batch_size,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_in_clears_buffer<Torus>(
      streams, params, num_clears, num_blocks, num_blocks_index, max_batch_size,
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

  host_compute_equality_selectors<Torus>(
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
    uint32_t num_blocks_index, uint32_t max_batch_size,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_in_clears_buffer<Torus>(
      streams, params, num_unique, num_blocks, num_blocks_index, max_batch_size,
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

  host_compute_equality_selectors<Torus>(streams, mem_ptr->packed_selectors,
                                         input, num_blocks, h_unique_values,
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
    uint32_t num_blocks_index, uint32_t max_batch_size,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_of_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index, max_batch_size,
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

  host_compute_equality_selectors_vs_ciphertext<Torus>(
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
    uint32_t num_blocks_index, uint32_t max_batch_size,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_of_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index, max_batch_size,
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

  host_compute_equality_selectors_vs_ciphertext<Torus>(
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
    uint32_t num_blocks_index, uint32_t max_batch_size,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_of_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index, max_batch_size,
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

  host_compute_equality_selectors_vs_ciphertext<Torus>(
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
    uint32_t num_blocks_index, uint32_t max_batch_size,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_of_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index, max_batch_size,
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

    host_compute_equality_selectors_vs_ciphertext<Torus>(
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
