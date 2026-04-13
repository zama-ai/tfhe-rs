#pragma once

#include "integer/cast.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/vector_find.h"

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
  uint32_t match_parallelism = mem_ptr->match_parallelism;
  uint32_t max_items = mem_ptr->max_items;

  // Stage 1: single batched many-LUT PBS producing, for every (block j,
  // value v), the encrypted bit "input block j == v". Layout in
  // tmp_many_luts_output: entry v * num_blocks + j.
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);

  // Stage 2: per-match AND-reduction of the `num_blocks` selected equality
  // bits, batched across `match_parallelism` matches via the additive-AND
  // pattern (sum booleans, PBS x == k, repeat).
  for (uint32_t i = 0; i < num_possible_values; i += match_parallelism) {
    uint32_t parallel_chunk =
        std::min(match_parallelism, num_possible_values - i);

    // Seed the accumulator with each match's first equality bit.
    for (uint32_t c = 0; c < parallel_chunk; c++) {
      uint32_t idx = i + c;
      uint64_t block_value = h_decomposed_cleartexts[idx * num_blocks];
      uint32_t input_start = (uint32_t)block_value * num_blocks;
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->packed_accumulator,
          c, c + 1, mem_ptr->tmp_many_luts_output, input_start,
          input_start + 1);
    }

    // Views over exactly the slots we touch. Unused slots
    // [parallel_chunk, match_parallelism) are never read nor written in this
    // iteration, so no padding is required.
    CudaRadixCiphertextFFI acc_slice, curr_slice;
    as_radix_ciphertext_slice<Torus>(&acc_slice, mem_ptr->packed_accumulator, 0,
                                     parallel_chunk);
    as_radix_ciphertext_slice<Torus>(&curr_slice, mem_ptr->packed_current_block,
                                     0, parallel_chunk);

    uint32_t items_in_acc = 1;
    for (uint32_t j = 1; j < num_blocks; j++) {
      for (uint32_t c = 0; c < parallel_chunk; c++) {
        uint32_t idx = i + c;
        uint64_t block_value = h_decomposed_cleartexts[idx * num_blocks + j];
        uint32_t input_start = (uint32_t)block_value * num_blocks + j;
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            mem_ptr->packed_current_block, c, c + 1,
            mem_ptr->tmp_many_luts_output, input_start, input_start + 1);
      }

      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &acc_slice,
                           &acc_slice, &curr_slice, parallel_chunk,
                           message_modulus, carry_modulus);
      items_in_acc++;

      // Flush carries when the next add would overflow, or on the final
      // block. PBS(x == items_in_acc) folds the sum back to a fresh boolean
      // equal to AND of all bits consumed since the last flush.
      if (items_in_acc == max_items || j == num_blocks - 1) {
        integer_radix_apply_univariate_lookup_table<Torus>(
            streams, &acc_slice, &acc_slice, bsks, ksks,
            mem_ptr->luts_eq[items_in_acc], parallel_chunk);
        items_in_acc = 1;
      }
    }

    // Distribute the per-match results to the output list.
    for (uint32_t c = 0; c < parallel_chunk; c++) {
      uint32_t idx = i + c;
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[idx], 0,
          1, mem_ptr->packed_accumulator, c, c + 1);
    }
  }
}

template <typename Torus>
__host__ void host_compute_bivariate_equality_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *inputs,
    CudaRadixCiphertextFFI const *value, uint32_t num_inputs,
    uint32_t num_blocks,
    int_bivariate_equality_selectors_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  uint32_t message_modulus = mem_ptr->params.message_modulus;
  uint32_t carry_modulus = mem_ptr->params.carry_modulus;
  uint32_t match_parallelism = mem_ptr->match_parallelism;
  uint32_t max_items = mem_ptr->max_items;

  for (uint32_t i = 0; i < num_inputs; i += match_parallelism) {
    uint32_t parallel_chunk =
        std::min(match_parallelism, num_inputs - i);

    for (uint32_t c = 0; c < parallel_chunk; c++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->packed_current_block,
          c, c + 1, &inputs[i + c], 0, 1);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->packed_value_block,
          c, c + 1, value, 0, 1);
    }

    CudaRadixCiphertextFFI acc_slice, curr_slice, val_slice;
    as_radix_ciphertext_slice<Torus>(&acc_slice, mem_ptr->packed_accumulator, 0,
                                     parallel_chunk);
    as_radix_ciphertext_slice<Torus>(&curr_slice, mem_ptr->packed_current_block,
                                     0, parallel_chunk);
    as_radix_ciphertext_slice<Torus>(&val_slice, mem_ptr->packed_value_block, 0,
                                     parallel_chunk);

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, &acc_slice, &curr_slice, &val_slice, bsks, ksks,
        mem_ptr->equality_lut, parallel_chunk, message_modulus);

    uint32_t items_in_acc = 1;
    for (uint32_t j = 1; j < num_blocks; j++) {
      for (uint32_t c = 0; c < parallel_chunk; c++) {
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            mem_ptr->packed_current_block, c, c + 1, &inputs[i + c], j, j + 1);
        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            mem_ptr->packed_value_block, c, c + 1, value, j, j + 1);
      }

      integer_radix_apply_bivariate_lookup_table<Torus>(
          streams, &curr_slice, &curr_slice, &val_slice, bsks, ksks,
          mem_ptr->equality_lut, parallel_chunk, message_modulus);

      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &acc_slice,
                           &acc_slice, &curr_slice, parallel_chunk,
                           message_modulus, carry_modulus);
      items_in_acc++;

      if (items_in_acc == max_items || j == num_blocks - 1) {
        integer_radix_apply_univariate_lookup_table<Torus>(
            streams, &acc_slice, &acc_slice, bsks, ksks,
            mem_ptr->luts_eq[items_in_acc], parallel_chunk);
        items_in_acc = 1;
      }
    }

    for (uint32_t c = 0; c < parallel_chunk; c++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[i + c], 0,
          1, mem_ptr->packed_accumulator, c, c + 1);
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_compute_equality_selectors(
    CudaStreams streams, int_equality_selectors_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_possible_values, uint32_t num_blocks,
    uint32_t match_parallelism, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_equality_selectors_buffer<Torus>(
      streams, params, num_possible_values, num_blocks, match_parallelism,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_create_possible_results(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *lwe_array_in_list,
    uint32_t num_possible_values, const uint64_t *h_decomposed_cleartexts,
    uint32_t num_blocks, int_possible_results_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  uint32_t max_packed_value = mem_ptr->max_packed_value;
  uint32_t max_luts_per_call = mem_ptr->max_luts_per_call;
  uint32_t num_lut_accumulators = mem_ptr->num_lut_accumulators;
  uint32_t match_parallelism = mem_ptr->match_parallelism;

  for (uint32_t i = 0; i < num_possible_values; i += match_parallelism) {
    uint32_t parallel_chunk =
        std::min(match_parallelism, num_possible_values - i);

    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->packed_selectors, 0,
        match_parallelism);

    for (uint32_t c = 0; c < parallel_chunk; c++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->packed_selectors, c,
          c + 1, &lwe_array_in_list[i + c], 0, 1);
    }

    CudaRadixCiphertextFFI current_packed_selectors;
    as_radix_ciphertext_slice<Torus>(&current_packed_selectors,
                                     mem_ptr->packed_selectors, 0,
                                     match_parallelism);

    for (uint32_t k = 0; k < num_lut_accumulators; k++) {
      int_radix_lut<Torus> *current_lut = mem_ptr->luts[k];
      uint32_t luts_in_this_call = current_lut->num_many_lut;

      CudaRadixCiphertextFFI current_packed_output;
      as_radix_ciphertext_slice<Torus>(
          &current_packed_output, mem_ptr->packed_tmp_many_luts_output, 0,
          match_parallelism * luts_in_this_call); // Pleine taille

      integer_radix_apply_many_univariate_lookup_table<Torus>(
          streams, &current_packed_output, &current_packed_selectors, bsks,
          (Torus *const *)ksks, current_lut, luts_in_this_call,
          mem_ptr->lut_stride);

      for (uint32_t c = 0; c < parallel_chunk; c++) {
        uint32_t idx = i + c;
        const uint64_t *current_clear_blocks =
            &h_decomposed_cleartexts[idx * num_blocks];

        for (uint32_t j = 0; j < num_blocks; j++) {
          uint64_t packed_block_value = current_clear_blocks[j];
          if (packed_block_value >= max_packed_value)
            PANIC("Exceeds max packed value");

          uint32_t accumulator_index = packed_block_value / max_luts_per_call;
          if (accumulator_index != k)
            continue;

          uint32_t lut_index_in_accumulator =
              packed_block_value % max_luts_per_call;

          uint32_t packed_output_idx =
              lut_index_in_accumulator * match_parallelism + c;

          copy_radix_ciphertext_slice_async<Torus>(
              streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[idx],
              j, j + 1, &current_packed_output, packed_output_idx,
              packed_output_idx + 1);
        }
      }
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_create_possible_results(
    CudaStreams streams, int_possible_results_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks, uint32_t num_possible_values,
    uint32_t match_parallelism, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_possible_results_buffer<Torus>(
      streams, params, num_blocks, num_possible_values, match_parallelism,
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
  uint32_t match_parallelism = mem_ptr->match_parallelism;

  CudaRadixCiphertextFFI *final_agg = mem_ptr->final_aggregated_vector;
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), final_agg, 0, num_blocks);

  uint32_t num_chunks = CEIL_DIV(num_input_ciphertexts, chunk_size);
  uint32_t chunks_accumulated = 0;

  for (uint32_t chunk_idx = 0; chunk_idx < num_chunks;
       chunk_idx += match_parallelism) {
    uint32_t parallel_chunks =
        std::min(match_parallelism, num_chunks - chunk_idx);

    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        mem_ptr->packed_partial_temp_vectors, 0,
        match_parallelism * num_blocks);

    for (uint32_t c = 0; c < parallel_chunks; c++) {
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
    as_radix_ciphertext_slice<Torus>(
        &current_packed_partial, mem_ptr->packed_partial_temp_vectors, 0,
        match_parallelism * num_blocks); // Pleine taille

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &current_packed_partial, &current_packed_partial, bsks, ksks,
        mem_ptr->batched_identity_lut, match_parallelism * num_blocks);

    for (uint32_t c = 0; c < parallel_chunks; c++) {
      CudaRadixCiphertextFFI current_temp;
      as_radix_ciphertext_slice<Torus>(&current_temp,
                                       mem_ptr->packed_partial_temp_vectors,
                                       c * num_blocks, (c + 1) * num_blocks);

      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), final_agg,
                           final_agg, &current_temp, num_blocks,
                           params.message_modulus, params.carry_modulus);

      chunks_accumulated++;
      // Flush final_agg's carry before the next add could overflow the
      // message+carry space. Each cleaned partial adds at most
      // `message_modulus - 1`, so we can safely accumulate up to
      // `chunk_size - 1` of them on top of a previously cleaned value.
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
    uint32_t match_parallelism, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_aggregate_one_hot_buffer<Torus>(
      streams, params, num_blocks, num_matches, match_parallelism,
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
      streams, mem_ptr->selectors_list, lwe_array_in_ct,
      mem_ptr->num_input_blocks, h_match_inputs, mem_ptr->eq_selectors_buffer,
      bsks, ksks);

  for (uint32_t i = 0; i < mem_ptr->num_matches; i++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->packed_selectors_ct,
        i, i + 1, &mem_ptr->selectors_list[i], 0, 1);
  }

  if (!mem_ptr->max_output_is_zero) {
    host_create_possible_results<Torus>(
        streams, mem_ptr->possible_results_list, mem_ptr->selectors_list,
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
    uint32_t match_parallelism, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_match_buffer<Torus>(
      streams, params, num_matches, num_input_blocks, num_output_packed_blocks,
      max_output_is_zero, match_parallelism, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_match_value_or(
    CudaStreams streams, int_unchecked_match_value_or_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_match_packed_blocks, uint32_t num_final_blocks,
    bool max_output_is_zero, uint32_t match_parallelism,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_match_value_or_buffer<Torus>(
      streams, params, num_matches, num_input_blocks, num_match_packed_blocks,
      num_final_blocks, max_output_is_zero, match_parallelism,
      allocate_gpu_memory, size_tracker);

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
                                uint32_t num_blocks,
                                uint32_t match_parallelism,
                                bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_contains_buffer<Torus>(
      streams, params, num_inputs, num_blocks, match_parallelism,
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

  CudaRadixCiphertextFFI *unpacked_selectors =
      new CudaRadixCiphertextFFI[num_inputs];
  for (uint32_t i = 0; i < num_inputs; i++) {
    as_radix_ciphertext_slice<Torus>(&unpacked_selectors[i],
                                     mem_ptr->packed_selectors, i, i + 1);
  }

  host_compute_bivariate_equality_selectors<Torus>(
      streams, unpacked_selectors, inputs, value, num_inputs, num_blocks,
      mem_ptr->eq_selectors_buf, bsks, ksks);

  delete[] unpacked_selectors;

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
      bsks, (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_contains_clear(
    CudaStreams streams, int_unchecked_contains_clear_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t match_parallelism, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_contains_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, match_parallelism,
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

  CudaRadixCiphertextFFI *unpacked_selectors =
      new CudaRadixCiphertextFFI[num_inputs];
  for (uint32_t i = 0; i < num_inputs; i++) {
    as_radix_ciphertext_slice<Torus>(&unpacked_selectors[i],
                                     mem_ptr->packed_selectors, i, i + 1);
  }

  host_compute_bivariate_equality_selectors<Torus>(
      streams, unpacked_selectors, inputs, mem_ptr->tmp_clear_val, num_inputs,
      num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  delete[] unpacked_selectors;

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
      bsks, (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_is_in_clears(
    CudaStreams streams, int_unchecked_is_in_clears_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_clears, uint32_t num_blocks,
    uint32_t match_parallelism, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_is_in_clears_buffer<Torus>(
      streams, params, num_clears, num_blocks, match_parallelism,
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

  host_compute_equality_selectors<Torus>(streams, mem_ptr->unpacked_selectors,
                                         input, num_blocks, h_cleartexts,
                                         mem_ptr->eq_buffer, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, output, mem_ptr->packed_selectors, mem_ptr->reduction_buffer,
      bsks, (Torus **)ksks, num_clears);
}

template <typename Torus>
__host__ void host_compute_final_index_from_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *selectors,
    uint32_t num_inputs, uint32_t num_blocks_index,
    int_final_index_from_selectors_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  for (uint32_t i = 0; i < num_inputs; i++) {
    CudaRadixCiphertextFFI const *src_selector = &selectors[i];

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->packed_selectors, i,
        i + 1, src_selector, 0, 1);
  }

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, mem_ptr->unpacked_selectors,
      num_inputs, mem_ptr->h_indices, packed_len, mem_ptr->possible_results_buf,
      bsks, ksks);

  host_aggregate_one_hot_vector<Torus>(
      streams, index_ct, mem_ptr->possible_results_ct_list, num_inputs,
      packed_len, mem_ptr->aggregate_buf, bsks, ksks);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->packed_selectors, mem_ptr->reduction_buf,
      bsks, (Torus **)ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_compute_final_index_from_selectors(
    CudaStreams streams, int_final_index_from_selectors_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks_index,
    uint32_t match_parallelism, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_final_index_from_selectors_buffer<Torus>(
      streams, params, num_inputs, num_blocks_index, match_parallelism,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_index_in_clears(
    CudaStreams streams, int_unchecked_index_in_clears_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_clears, uint32_t num_blocks,
    uint32_t num_blocks_index, uint32_t match_parallelism,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_in_clears_buffer<Torus>(
      streams, params, num_clears, num_blocks, num_blocks_index,
      match_parallelism, allocate_gpu_memory, size_tracker);

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
      streams, mem_ptr->final_index_buf->unpacked_selectors, input, num_blocks,
      h_cleartexts, mem_ptr->eq_selectors_buf, bsks, ksks);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->final_index_buf->possible_results_ct_list,
      mem_ptr->final_index_buf->unpacked_selectors, num_clears,
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
    uint32_t num_blocks_index, uint32_t match_parallelism,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_in_clears_buffer<Torus>(
      streams, params, num_unique, num_blocks, num_blocks_index,
      match_parallelism, allocate_gpu_memory, size_tracker);

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

  host_compute_equality_selectors<Torus>(streams, mem_ptr->unpacked_selectors,
                                         input, num_blocks, h_unique_values,
                                         mem_ptr->eq_selectors_buf, bsks, ksks);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->possible_results_ct_list, mem_ptr->unpacked_selectors,
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
    uint32_t num_blocks_index, uint32_t match_parallelism,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_of_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      match_parallelism, allocate_gpu_memory, size_tracker);

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

  host_compute_bivariate_equality_selectors<Torus>(
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
      streams, mem_ptr->possible_results_ct_list, mem_ptr->unpacked_selectors,
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
    uint32_t num_blocks_index, uint32_t match_parallelism,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_first_index_of_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      match_parallelism, allocate_gpu_memory, size_tracker);

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

  host_compute_bivariate_equality_selectors<Torus>(
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
      streams, mem_ptr->possible_results_ct_list, mem_ptr->unpacked_selectors,
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
    uint32_t num_blocks_index, uint32_t match_parallelism,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_of_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      match_parallelism, allocate_gpu_memory, size_tracker);

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

  host_compute_bivariate_equality_selectors<Torus>(
      streams, mem_ptr->final_index_buf->unpacked_selectors, inputs, value,
      num_inputs, num_blocks, mem_ptr->eq_selectors_buf, bsks, ksks);

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->final_index_buf->possible_results_ct_list,
      mem_ptr->final_index_buf->unpacked_selectors, num_inputs,
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
    uint32_t num_blocks_index, uint32_t match_parallelism,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_index_of_clear_buffer<Torus>(
      streams, params, num_inputs, num_blocks, num_blocks_index,
      match_parallelism, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_index_of_clear(
    CudaStreams streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    const uint64_t *h_clear_val, bool is_scalar_obviously_bigger,
    uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index,
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

    host_compute_bivariate_equality_selectors<Torus>(
        streams, mem_ptr->final_index_buf->unpacked_selectors, inputs,
        mem_ptr->tmp_clear_val, num_inputs, num_blocks,
        mem_ptr->eq_selectors_buf, bsks, ksks);
  }

  uint32_t packed_len = (num_blocks_index + 1) / 2;

  host_create_possible_results<Torus>(
      streams, mem_ptr->final_index_buf->possible_results_ct_list,
      mem_ptr->final_index_buf->unpacked_selectors, num_inputs,
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
