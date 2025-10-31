#pragma once

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

  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);

  for (uint32_t i = 0; i < num_possible_values; i++) {

    const uint64_t *current_clear_blocks =
        &h_decomposed_cleartexts[i * num_blocks];

    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t block_value = current_clear_blocks[j];

      if (block_value >= message_modulus) {
        PANIC("Cuda error: block value in compute_equality_selectors "
              "exceeds message modulus");
      }

      uint32_t input_start = (uint32_t)block_value * num_blocks + j;

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          mem_ptr->tmp_block_comparisons, j, j + 1,
          mem_ptr->tmp_many_luts_output, input_start, input_start + 1);
    }

    CudaRadixCiphertextFFI *current_output_block = &lwe_array_out_list[i];

    host_integer_are_all_comparisons_block_true<Torus>(
        streams, current_output_block, mem_ptr->tmp_block_comparisons,
        mem_ptr->reduction_buffer, bsks, (Torus **)ksks, num_blocks);
  }
}

template <typename Torus>
uint64_t scratch_cuda_compute_equality_selectors(
    CudaStreams streams, int_equality_selectors_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_possible_values, uint32_t num_blocks,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_equality_selectors_buffer<Torus>(
      streams, params, num_possible_values, num_blocks, allocate_gpu_memory,
      size_tracker);

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

  for (uint32_t i = 0; i < num_possible_values; i++) {

    CudaRadixCiphertextFFI const *current_selector = &lwe_array_in_list[i];
    CudaRadixCiphertextFFI *current_output = &lwe_array_out_list[i];
    const uint64_t *current_clear_blocks =
        &h_decomposed_cleartexts[i * num_blocks];

    for (uint32_t k = 0; k < num_lut_accumulators; k++) {

      uint32_t luts_in_this_call = mem_ptr->luts_vec[k]->num_many_lut;

      integer_radix_apply_many_univariate_lookup_table<Torus>(
          streams, mem_ptr->tmp_many_luts_output, current_selector, bsks,
          (Torus *const *)ksks, mem_ptr->luts_vec[k], luts_in_this_call,
          mem_ptr->lut_stride);

      for (uint32_t j = 0; j < num_blocks; j++) {
        uint64_t packed_block_value = current_clear_blocks[j];
        if (packed_block_value >= max_packed_value) {
          PANIC("Cuda error: block value in create_possible_results "
                "exceeds max packed value");
        }

        uint32_t accumulator_index = packed_block_value / max_luts_per_call;
        if (accumulator_index != k) {
          continue;
        }

        uint32_t lut_index_in_accumulator =
            packed_block_value % max_luts_per_call;

        copy_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0), current_output, j, j + 1,
            mem_ptr->tmp_many_luts_output, lut_index_in_accumulator,
            lut_index_in_accumulator + 1);
      }
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_create_possible_results(
    CudaStreams streams, int_possible_results_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_possible_results_buffer<Torus>(
      streams, params, num_blocks, allocate_gpu_memory, size_tracker);

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

  CudaRadixCiphertextFFI *aggregated_vector = mem_ptr->aggregated_vector;
  CudaRadixCiphertextFFI *temp_aggregated_vector =
      mem_ptr->temp_aggregated_vector;
  CudaRadixCiphertextFFI *message_ct = mem_ptr->message_ct;
  CudaRadixCiphertextFFI *carry_ct = mem_ptr->carry_ct;

  int_radix_lut<Torus> *identity_lut = mem_ptr->identity_lut;
  int_radix_lut<Torus> *message_extract_lut = mem_ptr->message_extract_lut;
  int_radix_lut<Torus> *carry_extract_lut = mem_ptr->carry_extract_lut;

  uint32_t num_chunks = (num_input_ciphertexts + chunk_size - 1) / chunk_size;

  for (uint32_t chunk_idx = 0; chunk_idx < num_chunks - 1; chunk_idx++) {
    for (uint32_t ct_idx = 0; ct_idx < chunk_size; ct_idx++) {
      uint32_t one_hot_idx = chunk_idx * chunk_size + ct_idx;
      CudaRadixCiphertextFFI const *current_one_hot_ct =
          &lwe_array_in_list[one_hot_idx];
      host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                           aggregated_vector, aggregated_vector,
                           current_one_hot_ct, num_blocks,
                           params.message_modulus, params.carry_modulus);
    }

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), temp_aggregated_vector, 0,
        num_blocks, aggregated_vector, 0, num_blocks);

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, aggregated_vector, temp_aggregated_vector, bsks, ksks,
        identity_lut, num_blocks);
  }

  uint32_t last_chunk_start = (num_chunks - 1) * chunk_size;
  uint32_t last_chunk_size = num_input_ciphertexts - last_chunk_start;
  for (uint32_t ct_idx = 0; ct_idx < last_chunk_size; ct_idx++) {
    uint32_t one_hot_idx = last_chunk_start + ct_idx;
    CudaRadixCiphertextFFI const *current_one_hot_ct =
        &lwe_array_in_list[one_hot_idx];
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                         aggregated_vector, aggregated_vector,
                         current_one_hot_ct, num_blocks, params.message_modulus,
                         params.carry_modulus);
  }

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), temp_aggregated_vector, 0,
      num_blocks, aggregated_vector, 0, num_blocks);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, carry_ct, temp_aggregated_vector, bsks, ksks, carry_extract_lut,
      num_blocks);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, message_ct, temp_aggregated_vector, bsks, ksks,
      message_extract_lut, num_blocks);

  for (uint32_t index = 0; index < num_blocks; index++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index,
        2 * index + 1, message_ct, index, index + 1);

    if (2 * index + 1 < lwe_array_out->num_radix_blocks) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index + 1,
          2 * index + 2, carry_ct, index, index + 1);
    }
  }
}

template <typename Torus>
uint64_t scratch_cuda_aggregate_one_hot_vector(
    CudaStreams streams, int_aggregate_one_hot_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_blocks, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_aggregate_one_hot_buffer<Torus>(
      streams, params, num_blocks, allocate_gpu_memory, size_tracker);

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
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_match_buffer<Torus>(
      streams, params, num_matches, num_input_blocks, num_output_packed_blocks,
      max_output_is_zero, allocate_gpu_memory, size_tracker);

  return size_tracker;
}
