#pragma once

#include "integer/cast.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/scalar_comparison.cuh"
#include "integer/vector_find.h"

template <typename Torus>
__global__ void
map_gather_kernel(Torus *__restrict__ dst, const Torus *__restrict__ src,
                  const uint32_t *__restrict__ map, uint32_t block_size) {

  uint32_t block_idx = blockIdx.x;
  uint32_t src_idx = map[block_idx];

  uint32_t dst_offset = block_idx * block_size;
  uint32_t src_offset = src_idx * block_size;

  for (uint32_t tid = threadIdx.x; tid < block_size; tid += blockDim.x) {
    dst[dst_offset + tid] = src[src_offset + tid];
  }
}

template <typename Torus>
__global__ void scatter_to_ptr_array_kernel(
    Torus **__restrict__ dst_ptr_array, const Torus *__restrict__ src_batched,
    uint32_t num_blocks, const uint32_t *__restrict__ src_offsets,
    uint32_t block_size) {

  uint32_t i = blockIdx.x / num_blocks;
  uint32_t j = blockIdx.x % num_blocks;

  Torus *dst = dst_ptr_array[i];
  uint32_t dst_offset = j * block_size;
  uint32_t src_idx = src_offsets[blockIdx.x];
  uint32_t src_offset = src_idx * block_size;

  for (uint32_t tid = threadIdx.x; tid < block_size; tid += blockDim.x) {
    dst[dst_offset + tid] = src_batched[src_offset + tid];
  }
}

template <typename Torus>
__global__ void
gather_from_ptr_array_kernel(Torus *__restrict__ dst_batched,
                             const Torus *const *__restrict__ src_ptr_array,
                             uint32_t num_blocks, uint32_t block_size) {

  uint32_t i = blockIdx.x / num_blocks;
  uint32_t j = blockIdx.x % num_blocks;

  const Torus *src = src_ptr_array[i];

  uint32_t dst_offset = blockIdx.x * block_size;
  uint32_t src_offset = j * block_size;

  for (uint32_t tid = threadIdx.x; tid < block_size; tid += blockDim.x) {
    dst_batched[dst_offset + tid] = src[src_offset + tid];
  }
}

template <typename Torus>
__global__ void
aggregate_chunk_prepare_kernel(Torus *__restrict__ batched_input,
                               const Torus *__restrict__ tmp_out, uint32_t k,
                               uint32_t chunk_size, uint32_t remaining,
                               uint32_t num_blocks, uint32_t block_size) {

  uint32_t c = blockIdx.x / num_blocks;
  uint32_t block_in_c = blockIdx.x % num_blocks;

  uint32_t idx = c * chunk_size + k;
  uint32_t dst_offset = blockIdx.x * block_size;

  if (idx < remaining) {
    uint32_t src_offset = (idx * num_blocks + block_in_c) * block_size;
    for (uint32_t tid = threadIdx.x; tid < block_size; tid += blockDim.x) {
      batched_input[dst_offset + tid] = tmp_out[src_offset + tid];
    }
  } else {
    for (uint32_t tid = threadIdx.x; tid < block_size; tid += blockDim.x) {
      batched_input[dst_offset + tid] = 0;
    }
  }
}

template <typename Torus>
__host__ void host_compute_equality_selectors(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_blocks,
    const uint64_t *h_decomposed_cleartexts,
    int_equality_selectors_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  uint32_t num_possible_values = mem_ptr->num_possible_values;
  uint32_t message_modulus = mem_ptr->params.message_modulus;

  PUSH_RANGE("eq_selectors_apply_univariate_lut")
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_many_luts_output, lwe_array_in, bsks,
      (Torus *const *)ksks, mem_ptr->comparison_luts, message_modulus,
      mem_ptr->lut_stride);
  POP_RANGE()

  CudaRadixCiphertextFFI *batched = mem_ptr->tmp_batched_block_comparisons;

  PUSH_RANGE("eq_selectors_scatter_comparisons")
  uint32_t total_blocks = num_possible_values * num_blocks;
  uint32_t *h_map = mem_ptr->h_map; // Utilisation du buffer pré-alloué

  for (uint32_t i = 0; i < num_possible_values; i++) {
    const uint64_t *current_clear_blocks =
        &h_decomposed_cleartexts[i * num_blocks];
    for (uint32_t j = 0; j < num_blocks; j++) {
      uint64_t block_value = current_clear_blocks[j];
      if (block_value >= message_modulus) {
        PANIC("Cuda error: block value in compute_equality_selectors exceeds "
              "message modulus");
      }
      h_map[i * num_blocks + j] = (uint32_t)block_value * num_blocks + j;
    }
  }

  cuda_memcpy_async_to_gpu(mem_ptr->d_map, h_map,
                           total_blocks * sizeof(uint32_t), streams.stream(0),
                           streams.gpu_index(0));

  uint32_t block_size = batched->lwe_dimension + 1;
  map_gather_kernel<Torus><<<total_blocks, 256, 0, streams.stream(0)>>>(
      (Torus *)batched->ptr, (Torus *)mem_ptr->tmp_many_luts_output->ptr,
      mem_ptr->d_map, block_size);
  POP_RANGE()

  PUSH_RANGE("eq_selectors_batched_are_all_eq_true")
  host_batched_are_all_comparisons_eq_true<Torus>(
      streams, lwe_array_out_list, batched, num_possible_values, num_blocks,
      mem_ptr->params, mem_ptr->tmp_batched_out,
      mem_ptr->tmp_batched_accumulated, mem_ptr->batched_is_max_value,
      mem_ptr->preallocated_h_lut, bsks, ksks);
  POP_RANGE()
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
    CudaRadixCiphertextFFI const *batched_selectors,
    uint32_t num_possible_values, const uint64_t *h_decomposed_cleartexts,
    uint32_t num_blocks, int_possible_results_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {
  uint32_t num_lut_accumulators = mem_ptr->num_lut_accumulators;
  uint32_t max_luts_per_call = mem_ptr->max_luts_per_call;
  uint32_t max_packed_value = mem_ptr->max_packed_value;

  PUSH_RANGE("possible_results_copy_selectors")
  for (uint32_t k = 0; k < num_lut_accumulators; k++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_batched_selectors,
        k * num_possible_values, (k + 1) * num_possible_values,
        batched_selectors, 0, num_possible_values);
  }
  POP_RANGE()

  PUSH_RANGE("possible_results_apply_accumulators_lut")
  integer_radix_apply_many_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_many_luts_output, mem_ptr->tmp_batched_selectors,
      bsks, (Torus *const *)ksks, mem_ptr->batched_accumulators_lut,
      max_luts_per_call, mem_ptr->lut_stride);
  POP_RANGE()

  PUSH_RANGE("possible_results_gather_blocks")
  uint32_t total_blocks = num_possible_values * num_blocks;

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
      if (packed_block_value >= max_packed_value) {
        PANIC("Cuda error: block value in create_possible_results exceeds max "
              "packed value");
      }
      uint32_t k = packed_block_value / max_luts_per_call;
      uint32_t lut_index_in_accumulator =
          packed_block_value % max_luts_per_call;
      uint32_t src_index = lut_index_in_accumulator *
                               (num_lut_accumulators * num_possible_values) +
                           k * num_possible_values + i;

      h_src_idx[i * num_blocks + j] = src_index;
    }
  }

  cuda_memcpy_async_to_gpu(mem_ptr->d_dst_ptrs, h_dst_ptrs,
                           num_possible_values * sizeof(Torus *),
                           streams.stream(0), streams.gpu_index(0));
  cuda_memcpy_async_to_gpu(mem_ptr->d_src_idx, h_src_idx,
                           total_blocks * sizeof(uint32_t), streams.stream(0),
                           streams.gpu_index(0));

  uint32_t block_size = lwe_array_out_list[0].lwe_dimension + 1;

  scatter_to_ptr_array_kernel<Torus>
      <<<total_blocks, 256, 0, streams.stream(0)>>>(
          mem_ptr->d_dst_ptrs, (Torus *)mem_ptr->tmp_many_luts_output->ptr,
          num_blocks, mem_ptr->d_src_idx, block_size);
  POP_RANGE()
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
  if (params.message_modulus > 4 && params.carry_modulus > 4) {
    PANIC("Cuda error: aggregate one hot vector is only implemented for 1_1 "
          "and 2_2 params");
  }

  if (num_input_ciphertexts == 0) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array_out, 0,
        lwe_array_out->num_radix_blocks);
    return;
  }

  uint32_t chunk_size = mem_ptr->chunk_size;
  uint32_t remaining = num_input_ciphertexts;

  PUSH_RANGE("aggregate_initial_copies")
  const Torus **h_src_ptrs = mem_ptr->h_src_ptrs;
  for (uint32_t i = 0; i < remaining; i++) {
    h_src_ptrs[i] = (const Torus *)lwe_array_in_list[i].ptr;
  }

  cuda_memcpy_async_to_gpu(mem_ptr->d_src_ptrs, h_src_ptrs,
                           remaining * sizeof(const Torus *), streams.stream(0),
                           streams.gpu_index(0));

  uint32_t block_size = mem_ptr->tmp_out->lwe_dimension + 1;
  uint32_t total_blocks_initial = remaining * num_blocks;

  gather_from_ptr_array_kernel<Torus>
      <<<total_blocks_initial, 256, 0, streams.stream(0)>>>(
          (Torus *)mem_ptr->tmp_out->ptr, mem_ptr->d_src_ptrs, num_blocks,
          block_size);
  POP_RANGE()

  PUSH_RANGE("aggregate_reduction_loop")
  while (remaining > 1) {
    uint32_t num_chunks = (remaining + chunk_size - 1) / chunk_size;

    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_accumulated, 0,
        num_chunks * num_blocks);

    PUSH_RANGE("aggregate_chunk_processing")
    for (uint32_t k = 0; k < chunk_size; k++) {
      bool has_active = (k < remaining);

      uint32_t total_blocks_chunk = num_chunks * num_blocks;
      aggregate_chunk_prepare_kernel<Torus>
          <<<total_blocks_chunk, 256, 0, streams.stream(0)>>>(
              (Torus *)mem_ptr->tmp_batched_input->ptr,
              (const Torus *)mem_ptr->tmp_out->ptr, k, chunk_size, remaining,
              num_blocks, block_size);

      if (has_active) {
        host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                             mem_ptr->tmp_accumulated, mem_ptr->tmp_accumulated,
                             mem_ptr->tmp_batched_input,
                             num_chunks * num_blocks, params.message_modulus,
                             params.carry_modulus);
      }
    }
    POP_RANGE()

    PUSH_RANGE("aggregate_identity_lut")
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, mem_ptr->tmp_out, mem_ptr->tmp_accumulated, bsks, ksks,
        mem_ptr->identity_lut, num_chunks * num_blocks);
    POP_RANGE()

    remaining = num_chunks;
  }
  POP_RANGE()

  PUSH_RANGE("aggregate_extract_and_reassemble")
  CudaRadixCiphertextFFI final_result;
  as_radix_ciphertext_slice<Torus>(&final_result, mem_ptr->tmp_out, 0,
                                   num_blocks);

  CudaRadixCiphertextFFI *message_ct = mem_ptr->message_ct;
  CudaRadixCiphertextFFI *carry_ct = mem_ptr->carry_ct;

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, message_ct, &final_result, bsks, ksks,
      mem_ptr->message_extract_lut, num_blocks);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, carry_ct, &final_result, bsks, ksks, mem_ptr->carry_extract_lut,
      num_blocks);

  for (uint32_t index = 0; index < num_blocks; index++) {
    if (2 * index < lwe_array_out->num_radix_blocks) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index,
          2 * index + 1, message_ct, index, index + 1);
    }

    if (2 * index + 1 < lwe_array_out->num_radix_blocks) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), lwe_array_out, 2 * index + 1,
          2 * index + 2, carry_ct, index, index + 1);
    }
  }
  POP_RANGE()
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
  PUSH_RANGE("MATCH_VALUE")

  PUSH_RANGE("host_compute_equality_selectors")
  host_compute_equality_selectors<Torus>(
      streams, mem_ptr->selectors_list, lwe_array_in_ct,
      mem_ptr->num_input_blocks, h_match_inputs, mem_ptr->eq_selectors_buffer,
      bsks, ksks);
  POP_RANGE()

  if (!mem_ptr->max_output_is_zero) {
    PUSH_RANGE("host_create_possible_results")
    host_create_possible_results<Torus>(
        streams, mem_ptr->possible_results_list, mem_ptr->packed_selectors_ct,
        mem_ptr->num_matches, h_match_outputs,
        mem_ptr->num_output_packed_blocks, mem_ptr->possible_results_buffer,
        bsks, ksks);
    POP_RANGE()
  }

  if (mem_ptr->max_output_is_zero) {
    PUSH_RANGE("host_integer_is_at_least_one_comparisons_block_true")
    host_integer_is_at_least_one_comparisons_block_true<Torus>(
        streams, lwe_array_out_boolean, mem_ptr->packed_selectors_ct,
        mem_ptr->at_least_one_true_buffer, bsks, (Torus **)ksks,
        mem_ptr->num_matches);
    POP_RANGE()
    return;
  }

  PUSH_RANGE("host_aggregate_one_hot_vector")
  host_aggregate_one_hot_vector<Torus>(
      streams, lwe_array_out_result, mem_ptr->possible_results_list,
      mem_ptr->num_matches, mem_ptr->num_output_packed_blocks,
      mem_ptr->aggregate_buffer, bsks, ksks);
  POP_RANGE()

  PUSH_RANGE("host_integer_is_at_least_one_comparisons_block_true")
  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, lwe_array_out_boolean, mem_ptr->packed_selectors_ct,
      mem_ptr->at_least_one_true_buffer, bsks, (Torus **)ksks,
      mem_ptr->num_matches);
  POP_RANGE()
  POP_RANGE()
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

  mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
      streams);

  uint32_t num_streams = mem_ptr->num_streams;

  for (uint32_t i = 0; i < num_inputs; i++) {
    uint32_t stream_idx = i % num_streams;
    CudaStreams current_stream = mem_ptr->internal_cuda_streams[stream_idx];

    CudaRadixCiphertextFFI const *input_ct = &inputs[i];

    CudaRadixCiphertextFFI current_selector_block;
    as_radix_ciphertext_slice<Torus>(&current_selector_block,
                                     mem_ptr->packed_selectors, i, i + 1);

    host_equality_check<Torus>(current_stream, &current_selector_block,
                               input_ct, value, mem_ptr->eq_buffers[stream_idx],
                               bsks, ksks, num_blocks);
  }

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
      streams);

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

  mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
      streams);

  uint32_t num_streams = mem_ptr->num_streams;

  for (uint32_t i = 0; i < num_inputs; i++) {
    uint32_t stream_idx = i % num_streams;
    CudaStreams current_stream = mem_ptr->internal_cuda_streams[stream_idx];

    CudaRadixCiphertextFFI const *input_ct = &inputs[i];

    CudaRadixCiphertextFFI current_selector_block;
    as_radix_ciphertext_slice<Torus>(&current_selector_block,
                                     mem_ptr->packed_selectors, i, i + 1);

    host_equality_check<Torus>(current_stream, &current_selector_block,
                               input_ct, mem_ptr->tmp_clear_val,
                               mem_ptr->eq_buffers[stream_idx], bsks, ksks,
                               num_blocks);
  }

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
      streams);

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
      streams, mem_ptr->possible_results_ct_list, mem_ptr->packed_selectors,
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

  host_compute_equality_selectors<Torus>(
      streams, mem_ptr->final_index_buf->unpacked_selectors, input, num_blocks,
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

  host_compute_equality_selectors<Torus>(streams, mem_ptr->unpacked_selectors,
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

  mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
      streams);

  uint32_t num_streams = mem_ptr->num_streams;

  for (uint32_t i = 0; i < num_inputs; i++) {
    uint32_t stream_idx = i % num_streams;
    CudaStreams current_stream = mem_ptr->internal_cuda_streams[stream_idx];

    CudaRadixCiphertextFFI const *input_ct = &inputs[i];

    CudaRadixCiphertextFFI current_selector_block;
    as_radix_ciphertext_slice<Torus>(&current_selector_block,
                                     mem_ptr->packed_selectors, i, i + 1);

    host_equality_check<Torus>(current_stream, &current_selector_block,
                               input_ct, mem_ptr->tmp_clear_val,
                               mem_ptr->eq_buffers[stream_idx], bsks, ksks,
                               num_blocks);
  }

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
      streams);

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

  mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
      streams);

  uint32_t num_streams = mem_ptr->num_streams;

  for (uint32_t i = 0; i < num_inputs; i++) {
    uint32_t stream_idx = i % num_streams;
    CudaStreams current_stream = mem_ptr->internal_cuda_streams[stream_idx];

    CudaRadixCiphertextFFI const *input_ct = &inputs[i];

    CudaRadixCiphertextFFI current_selector_block;
    as_radix_ciphertext_slice<Torus>(&current_selector_block,
                                     mem_ptr->packed_selectors, i, i + 1);

    host_equality_check<Torus>(current_stream, &current_selector_block,
                               input_ct, value, mem_ptr->eq_buffers[stream_idx],
                               bsks, ksks, num_blocks);
  }

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
      streams);

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

  mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
      streams);

  uint32_t num_streams = mem_ptr->num_streams;

  for (uint32_t i = 0; i < num_inputs; i++) {
    uint32_t stream_idx = i % num_streams;
    CudaStreams current_stream = mem_ptr->internal_cuda_streams[stream_idx];

    CudaRadixCiphertextFFI const *input_ct = &inputs[i];

    CudaRadixCiphertextFFI current_selector_block;
    as_radix_ciphertext_slice<Torus>(&current_selector_block,
                                     mem_ptr->final_index_buf->packed_selectors,
                                     i, i + 1);

    host_equality_check<Torus>(current_stream, &current_selector_block,
                               input_ct, value, mem_ptr->eq_buffers[stream_idx],
                               bsks, ksks, num_blocks);
  }

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
      streams);

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
    const Torus *d_scalar_blocks, bool is_scalar_obviously_bigger,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_scalar_blocks,
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
    mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
        streams);

    uint32_t num_streams = mem_ptr->num_streams;

    for (uint32_t i = 0; i < num_inputs; i++) {
      uint32_t stream_idx = i % num_streams;
      CudaStreams current_stream = mem_ptr->internal_cuda_streams[stream_idx];

      CudaRadixCiphertextFFI const *input_ct = &inputs[i];

      CudaRadixCiphertextFFI current_selector_dest;
      as_radix_ciphertext_slice<Torus>(&current_selector_dest, packed_selectors,
                                       i, i + 1);

      host_scalar_equality_check<Torus>(
          current_stream, &current_selector_dest, input_ct, d_scalar_blocks,
          mem_ptr->eq_buffers[stream_idx], bsks, (Torus **)ksks, num_blocks,
          num_scalar_blocks);
    }

    mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
        streams);
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
