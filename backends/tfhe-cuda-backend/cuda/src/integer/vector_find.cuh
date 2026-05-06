#pragma once

#include "integer/cast.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/scalar_comparison.cuh"
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
__host__ void accumulate_all_blocks_batched(
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
  // batched_comparisons[i * num_blocks + j] = grid[d_i_j][j]
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
    // Each candidate needs exactly one comparison block; no tree reduction.
    for (uint32_t i = 0; i < num_possible_values; i++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &lwe_array_out_list[i], 0, 1,
          batched, i, i + 1);
    }
    reset_radix_ciphertext_blocks(&lwe_array_out_list[0], 1);
    return;
  }

  // Step 3: Batched tree reduction.
  // At each level, accumulate chunks across ALL candidates in one kernel,
  // then apply one batched PBS.
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

    // Accumulate all chunks across all entries in one kernel launch
    accumulate_all_blocks_batched<Torus>(
        streams.stream(0), streams.gpu_index(0), (Torus *)tree_accumulator->ptr,
        current_input_ptr, big_lwe_dimension, blocks_per_entry, max_value,
        num_possible_values, num_chunks);

    // Configure LUT indexes: body 0 for full chunks, body 1 for short last
    // chunk
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

    // One batched PBS for all entries at this tree level
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, tree_pbs_output, tree_accumulator, bsks, ksks,
        is_max_value_lut, total_chunks);

    // Reset LUT indexes if we modified them
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
  uint32_t num_streams = mem_ptr->num_streams;

  mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
      streams);

  for (uint32_t i = 0; i < num_possible_values; i++) {

    uint32_t stream_idx = i % num_streams;
    CudaStreams current_stream = mem_ptr->internal_cuda_streams[stream_idx];
    CudaRadixCiphertextFFI *current_tmp_buffer =
        mem_ptr->tmp_many_luts_output[stream_idx];

    CudaRadixCiphertextFFI const *current_selector = &lwe_array_in_list[i];
    CudaRadixCiphertextFFI *current_output = &lwe_array_out_list[i];
    const uint64_t *current_clear_blocks =
        &h_decomposed_cleartexts[i * num_blocks];

    for (uint32_t k = 0; k < num_lut_accumulators; k++) {

      uint32_t lut_index = stream_idx * num_lut_accumulators + k;

      int_radix_lut<Torus> *current_lut = mem_ptr->stream_luts[lut_index];

      uint32_t luts_in_this_call = current_lut->num_many_lut;

      integer_radix_apply_many_univariate_lookup_table<Torus>(
          current_stream, current_tmp_buffer, current_selector, bsks,
          (Torus *const *)ksks, current_lut, luts_in_this_call,
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
            current_stream.stream(0), current_stream.gpu_index(0),
            current_output, j, j + 1, current_tmp_buffer,
            lut_index_in_accumulator, lut_index_in_accumulator + 1);
      }
    }
  }

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
      streams);
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
    CudaRadixCiphertextFFI const *lwe_array_in_list,
    uint32_t num_input_ciphertexts, uint32_t num_blocks,
    int_aggregate_one_hot_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  int_radix_params params = mem_ptr->params;
  if (params.message_modulus > 4 && params.carry_modulus > 4) {
    PANIC("Cuda error: aggregate one hot vector is only implemented for 1_1 "
          "and 2_2 params");
  }
  uint32_t chunk_size = mem_ptr->chunk_size;
  uint32_t num_streams = mem_ptr->num_streams;

  mem_ptr->internal_cuda_streams.internal_streams_wait_for_main_stream_0(
      streams);

  uint32_t inputs_per_stream = CEIL_DIV(num_input_ciphertexts, num_streams);

  for (uint32_t s = 0; s < num_streams; s++) {

    CudaStreams current_stream = mem_ptr->internal_cuda_streams[s];

    CudaRadixCiphertextFFI *current_agg =
        mem_ptr->partial_aggregated_vectors[s];
    CudaRadixCiphertextFFI *current_temp = mem_ptr->partial_temp_vectors[s];
    int_radix_lut<Torus> *current_identity_lut =
        mem_ptr->stream_identity_luts[s];

    uint32_t start_idx = s * inputs_per_stream;
    uint32_t end_idx =
        std::min(start_idx + inputs_per_stream, num_input_ciphertexts);
    uint32_t count_in_stream =
        (end_idx > start_idx) ? (end_idx - start_idx) : 0;

    //
    // Initialize the partial aggregated vector to zero for the current stream
    //
    set_zero_radix_ciphertext_slice_async<Torus>(current_stream.stream(0),
                                                 current_stream.gpu_index(0),
                                                 current_agg, 0, num_blocks);

    if (count_in_stream == 0)
      continue;

    uint32_t num_chunks = CEIL_DIV(count_in_stream, chunk_size);

    //
    // Process chunks of input ciphertexts for the current stream
    //
    for (uint32_t chunk_idx = 0; chunk_idx < num_chunks; chunk_idx++) {
      uint32_t chunk_start_relative = chunk_idx * chunk_size;
      uint32_t chunk_end_relative =
          std::min(chunk_start_relative + chunk_size, count_in_stream);
      uint32_t current_chunk_size = chunk_end_relative - chunk_start_relative;

      //
      // Accumulate ciphertexts in the current chunk
      //
      for (uint32_t k = 0; k < current_chunk_size; k++) {
        uint32_t global_idx = start_idx + chunk_start_relative + k;
        CudaRadixCiphertextFFI const *current_one_hot_ct =
            &lwe_array_in_list[global_idx];

        host_addition<Torus>(current_stream.stream(0),
                             current_stream.gpu_index(0), current_agg,
                             current_agg, current_one_hot_ct, num_blocks,
                             params.message_modulus, params.carry_modulus);
      }

      //
      // Apply identity LUT to reduce noise after accumulation
      //
      copy_radix_ciphertext_slice_async<Torus>(
          current_stream.stream(0), current_stream.gpu_index(0), current_temp,
          0, num_blocks, current_agg, 0, num_blocks);

      integer_radix_apply_univariate_lookup_table<Torus>(
          current_stream, current_agg, current_temp, bsks, ksks,
          current_identity_lut, num_blocks);
    }
  }

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams(
      streams);

  CudaRadixCiphertextFFI *final_agg = mem_ptr->partial_aggregated_vectors[0];

  //
  // Aggregate partial results from all streams into the final aggregated vector
  // num_streams has to be less than the max noise level otherwise we accumulate
  // too much and the noise limit is exceeded
  //
  CHECK_NOISE_LEVEL(num_streams, params.message_modulus, params.carry_modulus);
  for (uint32_t s = 1; s < num_streams; s++) {
    uint32_t start_idx = s * inputs_per_stream;
    if (start_idx >= num_input_ciphertexts)
      break;

    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), final_agg,
                         final_agg, mem_ptr->partial_aggregated_vectors[s],
                         num_blocks, params.message_modulus,
                         params.carry_modulus);
  }

  CudaRadixCiphertextFFI *temp_agg = mem_ptr->partial_temp_vectors[0];
  CudaRadixCiphertextFFI *message_ct = mem_ptr->message_ct;
  CudaRadixCiphertextFFI *carry_ct = mem_ptr->carry_ct;

  //
  // Copy the final aggregated result to a temporary buffer for extraction
  //
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), temp_agg, 0, num_blocks,
      final_agg, 0, num_blocks);

  CudaStreams message_stream = mem_ptr->internal_cuda_streams[0];
  CudaStreams carry_stream = mem_ptr->internal_cuda_streams[1];

  uint32_t stream_indexes[] = {0, 1};
  size_t num_stream_indexes = 2;

  mem_ptr->internal_cuda_streams.internal_streams_slice_wait_for_main_stream_0(
      streams, stream_indexes, num_stream_indexes);

  //
  // Extract message part on a first substream
  //
  integer_radix_apply_univariate_lookup_table<Torus>(
      message_stream, message_ct, temp_agg, bsks, ksks,
      mem_ptr->message_extract_lut, num_blocks);

  //
  // Extract carry part on a second substream
  //
  integer_radix_apply_univariate_lookup_table<Torus>(
      carry_stream, carry_ct, temp_agg, bsks, ksks, mem_ptr->carry_extract_lut,
      num_blocks);

  mem_ptr->internal_cuda_streams.main_stream_0_wait_for_internal_streams_slice(
      streams, stream_indexes, num_stream_indexes);

  //
  // Pack the message and carry parts into the output LWE array
  //
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
