#pragma once
#include "integer/cast.cuh"
#include "integer/comparison.cuh"
#include "integer/radix_ciphertext.cuh"
#include "integer/vector_comparison.h"

template <typename Torus>
uint64_t scratch_cuda_unchecked_all_eq_slices(
    CudaStreams streams, int_unchecked_all_eq_slices_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_inputs, uint32_t num_blocks,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_all_eq_slices_buffer<Torus>(
      streams, params, num_inputs, num_blocks, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_all_eq_slices(
    CudaStreams streams, CudaRadixCiphertextFFI *match_ct,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    uint32_t num_inputs, uint32_t num_blocks,
    int_unchecked_all_eq_slices_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  mem_ptr->sub_streams->sync_from(streams);

  uint32_t num_streams = mem_ptr->num_streams;

  for (uint32_t i = 0; i < num_inputs; i++) {
    uint32_t stream_idx = i % num_streams;
    CudaStreams current_stream = (*mem_ptr->sub_streams)[stream_idx];

    CudaRadixCiphertextFFI const *input_lhs = &lhs[i];
    CudaRadixCiphertextFFI const *input_rhs = &rhs[i];

    CudaRadixCiphertextFFI current_result_dest;
    as_radix_ciphertext_slice<Torus>(&current_result_dest,
                                     mem_ptr->packed_results, i, i + 1);

    host_equality_check<Torus>(current_stream, &current_result_dest, input_lhs,
                               input_rhs, mem_ptr->eq_buffers[stream_idx], bsks,
                               ksks, num_blocks);
  }

  mem_ptr->sub_streams->sync_to(streams);

  host_integer_are_all_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->packed_results, mem_ptr->reduction_buffer,
      bsks, ksks, num_inputs);
}

template <typename Torus>
uint64_t scratch_cuda_unchecked_contains_sub_slice(
    CudaStreams streams,
    int_unchecked_contains_sub_slice_buffer<Torus> **mem_ptr,
    int_radix_params params, uint32_t num_lhs, uint32_t num_rhs,
    uint32_t num_blocks, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_unchecked_contains_sub_slice_buffer<Torus>(
      streams, params, num_lhs, num_rhs, num_blocks, allocate_gpu_memory,
      size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_unchecked_contains_sub_slice(
    CudaStreams streams, CudaRadixCiphertextFFI *match_ct,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    uint32_t num_rhs, uint32_t num_blocks,
    int_unchecked_contains_sub_slice_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  mem_ptr->sub_streams->sync_from(streams);

  uint32_t num_streams = mem_ptr->num_streams;
  uint32_t num_windows = mem_ptr->num_windows;

  for (uint32_t w = 0; w < num_windows; w++) {
    uint32_t stream_idx = w % num_streams;
    CudaStreams current_stream = (*mem_ptr->sub_streams)[stream_idx];

    CudaRadixCiphertextFFI *current_window_results =
        mem_ptr->stream_comparisons_results[stream_idx];
    int_comparison_buffer<Torus> *current_eq_buffer =
        mem_ptr->window_eq_buffers[stream_idx];
    int_comparison_buffer<Torus> *current_reduction_buffer =
        mem_ptr->window_reduction_buffers[stream_idx];

    for (uint32_t i = 0; i < num_rhs; i++) {
      CudaRadixCiphertextFFI const *input_lhs = &lhs[w + i];
      CudaRadixCiphertextFFI const *input_rhs = &rhs[i];

      CudaRadixCiphertextFFI current_result_dest;
      as_radix_ciphertext_slice<Torus>(&current_result_dest,
                                       current_window_results, i, i + 1);

      host_equality_check<Torus>(current_stream, &current_result_dest,
                                 input_lhs, input_rhs, current_eq_buffer, bsks,
                                 ksks, num_blocks);
    }

    CudaRadixCiphertextFFI window_result_dest;
    as_radix_ciphertext_slice<Torus>(&window_result_dest,
                                     mem_ptr->packed_results, w, w + 1);

    host_integer_are_all_comparisons_block_true<Torus>(
        current_stream, &window_result_dest, current_window_results,
        current_reduction_buffer, bsks, ksks, num_rhs);
  }

  mem_ptr->sub_streams->sync_to(streams);

  host_integer_is_at_least_one_comparisons_block_true<Torus>(
      streams, match_ct, mem_ptr->packed_results,
      mem_ptr->final_reduction_buffer, bsks, ksks, num_windows);
}
