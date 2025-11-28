#pragma once
#include "helper_multi_gpu.h"
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"
#include <functional>

const uint32_t MAX_STREAMS_FOR_VECTOR_COMPARISON = 10;

template <typename Torus> struct int_unchecked_all_eq_slices_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_results;

  CudaStreams active_streams;
  MultiStreamMultiGpu *sub_streams;
  uint32_t num_streams;

  int_unchecked_all_eq_slices_buffer(CudaStreams streams,
                                     int_radix_params params,
                                     uint32_t num_inputs, uint32_t num_blocks,
                                     bool allocate_gpu_memory,
                                     uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_COMPARISON, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams = streams.active_gpu_subset(num_blocks);

    sub_streams = new MultiStreamMultiGpu(active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_results = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_results,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_results,
                                   this->allocate_gpu_memory);
    delete this->packed_results;

    sub_streams->release(streams);
    delete sub_streams;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_sub_slice_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_windows;
  uint32_t num_rhs;

  int_comparison_buffer<Torus> **window_eq_buffers;
  CudaRadixCiphertextFFI **stream_comparisons_results;

  int_comparison_buffer<Torus> **window_reduction_buffers;

  CudaRadixCiphertextFFI *packed_results;
  int_comparison_buffer<Torus> *final_reduction_buffer;

  CudaStreams active_streams;
  MultiStreamMultiGpu *sub_streams;
  uint32_t num_streams;

  int_unchecked_contains_sub_slice_buffer(CudaStreams streams,
                                          int_radix_params params,
                                          uint32_t num_lhs, uint32_t num_rhs,
                                          uint32_t num_blocks,
                                          bool allocate_gpu_memory,
                                          uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_rhs = num_rhs;
    this->num_windows = num_lhs - num_rhs + 1;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_COMPARISON, num_windows);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams = streams.active_gpu_subset(num_blocks);

    sub_streams = new MultiStreamMultiGpu(active_streams, num_streams_to_use);

    this->window_eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    this->stream_comparisons_results =
        new CudaRadixCiphertextFFI *[num_streams];
    this->window_reduction_buffers =
        new int_comparison_buffer<Torus> *[num_streams];

    for (uint32_t i = 0; i < num_streams; i++) {
      this->window_eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);

      this->stream_comparisons_results[i] = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->stream_comparisons_results[i], num_rhs,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      this->window_reduction_buffers[i] =
          new int_comparison_buffer<Torus>(streams, EQ, params, num_rhs, false,
                                           allocate_gpu_memory, size_tracker);
    }

    this->final_reduction_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_windows, false, allocate_gpu_memory,
        size_tracker);

    this->packed_results = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_results,
        num_windows, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      window_eq_buffers[i]->release(streams);
      delete window_eq_buffers[i];

      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->stream_comparisons_results[i],
                                     this->allocate_gpu_memory);
      delete stream_comparisons_results[i];

      window_reduction_buffers[i]->release(streams);
      delete window_reduction_buffers[i];
    }
    delete[] window_eq_buffers;
    delete[] stream_comparisons_results;
    delete[] window_reduction_buffers;

    this->final_reduction_buffer->release(streams);
    delete this->final_reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_results,
                                   this->allocate_gpu_memory);
    delete this->packed_results;

    sub_streams->release(streams);
    delete sub_streams;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
