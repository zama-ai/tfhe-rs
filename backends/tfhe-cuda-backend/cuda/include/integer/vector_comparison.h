#pragma once
#include "helper_multi_gpu.h"
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"

const uint32_t MAX_STREAMS_FOR_VECTOR_COMPARISON = 8;

template <typename Torus> struct int_unchecked_all_eq_slices_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_results;

  CudaStreams active_streams;

  CudaStreams *sub_streams;
  cudaEvent_t incoming_event;
  cudaEvent_t *outgoing_events;
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
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    uint32_t num_gpus = active_streams.count();

    this->sub_streams = nullptr;
    this->outgoing_events = nullptr;
    this->incoming_event = nullptr;

    if (num_streams_to_use > 0) {
      this->sub_streams = new CudaStreams[num_streams_to_use];
      for (uint32_t i = 0; i < num_streams_to_use; ++i) {
        this->sub_streams[i].create_on_same_gpus(active_streams);
      }
    }

    if (num_gpus > 0) {
      this->incoming_event = cuda_create_event(active_streams.gpu_index(0));
    }

    uint32_t total_events = num_streams_to_use * num_gpus;
    if (total_events > 0) {
      this->outgoing_events = new cudaEvent_t[total_events];
      for (uint32_t s = 0; s < num_streams_to_use; ++s) {
        for (uint32_t g = 0; g < num_gpus; ++g) {
          this->outgoing_events[s * num_gpus + g] =
              cuda_create_event(active_streams.gpu_index(g));
        }
      }
    }

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

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    if (this->outgoing_events && this->sub_streams) {
      for (uint32_t s = 0; s < this->num_streams; ++s) {
        for (uint32_t g = 0; g < active_streams.count(); ++g) {
          cuda_event_destroy(
              this->outgoing_events[s * active_streams.count() + g],
              this->sub_streams[s].gpu_index(g));
        }
      }
      delete[] this->outgoing_events;
      this->outgoing_events = nullptr;
    }

    if (this->incoming_event && this->sub_streams) {
      cuda_event_destroy(this->incoming_event,
                         this->sub_streams[0].gpu_index(0));
      this->incoming_event = nullptr;
    }

    if (this->sub_streams) {
      for (uint32_t i = 0; i < this->num_streams; ++i) {
        this->sub_streams[i].release();
      }
      delete[] this->sub_streams;
      this->sub_streams = nullptr;
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_sub_slice_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_windows;

  int_unchecked_all_eq_slices_buffer<Torus> *all_eq_buffer;
  CudaRadixCiphertextFFI *packed_results;
  int_comparison_buffer<Torus> *final_reduction_buffer;

  int_unchecked_contains_sub_slice_buffer(CudaStreams streams,
                                          int_radix_params params,
                                          uint32_t num_lhs, uint32_t num_rhs,
                                          uint32_t num_blocks,
                                          bool allocate_gpu_memory,
                                          uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_windows = num_lhs - num_rhs + 1;

    this->all_eq_buffer = new int_unchecked_all_eq_slices_buffer<Torus>(
        streams, params, num_rhs, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->packed_results = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_results,
        this->num_windows, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->final_reduction_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, this->num_windows, false, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->all_eq_buffer->release(streams);
    delete this->all_eq_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_results,
                                   this->allocate_gpu_memory);
    delete this->packed_results;

    this->final_reduction_buffer->release(streams);
    delete this->final_reduction_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
