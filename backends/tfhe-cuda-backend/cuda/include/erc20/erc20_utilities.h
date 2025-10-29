#pragma once
#include "../integer/integer_utilities.h"
#include "integer/comparison.h"
#include "integer/multiplication.h"
#include "integer/subtraction.h"

template <typename Torus> struct int_erc20_buffer {
  int_radix_params params;

  int_comparison_buffer<Torus> *diff_buffer;
  int_mul_memory<Torus> *mul_buffer;
  int_sc_prop_memory<Torus> *add_buffer;
  int_sub_and_propagate<Torus> *sub_buffer;
  CudaRadixCiphertextFFI *tmp_amount;
  CudaRadixCiphertextFFI *has_enough_funds;
  CudaStreams active_streams;
  CudaStreams sub_streams_1;
  CudaStreams sub_streams_2;
  cudaEvent_t *incoming_events;
  cudaEvent_t *outgoing_events1;
  cudaEvent_t *outgoing_events2;
  bool allocate_gpu_memory;

  int_erc20_buffer(CudaStreams streams, int_radix_params params,
                   uint32_t num_radix_blocks, bool allocate_gpu_memory,
                   uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    diff_buffer = new int_comparison_buffer<Torus>(
        streams, COMPARISON_TYPE::GT, params, num_radix_blocks, false,
        allocate_gpu_memory, size_tracker);
    mul_buffer = new int_mul_memory<Torus>(streams, params, false, true,
                                           num_radix_blocks,
                                           allocate_gpu_memory, size_tracker);
    add_buffer = new int_sc_prop_memory<Torus>(
        streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker);
    sub_buffer = new int_sub_and_propagate<Torus>(
        streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker);
    tmp_amount = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_amount, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    has_enough_funds = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), has_enough_funds, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    active_streams = streams.active_gpu_subset(num_radix_blocks);
    sub_streams_1.create_on_same_gpus(active_streams);
    sub_streams_2.create_on_same_gpus(active_streams);

    incoming_events =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    outgoing_events1 =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    outgoing_events2 =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    for (uint j = 0; j < active_streams.count(); j++) {
      incoming_events[j] = cuda_create_event(active_streams.gpu_index(j));
      outgoing_events1[j] = cuda_create_event(active_streams.gpu_index(j));
      outgoing_events2[j] = cuda_create_event(active_streams.gpu_index(j));
    }
  }

  void release(CudaStreams streams) {
    diff_buffer->release(streams);
    delete diff_buffer;
    diff_buffer = nullptr;
    mul_buffer->release(streams);
    delete mul_buffer;
    mul_buffer = nullptr;
    add_buffer->release(streams);
    delete add_buffer;
    add_buffer = nullptr;
    sub_buffer->release(streams);
    delete sub_buffer;
    sub_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_amount, this->allocate_gpu_memory);
    delete tmp_amount;
    tmp_amount = nullptr;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   has_enough_funds, this->allocate_gpu_memory);
    delete has_enough_funds;
    has_enough_funds = nullptr;

    // The substreams have to be synchronized before destroying events
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    // release events
    for (uint j = 0; j < active_streams.count(); j++) {
      cuda_event_destroy(incoming_events[j], active_streams.gpu_index(j));
      cuda_event_destroy(outgoing_events1[j], active_streams.gpu_index(j));
      cuda_event_destroy(outgoing_events2[j], active_streams.gpu_index(j));
    }
    free(incoming_events);
    free(outgoing_events1);
    free(outgoing_events2);

    sub_streams_1.release();
    sub_streams_2.release();
  }
};
