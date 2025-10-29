#pragma once
#include "erc20/erc20.h"
#include "erc20/erc20_utilities.h"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/multiplication.cuh"
#include "integer/subtraction.cuh"

template <typename Torus, class params>
__host__ void host_erc20_assign(CudaStreams streams,
                                CudaRadixCiphertextFFI *from_amount,
                                CudaRadixCiphertextFFI *to_amount,
                                CudaRadixCiphertextFFI const *amount,
                                int_erc20_buffer<Torus> *mem_ptr,
                                void *const *bsks, Torus *const *ksks) {
  auto num_radix_blocks = from_amount->num_radix_blocks;
  host_difference_check<Torus>(streams, mem_ptr->has_enough_funds, from_amount,
                               amount, mem_ptr->diff_buffer,
                               mem_ptr->diff_buffer->diff_buffer->operator_f,
                               bsks, ksks, num_radix_blocks);
  host_integer_mult_radix<Torus, params>(
      streams, mem_ptr->tmp_amount, amount, false, mem_ptr->has_enough_funds,
      true, bsks, ksks, mem_ptr->mul_buffer, num_radix_blocks);
  cuda_event_record(mem_ptr->incoming_events[0], streams.stream(0),
                    streams.gpu_index(0));
  for (int j = 0; j < mem_ptr->active_streams.count(); j++) {
    cuda_stream_wait_event(mem_ptr->sub_streams_1.stream(j),
                           mem_ptr->incoming_events[0],
                           mem_ptr->sub_streams_1.gpu_index(j));
    cuda_stream_wait_event(mem_ptr->sub_streams_2.stream(j),
                           mem_ptr->incoming_events[0],
                           mem_ptr->sub_streams_1.gpu_index(j));
  }

  // stream1
  host_add_and_propagate_single_carry(
      mem_ptr->sub_streams_1, to_amount, mem_ptr->tmp_amount, nullptr, nullptr,
      mem_ptr->add_buffer, bsks, ksks, FLAG_NONE, 0);
  for (int j = 0; j < mem_ptr->active_streams.count(); j++) {
    cuda_event_record(mem_ptr->outgoing_events1[j],
                      mem_ptr->sub_streams_1.stream(j),
                      mem_ptr->sub_streams_1.gpu_index(j));
  }
  // stream2
  host_sub_and_propagate_single_carry(
      mem_ptr->sub_streams_2, to_amount, mem_ptr->tmp_amount, nullptr, nullptr,
      mem_ptr->sub_buffer, bsks, ksks, FLAG_NONE, 0);
  for (int j = 0; j < mem_ptr->active_streams.count(); j++) {
    cuda_event_record(mem_ptr->outgoing_events2[j],
                      mem_ptr->sub_streams_2.stream(j),
                      mem_ptr->sub_streams_2.gpu_index(j));
    cuda_stream_wait_event(streams.stream(0), mem_ptr->outgoing_events1[j],
                           streams.gpu_index(0));
    cuda_stream_wait_event(streams.stream(0), mem_ptr->outgoing_events2[j],
                           streams.gpu_index(0));
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_erc20(CudaStreams streams,
                                     int_erc20_buffer<Torus> **mem_ptr,
                                     uint32_t num_radix_blocks,
                                     int_radix_params params,
                                     bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_erc20_buffer<Torus>(streams, params, num_radix_blocks,
                                         allocate_gpu_memory, size_tracker);
  return size_tracker;
}
