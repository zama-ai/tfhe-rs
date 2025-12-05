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
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_internal_streams;
  bool allocate_gpu_memory;
  Torus *preallocated_h_lut;

  int_erc20_buffer(CudaStreams streams, int_radix_params params,
                   uint32_t num_radix_blocks, bool allocate_gpu_memory,
                   uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    preallocated_h_lut = (Torus *)malloc(
        (params.glwe_dimension + 1) * params.polynomial_size * sizeof(Torus));
    diff_buffer = new int_comparison_buffer<Torus>(
        streams, COMPARISON_TYPE::GT, params, num_radix_blocks, false,
        allocate_gpu_memory, size_tracker, preallocated_h_lut);
    mul_buffer = new int_mul_memory<Torus>(
        streams, params, false, true, num_radix_blocks, allocate_gpu_memory,
        size_tracker, preallocated_h_lut);
    add_buffer = new int_sc_prop_memory<Torus>(
        streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker, preallocated_h_lut);
    sub_buffer = new int_sub_and_propagate<Torus>(
        streams, params, num_radix_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker, preallocated_h_lut);
    tmp_amount = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_amount, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    has_enough_funds = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), has_enough_funds, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    active_streams = streams.active_gpu_subset(num_radix_blocks);
    num_internal_streams = 2;
    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_internal_streams);
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

    internal_cuda_streams.release(streams);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(preallocated_h_lut);
  }
};
