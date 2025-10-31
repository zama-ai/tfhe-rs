#pragma once
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"

template <typename Torus> struct int_equality_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *tmp_block_comparisons;

  int_comparison_buffer<Torus> *comparison_buffer;

  uint32_t num_possible_values;
  uint32_t num_blocks_in_value;

  int_equality_selectors_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_possible_values,
                                uint32_t num_blocks_in_value,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_possible_values = num_possible_values;
    this->num_blocks_in_value = num_blocks_in_value;

    this->tmp_block_comparisons = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_block_comparisons,
        num_blocks_in_value, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->comparison_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_blocks_in_value, false, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_block_comparisons,
                                   this->allocate_gpu_memory);
    delete this->tmp_block_comparisons;

    this->comparison_buffer->release(streams);
    delete this->comparison_buffer;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
