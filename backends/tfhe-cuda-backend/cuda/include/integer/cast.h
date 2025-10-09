#pragma once
#include "integer_utilities.h"

template <typename Torus> struct int_extend_radix_with_sign_msb_buffer {

  int_radix_params params;
  bool allocate_gpu_memory;

  int_radix_lut<Torus> *lut = nullptr;

  CudaRadixCiphertextFFI *last_block = nullptr;
  CudaRadixCiphertextFFI *padding_block = nullptr;

  int_extend_radix_with_sign_msb_buffer(CudaStreams streams,
                                        const int_radix_params params,
                                        uint32_t num_radix_blocks,
                                        uint32_t num_additional_blocks,
                                        const bool allocate_gpu_memory,
                                        uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    if (num_additional_blocks != 0) {
      this->lut = new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                           allocate_gpu_memory, size_tracker);

      uint32_t bits_per_block = std::log2(params.message_modulus);
      uint32_t msg_modulus = params.message_modulus;

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), lut->get_lut(0, 0),
          lut->get_degree(0), lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          [msg_modulus, bits_per_block](Torus x) {
            const auto xm = x % msg_modulus;
            const auto sign_bit = (xm >> (bits_per_block - 1)) & 1;
            return (Torus)((msg_modulus - 1) * sign_bit);
          },
          allocate_gpu_memory);

      auto active_streams = streams.active_gpu_subset(num_radix_blocks);
      lut->broadcast_lut(active_streams);

      this->last_block = new CudaRadixCiphertextFFI;

      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), last_block, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      this->padding_block = new CudaRadixCiphertextFFI;

      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), padding_block, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }
  }

  void release(CudaStreams streams) {

    if (lut != nullptr) {
      lut->release(streams);
      delete lut;
    }
    if (last_block != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     last_block, allocate_gpu_memory);
      delete last_block;
    }
    if (padding_block != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     padding_block, allocate_gpu_memory);
      delete padding_block;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
