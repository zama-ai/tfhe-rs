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

      auto active_streams =
          streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
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

template <typename Torus> struct int_cast_to_unsigned_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  bool requires_full_propagate;
  bool requires_sign_extension;

  int_fullprop_buffer<Torus> *prop_buffer;
  int_extend_radix_with_sign_msb_buffer<Torus> *extend_buffer;

  int_cast_to_unsigned_buffer(CudaStreams streams, int_radix_params params,
                              uint32_t num_input_blocks,
                              uint32_t target_num_blocks, bool input_is_signed,
                              bool requires_full_propagate,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->requires_full_propagate = requires_full_propagate;

    this->prop_buffer = nullptr;
    this->extend_buffer = nullptr;

    if (requires_full_propagate) {
      this->prop_buffer = new int_fullprop_buffer<Torus>(
          streams, params, allocate_gpu_memory, size_tracker);
    }

    this->requires_sign_extension =
        (target_num_blocks > num_input_blocks) && input_is_signed;

    if (this->requires_sign_extension) {
      uint32_t num_blocks_to_add = target_num_blocks - num_input_blocks;
      this->extend_buffer = new int_extend_radix_with_sign_msb_buffer<Torus>(
          streams, params, num_input_blocks, num_blocks_to_add,
          allocate_gpu_memory, size_tracker);
    }
  }

  void release(CudaStreams streams) {
    if (this->prop_buffer) {
      this->prop_buffer->release(streams);
      delete this->prop_buffer;
    }
    if (this->extend_buffer) {
      this->extend_buffer->release(streams);
      delete this->extend_buffer;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_cast_to_signed_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_input_blocks;
  uint32_t target_num_blocks;

  int_extend_radix_with_sign_msb_buffer<Torus> *extend_buffer;

  int_cast_to_signed_buffer(CudaStreams streams, int_radix_params params,
                            uint32_t num_input_blocks,
                            uint32_t target_num_blocks, bool input_is_signed,
                            bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_input_blocks = num_input_blocks;
    this->target_num_blocks = target_num_blocks;
    this->extend_buffer = nullptr;

    if (input_is_signed && target_num_blocks > num_input_blocks) {
      uint32_t num_additional_blocks = target_num_blocks - num_input_blocks;
      this->extend_buffer = new int_extend_radix_with_sign_msb_buffer<Torus>(
          streams, params, num_input_blocks, num_additional_blocks,
          allocate_gpu_memory, size_tracker);
    }
  }

  void release(CudaStreams streams) {
    if (this->extend_buffer) {
      this->extend_buffer->release(streams);
      delete this->extend_buffer;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
