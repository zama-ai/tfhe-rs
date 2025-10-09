#pragma once
#include "integer_utilities.h"

template <typename Torus> struct int_logical_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  CudaRadixCiphertextFFI *tmp_rotated;

  bool reuse_memory = false;
  bool gpu_memory_allocated;

  int_logical_scalar_shift_buffer(CudaStreams streams,
                                  SHIFT_OR_ROTATE_TYPE shift_type,
                                  int_radix_params params,
                                  uint32_t num_radix_blocks,
                                  bool allocate_gpu_memory,
                                  uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->shift_type = shift_type;
    this->params = params;

    uint32_t max_amount_of_pbs = num_radix_blocks;

    tmp_rotated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_rotated,
        max_amount_of_pbs + 2, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

    // LUT
    // pregenerate lut vector and indexes
    // lut for left shift
    // here we generate 'num_bits_in_block' times lut
    // one for each 'shift_within_block' = 'shift' % 'num_bits_in_block'
    // even though lut_left contains 'num_bits_in_block' lut
    // lut_indexes_vec will have indexes for single lut only and those indexes
    // will be 0 it means for pbs corresponding lut should be selected and
    // pass along lut_indexes_vec filled with zeros

    // calculate bivariate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto cur_lut_bivariate =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus, Torus)> shift_lut_f;

      if (shift_type == LEFT_SHIFT) {
        shift_lut_f = [shift_within_block, params](
                          Torus current_block, Torus previous_block) -> Torus {
          current_block = current_block << shift_within_block;
          previous_block = previous_block << shift_within_block;

          Torus message_of_current_block =
              current_block % params.message_modulus;
          Torus carry_of_previous_block =
              previous_block / params.message_modulus;
          return message_of_current_block + carry_of_previous_block;
        };
      } else {
        shift_lut_f = [num_bits_in_block, shift_within_block,
                       params](Torus current_block, Torus next_block) -> Torus {
          // left shift so as not to lose
          // bits when shifting right afterwards
          next_block <<= num_bits_in_block;
          next_block >>= shift_within_block;

          // The way of getting carry / message is reversed compared
          // to the usual way but its normal:
          // The message is in the upper bits, the carry in lower bits
          Torus message_of_current_block = current_block >> shift_within_block;
          Torus carry_of_previous_block = next_block % params.message_modulus;

          return message_of_current_block + carry_of_previous_block;
        };
      }

      // right shift
      generate_device_accumulator_bivariate<Torus>(
          streams.stream(0), streams.gpu_index(0),
          cur_lut_bivariate->get_lut(0, 0), cur_lut_bivariate->get_degree(0),
          cur_lut_bivariate->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          shift_lut_f, gpu_memory_allocated);
      auto active_streams = streams.active_gpu_subset(num_radix_blocks);
      cur_lut_bivariate->broadcast_lut(active_streams);

      lut_buffers_bivariate.push_back(cur_lut_bivariate);
    }
  }

  int_logical_scalar_shift_buffer(CudaStreams streams,
                                  SHIFT_OR_ROTATE_TYPE shift_type,
                                  int_radix_params params,
                                  uint32_t num_radix_blocks,
                                  bool allocate_gpu_memory,
                                  CudaRadixCiphertextFFI *pre_allocated_buffer,
                                  uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->shift_type = shift_type;
    this->params = params;
    tmp_rotated = pre_allocated_buffer;
    reuse_memory = true;

    if (allocate_gpu_memory)
      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), tmp_rotated, 0,
          tmp_rotated->num_radix_blocks);

    uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

    // LUT
    // pregenerate lut vector and indexes
    // lut for left shift
    // here we generate 'num_bits_in_block' times lut
    // one for each 'shift_within_block' = 'shift' % 'num_bits_in_block'
    // even though lut_left contains 'num_bits_in_block' lut
    // lut_indexes_vec will have indexes for single lut only and those indexes
    // will be 0 it means for pbs corresponding lut should be selected and
    // pass along lut_indexes_vec filled with zeros

    // calculate bivariate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto cur_lut_bivariate =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus, Torus)> shift_lut_f;

      if (shift_type == LEFT_SHIFT) {
        shift_lut_f = [shift_within_block, params](
                          Torus current_block, Torus previous_block) -> Torus {
          current_block = current_block << shift_within_block;
          previous_block = previous_block << shift_within_block;

          Torus message_of_current_block =
              current_block % params.message_modulus;
          Torus carry_of_previous_block =
              previous_block / params.message_modulus;
          return message_of_current_block + carry_of_previous_block;
        };
      } else {
        shift_lut_f = [num_bits_in_block, shift_within_block,
                       params](Torus current_block, Torus next_block) -> Torus {
          // left shift so as not to lose
          // bits when shifting right afterwards
          next_block <<= num_bits_in_block;
          next_block >>= shift_within_block;

          // The way of getting carry / message is reversed compared
          // to the usual way but its normal:
          // The message is in the upper bits, the carry in lower bits
          Torus message_of_current_block = current_block >> shift_within_block;
          Torus carry_of_previous_block = next_block % params.message_modulus;

          return message_of_current_block + carry_of_previous_block;
        };
      }

      // right shift
      generate_device_accumulator_bivariate<Torus>(
          streams.stream(0), streams.gpu_index(0),
          cur_lut_bivariate->get_lut(0, 0), cur_lut_bivariate->get_degree(0),
          cur_lut_bivariate->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          shift_lut_f, gpu_memory_allocated);
      auto active_streams = streams.active_gpu_subset(num_radix_blocks);
      cur_lut_bivariate->broadcast_lut(active_streams);

      lut_buffers_bivariate.push_back(cur_lut_bivariate);
    }
  }
  void release(CudaStreams streams) {
    for (auto &buffer : lut_buffers_bivariate) {
      buffer->release(streams);
      delete buffer;
    }
    lut_buffers_bivariate.clear();

    if (!reuse_memory) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_rotated, gpu_memory_allocated);
      delete tmp_rotated;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_arithmetic_scalar_shift_buffer {
  int_radix_params params;
  std::vector<int_radix_lut<Torus> *> lut_buffers_univariate;
  std::vector<int_radix_lut<Torus> *> lut_buffers_bivariate;

  SHIFT_OR_ROTATE_TYPE shift_type;

  CudaRadixCiphertextFFI *tmp_rotated;

  CudaStreams local_streams_1;
  CudaStreams local_streams_2;
  bool gpu_memory_allocated;

  int_arithmetic_scalar_shift_buffer(CudaStreams streams,
                                     SHIFT_OR_ROTATE_TYPE shift_type,
                                     int_radix_params params,
                                     uint32_t num_radix_blocks,
                                     bool allocate_gpu_memory,
                                     uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;

    auto active_streams = streams.active_gpu_subset(1);
    // In the arithmetic shift, a PBS has to be applied to the last rotated
    // block twice: once to shift it, once to compute the padding block to be
    // copied onto all blocks to the left of the last rotated block
    local_streams_1.create_on_same_gpus(active_streams);
    local_streams_2.create_on_same_gpus(active_streams);
    this->shift_type = shift_type;
    this->params = params;

    tmp_rotated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_rotated,
        num_radix_blocks + 3, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint32_t num_bits_in_block = (uint32_t)std::log2(params.message_modulus);

    // LUT
    // pregenerate lut vector and indexes lut

    // lut to shift the last block
    // calculate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    // With two bits of message this is actually only one LUT.
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto shift_last_block_lut_univariate = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus)> last_block_lut_f;
      last_block_lut_f = [num_bits_in_block, shift_within_block,
                          params](Torus x) -> Torus {
        x = x % params.message_modulus;
        uint32_t x_sign_bit = x >> (num_bits_in_block - 1) & 1;
        uint32_t shifted = x >> shift_within_block;
        // padding is a message full of 1 if sign bit is one
        // else padding is a zero message
        uint32_t padding = (params.message_modulus - 1) * x_sign_bit;

        // Make padding have 1s only in places where bits
        // where actually need to be padded
        padding <<= num_bits_in_block - shift_within_block;
        padding %= params.message_modulus;

        return shifted | padding;
      };

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          shift_last_block_lut_univariate->get_lut(0, 0),
          shift_last_block_lut_univariate->get_degree(0),
          shift_last_block_lut_univariate->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, last_block_lut_f, gpu_memory_allocated);
      auto active_streams_shift_last = streams.active_gpu_subset(1);
      shift_last_block_lut_univariate->broadcast_lut(active_streams_shift_last);

      lut_buffers_univariate.push_back(shift_last_block_lut_univariate);
    }

    auto padding_block_lut_univariate = new int_radix_lut<Torus>(
        streams, params, 1, 1, allocate_gpu_memory, size_tracker);

    // lut to compute the padding block
    std::function<Torus(Torus)> padding_block_lut_f;
    padding_block_lut_f = [num_bits_in_block, params](Torus x) -> Torus {
      x = x % params.message_modulus;
      uint32_t x_sign_bit = x >> (num_bits_in_block - 1) & 1;
      // padding is a message full of 1 if sign bit is one
      // else padding is a zero message
      return (params.message_modulus - 1) * x_sign_bit;
    };

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        padding_block_lut_univariate->get_lut(0, 0),
        padding_block_lut_univariate->get_degree(0),
        padding_block_lut_univariate->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        padding_block_lut_f, gpu_memory_allocated);
    // auto active_streams = streams.active_gpu_subset(1);
    padding_block_lut_univariate->broadcast_lut(active_streams);

    lut_buffers_univariate.push_back(padding_block_lut_univariate);

    // lut to shift the first blocks
    // calculate lut for each 'shift_within_block'
    // so that in case an application calls scratches only once for a whole
    // circuit it can reuse memory for different shift values
    // NB: with two bits of message, this is actually only one LUT.
    for (int s_w_b = 1; s_w_b < num_bits_in_block; s_w_b++) {
      auto shift_blocks_lut_bivariate =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);

      uint32_t shift_within_block = s_w_b;

      std::function<Torus(Torus, Torus)> blocks_lut_f;
      blocks_lut_f = [num_bits_in_block, shift_within_block,
                      params](Torus current_block, Torus next_block) -> Torus {
        // left shift so as not to lose
        // bits when shifting right after
        next_block <<= num_bits_in_block;
        next_block >>= shift_within_block;

        // The way of getting carry / message is reversed compared
        // to the usual way but its normal:
        // The message is in the upper bits, the carry in lower bits
        uint32_t message_of_current_block = current_block >> shift_within_block;
        uint32_t carry_of_previous_block = next_block % params.message_modulus;

        return message_of_current_block + carry_of_previous_block;
      };

      generate_device_accumulator_bivariate<Torus>(
          streams.stream(0), streams.gpu_index(0),
          shift_blocks_lut_bivariate->get_lut(0, 0),
          shift_blocks_lut_bivariate->get_degree(0),
          shift_blocks_lut_bivariate->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          blocks_lut_f, gpu_memory_allocated);
      auto active_streams_shift_blocks =
          streams.active_gpu_subset(num_radix_blocks);
      shift_blocks_lut_bivariate->broadcast_lut(active_streams_shift_blocks);

      lut_buffers_bivariate.push_back(shift_blocks_lut_bivariate);
    }
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_rotated, gpu_memory_allocated);
    for (auto &buffer : lut_buffers_bivariate) {
      buffer->release(streams);
      delete buffer;
    }
    for (auto &buffer : lut_buffers_univariate) {
      buffer->release(streams);
      delete buffer;
    }
    lut_buffers_bivariate.clear();
    lut_buffers_univariate.clear();

    delete tmp_rotated;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    local_streams_1.release();
    local_streams_2.release();
  }
};
