#pragma once
#include "integer_utilities.h"

template <typename Torus> struct boolean_bitop_buffer {

  int_radix_params params;
  int_radix_lut<Torus> *lut;
  int_radix_lut<Torus> *message_extract_lut;

  CudaRadixCiphertextFFI *tmp_lwe_left;
  CudaRadixCiphertextFFI *tmp_lwe_right;

  BITOP_TYPE op;
  bool unchecked;
  bool gpu_memory_allocated;

  boolean_bitop_buffer(CudaStreams streams, BITOP_TYPE op, bool is_unchecked,
                       int_radix_params params, uint32_t lwe_ciphertext_count,
                       bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->op = op;
    this->params = params;
    auto active_streams = streams.active_gpu_subset(lwe_ciphertext_count);
    this->unchecked = is_unchecked;
    switch (op) {
    case BITAND:
    case BITOR:
    case BITXOR:
      lut = new int_radix_lut<Torus>(streams, params, 1, lwe_ciphertext_count,
                                     allocate_gpu_memory, size_tracker);
      {
        auto lut_bivariate_f = [op](Torus lhs, Torus rhs) -> Torus {
          if (op == BITOP_TYPE::BITAND) {
            // AND
            return lhs & rhs;
          } else if (op == BITOP_TYPE::BITOR) {
            // OR
            return lhs | rhs;
          } else {
            // XOR
            return lhs ^ rhs;
          }
        };

        // BooleanBlock can have degree 0 or 1. when ct is 0 path is hardcoded,
        // only lut for degree = 1 is generated
        generate_device_accumulator_bivariate_with_factor<Torus>(
            streams.stream(0), streams.gpu_index(0), lut->get_lut(0, 0),
            lut->get_degree(0), lut->get_max_degree(0), params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, lut_bivariate_f, 2, gpu_memory_allocated);
        lut->broadcast_lut(active_streams);
      }
      break;
    default:
      PANIC("Boolean bitwise operation type is not specified");
    }

    if (!unchecked) {
      message_extract_lut =
          new int_radix_lut<Torus>(streams, params, 1, lwe_ciphertext_count,
                                   gpu_memory_allocated, size_tracker);
      auto lut_f_message_extract = [params](Torus x) -> Torus {
        return x % params.message_modulus;
      };

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          message_extract_lut->get_lut(0, 0),
          message_extract_lut->get_degree(0),
          message_extract_lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          lut_f_message_extract, gpu_memory_allocated);
      message_extract_lut->broadcast_lut(active_streams);
    }
    tmp_lwe_left = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_lwe_left,
        lwe_ciphertext_count, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    tmp_lwe_right = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_lwe_right,
        lwe_ciphertext_count, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    if (!unchecked) {
      message_extract_lut->release(streams);
      delete message_extract_lut;
    }

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_lwe_left, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_lwe_right, gpu_memory_allocated);
    delete tmp_lwe_left;
    delete tmp_lwe_right;
    tmp_lwe_left = nullptr;
    tmp_lwe_right = nullptr;

    lut->release(streams);
    delete lut;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_bitop_buffer {

  int_radix_params params;
  int_radix_lut<Torus> *lut;
  BITOP_TYPE op;
  bool gpu_memory_allocated;

  int_bitop_buffer(CudaStreams streams, BITOP_TYPE op, int_radix_params params,
                   uint32_t num_radix_blocks, bool allocate_gpu_memory,
                   uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->op = op;
    this->params = params;
    auto active_streams = streams.active_gpu_subset(num_radix_blocks);
    switch (op) {
    case BITAND:
    case BITOR:
    case BITXOR:
      lut = new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                     allocate_gpu_memory, size_tracker);
      {
        auto lut_bivariate_f = [op](Torus lhs, Torus rhs) -> Torus {
          if (op == BITOP_TYPE::BITAND) {
            // AND
            return lhs & rhs;
          } else if (op == BITOP_TYPE::BITOR) {
            // OR
            return lhs | rhs;
          } else {
            // XOR
            return lhs ^ rhs;
          }
        };

        generate_device_accumulator_bivariate<Torus>(
            streams.stream(0), streams.gpu_index(0), lut->get_lut(0, 0),
            lut->get_degree(0), lut->get_max_degree(0), params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, lut_bivariate_f, gpu_memory_allocated);
        lut->broadcast_lut(active_streams);
      }
      break;
    default:
      // Scalar OP
      lut = new int_radix_lut<Torus>(streams, params, params.message_modulus,
                                     num_radix_blocks, allocate_gpu_memory,
                                     size_tracker);

      for (int i = 0; i < params.message_modulus; i++) {
        auto rhs = i;

        auto lut_univariate_scalar_f = [op, rhs](Torus x) -> Torus {
          if (op == BITOP_TYPE::SCALAR_BITAND) {
            // AND
            return x & rhs;
          } else if (op == BITOP_TYPE::SCALAR_BITOR) {
            // OR
            return x | rhs;
          } else {
            // XOR
            return x ^ rhs;
          }
        };
        generate_device_accumulator<Torus>(
            streams.stream(0), streams.gpu_index(0), lut->get_lut(0, i),
            lut->get_degree(i), lut->get_max_degree(i), params.glwe_dimension,
            params.polynomial_size, params.message_modulus,
            params.carry_modulus, lut_univariate_scalar_f,
            gpu_memory_allocated);
        lut->broadcast_lut(active_streams);
      }
    }
  }

  void release(CudaStreams streams) {
    lut->release(streams);
    delete lut;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct boolean_bitnot_buffer {
  int_radix_params params;
  int_radix_lut<Torus> *message_extract_lut;
  bool gpu_memory_allocated;
  bool unchecked;
  boolean_bitnot_buffer(CudaStreams streams, int_radix_params params,
                        uint32_t lwe_ciphertext_count, bool is_unchecked,
                        bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    unchecked = is_unchecked;
    this->params = params;

    auto message_modulus = params.message_modulus;

    if (!unchecked) {
      message_extract_lut =
          new int_radix_lut<Torus>(streams, params, 1, lwe_ciphertext_count,
                                   gpu_memory_allocated, size_tracker);
      auto lut_f_message_extract = [message_modulus](Torus x) -> Torus {
        return x % message_modulus;
      };

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0),
          message_extract_lut->get_lut(0, 0),
          message_extract_lut->get_degree(0),
          message_extract_lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          lut_f_message_extract, gpu_memory_allocated);
      auto active_streams = streams.active_gpu_subset(lwe_ciphertext_count);
      message_extract_lut->broadcast_lut(active_streams);
    }
  }

  void release(CudaStreams streams) {
    if (!unchecked) {
      message_extract_lut->release(streams);
      delete message_extract_lut;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

void update_degrees_after_bitand(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks);
void update_degrees_after_bitor(uint64_t *output_degrees,
                                uint64_t *lwe_array_1_degrees,
                                uint64_t *lwe_array_2_degrees,
                                uint32_t num_radix_blocks);
void update_degrees_after_bitxor(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks);
void update_degrees_after_scalar_bitand(uint64_t *output_degrees,
                                        uint64_t const *clear_degrees,
                                        uint64_t const *input_degrees,
                                        uint32_t num_clear_blocks);
void update_degrees_after_scalar_bitor(uint64_t *output_degrees,
                                       uint64_t const *clear_degrees,
                                       uint64_t const *input_degrees,
                                       uint32_t num_clear_blocks);
void update_degrees_after_scalar_bitxor(uint64_t *output_degrees,
                                        uint64_t const *clear_degrees,
                                        uint64_t const *input_degrees,
                                        uint32_t num_clear_blocks);
