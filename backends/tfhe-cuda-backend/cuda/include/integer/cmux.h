#pragma once
#include "integer_utilities.h"

template <typename Torus> struct int_zero_out_if_buffer {

  int_radix_params params;

  CudaRadixCiphertextFFI *tmp;

  bool gpu_memory_allocated;

  int_zero_out_if_buffer(CudaStreams streams, int_radix_params params,
                         uint32_t num_radix_blocks, bool allocate_gpu_memory,
                         uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    auto active_streams = streams.active_gpu_subset(num_radix_blocks);

    tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }
  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), tmp,
                                   gpu_memory_allocated);
    delete tmp;
    tmp = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
template <typename Torus> struct int_cmux_buffer {
  int_radix_lut<Torus> *predicate_lut;
  int_radix_lut<Torus> *message_extract_lut;

  CudaRadixCiphertextFFI *buffer_in;
  CudaRadixCiphertextFFI *buffer_out;
  CudaRadixCiphertextFFI *condition_array;

  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;
  int_cmux_buffer(CudaStreams streams,
                  std::function<Torus(Torus)> predicate_lut_f,
                  int_radix_params params, uint32_t num_radix_blocks,
                  bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    buffer_in = new CudaRadixCiphertextFFI;
    buffer_out = new CudaRadixCiphertextFFI;
    condition_array = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), buffer_in,
        2 * num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), buffer_out,
        2 * num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), condition_array,
        2 * num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    auto lut_f = [predicate_lut_f](Torus block, Torus condition) -> Torus {
      return predicate_lut_f(condition) ? 0 : block;
    };
    auto inverted_lut_f = [predicate_lut_f](Torus block,
                                            Torus condition) -> Torus {
      return predicate_lut_f(condition) ? block : 0;
    };
    auto message_extract_lut_f = [params](Torus x) -> Torus {
      return x % params.message_modulus;
    };

    predicate_lut =
        new int_radix_lut<Torus>(streams, params, 2, 2 * num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    message_extract_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), predicate_lut->get_lut(0, 0),
        predicate_lut->get_degree(0), predicate_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, inverted_lut_f, gpu_memory_allocated);

    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), predicate_lut->get_lut(0, 1),
        predicate_lut->get_degree(1), predicate_lut->get_max_degree(1),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, lut_f, gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        message_extract_lut->get_lut(0, 0), message_extract_lut->get_degree(0),
        message_extract_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        message_extract_lut_f, gpu_memory_allocated);
    Torus *h_lut_indexes = predicate_lut->h_lut_indexes;
    for (int index = 0; index < 2 * num_radix_blocks; index++) {
      if (index < num_radix_blocks) {
        h_lut_indexes[index] = 0;
      } else {
        h_lut_indexes[index] = 1;
      }
    }
    cuda_memcpy_with_size_tracking_async_to_gpu(
        predicate_lut->get_lut_indexes(0, 0), h_lut_indexes,
        2 * num_radix_blocks * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);
    auto active_streams_pred = streams.active_gpu_subset(2 * num_radix_blocks);
    predicate_lut->broadcast_lut(active_streams_pred);
    auto active_streams_msg = streams.active_gpu_subset(num_radix_blocks);
    message_extract_lut->broadcast_lut(active_streams_msg);
  }

  void release(CudaStreams streams) {
    predicate_lut->release(streams);
    delete predicate_lut;
    message_extract_lut->release(streams);
    delete message_extract_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   buffer_in, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   buffer_out, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   condition_array, gpu_memory_allocated);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete buffer_in;
    delete buffer_out;
    delete condition_array;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
