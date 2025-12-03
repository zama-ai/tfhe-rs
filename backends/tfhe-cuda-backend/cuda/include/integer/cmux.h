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
    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);

    tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }
  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), tmp,
                                   gpu_memory_allocated);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete tmp;
    tmp = nullptr;
  }
};

/// @brief GPU scratch buffer for batched zero_out_if.
///
/// Holds the packed intermediate ciphertext used to combine each input block
/// with its per-entry boolean condition before a single batched PBS call.
template <typename Torus> struct int_zero_out_if_batch_buffer {

  int_radix_params params;

  /// Packed bivariate input for the predicate PBS
  CudaRadixCiphertextFFI *tmp;

  bool gpu_memory_allocated;

  /// @brief Allocates the packed intermediate ciphertext for batched
  /// zero_out_if.
  ///
  /// @param num_entries        Number of ciphertexts in the batch
  /// @param num_blocks_per_ct  Number of radix blocks per ciphertext
  int_zero_out_if_batch_buffer(CudaStreams streams, int_radix_params params,
                               uint32_t num_entries, uint32_t num_blocks_per_ct,
                               bool allocate_gpu_memory,
                               uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->params = params;
    uint32_t total_num_blocks =
        static_cast<uint32_t>(safe_mul((size_t)num_entries, num_blocks_per_ct));

    tmp = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp, total_num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }
  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), tmp,
                                   gpu_memory_allocated);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete tmp;
    tmp = nullptr;
  }
};

template <typename Torus> struct int_cmux_buffer {
  int_radix_lut<Torus> *predicate_lut;
  /// Univariate LUT for message extraction after addition
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
                  bool allocate_gpu_memory, uint64_t &size_tracker,
                  Torus *preallocated_h_lut = nullptr) {
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

    auto active_streams_pred =
        streams.active_gpu_subset(2 * num_radix_blocks, params.pbs_type);
    auto lut_index_generator = [num_radix_blocks](Torus *h_lut_indexes,
                                                  uint32_t num_indexes) {
      for (int index = 0; index < 2 * num_radix_blocks; index++) {
        if (index < num_radix_blocks) {
          h_lut_indexes[index] = 0;
        } else {
          h_lut_indexes[index] = 1;
        }
      }
    };

    predicate_lut->generate_and_broadcast_bivariate_lut(
        active_streams_pred, {0, 1}, {inverted_lut_f, lut_f},
        lut_index_generator);

    auto active_streams_msg =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);

    message_extract_lut->generate_and_broadcast_lut(
        active_streams_msg, {0}, {message_extract_lut_f}, LUT_0_FOR_ALL_BLOCKS);
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

/// @brief GPU scratch buffer for batched CMUX.
///
/// Preallocates LUTs and intermediate ciphertext buffers needed to evaluate
/// N independent CMUX selections in a single batched PBS pass.
template <typename Torus> struct int_cmux_batch_buffer {
  /// Bivariate LUT that zeroes the non-selected branch
  int_radix_lut<Torus> *predicate_lut;
  /// Univariate LUT for message extraction after addition
  int_radix_lut<Torus> *message_extract_lut;

  /// Packed bivariate input (true + false regions)
  CudaRadixCiphertextFFI *tmp_packed;
  /// PBS output for both branches before addition
  CudaRadixCiphertextFFI *buffer_out;

  int_radix_params params;
  bool allocate_gpu_memory;
  bool gpu_memory_allocated;

  /// @brief Allocates LUTs and intermediate buffers for batched CMUX.
  ///
  /// @param predicate_lut_f    Predicate function used to build the CMUX
  /// selection LUT
  /// @param num_entries        Number of CMUX entries in the batch
  /// @param num_blocks_per_ct  Number of radix blocks per ciphertext
  int_cmux_batch_buffer(CudaStreams streams,
                        std::function<Torus(Torus)> predicate_lut_f,
                        int_radix_params params, uint32_t num_entries,
                        uint32_t num_blocks_per_ct, bool allocate_gpu_memory,
                        uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    uint32_t total_num_blocks =
        static_cast<uint32_t>(safe_mul(static_cast<size_t>(num_entries),
                                       static_cast<size_t>(num_blocks_per_ct)));

    tmp_packed = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_packed,
        2 * total_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    buffer_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), buffer_out,
        2 * total_num_blocks, params.big_lwe_dimension, size_tracker,
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
        new int_radix_lut<Torus>(streams, params, 2, 2 * total_num_blocks,
                                 allocate_gpu_memory, size_tracker);

    message_extract_lut =
        new int_radix_lut<Torus>(streams, params, 1, total_num_blocks,
                                 allocate_gpu_memory, size_tracker);

    auto active_streams_pred =
        streams.active_gpu_subset(2 * total_num_blocks, params.pbs_type);
    auto lut_index_generator = [total_num_blocks](Torus *h_lut_indexes,
                                                  uint32_t num_indexes) {
      for (uint32_t index = 0; index < 2 * total_num_blocks; index++) {
        h_lut_indexes[index] = (index < total_num_blocks) ? 0 : 1;
      }
    };

    predicate_lut->generate_and_broadcast_bivariate_lut(
        active_streams_pred, {0, 1}, {inverted_lut_f, lut_f},
        lut_index_generator);

    auto active_streams_msg =
        streams.active_gpu_subset(total_num_blocks, params.pbs_type);

    message_extract_lut->generate_and_broadcast_lut(
        active_streams_msg, {0}, {message_extract_lut_f}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    predicate_lut->release(streams);
    delete predicate_lut;
    message_extract_lut->release(streams);
    delete message_extract_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_packed, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   buffer_out, gpu_memory_allocated);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    delete tmp_packed;
    delete buffer_out;
  }
};
