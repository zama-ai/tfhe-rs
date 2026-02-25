#pragma once
#include "cast.h"
#include "helper_multi_gpu.h"
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"
#include <functional>
#include <vector>

// If we use more than 5 streams the result is incorrect
const uint32_t MAX_STREAMS_FOR_VECTOR_FIND = 5;

template <typename Torus> struct int_equality_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t lut_stride;

  uint32_t num_possible_values;
  int_radix_lut<Torus> *comparison_luts;
  CudaRadixCiphertextFFI *tmp_many_luts_output;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  CudaRadixCiphertextFFI **tmp_block_comparisons;
  int_comparison_buffer<Torus> **reduction_buffers;

  int_equality_selectors_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_possible_values,
                                uint32_t num_blocks, bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_possible_values = num_possible_values;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_possible_values);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;

    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    uint32_t ciphertext_modulus = params.message_modulus * params.carry_modulus;
    uint32_t box_size = params.polynomial_size / ciphertext_modulus;
    lut_stride = (ciphertext_modulus / params.message_modulus) * box_size;

    this->comparison_luts = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, params.message_modulus,
        allocate_gpu_memory, size_tracker);

    std::vector<std::function<Torus(Torus)>> fns;
    fns.reserve(params.message_modulus);
    for (uint32_t i = 0; i < params.message_modulus; i++) {
      fns.push_back([i](Torus x) -> Torus { return (x == i); });
    }

    this->comparison_luts->generate_and_broadcast_many_lut(
        active_streams, {0}, {fns}, LUT_0_FOR_ALL_BLOCKS);
    fns.clear();

    this->tmp_many_luts_output = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_many_luts_output,
        params.message_modulus * num_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->tmp_block_comparisons =
        new CudaRadixCiphertextFFI *[this->num_streams];
    this->reduction_buffers =
        new int_comparison_buffer<Torus> *[this->num_streams];
    for (uint32_t j = 0; j < this->num_streams; j++) {
      this->tmp_block_comparisons[j] = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->tmp_block_comparisons[j], num_blocks, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);

      this->reduction_buffers[j] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }
  }

  void release(CudaStreams streams) {
    this->comparison_luts->release(streams);
    delete this->comparison_luts;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_many_luts_output,
                                   this->allocate_gpu_memory);
    delete this->tmp_many_luts_output;

    for (uint32_t i = 0; i < this->num_streams; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_block_comparisons[i],
                                     this->allocate_gpu_memory);
      delete this->tmp_block_comparisons[i];
    }
    delete[] this->tmp_block_comparisons;

    for (uint32_t i = 0; i < this->num_streams; i++) {
      this->reduction_buffers[i]->release(streams);
      delete this->reduction_buffers[i];
    }
    delete[] this->reduction_buffers;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_possible_results_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t max_packed_value;
  uint32_t max_luts_per_call;
  uint32_t num_lut_accumulators;
  uint32_t lut_stride;

  int_radix_lut<Torus> **stream_luts;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  CudaRadixCiphertextFFI **tmp_many_luts_output;

  int_possible_results_buffer(CudaStreams streams, int_radix_params params,
                              uint32_t num_blocks, uint32_t num_possible_values,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_possible_values);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;

    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->max_packed_value = params.message_modulus * params.message_modulus;
    uint32_t total_luts_needed = this->max_packed_value;

    uint32_t ciphertext_modulus = params.message_modulus * params.carry_modulus;
    uint32_t box_size = params.polynomial_size / ciphertext_modulus;

    this->max_luts_per_call = (ciphertext_modulus) / 2;
    if (this->max_luts_per_call == 0) {
      this->max_luts_per_call = 1;
    }

    this->lut_stride =
        (ciphertext_modulus / this->max_luts_per_call) * box_size;

    this->num_lut_accumulators = CEIL_DIV(total_luts_needed, max_luts_per_call);

    stream_luts =
        new int_radix_lut<Torus> *[num_streams * num_lut_accumulators];

    std::vector<std::function<Torus(Torus)>> fns;
    fns.reserve(max_luts_per_call);

    uint32_t lut_count = 0;
    for (uint32_t s = 0; s < num_streams; s++) {
      uint32_t lut_value_start = 0;

      for (uint32_t i = 0; i < num_lut_accumulators; i++) {
        fns.clear();
        uint32_t luts_in_this_call =
            std::min(max_luts_per_call, total_luts_needed - lut_value_start);

        int_radix_lut<Torus> *current_lut =
            new int_radix_lut<Torus>(streams, params, 1, 1, luts_in_this_call,
                                     allocate_gpu_memory, size_tracker);

        for (uint32_t j = 0; j < luts_in_this_call; j++) {
          uint32_t c = lut_value_start + j;
          fns.push_back([c](Torus x) -> Torus { return (x == 1) * c; });
        }

        current_lut->generate_and_broadcast_many_lut(
            streams.active_gpu_subset(1, params.pbs_type), {0}, {fns},
            LUT_0_FOR_ALL_BLOCKS);

        stream_luts[lut_count++] = current_lut;
        lut_value_start += luts_in_this_call;
      }
    }
    fns.clear();

    this->tmp_many_luts_output =
        new CudaRadixCiphertextFFI *[this->num_streams];
    for (uint32_t j = 0; j < this->num_streams; j++) {
      this->tmp_many_luts_output[j] = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->tmp_many_luts_output[j], max_luts_per_call,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams * num_lut_accumulators; i++) {
      stream_luts[i]->release(streams);
      delete stream_luts[i];
    }
    delete[] stream_luts;

    for (uint32_t i = 0; i < this->num_streams; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->tmp_many_luts_output[i],
                                     this->allocate_gpu_memory);
      delete this->tmp_many_luts_output[i];
    }
    delete[] this->tmp_many_luts_output;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_aggregate_one_hot_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t chunk_size;

  int_radix_lut<Torus> **stream_identity_luts;
  int_radix_lut<Torus> *message_extract_lut;
  int_radix_lut<Torus> *carry_extract_lut;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;

  uint32_t num_streams;

  CudaRadixCiphertextFFI **partial_aggregated_vectors;
  CudaRadixCiphertextFFI **partial_temp_vectors;

  CudaRadixCiphertextFFI *message_ct;
  CudaRadixCiphertextFFI *carry_ct;

  int_aggregate_one_hot_buffer(CudaStreams streams, int_radix_params params,
                               uint32_t num_blocks, uint32_t num_matches,
                               bool allocate_gpu_memory,
                               uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    this->chunk_size = (total_modulus - 1) / (params.message_modulus - 1);

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_matches);
    num_streams_to_use = std::max((uint32_t)2, num_streams_to_use);

    this->num_streams = num_streams_to_use;

    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams);

    this->stream_identity_luts = new int_radix_lut<Torus> *[num_streams];
    std::function<Torus(Torus)> id_fn = [](Torus x) -> Torus { return x; };

    for (uint32_t i = 0; i < num_streams; i++) {
      int_radix_lut<Torus> *lut = new int_radix_lut<Torus>(
          streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

      lut->generate_and_broadcast_lut(
          streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {id_fn},
          LUT_0_FOR_ALL_BLOCKS);

      this->stream_identity_luts[i] = lut;
    }

    std::function<Torus(Torus)> msg_fn = [params](Torus x) -> Torus {
      return (x % params.message_modulus) % params.message_modulus;
    };
    std::function<Torus(Torus)> carry_fn = [params](Torus x) -> Torus {
      return x / params.message_modulus;
    };

    this->message_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

    this->message_extract_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {msg_fn},
        LUT_0_FOR_ALL_BLOCKS);

    this->carry_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

    this->carry_extract_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_blocks, params.pbs_type), {0}, {carry_fn},
        LUT_0_FOR_ALL_BLOCKS);

    this->partial_aggregated_vectors =
        new CudaRadixCiphertextFFI *[num_streams];
    this->partial_temp_vectors = new CudaRadixCiphertextFFI *[num_streams];

    for (uint32_t i = 0; i < num_streams; i++) {
      this->partial_aggregated_vectors[i] = new CudaRadixCiphertextFFI;
      this->partial_temp_vectors[i] = new CudaRadixCiphertextFFI;

      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->partial_aggregated_vectors[i], num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->partial_temp_vectors[i], num_blocks, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);
    }

    this->message_ct = new CudaRadixCiphertextFFI;
    this->carry_ct = new CudaRadixCiphertextFFI;

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->message_ct, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->carry_ct, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      stream_identity_luts[i]->release(streams);
      delete stream_identity_luts[i];
    }
    delete[] stream_identity_luts;

    this->message_extract_lut->release(streams);
    delete this->message_extract_lut;
    this->carry_extract_lut->release(streams);
    delete this->carry_extract_lut;

    for (uint32_t i = 0; i < num_streams; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->partial_aggregated_vectors[i],
                                     this->allocate_gpu_memory);
      delete this->partial_aggregated_vectors[i];

      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->partial_temp_vectors[i],
                                     this->allocate_gpu_memory);
      delete this->partial_temp_vectors[i];
    }
    delete[] partial_aggregated_vectors;
    delete[] partial_temp_vectors;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->message_ct, this->allocate_gpu_memory);
    delete this->message_ct;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->carry_ct, this->allocate_gpu_memory);
    delete this->carry_ct;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_match_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_matches;
  uint32_t num_input_blocks;
  uint32_t num_output_packed_blocks;
  bool max_output_is_zero;

  int_equality_selectors_buffer<Torus> *eq_selectors_buffer;
  int_possible_results_buffer<Torus> *possible_results_buffer;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buffer;
  int_comparison_buffer<Torus> *at_least_one_true_buffer;

  CudaRadixCiphertextFFI *selectors_list;
  CudaRadixCiphertextFFI *packed_selectors_ct;
  CudaRadixCiphertextFFI *possible_results_list;

  int_unchecked_match_buffer(CudaStreams streams, int_radix_params params,
                             uint32_t num_matches, uint32_t num_input_blocks,
                             uint32_t num_output_packed_blocks,
                             bool max_output_is_zero, bool allocate_gpu_memory,
                             uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_matches = num_matches;
    this->num_input_blocks = num_input_blocks;
    this->num_output_packed_blocks = num_output_packed_blocks;
    this->max_output_is_zero = max_output_is_zero;

    this->eq_selectors_buffer = new int_equality_selectors_buffer<Torus>(
        streams, params, num_matches, num_input_blocks, allocate_gpu_memory,
        size_tracker);

    this->possible_results_buffer = new int_possible_results_buffer<Torus>(
        streams, params, num_output_packed_blocks, num_matches,
        allocate_gpu_memory, size_tracker);

    if (!max_output_is_zero) {
      this->aggregate_buffer = new int_aggregate_one_hot_buffer<Torus>(
          streams, params, num_output_packed_blocks, num_matches,
          allocate_gpu_memory, size_tracker);
    }

    this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
        streams, EQ, params, num_matches, false, allocate_gpu_memory,
        size_tracker);

    this->selectors_list = new CudaRadixCiphertextFFI[num_matches];
    this->possible_results_list = new CudaRadixCiphertextFFI[num_matches];

    for (uint32_t i = 0; i < num_matches; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &this->selectors_list[i], 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      if (!max_output_is_zero) {
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            &this->possible_results_list[i], num_output_packed_blocks,
            params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      }
    }

    this->packed_selectors_ct = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors_ct,
        num_matches, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buffer->release(streams);
    delete this->eq_selectors_buffer;

    this->possible_results_buffer->release(streams);
    delete this->possible_results_buffer;

    if (!max_output_is_zero) {
      this->aggregate_buffer->release(streams);
      delete this->aggregate_buffer;
    }

    this->at_least_one_true_buffer->release(streams);
    delete this->at_least_one_true_buffer;

    for (uint32_t i = 0; i < num_matches; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->selectors_list[i],
                                     this->allocate_gpu_memory);
      if (!max_output_is_zero) {
        release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                       &this->possible_results_list[i],
                                       this->allocate_gpu_memory);
      }
    }

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors_ct,
                                   this->allocate_gpu_memory);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] this->selectors_list;
    delete[] this->possible_results_list;
    delete this->packed_selectors_ct;
  }
};

template <typename Torus> struct int_unchecked_match_value_or_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t num_matches;
  uint32_t num_input_blocks;
  uint32_t num_match_packed_blocks;
  uint32_t num_final_blocks;
  bool max_output_is_zero;

  int_unchecked_match_buffer<Torus> *match_buffer;
  int_cmux_buffer<Torus> *cmux_buffer;

  CudaRadixCiphertextFFI *tmp_match_result;
  CudaRadixCiphertextFFI *tmp_match_bool;
  CudaRadixCiphertextFFI *tmp_or_value;

  Torus *d_or_value;

  int_unchecked_match_value_or_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_matches,
      uint32_t num_input_blocks, uint32_t num_match_packed_blocks,
      uint32_t num_final_blocks, bool max_output_is_zero,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_matches = num_matches;
    this->num_input_blocks = num_input_blocks;
    this->num_match_packed_blocks = num_match_packed_blocks;
    this->num_final_blocks = num_final_blocks;
    this->max_output_is_zero = max_output_is_zero;

    this->match_buffer = new int_unchecked_match_buffer<Torus>(
        streams, params, num_matches, num_input_blocks, num_match_packed_blocks,
        max_output_is_zero, allocate_gpu_memory, size_tracker);

    this->cmux_buffer = new int_cmux_buffer<Torus>(
        streams, [](Torus x) -> Torus { return x == 1; }, params,
        num_final_blocks, allocate_gpu_memory, size_tracker);

    this->tmp_match_result = new CudaRadixCiphertextFFI;
    this->tmp_match_bool = new CudaRadixCiphertextFFI;
    this->tmp_or_value = new CudaRadixCiphertextFFI;

    this->d_or_value = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_final_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_match_result,
        num_final_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_match_bool, 1,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_or_value,
        num_final_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->match_buffer->release(streams);
    delete this->match_buffer;

    this->cmux_buffer->release(streams);
    delete this->cmux_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_match_result,
                                   this->allocate_gpu_memory);
    delete this->tmp_match_result;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_match_bool,
                                   this->allocate_gpu_memory);
    delete this->tmp_match_bool;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_or_value,
                                   this->allocate_gpu_memory);
    delete this->tmp_or_value;

    cuda_drop_async(this->d_or_value, streams.stream(0), streams.gpu_index(0));

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_selectors;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_contains_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_inputs, uint32_t num_blocks,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_contains_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *tmp_clear_val;
  Torus *d_clear_val;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_contains_clear_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->tmp_clear_val = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_clear_val,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->d_clear_val = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_clear_val,
                                   this->allocate_gpu_memory);
    delete this->tmp_clear_val;

    cuda_drop_async(this->d_clear_val, streams.stream(0), streams.gpu_index(0));

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_is_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_clears;

  int_equality_selectors_buffer<Torus> *eq_buffer;
  int_comparison_buffer<Torus> *reduction_buffer;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;

  int_unchecked_is_in_clears_buffer(CudaStreams streams,
                                    int_radix_params params,
                                    uint32_t num_clears, uint32_t num_blocks,
                                    bool allocate_gpu_memory,
                                    uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_clears = num_clears;

    this->eq_buffer = new int_equality_selectors_buffer<Torus>(
        streams, params, num_clears, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->reduction_buffer =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_clears, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_clears, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_clears];

    for (uint32_t i = 0; i < num_clears; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }
  }

  void release(CudaStreams streams) {
    this->eq_buffer->release(streams);
    delete this->eq_buffer;

    this->reduction_buffer->release(streams);
    delete this->reduction_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_final_index_from_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;

  uint64_t *h_indices;

  int_final_index_from_selectors_buffer(CudaStreams streams,
                                        int_radix_params params,
                                        uint32_t num_inputs,
                                        uint32_t num_blocks_index,
                                        bool allocate_gpu_memory,
                                        uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }

    uint32_t num_bits_in_message = log2_int(params.message_modulus);
    uint32_t bits_per_packed_block = 2 * num_bits_in_message;

    h_indices = new uint64_t[safe_mul((size_t)num_inputs, (size_t)packed_len)];
    for (uint32_t i = 0; i < num_inputs; i++) {
      uint64_t val = i;
      for (uint32_t b = 0; b < packed_len; b++) {
        uint64_t mask = (1ULL << bits_per_packed_block) - 1;
        uint64_t block_val = (val >> (b * bits_per_packed_block)) & mask;
        h_indices[i * packed_len + b] = block_val;
      }
    }
  }

  void release(CudaStreams streams) {
    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_index_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_clears;

  int_equality_selectors_buffer<Torus> *eq_selectors_buf;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  int_unchecked_index_in_clears_buffer(CudaStreams streams,
                                       int_radix_params params,
                                       uint32_t num_clears, uint32_t num_blocks,
                                       uint32_t num_blocks_index,
                                       bool allocate_gpu_memory,
                                       uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_clears = num_clears;

    this->eq_selectors_buf = new int_equality_selectors_buffer<Torus>(
        streams, params, num_clears, num_blocks, allocate_gpu_memory,
        size_tracker);

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_clears, num_blocks_index, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_first_index_in_clears_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_unique;

  int_equality_selectors_buffer<Torus> *eq_selectors_buf;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;

  int_unchecked_first_index_in_clears_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_unique,
      uint32_t num_blocks, uint32_t num_blocks_index, bool allocate_gpu_memory,
      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_unique = num_unique;

    this->eq_selectors_buf = new int_equality_selectors_buffer<Torus>(
        streams, params, num_unique, num_blocks, allocate_gpu_memory,
        size_tracker);

    uint32_t packed_len = (num_blocks_index + 1) / 2;
    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_unique, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_unique, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_unique, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_unique, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_unique];
    for (uint32_t i = 0; i < num_unique; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_unique];
    for (uint32_t i = 0; i < num_unique; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }
  }

  void release(CudaStreams streams) {
    this->eq_selectors_buf->release(streams);
    delete this->eq_selectors_buf;

    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_unique; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_first_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;
  CudaRadixCiphertextFFI *tmp_clear_val;
  Torus *d_clear_val;
  uint64_t *h_indices;

  int_radix_lut<Torus> *prefix_sum_lut;
  int_radix_lut<Torus> *cleanup_lut;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_first_index_of_clear_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_inputs,
      uint32_t num_blocks, uint32_t num_blocks_index, bool allocate_gpu_memory,
      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }

    this->tmp_clear_val = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_clear_val,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->d_clear_val = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);

    h_indices = nullptr;
    if (allocate_gpu_memory) {
      uint32_t num_bits_in_message = log2_int(params.message_modulus);
      uint32_t bits_per_packed_block = 2 * num_bits_in_message;

      h_indices =
          new uint64_t[safe_mul((size_t)num_inputs, (size_t)packed_len)];
      for (uint32_t i = 0; i < num_inputs; i++) {
        uint64_t val = i;
        for (uint32_t b = 0; b < packed_len; b++) {
          uint64_t mask = (1ULL << bits_per_packed_block) - 1;
          uint64_t block_val = (val >> (b * bits_per_packed_block)) & mask;
          h_indices[i * packed_len + b] = block_val;
        }
      }
    }

    const Torus ALREADY_SEEN = 2;
    auto prefix_sum_fn = [ALREADY_SEEN](Torus current,
                                        Torus previous) -> Torus {
      if (previous == 1 || previous == ALREADY_SEEN) {
        return ALREADY_SEEN;
      }
      return current;
    };
    this->prefix_sum_lut = new int_radix_lut<Torus>(
        streams, params, 2, num_inputs, allocate_gpu_memory, size_tracker);

    this->prefix_sum_lut->generate_and_broadcast_bivariate_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {prefix_sum_fn}, LUT_0_FOR_ALL_BLOCKS);

    auto cleanup_fn = [ALREADY_SEEN, params](Torus x) -> Torus {
      Torus val = x % params.message_modulus;
      if (val == ALREADY_SEEN)
        return 0;
      return val;
    };
    this->cleanup_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_inputs, allocate_gpu_memory, size_tracker);
    this->cleanup_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {cleanup_fn}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    this->prefix_sum_lut->release(streams);
    delete this->prefix_sum_lut;

    this->cleanup_lut->release(streams);
    delete this->cleanup_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_clear_val,
                                   this->allocate_gpu_memory);
    delete this->tmp_clear_val;

    cuda_drop_async(this->d_clear_val, streams.stream(0), streams.gpu_index(0));

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_first_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_possible_results_buffer<Torus> *possible_results_buf;
  int_aggregate_one_hot_buffer<Torus> *aggregate_buf;
  int_comparison_buffer<Torus> *reduction_buf;

  CudaRadixCiphertextFFI *packed_selectors;
  CudaRadixCiphertextFFI *unpacked_selectors;
  CudaRadixCiphertextFFI *possible_results_ct_list;
  uint64_t *h_indices;

  int_radix_lut<Torus> *prefix_sum_lut;
  int_radix_lut<Torus> *cleanup_lut;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_first_index_of_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    uint32_t packed_len = (num_blocks_index + 1) / 2;

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->possible_results_buf = new int_possible_results_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->aggregate_buf = new int_aggregate_one_hot_buffer<Torus>(
        streams, params, packed_len, num_inputs, allocate_gpu_memory,
        size_tracker);

    this->reduction_buf =
        new int_comparison_buffer<Torus>(streams, EQ, params, num_inputs, false,
                                         allocate_gpu_memory, size_tracker);

    this->packed_selectors = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_selectors,
        num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->unpacked_selectors = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      as_radix_ciphertext_slice<Torus>(&this->unpacked_selectors[i],
                                       this->packed_selectors, i, i + 1);
    }

    this->possible_results_ct_list = new CudaRadixCiphertextFFI[num_inputs];
    for (uint32_t i = 0; i < num_inputs; i++) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->possible_results_ct_list[i], packed_len,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }

    h_indices = nullptr;
    if (allocate_gpu_memory) {
      uint32_t num_bits_in_message = log2_int(params.message_modulus);
      uint32_t bits_per_packed_block = 2 * num_bits_in_message;

      h_indices =
          new uint64_t[safe_mul((size_t)num_inputs, (size_t)packed_len)];
      for (uint32_t i = 0; i < num_inputs; i++) {
        uint64_t val = i;
        for (uint32_t b = 0; b < packed_len; b++) {
          uint64_t mask = (1ULL << bits_per_packed_block) - 1;
          uint64_t block_val = (val >> (b * bits_per_packed_block)) & mask;
          h_indices[i * packed_len + b] = block_val;
        }
      }
    }

    const Torus ALREADY_SEEN = 2;
    auto prefix_sum_fn = [ALREADY_SEEN](Torus current,
                                        Torus previous) -> Torus {
      if (previous == 1 || previous == ALREADY_SEEN) {
        return ALREADY_SEEN;
      }
      return current;
    };
    this->prefix_sum_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_inputs, allocate_gpu_memory, size_tracker);

    this->prefix_sum_lut->generate_and_broadcast_bivariate_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {prefix_sum_fn}, LUT_0_FOR_ALL_BLOCKS);

    auto cleanup_fn = [ALREADY_SEEN, params](Torus x) -> Torus {
      Torus val = x % params.message_modulus;
      if (val == ALREADY_SEEN)
        return 0;
      return val;
    };
    this->cleanup_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_inputs, allocate_gpu_memory, size_tracker);
    this->cleanup_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_inputs, params.pbs_type), {0},
        {cleanup_fn}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->possible_results_buf->release(streams);
    delete this->possible_results_buf;

    this->aggregate_buf->release(streams);
    delete this->aggregate_buf;

    this->reduction_buf->release(streams);
    delete this->reduction_buf;

    this->prefix_sum_lut->release(streams);
    delete this->prefix_sum_lut;

    this->cleanup_lut->release(streams);
    delete this->cleanup_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_selectors,
                                   this->allocate_gpu_memory);
    delete this->packed_selectors;

    delete[] this->unpacked_selectors;

    for (uint32_t i = 0; i < num_inputs; i++) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->possible_results_ct_list[i],
                                     this->allocate_gpu_memory);
    }
    delete[] this->possible_results_ct_list;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    delete[] h_indices;
  }
};

template <typename Torus> struct int_unchecked_index_of_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_index_of_buffer(CudaStreams streams, int_radix_params params,
                                uint32_t num_inputs, uint32_t num_blocks,
                                uint32_t num_blocks_index,
                                bool allocate_gpu_memory,
                                uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_inputs, num_blocks_index, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_unchecked_index_of_clear_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_comparison_buffer<Torus> **eq_buffers;
  int_final_index_from_selectors_buffer<Torus> *final_index_buf;

  CudaStreams active_streams;
  InternalCudaStreams internal_cuda_streams;
  uint32_t num_streams;

  int_unchecked_index_of_clear_buffer(CudaStreams streams,
                                      int_radix_params params,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index,
                                      bool allocate_gpu_memory,
                                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    uint32_t num_streams_to_use =
        std::min((uint32_t)MAX_STREAMS_FOR_VECTOR_FIND, num_inputs);
    if (num_streams_to_use == 0)
      num_streams_to_use = 1;

    this->num_streams = num_streams_to_use;
    this->active_streams =
        streams.active_gpu_subset(num_blocks, params.pbs_type);

    this->internal_cuda_streams.create_internal_cuda_streams_on_same_gpus(
        active_streams, num_streams_to_use);

    this->eq_buffers = new int_comparison_buffer<Torus> *[num_streams];
    for (uint32_t i = 0; i < num_streams; i++) {
      this->eq_buffers[i] = new int_comparison_buffer<Torus>(
          streams, EQ, params, num_blocks, false, allocate_gpu_memory,
          size_tracker);
    }

    this->final_index_buf = new int_final_index_from_selectors_buffer<Torus>(
        streams, params, num_inputs, num_blocks_index, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    for (uint32_t i = 0; i < num_streams; i++) {
      eq_buffers[i]->release(streams);
      delete eq_buffers[i];
    }
    delete[] eq_buffers;

    this->final_index_buf->release(streams);
    delete this->final_index_buf;

    internal_cuda_streams.release(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
