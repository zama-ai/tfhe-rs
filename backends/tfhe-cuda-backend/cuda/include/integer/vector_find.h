#pragma once
#include "integer/comparison.h"
#include "integer/radix_ciphertext.cuh"
#include "integer_utilities.h"
#include <functional>
#include <vector>

const uint32_t MAX_STREAMS_FOR_VECTOR_FIND = 10;

template <typename Torus> struct int_equality_selectors_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t lut_stride;

  uint32_t num_possible_values;
  int_radix_lut<Torus> *comparison_luts;
  CudaRadixCiphertextFFI *tmp_many_luts_output;

  CudaStreams active_streams;
  CudaStreams sub_streams;
  cudaEvent_t *incoming_events;
  cudaEvent_t *outgoing_events;
  uint32_t num_streams;

  std::vector<CudaRadixCiphertextFFI *> tmp_block_comparisons_vec;
  std::vector<int_comparison_buffer<Torus> *> reduction_buffers;

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

    active_streams = streams.active_gpu_subset(num_streams_to_use);
    sub_streams.create_on_same_gpus(active_streams);

    this->num_streams = active_streams.count();

    incoming_events =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    outgoing_events =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    for (uint j = 0; j < active_streams.count(); j++) {
      incoming_events[j] = cuda_create_event(active_streams.gpu_index(j));
      outgoing_events[j] = cuda_create_event(active_streams.gpu_index(j));
    }

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

    generate_many_lut_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->comparison_luts->get_lut(0, 0),
        this->comparison_luts->get_degree(0),
        this->comparison_luts->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        fns, allocate_gpu_memory);

    fns.clear();

    this->comparison_luts->broadcast_lut(streams.active_gpu_subset(num_blocks));

    this->tmp_many_luts_output = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_many_luts_output,
        params.message_modulus * num_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->tmp_block_comparisons_vec.resize(this->num_streams);
    this->reduction_buffers.resize(this->num_streams);
    for (uint32_t j = 0; j < this->num_streams; j++) {
      this->tmp_block_comparisons_vec[j] = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->tmp_block_comparisons_vec[j], num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      this->reduction_buffers[j] = new int_comparison_buffer<Torus>(
          streams, COMPARISON_TYPE::EQ, params, num_blocks, false,
          allocate_gpu_memory, size_tracker);
    }
  }

  void release(CudaStreams streams) {
    this->comparison_luts->release(streams);
    delete this->comparison_luts;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_many_luts_output,
                                   this->allocate_gpu_memory);
    delete this->tmp_many_luts_output;

    for (auto ct : this->tmp_block_comparisons_vec) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, this->allocate_gpu_memory);
      delete ct;
    }
    this->tmp_block_comparisons_vec.clear();

    for (auto buffer : this->reduction_buffers) {
      buffer->release(streams);
      delete buffer;
    }
    this->reduction_buffers.clear();

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    for (uint j = 0; j < active_streams.count(); j++) {
      cuda_event_destroy(incoming_events[j], active_streams.gpu_index(j));
      cuda_event_destroy(outgoing_events[j], active_streams.gpu_index(j));
    }
    free(incoming_events);
    free(outgoing_events);

    sub_streams.release();
  }
};

template <typename Torus> struct int_possible_results_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t max_packed_value;
  uint32_t max_luts_per_call;
  uint32_t num_lut_accumulators;
  uint32_t lut_stride;

  std::vector<int_radix_lut<Torus> *> luts_vec;

  CudaStreams active_streams;
  CudaStreams sub_streams;
  cudaEvent_t *incoming_events;
  cudaEvent_t *outgoing_events;
  uint32_t num_streams;

  std::vector<CudaRadixCiphertextFFI *> tmp_many_luts_output_vec;

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

    active_streams = streams.active_gpu_subset(num_streams_to_use);
    sub_streams.create_on_same_gpus(active_streams);

    this->num_streams = active_streams.count();

    incoming_events =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    outgoing_events =
        (cudaEvent_t *)malloc(active_streams.count() * sizeof(cudaEvent_t));
    for (uint j = 0; j < active_streams.count(); j++) {
      incoming_events[j] = cuda_create_event(active_streams.gpu_index(j));
      outgoing_events[j] = cuda_create_event(active_streams.gpu_index(j));
    }

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

    this->num_lut_accumulators =
        (total_luts_needed + max_luts_per_call - 1) / max_luts_per_call;

    luts_vec.reserve(num_lut_accumulators);

    std::vector<std::function<Torus(Torus)>> fns;
    fns.reserve(max_luts_per_call);

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

      generate_many_lut_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), current_lut->get_lut(0, 0),
          current_lut->get_degree(0), current_lut->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, fns, allocate_gpu_memory);

      current_lut->broadcast_lut(streams.active_gpu_subset(1));
      luts_vec.push_back(current_lut);
      lut_value_start += luts_in_this_call;
    }

    this->tmp_many_luts_output_vec.resize(this->num_streams);
    for (uint32_t j = 0; j < this->num_streams; j++) {
      this->tmp_many_luts_output_vec[j] = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->tmp_many_luts_output_vec[j], max_luts_per_call,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    }
  }

  void release(CudaStreams streams) {
    for (auto lut : luts_vec) {
      lut->release(streams);
      delete lut;
    }
    luts_vec.clear();

    for (auto ct : this->tmp_many_luts_output_vec) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, this->allocate_gpu_memory);
      delete ct;
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    this->tmp_many_luts_output_vec.clear();

    for (uint j = 0; j < active_streams.count(); j++) {
      cuda_event_destroy(incoming_events[j], active_streams.gpu_index(j));
      cuda_event_destroy(outgoing_events[j], active_streams.gpu_index(j));
    }
    free(incoming_events);
    free(outgoing_events);

    sub_streams.release();
  }
};

template <typename Torus> struct int_aggregate_one_hot_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t chunk_size;

  int_radix_lut<Torus> *identity_lut;
  int_radix_lut<Torus> *message_extract_lut;
  int_radix_lut<Torus> *carry_extract_lut;

  CudaRadixCiphertextFFI *aggregated_vector;
  CudaRadixCiphertextFFI *temp_aggregated_vector;
  CudaRadixCiphertextFFI *message_ct;
  CudaRadixCiphertextFFI *carry_ct;

  int_aggregate_one_hot_buffer(CudaStreams streams, int_radix_params params,
                               uint32_t num_blocks, bool allocate_gpu_memory,
                               uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    uint32_t total_modulus = params.message_modulus * params.carry_modulus;
    this->chunk_size = (total_modulus - 1) / (params.message_modulus - 1);

    this->identity_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    this->message_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    this->carry_extract_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus)> id_fn = [](Torus x) -> Torus { return x; };
    std::function<Torus(Torus)> msg_fn = [params](Torus x) -> Torus {
      return (x % params.message_modulus) % params.message_modulus;
    };
    std::function<Torus(Torus)> carry_fn = [params](Torus x) -> Torus {
      return x / params.message_modulus;
    };

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->identity_lut->get_lut(0, 0), this->identity_lut->get_degree(0),
        this->identity_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        id_fn, allocate_gpu_memory);
    this->identity_lut->broadcast_lut(streams.active_gpu_subset(num_blocks));

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->message_extract_lut->get_lut(0, 0),
        this->message_extract_lut->get_degree(0),
        this->message_extract_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        msg_fn, allocate_gpu_memory);
    this->message_extract_lut->broadcast_lut(
        streams.active_gpu_subset(num_blocks));

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->carry_extract_lut->get_lut(0, 0),
        this->carry_extract_lut->get_degree(0),
        this->carry_extract_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        carry_fn, allocate_gpu_memory);
    this->carry_extract_lut->broadcast_lut(
        streams.active_gpu_subset(num_blocks));

    this->aggregated_vector = new CudaRadixCiphertextFFI;
    this->temp_aggregated_vector = new CudaRadixCiphertextFFI;
    this->message_ct = new CudaRadixCiphertextFFI;
    this->carry_ct = new CudaRadixCiphertextFFI;

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->aggregated_vector,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->temp_aggregated_vector,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->message_ct, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->carry_ct, num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->identity_lut->release(streams);
    delete this->identity_lut;
    this->message_extract_lut->release(streams);
    delete this->message_extract_lut;
    this->carry_extract_lut->release(streams);
    delete this->carry_extract_lut;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->aggregated_vector,
                                   this->allocate_gpu_memory);
    delete this->aggregated_vector;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->temp_aggregated_vector,
                                   this->allocate_gpu_memory);
    delete this->temp_aggregated_vector;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->message_ct, this->allocate_gpu_memory);
    delete this->message_ct;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->carry_ct, this->allocate_gpu_memory);
    delete this->carry_ct;

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
          streams, params, num_output_packed_blocks, allocate_gpu_memory,
          size_tracker);

      this->at_least_one_true_buffer = new int_comparison_buffer<Torus>(
          streams, COMPARISON_TYPE::EQ, params, num_matches, false,
          allocate_gpu_memory, size_tracker);
    }

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
