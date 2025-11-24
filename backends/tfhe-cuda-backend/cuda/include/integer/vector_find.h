#pragma once
#include "cast.h"
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
  std::vector<CudaStreams> sub_streams_vec;
  cudaEvent_t incoming_event;
  std::vector<std::vector<cudaEvent_t>> outgoing_events;
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

    this->num_streams = num_streams_to_use;

    this->active_streams = streams.active_gpu_subset(num_blocks);

    incoming_event = cuda_create_event(streams.gpu_index(0));

    sub_streams_vec.resize(num_streams_to_use);
    outgoing_events.resize(num_streams_to_use);

    for (uint32_t i = 0; i < num_streams_to_use; i++) {
      sub_streams_vec[i].create_on_same_gpus(active_streams);
      outgoing_events[i].resize(active_streams.count());
      for (uint32_t j = 0; j < active_streams.count(); j++) {
        outgoing_events[i][j] = cuda_create_event(active_streams.gpu_index(j));
      }
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

    this->comparison_luts->broadcast_lut(active_streams);

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
          sub_streams_vec[j], COMPARISON_TYPE::EQ, params, num_blocks, false,
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

    cuda_event_destroy(incoming_event, streams.gpu_index(0));
    for (uint j = 0; j < num_streams; j++) {
      for (uint k = 0; k < active_streams.count(); k++) {
        cuda_event_destroy(outgoing_events[j][k], active_streams.gpu_index(k));
      }
    }
    outgoing_events.clear();

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    for (auto &stream : sub_streams_vec) {
      stream.release();
    }
    sub_streams_vec.clear();
  }
};

template <typename Torus> struct int_possible_results_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  uint32_t max_packed_value;
  uint32_t max_luts_per_call;
  uint32_t num_lut_accumulators;
  uint32_t lut_stride;

  std::vector<int_radix_lut<Torus> *> stream_luts_vec;

  CudaStreams active_streams;
  std::vector<CudaStreams> sub_streams_vec;
  cudaEvent_t incoming_event;
  std::vector<std::vector<cudaEvent_t>> outgoing_events;
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

    this->num_streams = num_streams_to_use;

    this->active_streams = streams.active_gpu_subset(num_blocks);

    incoming_event = cuda_create_event(streams.gpu_index(0));

    sub_streams_vec.resize(num_streams_to_use);
    outgoing_events.resize(num_streams_to_use);

    for (uint32_t i = 0; i < num_streams_to_use; i++) {
      sub_streams_vec[i].create_on_same_gpus(active_streams);
      outgoing_events[i].resize(active_streams.count());
      for (uint32_t j = 0; j < active_streams.count(); j++) {
        outgoing_events[i][j] = cuda_create_event(active_streams.gpu_index(j));
      }
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

    stream_luts_vec.reserve(num_streams * num_lut_accumulators);

    std::vector<std::function<Torus(Torus)>> fns;
    fns.reserve(max_luts_per_call);

    for (uint32_t s = 0; s < num_streams; s++) {
      uint32_t lut_value_start = 0;

      for (uint32_t i = 0; i < num_lut_accumulators; i++) {
        fns.clear();
        uint32_t luts_in_this_call =
            std::min(max_luts_per_call, total_luts_needed - lut_value_start);

        int_radix_lut<Torus> *current_lut = new int_radix_lut<Torus>(
            sub_streams_vec[s], params, 1, 1, luts_in_this_call,
            allocate_gpu_memory, size_tracker);

        for (uint32_t j = 0; j < luts_in_this_call; j++) {
          uint32_t c = lut_value_start + j;
          fns.push_back([c](Torus x) -> Torus { return (x == 1) * c; });
        }

        generate_many_lut_device_accumulator<Torus>(
            streams.stream(0), streams.gpu_index(0), current_lut->get_lut(0, 0),
            current_lut->get_degree(0), current_lut->get_max_degree(0),
            params.glwe_dimension, params.polynomial_size,
            params.message_modulus, params.carry_modulus, fns,
            allocate_gpu_memory);

        current_lut->broadcast_lut(sub_streams_vec[s].active_gpu_subset(1));
        stream_luts_vec.push_back(current_lut);
        lut_value_start += luts_in_this_call;
      }
    }
    fns.clear();

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
    for (auto lut : stream_luts_vec) {
      lut->release(streams);
      delete lut;
    }
    stream_luts_vec.clear();

    for (auto ct : this->tmp_many_luts_output_vec) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, this->allocate_gpu_memory);
      delete ct;
    }
    this->tmp_many_luts_output_vec.clear();

    cuda_event_destroy(incoming_event, streams.gpu_index(0));
    for (uint j = 0; j < num_streams; j++) {
      for (uint k = 0; k < active_streams.count(); k++) {
        cuda_event_destroy(outgoing_events[j][k], active_streams.gpu_index(k));
      }
    }
    outgoing_events.clear();

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    for (auto &stream : sub_streams_vec) {
      stream.release();
    }
    sub_streams_vec.clear();
  }
};

template <typename Torus> struct int_aggregate_one_hot_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t chunk_size;

  std::vector<int_radix_lut<Torus> *> stream_identity_luts;
  int_radix_lut<Torus> *message_extract_lut;
  int_radix_lut<Torus> *carry_extract_lut;

  CudaStreams active_streams;
  std::vector<CudaStreams> sub_streams_vec;
  cudaEvent_t incoming_event;
  std::vector<std::vector<cudaEvent_t>> outgoing_events;

  cudaEvent_t reduction_done_event;
  std::vector<cudaEvent_t> message_done_events;
  std::vector<cudaEvent_t> carry_done_events;

  uint32_t num_streams;

  std::vector<CudaRadixCiphertextFFI *> partial_aggregated_vectors;
  std::vector<CudaRadixCiphertextFFI *> partial_temp_vectors;

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

    this->active_streams = streams.active_gpu_subset(num_blocks);

    this->incoming_event = cuda_create_event(streams.gpu_index(0));
    this->reduction_done_event = cuda_create_event(streams.gpu_index(0));

    this->message_done_events.resize(active_streams.count());
    this->carry_done_events.resize(active_streams.count());
    for (uint32_t i = 0; i < active_streams.count(); i++) {
      this->message_done_events[i] =
          cuda_create_event(active_streams.gpu_index(i));
      this->carry_done_events[i] =
          cuda_create_event(active_streams.gpu_index(i));
    }

    this->sub_streams_vec.resize(num_streams);
    this->outgoing_events.resize(num_streams);

    for (uint32_t i = 0; i < num_streams; i++) {
      this->sub_streams_vec[i].create_on_same_gpus(active_streams);
      this->outgoing_events[i].resize(active_streams.count());
      for (uint32_t j = 0; j < active_streams.count(); j++) {
        this->outgoing_events[i][j] =
            cuda_create_event(active_streams.gpu_index(j));
      }
    }

    this->stream_identity_luts.reserve(num_streams);
    std::function<Torus(Torus)> id_fn = [](Torus x) -> Torus { return x; };

    for (uint32_t i = 0; i < num_streams; i++) {
      int_radix_lut<Torus> *lut =
          new int_radix_lut<Torus>(sub_streams_vec[i], params, 1, num_blocks,
                                   allocate_gpu_memory, size_tracker);

      generate_device_accumulator<Torus>(
          streams.stream(0), streams.gpu_index(0), lut->get_lut(0, 0),
          lut->get_degree(0), lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          id_fn, allocate_gpu_memory);

      lut->broadcast_lut(sub_streams_vec[i].active_gpu_subset(num_blocks));
      this->stream_identity_luts.push_back(lut);
    }

    std::function<Torus(Torus)> msg_fn = [params](Torus x) -> Torus {
      return (x % params.message_modulus) % params.message_modulus;
    };
    std::function<Torus(Torus)> carry_fn = [params](Torus x) -> Torus {
      return x / params.message_modulus;
    };

    this->message_extract_lut =
        new int_radix_lut<Torus>(sub_streams_vec[0], params, 1, num_blocks,
                                 allocate_gpu_memory, size_tracker);
    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->message_extract_lut->get_lut(0, 0),
        this->message_extract_lut->get_degree(0),
        this->message_extract_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        msg_fn, allocate_gpu_memory);
    this->message_extract_lut->broadcast_lut(
        sub_streams_vec[0].active_gpu_subset(num_blocks));

    this->carry_extract_lut =
        new int_radix_lut<Torus>(sub_streams_vec[1], params, 1, num_blocks,
                                 allocate_gpu_memory, size_tracker);
    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->carry_extract_lut->get_lut(0, 0),
        this->carry_extract_lut->get_degree(0),
        this->carry_extract_lut->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        carry_fn, allocate_gpu_memory);
    this->carry_extract_lut->broadcast_lut(
        sub_streams_vec[1].active_gpu_subset(num_blocks));

    this->partial_aggregated_vectors.resize(num_streams);
    this->partial_temp_vectors.resize(num_streams);

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
    for (auto lut : stream_identity_luts) {
      lut->release(streams);
      delete lut;
    }
    stream_identity_luts.clear();

    this->message_extract_lut->release(streams);
    delete this->message_extract_lut;
    this->carry_extract_lut->release(streams);
    delete this->carry_extract_lut;

    for (uint32_t i = 0; i < num_streams; i++) {
      release_radix_ciphertext_async(
          sub_streams_vec[i].stream(0), sub_streams_vec[i].gpu_index(0),
          this->partial_aggregated_vectors[i], this->allocate_gpu_memory);
      delete this->partial_aggregated_vectors[i];

      release_radix_ciphertext_async(
          sub_streams_vec[i].stream(0), sub_streams_vec[i].gpu_index(0),
          this->partial_temp_vectors[i], this->allocate_gpu_memory);
      delete this->partial_temp_vectors[i];
    }
    partial_aggregated_vectors.clear();
    partial_temp_vectors.clear();

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->message_ct, this->allocate_gpu_memory);
    delete this->message_ct;
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->carry_ct, this->allocate_gpu_memory);
    delete this->carry_ct;

    cuda_event_destroy(incoming_event, streams.gpu_index(0));
    cuda_event_destroy(reduction_done_event, streams.gpu_index(0));
    for (uint i = 0; i < active_streams.count(); i++) {
      cuda_event_destroy(message_done_events[i], active_streams.gpu_index(i));
      cuda_event_destroy(carry_done_events[i], active_streams.gpu_index(i));
    }

    for (uint j = 0; j < num_streams; j++) {
      for (uint k = 0; k < active_streams.count(); k++) {
        cuda_event_destroy(outgoing_events[j][k], active_streams.gpu_index(k));
      }
    }
    outgoing_events.clear();

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    for (auto &stream : sub_streams_vec) {
      stream.release();
    }
    sub_streams_vec.clear();
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
        num_final_blocks * sizeof(Torus), streams.stream(0),
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
