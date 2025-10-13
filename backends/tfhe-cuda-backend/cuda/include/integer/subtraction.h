#pragma once
#include "integer_utilities.h"

template <typename Torus> struct int_overflowing_sub_memory {
  Torus *generates_or_propagates;
  Torus *step_output;

  int_radix_lut<Torus> *luts_array;
  int_radix_lut<Torus> *luts_borrow_propagation_sum;
  int_radix_lut<Torus> *message_acc;

  int_radix_params params;
  bool gpu_memory_allocated;

  int_overflowing_sub_memory(CudaStreams streams, int_radix_params params,
                             uint32_t num_radix_blocks,
                             bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;
    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;
    auto big_lwe_size = (polynomial_size * glwe_dimension + 1);
    auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

    // allocate memory for intermediate calculations
    generates_or_propagates = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * big_lwe_size_bytes, streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    step_output = (Torus *)cuda_malloc_with_size_tracking_async(
        num_radix_blocks * big_lwe_size_bytes, streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    cuda_memset_with_size_tracking_async(
        generates_or_propagates, 0, num_radix_blocks * big_lwe_size_bytes,
        streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
    cuda_memset_with_size_tracking_async(
        step_output, 0, num_radix_blocks * big_lwe_size_bytes,
        streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);

    // declare functions for lut generation
    auto f_lut_does_block_generate_carry = [message_modulus](Torus x) -> Torus {
      if (x < message_modulus)
        return OUTPUT_CARRY::GENERATED;
      return OUTPUT_CARRY::NONE;
    };

    auto f_lut_does_block_generate_or_propagate =
        [message_modulus](Torus x) -> Torus {
      if (x < message_modulus)
        return OUTPUT_CARRY::GENERATED;
      else if (x == message_modulus)
        return OUTPUT_CARRY::PROPAGATED;
      return OUTPUT_CARRY::NONE;
    };

    auto f_luts_borrow_propagation_sum = [](Torus msb, Torus lsb) -> Torus {
      if (msb == OUTPUT_CARRY::PROPAGATED)
        return lsb;
      return msb;
    };

    auto f_message_acc = [message_modulus](Torus x) -> Torus {
      return x % message_modulus;
    };

    // create lut objects
    luts_array = new int_radix_lut<Torus>(streams, params, 2, num_radix_blocks,
                                          allocate_gpu_memory, size_tracker);
    luts_borrow_propagation_sum = new int_radix_lut<Torus>(
        streams, params, 1, num_radix_blocks, luts_array, size_tracker,
        allocate_gpu_memory, size_tracker);
    message_acc = new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                           luts_array, size_tracker,
                                           allocate_gpu_memory, size_tracker);

    auto lut_does_block_generate_carry = luts_array->get_lut(0, 0);
    auto lut_does_block_generate_or_propagate = luts_array->get_lut(0, 1);

    // generate luts (aka accumulators)
    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), lut_does_block_generate_carry,
        luts_array->get_degree(0), luts_array->get_max_degree(0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_lut_does_block_generate_carry, gpu_memory_allocated);
    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0),
        lut_does_block_generate_or_propagate, luts_array->get_degree(1),
        luts_array->get_max_degree(1), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, f_lut_does_block_generate_or_propagate,
        gpu_memory_allocated);
    if (allocate_gpu_memory)
      cuda_set_value_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                  luts_array->get_lut_indexes(0, 1), 1,
                                  num_radix_blocks - 1);

    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0),
        luts_borrow_propagation_sum->get_lut(0, 0),
        luts_borrow_propagation_sum->get_degree(0),
        luts_borrow_propagation_sum->get_max_degree(0), glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        f_luts_borrow_propagation_sum, gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), message_acc->get_lut(0, 0),
        message_acc->get_degree(0), message_acc->get_max_degree(0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        f_message_acc, gpu_memory_allocated);

    auto active_streams = streams.active_gpu_subset(num_radix_blocks);
    luts_array->broadcast_lut(active_streams);
    luts_borrow_propagation_sum->broadcast_lut(active_streams);
    message_acc->broadcast_lut(active_streams);
  }

  void release(CudaStreams streams) {
    cuda_drop_with_size_tracking_async(generates_or_propagates,
                                       streams.stream(0), streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(step_output, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);

    luts_array->release(streams);
    luts_borrow_propagation_sum->release(streams);
    message_acc->release(streams);

    delete luts_array;
    delete luts_borrow_propagation_sum;
    delete message_acc;
  }
};

template <typename Torus> struct int_sub_and_propagate {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *neg_rhs_array;

  int_sc_prop_memory<Torus> *sc_prop_mem;

  int_sub_and_propagate(CudaStreams streams, const int_radix_params params,
                        uint32_t num_radix_blocks, uint32_t requested_flag_in,
                        bool allocate_gpu_memory, uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, params, num_radix_blocks, requested_flag_in,
        allocate_gpu_memory, size_tracker);

    this->neg_rhs_array = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), neg_rhs_array,
        num_radix_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {

    sc_prop_mem->release(streams);
    delete sc_prop_mem;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   neg_rhs_array, allocate_gpu_memory);
    delete neg_rhs_array;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
