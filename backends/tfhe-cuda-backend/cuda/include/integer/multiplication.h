#pragma once
#include "cmux.h"
#include "integer_utilities.h"

template <typename Torus> struct int_mul_memory {
  CudaRadixCiphertextFFI *vector_result_sb;
  CudaRadixCiphertextFFI *block_mul_res;
  CudaRadixCiphertextFFI *small_lwe_vector;

  int_radix_lut<Torus> *luts_array; // lsb msb
  int_radix_lut<Torus> *zero_out_predicate_lut;

  int_sum_ciphertexts_vec_memory<Torus> *sum_ciphertexts_mem;
  int_sc_prop_memory<Torus> *sc_prop_mem;
  int_zero_out_if_buffer<Torus> *zero_out_mem;

  int_radix_params params;
  bool boolean_mul = false;
  bool gpu_memory_allocated;

  int_mul_memory(CudaStreams streams, int_radix_params params,
                 bool const is_boolean_left, bool const is_boolean_right,
                 uint32_t num_radix_blocks, bool allocate_gpu_memory,
                 uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->boolean_mul = is_boolean_left || is_boolean_right;
    this->params = params;

    if (boolean_mul) {
      auto zero_out_predicate_lut_f = [](Torus block,
                                         Torus condition) -> Torus {
        if (condition == 0)
          return 0;
        else
          return block;
      };
      zero_out_predicate_lut =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);
      generate_device_accumulator_bivariate<Torus>(
          streams.stream(0), streams.gpu_index(0),
          zero_out_predicate_lut->get_lut(0, 0),
          zero_out_predicate_lut->get_degree(0),
          zero_out_predicate_lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          zero_out_predicate_lut_f, gpu_memory_allocated);

      auto active_streams = streams.active_gpu_subset(num_radix_blocks);
      zero_out_predicate_lut->broadcast_lut(active_streams);

      zero_out_mem = new int_zero_out_if_buffer<Torus>(
          streams, params, num_radix_blocks, allocate_gpu_memory, size_tracker);

      return;
    }

    auto glwe_dimension = params.glwe_dimension;
    auto polynomial_size = params.polynomial_size;
    auto message_modulus = params.message_modulus;
    auto carry_modulus = params.carry_modulus;

    // 'vector_result_lsb' contains blocks from all possible shifts of
    // radix_lwe_left excluding zero ciphertext blocks
    int lsb_vector_block_count = num_radix_blocks * (num_radix_blocks + 1) / 2;

    // 'vector_result_msb' contains blocks from all possible shifts of
    // radix_lwe_left except the last blocks of each shift
    int msb_vector_block_count = num_radix_blocks * (num_radix_blocks - 1) / 2;

    int total_block_count = num_radix_blocks * num_radix_blocks;

    // allocate memory for intermediate buffers
    vector_result_sb = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), vector_result_sb,
        2 * total_block_count, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    block_mul_res = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), block_mul_res,
        2 * total_block_count, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    small_lwe_vector = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), small_lwe_vector,
        2 * total_block_count, params.small_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    // create int_radix_lut objects for lsb, msb, message, carry
    // luts_array -> lut = {lsb_acc, msb_acc}
    luts_array = new int_radix_lut<Torus>(streams, params, 2, total_block_count,
                                          allocate_gpu_memory, size_tracker);
    auto lsb_acc = luts_array->get_lut(0, 0);
    auto msb_acc = luts_array->get_lut(0, 1);

    // define functions for each accumulator
    auto lut_f_lsb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) % message_modulus;
    };
    auto lut_f_msb = [message_modulus](Torus x, Torus y) -> Torus {
      return (x * y) / message_modulus;
    };

    // generate accumulators
    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), lsb_acc,
        luts_array->get_degree(0), luts_array->get_max_degree(0),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        lut_f_lsb, gpu_memory_allocated);
    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), msb_acc,
        luts_array->get_degree(1), luts_array->get_max_degree(1),
        glwe_dimension, polynomial_size, message_modulus, carry_modulus,
        lut_f_msb, gpu_memory_allocated);

    // lut_indexes_vec for luts_array should be reinitialized
    // first lsb_vector_block_count value should reference to lsb_acc
    // last msb_vector_block_count values should reference to msb_acc
    // for message and carry default lut_indexes_vec is fine
    if (allocate_gpu_memory)
      cuda_set_value_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          luts_array->get_lut_indexes(0, lsb_vector_block_count), 1,
          msb_vector_block_count);
    auto active_streams = streams.active_gpu_subset(total_block_count);
    luts_array->broadcast_lut(active_streams);
    // create memory object for sum ciphertexts
    sum_ciphertexts_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, params, num_radix_blocks, 2 * num_radix_blocks,
        vector_result_sb, small_lwe_vector, luts_array, true,
        allocate_gpu_memory, size_tracker);
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, params, num_radix_blocks, requested_flag, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {

    if (boolean_mul) {
      zero_out_predicate_lut->release(streams);
      zero_out_mem->release(streams);
      delete zero_out_mem;
      delete zero_out_predicate_lut;

      return;
    }
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   vector_result_sb, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   block_mul_res, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   small_lwe_vector, gpu_memory_allocated);

    luts_array->release(streams);
    sum_ciphertexts_mem->release(streams);
    sc_prop_mem->release(streams);

    delete vector_result_sb;
    delete block_mul_res;
    delete small_lwe_vector;
    delete luts_array;
    delete sum_ciphertexts_mem;
    delete sc_prop_mem;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
