#include "integer_utilities.h"

template <typename Torus> struct int_prepare_count_of_consecutive_bits_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_radix_lut<Torus> *univ_lut_mem;
  int_radix_lut<Torus> *biv_lut_mem;

  Direction direction;
  BitValue bit_value;

  CudaRadixCiphertextFFI *tmp_ct;

  int_prepare_count_of_consecutive_bits_buffer(
      CudaStreams streams, const int_radix_params params,
      uint32_t num_radix_blocks, Direction direction, BitValue bit_value,
      const bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->direction = direction;
    this->bit_value = bit_value;
    auto active_streams = streams.active_gpu_subset(num_radix_blocks);
    this->univ_lut_mem =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);
    this->biv_lut_mem =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    const uint32_t num_bits = std::log2(this->params.message_modulus);

    auto generate_uni_lut_lambda = [this, num_bits](Torus x) -> Torus {
      x %= this->params.message_modulus;
      uint64_t count = 0;

      if (this->direction == Trailing) {
        for (uint32_t i = 0; i < num_bits; ++i) {
          if (((x >> i) & 1) != this->bit_value) {
            break;
          }
          count++;
        }
      } else {
        for (int32_t i = num_bits - 1; i >= 0; --i) {
          if (((x >> i) & 1) != this->bit_value) {
            break;
          }
          count++;
        }
      }
      return count;
    };

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), univ_lut_mem->get_lut(0, 0),
        univ_lut_mem->get_degree(0), univ_lut_mem->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, generate_uni_lut_lambda, allocate_gpu_memory);

    univ_lut_mem->broadcast_lut(active_streams);

    auto generate_bi_lut_lambda =
        [num_bits](Torus block_num_bit_count,
                   Torus more_significant_block_bit_count) -> Torus {
      if (more_significant_block_bit_count == num_bits) {
        return block_num_bit_count;
      }
      return 0;
    };

    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), biv_lut_mem->get_lut(0, 0),
        biv_lut_mem->get_degree(0), biv_lut_mem->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, generate_bi_lut_lambda, allocate_gpu_memory);

    biv_lut_mem->broadcast_lut(active_streams);

    this->tmp_ct = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_ct, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    univ_lut_mem->release(streams);
    delete univ_lut_mem;

    biv_lut_mem->release(streams);
    delete biv_lut_mem;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_ct, allocate_gpu_memory);
    delete tmp_ct;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_count_of_consecutive_bits_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t counter_num_blocks;

  int_prepare_count_of_consecutive_bits_buffer<Torus> *prepare_mem = nullptr;
  CudaRadixCiphertextFFI *ct_prepared = nullptr;

  int_sum_ciphertexts_vec_memory<Torus> *sum_mem = nullptr;
  int_sc_prop_memory<Torus> *propagate_mem = nullptr;
  CudaRadixCiphertextFFI *cts = nullptr;

  int_count_of_consecutive_bits_buffer(CudaStreams streams,
                                       const int_radix_params params,
                                       uint32_t num_radix_blocks,
                                       uint32_t counter_num_blocks,
                                       Direction direction, BitValue bit_value,
                                       const bool allocate_gpu_memory,
                                       uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->counter_num_blocks = counter_num_blocks;

    this->ct_prepared = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), ct_prepared, num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->prepare_mem = new int_prepare_count_of_consecutive_bits_buffer<Torus>(
        streams, params, num_radix_blocks, direction, bit_value,
        allocate_gpu_memory, size_tracker);

    this->cts = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), cts,
        counter_num_blocks * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->sum_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, params, counter_num_blocks, num_radix_blocks, true,
        allocate_gpu_memory, size_tracker);

    this->propagate_mem = new int_sc_prop_memory<Torus>(
        streams, params, counter_num_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   ct_prepared, allocate_gpu_memory);
    delete ct_prepared;
    ct_prepared = nullptr;

    prepare_mem->release(streams);
    delete prepare_mem;
    prepare_mem = nullptr;

    sum_mem->release(streams);
    delete sum_mem;
    sum_mem = nullptr;

    propagate_mem->release(streams);
    delete propagate_mem;
    propagate_mem = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0), cts,
                                   allocate_gpu_memory);
    delete cts;
    cts = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
template <typename Torus> struct int_ilog2_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t input_num_blocks;
  uint32_t counter_num_blocks;
  uint32_t num_bits_in_ciphertext;

  int_prepare_count_of_consecutive_bits_buffer<Torus> *prepare_mem;
  int_sum_ciphertexts_vec_memory<Torus> *sum_mem;
  int_fullprop_buffer<Torus> *final_propagate_mem;

  CudaRadixCiphertextFFI *ct_in_buffer;
  CudaRadixCiphertextFFI *sum_input_cts;
  CudaRadixCiphertextFFI *sum_output_not_propagated;
  CudaRadixCiphertextFFI *message_blocks_not;
  CudaRadixCiphertextFFI *carry_blocks_not;
  CudaRadixCiphertextFFI *rotated_carry_blocks;

  int_radix_lut<Torus> *lut_message_not;
  int_radix_lut<Torus> *lut_carry_not;

  int_ilog2_buffer(CudaStreams streams, const int_radix_params params,
                   uint32_t input_num_blocks, uint32_t counter_num_blocks,
                   uint32_t num_bits_in_ciphertext,
                   const bool allocate_gpu_memory, uint64_t &size_tracker) {

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->input_num_blocks = input_num_blocks;
    this->counter_num_blocks = counter_num_blocks;
    this->num_bits_in_ciphertext = num_bits_in_ciphertext;

    this->ct_in_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->ct_in_buffer,
        input_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->prepare_mem = new int_prepare_count_of_consecutive_bits_buffer<Torus>(
        streams, params, input_num_blocks, Leading, Zero, allocate_gpu_memory,
        size_tracker);

    uint32_t sum_input_total_blocks =
        (input_num_blocks + 1) * counter_num_blocks;
    this->sum_input_cts = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->sum_input_cts,
        sum_input_total_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->sum_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, params, counter_num_blocks, input_num_blocks + 1, false,
        allocate_gpu_memory, size_tracker);

    this->sum_output_not_propagated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->sum_output_not_propagated, counter_num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->lut_message_not =
        new int_radix_lut<Torus>(streams, params, 1, counter_num_blocks,
                                 allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> lut_message_lambda =
        [this](uint64_t x) -> uint64_t {
      uint64_t message = x % this->params.message_modulus;
      return (~message) % this->params.message_modulus;
    };
    generate_device_accumulator(streams.stream(0), streams.gpu_index(0),
                                this->lut_message_not->get_lut(0, 0),
                                this->lut_message_not->get_degree(0),
                                this->lut_message_not->get_max_degree(0),
                                params.glwe_dimension, params.polynomial_size,
                                params.message_modulus, params.carry_modulus,
                                lut_message_lambda, allocate_gpu_memory);
    auto active_streams = streams.active_gpu_subset(counter_num_blocks);
    lut_message_not->broadcast_lut(active_streams);

    this->lut_carry_not =
        new int_radix_lut<Torus>(streams, params, 1, counter_num_blocks,
                                 allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> lut_carry_lambda =
        [this](uint64_t x) -> uint64_t {
      uint64_t carry = x / this->params.message_modulus;
      return (~carry) % this->params.message_modulus;
    };
    generate_device_accumulator(
        streams.stream(0), streams.gpu_index(0),
        this->lut_carry_not->get_lut(0, 0), this->lut_carry_not->get_degree(0),
        this->lut_carry_not->get_max_degree(0), params.glwe_dimension,
        params.polynomial_size, params.message_modulus, params.carry_modulus,
        lut_carry_lambda, allocate_gpu_memory);
    lut_carry_not->broadcast_lut(active_streams);

    this->message_blocks_not = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->message_blocks_not,
        counter_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->carry_blocks_not = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->carry_blocks_not,
        counter_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->rotated_carry_blocks = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->rotated_carry_blocks,
        counter_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->final_propagate_mem = new int_fullprop_buffer<Torus>(
        streams, params, allocate_gpu_memory, size_tracker);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->ct_in_buffer, allocate_gpu_memory);
    delete this->ct_in_buffer;
    this->ct_in_buffer = nullptr;

    this->prepare_mem->release(streams);
    delete this->prepare_mem;
    this->prepare_mem = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->sum_input_cts, allocate_gpu_memory);
    delete this->sum_input_cts;
    this->sum_input_cts = nullptr;

    this->sum_mem->release(streams);
    delete this->sum_mem;
    this->sum_mem = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->sum_output_not_propagated,
                                   allocate_gpu_memory);
    delete this->sum_output_not_propagated;
    this->sum_output_not_propagated = nullptr;

    this->lut_message_not->release(streams);
    delete this->lut_message_not;
    this->lut_message_not = nullptr;

    this->lut_carry_not->release(streams);
    delete this->lut_carry_not;
    this->lut_carry_not = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->message_blocks_not,
                                   allocate_gpu_memory);
    delete this->message_blocks_not;
    this->message_blocks_not = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->carry_blocks_not, allocate_gpu_memory);
    delete this->carry_blocks_not;
    this->carry_blocks_not = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->rotated_carry_blocks,
                                   allocate_gpu_memory);
    delete this->rotated_carry_blocks;
    this->rotated_carry_blocks = nullptr;

    this->final_propagate_mem->release(streams);
    delete this->final_propagate_mem;
    this->final_propagate_mem = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
