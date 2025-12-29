#ifndef KREYVIUM_UTILITIES_H
#define KREYVIUM_UTILITIES_H
#include "../integer/integer_utilities.h"

template <typename Torus> struct int_kreyvium_lut_buffers {
  int_radix_lut<Torus> *and_lut;
  int_radix_lut<Torus> *flush_lut;

  int_kreyvium_lut_buffers(CudaStreams streams, const int_radix_params &params,
                           bool allocate_gpu_memory, uint32_t num_inputs,
                           uint64_t &size_tracker) {

    constexpr uint32_t BATCH_SIZE = 64;
    constexpr uint32_t MAX_AND_PER_STEP = 3;
    uint32_t total_lut_ops = num_inputs * BATCH_SIZE * MAX_AND_PER_STEP;

    this->and_lut = new int_radix_lut<Torus>(streams, params, 1, total_lut_ops,
                                             allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus, Torus)> and_lambda =
        [](Torus a, Torus b) -> Torus { return a & b; };

    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), this->and_lut->get_lut(0, 0),
        this->and_lut->get_degree(0), this->and_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, and_lambda, allocate_gpu_memory);

    auto active_streams_and =
        streams.active_gpu_subset(total_lut_ops, params.pbs_type);
    this->and_lut->broadcast_lut(active_streams_and);
    this->and_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);

    uint32_t total_flush_ops = num_inputs * BATCH_SIZE * 4;

    this->flush_lut = new int_radix_lut<Torus>(
        streams, params, 1, total_flush_ops, allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus)> flush_lambda = [](Torus x) -> Torus {
      return x & 1;
    };

    generate_device_accumulator(
        streams.stream(0), streams.gpu_index(0), this->flush_lut->get_lut(0, 0),
        this->flush_lut->get_degree(0), this->flush_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, flush_lambda, allocate_gpu_memory);

    auto active_streams_flush =
        streams.active_gpu_subset(total_flush_ops, params.pbs_type);
    this->flush_lut->broadcast_lut(active_streams_flush);
    this->flush_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);
  }

  void release(CudaStreams streams) {
    this->and_lut->release(streams);
    delete this->and_lut;
    this->and_lut = nullptr;

    this->flush_lut->release(streams);
    delete this->flush_lut;
    this->flush_lut = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_kreyvium_state_workspaces {
  CudaRadixCiphertextFFI *a_reg;
  CudaRadixCiphertextFFI *b_reg;
  CudaRadixCiphertextFFI *c_reg;

  CudaRadixCiphertextFFI *k_reg;
  CudaRadixCiphertextFFI *iv_reg;

  CudaRadixCiphertextFFI *shift_workspace;

  CudaRadixCiphertextFFI *temp_t1;
  CudaRadixCiphertextFFI *temp_t2;
  CudaRadixCiphertextFFI *temp_t3;
  CudaRadixCiphertextFFI *new_a;
  CudaRadixCiphertextFFI *new_b;
  CudaRadixCiphertextFFI *new_c;

  CudaRadixCiphertextFFI *packed_pbs_lhs;
  CudaRadixCiphertextFFI *packed_pbs_rhs;
  CudaRadixCiphertextFFI *packed_pbs_out;

  CudaRadixCiphertextFFI *packed_flush_in;
  CudaRadixCiphertextFFI *packed_flush_out;

  int_kreyvium_state_workspaces(CudaStreams streams,
                                const int_radix_params &params,
                                bool allocate_gpu_memory, uint32_t num_inputs,
                                uint64_t &size_tracker) {

    this->a_reg = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->a_reg, 93 * num_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->b_reg = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->b_reg, 84 * num_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->c_reg = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->c_reg, 111 * num_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->k_reg = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->k_reg, 128 * num_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->iv_reg = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->iv_reg, 128 * num_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->shift_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->shift_workspace,
        128 * num_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint32_t batch_blocks = 64 * num_inputs;

    this->temp_t1 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->temp_t1, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->temp_t2 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->temp_t2, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->temp_t3 = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->temp_t3, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->new_a = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->new_a, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->new_b = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->new_b, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->new_c = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->new_c, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->packed_pbs_lhs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_pbs_lhs,
        3 * batch_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->packed_pbs_rhs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_pbs_rhs,
        3 * batch_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->packed_pbs_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_pbs_out,
        3 * batch_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->packed_flush_in = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_flush_in,
        4 * batch_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->packed_flush_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_flush_out,
        4 * batch_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    auto release_and_delete = [&](CudaRadixCiphertextFFI *&ptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ptr, allocate_gpu_memory);
      delete ptr;
      ptr = nullptr;
    };

    release_and_delete(this->a_reg);
    release_and_delete(this->b_reg);
    release_and_delete(this->c_reg);
    release_and_delete(this->k_reg);
    release_and_delete(this->iv_reg);
    release_and_delete(this->shift_workspace);
    release_and_delete(this->temp_t1);
    release_and_delete(this->temp_t2);
    release_and_delete(this->temp_t3);
    release_and_delete(this->new_a);
    release_and_delete(this->new_b);
    release_and_delete(this->new_c);
    release_and_delete(this->packed_pbs_lhs);
    release_and_delete(this->packed_pbs_rhs);
    release_and_delete(this->packed_pbs_out);
    release_and_delete(this->packed_flush_in);
    release_and_delete(this->packed_flush_out);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_kreyvium_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_kreyvium_lut_buffers<Torus> *luts;
  int_kreyvium_state_workspaces<Torus> *state;

  int_kreyvium_buffer(CudaStreams streams, const int_radix_params &params,
                      bool allocate_gpu_memory, uint32_t num_inputs,
                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->luts = new int_kreyvium_lut_buffers<Torus>(
        streams, params, allocate_gpu_memory, num_inputs, size_tracker);

    this->state = new int_kreyvium_state_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_inputs, size_tracker);
  }

  void release(CudaStreams streams) {
    luts->release(streams);
    delete luts;
    luts = nullptr;

    state->release(streams, allocate_gpu_memory);
    delete state;
    state = nullptr;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

#endif
