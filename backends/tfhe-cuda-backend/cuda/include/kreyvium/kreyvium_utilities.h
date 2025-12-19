#ifndef KREYVIUM_UTILITIES_H
#define KREYVIUM_UTILITIES_H
#include "../integer/integer_utilities.h"

// Kreyvium specific constants
// The batch size is set to 64 to allow efficient parallel processing of 64
// steps at once.
constexpr uint32_t KREYVIUM_BATCH_SIZE = 64;

// In each Kreyvium step, there are exactly 3 non-linear AND operations:
// 1. (c109 & c108)
// 2. (a91 & a90)
// 3. (b82 & b81)
constexpr uint32_t KREYVIUM_NUM_AND_GATES = 3;

// In each Kreyvium step, there are 4 paths that require a "flush"
// to noise-cancel and extract the bit:
// 1. New bit for Register A
// 2. New bit for Register B
// 3. New bit for Register C
// 4. The Output Keystream bit
constexpr uint32_t KREYVIUM_NUM_FLUSH_PATHS = 4;

/// Struct to hold the LUTs.
template <typename Torus> struct int_kreyvium_lut_buffers {
  // Bivariate AND Gate LUT:
  // AND operation: f(a, b) = (a & 1) & (b & 1).
  // This is a Bivariate PBS used for the non-linear parts of Kreyvium.
  int_radix_lut<Torus> *and_lut;

  // Univariate Flush/Identity LUT:
  // MESSAGE EXTRACTION operation: f(x) = x & 1.
  // This is a Univariate PBS used to "flush" the state (reset noise/carries).
  int_radix_lut<Torus> *flush_lut;

  int_kreyvium_lut_buffers(CudaStreams streams, const int_radix_params &params,
                           bool allocate_gpu_memory, uint32_t num_inputs,
                           uint64_t &size_tracker) {

    uint32_t and_ops =
        num_inputs * KREYVIUM_BATCH_SIZE * KREYVIUM_NUM_AND_GATES;
    uint32_t flush_ops =
        num_inputs * KREYVIUM_BATCH_SIZE * KREYVIUM_NUM_FLUSH_PATHS;

    this->and_lut = new int_radix_lut<Torus>(streams, params, 1, and_ops,
                                             allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus, Torus)> and_lambda =
        [](Torus lhs, Torus rhs) -> Torus { return (lhs & 1) & (rhs & 1); };

    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), this->and_lut->get_lut(0, 0),
        this->and_lut->get_degree(0), this->and_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, and_lambda, allocate_gpu_memory);

    auto active_streams_and =
        streams.active_gpu_subset(and_ops, params.pbs_type);
    this->and_lut->broadcast_lut(active_streams_and);
    this->and_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);

    this->flush_lut = new int_radix_lut<Torus>(
        streams, params, 1, flush_ops, allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus)> flush_lambda = [](Torus x) -> Torus {
      return x & 1;
    };

    generate_device_accumulator<Torus>(
        streams.stream(0), streams.gpu_index(0), this->flush_lut->get_lut(0, 0),
        this->flush_lut->get_degree(0), this->flush_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, flush_lambda, allocate_gpu_memory);

    auto active_streams_flush =
        streams.active_gpu_subset(flush_ops, params.pbs_type);
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

/// Struct to hold the Kreyvium internal state and temporary workspaces.
template <typename Torus> struct int_kreyvium_state_workspaces {

  CudaRadixCiphertextFFI *a_reg;
  CudaRadixCiphertextFFI *b_reg;
  CudaRadixCiphertextFFI *c_reg;
  CudaRadixCiphertextFFI *k_reg;
  CudaRadixCiphertextFFI *iv_reg;

  // Shift Workspace
  CudaRadixCiphertextFFI *shift_workspace;

  // Temporary Update Buffers
  CudaRadixCiphertextFFI *temp_a;
  CudaRadixCiphertextFFI *temp_b;
  CudaRadixCiphertextFFI *temp_c;

  CudaRadixCiphertextFFI *packed_and_lhs;
  CudaRadixCiphertextFFI *packed_and_rhs;
  CudaRadixCiphertextFFI *packed_and_out;

  // Flush/Cleanup Packing Buffers
  CudaRadixCiphertextFFI *packed_flush_in;
  CudaRadixCiphertextFFI *packed_flush_out;

  uint32_t max_batch_blocks;
  uint32_t k_offset;
  uint32_t iv_offset;

  int_kreyvium_state_workspaces(CudaStreams streams,
                                const int_radix_params &params,
                                bool allocate_gpu_memory, uint32_t num_inputs,
                                uint64_t &size_tracker) {

    uint32_t batch_blocks = KREYVIUM_BATCH_SIZE * num_inputs;
    this->max_batch_blocks = batch_blocks;
    this->k_offset = 0;
    this->iv_offset = 0;

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

    this->temp_a = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->temp_a, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->temp_b = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->temp_b, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->temp_c = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->temp_c, batch_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->packed_and_lhs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_and_lhs,
        KREYVIUM_NUM_AND_GATES * batch_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->packed_and_rhs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_and_rhs,
        KREYVIUM_NUM_AND_GATES * batch_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->packed_and_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_and_out,
        KREYVIUM_NUM_AND_GATES * batch_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->packed_flush_in = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_flush_in,
        KREYVIUM_NUM_FLUSH_PATHS * batch_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->packed_flush_out = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->packed_flush_out,
        KREYVIUM_NUM_FLUSH_PATHS * batch_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->a_reg, allocate_gpu_memory);
    delete this->a_reg;
    this->a_reg = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->b_reg, allocate_gpu_memory);
    delete this->b_reg;
    this->b_reg = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->c_reg, allocate_gpu_memory);
    delete this->c_reg;
    this->c_reg = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->k_reg, allocate_gpu_memory);
    delete this->k_reg;
    this->k_reg = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->iv_reg, allocate_gpu_memory);
    delete this->iv_reg;
    this->iv_reg = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->shift_workspace, allocate_gpu_memory);
    delete this->shift_workspace;
    this->shift_workspace = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->temp_a, allocate_gpu_memory);
    delete this->temp_a;
    this->temp_a = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->temp_b, allocate_gpu_memory);
    delete this->temp_b;
    this->temp_b = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->temp_c, allocate_gpu_memory);
    delete this->temp_c;
    this->temp_c = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_and_lhs, allocate_gpu_memory);
    delete this->packed_and_lhs;
    this->packed_and_lhs = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_and_rhs, allocate_gpu_memory);
    delete this->packed_and_rhs;
    this->packed_and_rhs = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_and_out, allocate_gpu_memory);
    delete this->packed_and_out;
    this->packed_and_out = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_flush_in, allocate_gpu_memory);
    delete this->packed_flush_in;
    this->packed_flush_in = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_flush_out, allocate_gpu_memory);
    delete this->packed_flush_out;
    this->packed_flush_out = nullptr;

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
