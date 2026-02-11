#ifndef TRIVIUM_UTILITIES_H
#define TRIVIUM_UTILITIES_H
#include "../integer/integer_utilities.h"

/// Struct to hold the LUTs.
template <typename Torus> struct int_trivium_lut_buffers {
  // Bivariate AND Gate LUT:
  // AND operation: f(a, b) = (a & 1) & (b & 1).
  // This is a Bivariate PBS used for the non-linear parts of Trivium.
  int_radix_lut<Torus> *and_lut;

  // Univariate Identity LUT:
  // MESSAGE EXTRACTION operation: f(x) = x & 1.
  // This is a Univariate PBS used to "flush" the state: it resets the noise
  // after additions and ensures the message stays within the binary message
  // space.
  int_radix_lut<Torus> *flush_lut;

  int_trivium_lut_buffers(CudaStreams streams, const int_radix_params &params,
                          bool allocate_gpu_memory, uint32_t num_trivium_inputs,
                          uint64_t &size_tracker) {

    constexpr uint32_t BATCH_SIZE = 64;
    constexpr uint32_t MAX_AND_PER_STEP = 3;
    uint32_t total_lut_ops = num_trivium_inputs * BATCH_SIZE * MAX_AND_PER_STEP;

    this->and_lut = new int_radix_lut<Torus>(streams, params, 1, total_lut_ops,
                                             allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus, Torus)> and_lambda =
        [](Torus a, Torus b) -> Torus { return (a & 1) & (b & 1); };

    auto active_streams_and =
        streams.active_gpu_subset(total_lut_ops, params.pbs_type);
    this->and_lut->generate_and_broadcast_bivariate_lut(
        active_streams_and, {0}, {and_lambda}, LUT_0_FOR_ALL_BLOCKS);
    this->and_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);

    uint32_t total_flush_ops = num_trivium_inputs * BATCH_SIZE * 4;

    this->flush_lut = new int_radix_lut<Torus>(
        streams, params, 1, total_flush_ops, allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus)> flush_lambda = [](Torus x) -> Torus {
      return x & 1;
    };

    auto active_streams_flush =
        streams.active_gpu_subset(total_flush_ops, params.pbs_type);
    this->flush_lut->generate_and_broadcast_lut(
        active_streams_flush, {0}, {flush_lambda}, LUT_0_FOR_ALL_BLOCKS);
    this->flush_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);
  }

  void release(CudaStreams streams) {
    this->and_lut->release(streams);
    delete this->and_lut;
    this->and_lut = nullptr;

    this->flush_lut->release(streams);
    delete this->flush_lut;
    this->flush_lut = nullptr;
  }
};

/// Struct to hold the state and temporary workspaces required for
/// Trivium execution on the GPU.
///
/// This struct manages the memory for the internal registers (A, B, C),
/// temporary buffers used during the update function, and buffers used for
/// packing data before and after PBS.
template <typename Torus> struct int_trivium_state_workspaces {
  // Trivium Internal State Registers:
  // Register A: 93 bits
  CudaRadixCiphertextFFI *a_reg;
  // Register B: 84 bits
  CudaRadixCiphertextFFI *b_reg;
  // Register C: 111 bits
  CudaRadixCiphertextFFI *c_reg;

  // Shift Workspace:
  // Used to manage bitshifting operations on the registers
  CudaRadixCiphertextFFI *shift_workspace;

  // Temporary Update Buffers:
  // Intermediate buffers for the trivium update logic (t1, t2, t3)
  CudaRadixCiphertextFFI *temp_t1;
  CudaRadixCiphertextFFI *temp_t2;
  CudaRadixCiphertextFFI *temp_t3;

  // Buffers to hold the new values for the registers after an update step
  CudaRadixCiphertextFFI *new_a;
  CudaRadixCiphertextFFI *new_b;
  CudaRadixCiphertextFFI *new_c;

  // PBS Packing Buffers:
  // Buffers for packing inputs into the bivariate lookup table (AND gate)
  CudaRadixCiphertextFFI *packed_pbs_lhs;
  CudaRadixCiphertextFFI *packed_pbs_rhs;
  // Buffer for the output of the bivariate PBS
  CudaRadixCiphertextFFI *packed_pbs_out;

  // Flush/Cleanup Packing Buffers:
  // Buffers for the "flush" LUT which cleans up noise after additions
  CudaRadixCiphertextFFI *packed_flush_in;
  CudaRadixCiphertextFFI *packed_flush_out;

  int_trivium_state_workspaces(CudaStreams streams,
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
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->a_reg, allocate_gpu_memory);
    delete this->a_reg;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->b_reg, allocate_gpu_memory);
    delete this->b_reg;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->c_reg, allocate_gpu_memory);
    delete this->c_reg;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->shift_workspace, allocate_gpu_memory);
    delete this->shift_workspace;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->temp_t1, allocate_gpu_memory);
    delete this->temp_t1;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->temp_t2, allocate_gpu_memory);
    delete this->temp_t2;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->temp_t3, allocate_gpu_memory);
    delete this->temp_t3;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->new_a, allocate_gpu_memory);
    delete this->new_a;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->new_b, allocate_gpu_memory);
    delete this->new_b;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->new_c, allocate_gpu_memory);
    delete this->new_c;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_pbs_lhs, allocate_gpu_memory);
    delete this->packed_pbs_lhs;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_pbs_rhs, allocate_gpu_memory);
    delete this->packed_pbs_rhs;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_pbs_out, allocate_gpu_memory);
    delete this->packed_pbs_out;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_flush_in, allocate_gpu_memory);
    delete this->packed_flush_in;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->packed_flush_out, allocate_gpu_memory);
    delete this->packed_flush_out;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_trivium_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;

  int_trivium_lut_buffers<Torus> *luts;
  int_trivium_state_workspaces<Torus> *state;

  int_trivium_buffer(CudaStreams streams, const int_radix_params &params,
                     bool allocate_gpu_memory, uint32_t num_inputs,
                     uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    this->luts = new int_trivium_lut_buffers<Torus>(
        streams, params, allocate_gpu_memory, num_inputs, size_tracker);

    this->state = new int_trivium_state_workspaces<Torus>(
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
