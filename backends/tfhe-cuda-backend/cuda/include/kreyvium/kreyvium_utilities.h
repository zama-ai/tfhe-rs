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
constexpr uint32_t KREYVIUM_REGISTER_A_BITS = 93;
constexpr uint32_t KREYVIUM_REGISTER_B_BITS = 84;
constexpr uint32_t KREYVIUM_REGISTER_C_BITS = 111;
constexpr uint32_t KREYVIUM_KEY_BITS = 128;
constexpr uint32_t KREYVIUM_IV_BITS = 128;

// Standard Kreyvium warm-up: 1152 cycles before the first keystream bit is
// emitted, processed in batches of KREYVIUM_BATCH_SIZE.
constexpr uint32_t KREYVIUM_WARMUP_CYCLES = 1152;
constexpr uint32_t KREYVIUM_WARMUP_BATCHES =
    KREYVIUM_WARMUP_CYCLES / KREYVIUM_BATCH_SIZE;

// During init, c[1..67] are set to 1 per the Kreyvium spec: 66 bits starting
// at offset 1 in the 111-bit C register.
constexpr uint32_t KREYVIUM_C_ONES_OFFSET = 1;
constexpr uint32_t KREYVIUM_C_ONES_COUNT = 66;

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

    // BIVARIATE AND LUT
    //
    this->and_lut = new int_radix_lut<Torus>(streams, params, 1, and_ops,
                                             allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus, Torus)> and_lambda =
        [](Torus lhs, Torus rhs) -> Torus { return (lhs & 1) & (rhs & 1); };

    auto active_streams_and =
        streams.active_gpu_subset(and_ops, params.pbs_type);

    this->and_lut->generate_and_broadcast_bivariate_lut(
        active_streams_and, {0}, {and_lambda}, LUT_0_FOR_ALL_BLOCKS);

    // UNIVARIATE FLUSH LUTS
    //
    std::function<Torus(Torus)> flush_lambda = [](Torus x) -> Torus {
      return x & 1;
    };
    this->flush_lut = new int_radix_lut<Torus>(
        streams, params, 1, flush_ops, allocate_gpu_memory, size_tracker);
    auto active_streams_flush =
        streams.active_gpu_subset(flush_ops, params.pbs_type);

    this->flush_lut->generate_and_broadcast_lut(
        active_streams_flush, {0}, {flush_lambda}, LUT_0_FOR_ALL_BLOCKS);
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

// Holds the temporary GPU buffers and workspaces required during the
// execution of the Kreyvium cipher. Registers a/b/c/k/iv are owned by the
// caller (the persistent state) and passed in to each call.
//
template <typename Torus> struct int_kreyvium_workspaces {
  CudaRadixCiphertextFFI *shift_workspace;
  CudaRadixCiphertextFFI *temp_a;
  CudaRadixCiphertextFFI *temp_b;
  CudaRadixCiphertextFFI *temp_c;
  CudaRadixCiphertextFFI *packed_and_lhs;
  CudaRadixCiphertextFFI *packed_and_rhs;
  CudaRadixCiphertextFFI *packed_and_out;
  CudaRadixCiphertextFFI *packed_flush_in;
  CudaRadixCiphertextFFI *packed_flush_out;

  int_kreyvium_workspaces(CudaStreams streams, const int_radix_params &params,
                          bool allocate_gpu_memory, uint32_t num_inputs,
                          uint64_t &size_tracker) {
    uint32_t batch_blocks = KREYVIUM_BATCH_SIZE * num_inputs;
    this->shift_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->shift_workspace,
        KREYVIUM_KEY_BITS * num_inputs, params.big_lwe_dimension, size_tracker,
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
  int_kreyvium_workspaces<Torus> *ws;

  int_kreyvium_buffer(CudaStreams streams, const int_radix_params &params,
                      bool allocate_gpu_memory, uint32_t num_inputs,
                      uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;
    this->luts = new int_kreyvium_lut_buffers<Torus>(
        streams, params, allocate_gpu_memory, num_inputs, size_tracker);
    this->ws = new int_kreyvium_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_inputs, size_tracker);
  }

  void release(CudaStreams streams) {
    luts->release(streams);
    delete luts;
    luts = nullptr;
    ws->release(streams, allocate_gpu_memory);
    delete ws;
    ws = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

#endif
