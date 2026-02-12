#ifndef AES_UTILITIES
#define AES_UTILITIES
#include "../integer/integer_utilities.h"

/**
 * This structure holds pre-computed LUTs for essential bitwise operations
 * required by the homomorphic AES circuit. Pre-computing these tables allows
 * for efficient application of non-linear functions like AND during the PBS
 * process. It includes LUTs for:
 * - AND: for the non-linear part of the S-Box.
 * - FLUSH: to clear carry bits and isolate the message bit (x -> x & 1).
 * - CARRY: to extract the carry bit for additions (x -> (x >> 1) & 1).
 */
template <typename Torus> struct int_aes_lut_buffers {
  int_radix_lut<Torus> *and_lut;
  int_radix_lut<Torus> *flush_lut;
  int_radix_lut<Torus> *carry_lut;

  int_aes_lut_buffers(CudaStreams streams, const int_radix_params &params,
                      bool allocate_gpu_memory, uint32_t num_aes_inputs,
                      uint32_t sbox_parallelism, uint64_t &size_tracker) {

    constexpr uint32_t AES_STATE_BITS = 128;
    constexpr uint32_t SBOX_MAX_AND_GATES = 18;

    this->and_lut = new int_radix_lut<Torus>(
        streams, params, 1,
        SBOX_MAX_AND_GATES * num_aes_inputs * sbox_parallelism,
        allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus, Torus)> and_lambda =
        [](Torus a, Torus b) -> Torus { return a & b; };

    auto active_streams_and_lut = streams.active_gpu_subset(
        SBOX_MAX_AND_GATES * num_aes_inputs * sbox_parallelism,
        params.pbs_type);
    this->and_lut->generate_and_broadcast_bivariate_lut(
        active_streams_and_lut, {0}, {and_lambda}, LUT_0_FOR_ALL_BLOCKS);

    this->and_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);

    this->flush_lut = new int_radix_lut<Torus>(
        streams, params, 1, AES_STATE_BITS * num_aes_inputs,
        allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> flush_lambda = [](Torus x) -> Torus {
      return x & 1;
    };

    auto active_streams_flush_lut = streams.active_gpu_subset(
        AES_STATE_BITS * num_aes_inputs, params.pbs_type);
    this->flush_lut->generate_and_broadcast_lut(
        active_streams_flush_lut, {0}, {flush_lambda}, LUT_0_FOR_ALL_BLOCKS);
    this->flush_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);

    this->carry_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_aes_inputs, allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> carry_lambda = [](Torus x) -> Torus {
      return (x >> 1) & 1;
    };

    auto active_streams_carry_lut =
        streams.active_gpu_subset(num_aes_inputs, params.pbs_type);
    this->carry_lut->generate_and_broadcast_lut(
        active_streams_carry_lut, {0}, {carry_lambda}, LUT_0_FOR_ALL_BLOCKS);
    this->carry_lut->setup_gemm_batch_ks_temp_buffers(size_tracker);
  }

  void release(CudaStreams streams) {
    this->and_lut->release(streams);
    delete this->and_lut;
    this->and_lut = nullptr;

    this->flush_lut->release(streams);
    delete this->flush_lut;
    this->flush_lut = nullptr;

    this->carry_lut->release(streams);
    delete this->carry_lut;
    this->carry_lut = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * The operations within an AES round, particularly MixColumns, require
 * intermediate storage for calculations. These buffers are designed to hold
 * temporary values like copies of columns or the results of multiplications,
 * avoiding overwriting data that is still needed in the same round.
 */
template <typename Torus> struct int_aes_round_workspaces {
  CudaRadixCiphertextFFI *mix_columns_col_copy_buffer;
  CudaRadixCiphertextFFI *mix_columns_mul_workspace_buffer;
  CudaRadixCiphertextFFI *vec_tmp_bit_buffer;

  int_aes_round_workspaces(CudaStreams streams, const int_radix_params &params,
                           bool allocate_gpu_memory, uint32_t num_aes_inputs,
                           uint64_t &size_tracker) {

    constexpr uint32_t BITS_PER_BYTE = 8;
    constexpr uint32_t BYTES_PER_COLUMN = 4;
    constexpr uint32_t BITS_PER_COLUMN = BITS_PER_BYTE * BYTES_PER_COLUMN;
    constexpr uint32_t MIX_COLUMNS_MUL_WORKSPACE_BYTES = BYTES_PER_COLUMN + 1;

    this->mix_columns_col_copy_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->mix_columns_col_copy_buffer, BITS_PER_COLUMN * num_aes_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->mix_columns_mul_workspace_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->mix_columns_mul_workspace_buffer,
        MIX_COLUMNS_MUL_WORKSPACE_BYTES * BITS_PER_BYTE * num_aes_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->vec_tmp_bit_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->vec_tmp_bit_buffer,
        num_aes_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->mix_columns_col_copy_buffer,
                                   allocate_gpu_memory);
    delete this->mix_columns_col_copy_buffer;
    this->mix_columns_col_copy_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->mix_columns_mul_workspace_buffer,
                                   allocate_gpu_memory);
    delete this->mix_columns_mul_workspace_buffer;
    this->mix_columns_mul_workspace_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->vec_tmp_bit_buffer,
                                   allocate_gpu_memory);
    delete this->vec_tmp_bit_buffer;
    this->vec_tmp_bit_buffer = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * In CTR mode, a counter is homomorphically added to the encrypted IV. This
 * structure holds the necessary buffers for this 128-bit ripple-carry
 * addition, such as the buffer for the propagating carry bit
 * (`vec_tmp_carry_buffer`) across the addition chain.
 */
template <typename Torus> struct int_aes_counter_workspaces {
  CudaRadixCiphertextFFI *vec_tmp_carry_buffer;
  CudaRadixCiphertextFFI *vec_tmp_sum_buffer;
  CudaRadixCiphertextFFI *vec_trivial_b_bits_buffer;
  Torus *h_counter_bits_buffer;
  Torus *d_counter_bits_buffer;

  int_aes_counter_workspaces(CudaStreams streams,
                             const int_radix_params &params,
                             bool allocate_gpu_memory, uint32_t num_aes_inputs,
                             uint64_t &size_tracker) {

    this->vec_tmp_carry_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->vec_tmp_carry_buffer,
        num_aes_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->vec_tmp_sum_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->vec_tmp_sum_buffer,
        num_aes_inputs, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->vec_trivial_b_bits_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->vec_trivial_b_bits_buffer, num_aes_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->h_counter_bits_buffer =
        (Torus *)malloc(safe_mul_sizeof<Torus>(num_aes_inputs));
    size_tracker += safe_mul_sizeof<Torus>(num_aes_inputs);
    this->d_counter_bits_buffer = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_aes_inputs), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->vec_tmp_carry_buffer,
                                   allocate_gpu_memory);
    delete this->vec_tmp_carry_buffer;
    this->vec_tmp_carry_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->vec_tmp_sum_buffer,
                                   allocate_gpu_memory);
    delete this->vec_tmp_sum_buffer;
    this->vec_tmp_sum_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->vec_trivial_b_bits_buffer,
                                   allocate_gpu_memory);
    delete this->vec_trivial_b_bits_buffer;
    this->vec_trivial_b_bits_buffer = nullptr;

    if (allocate_gpu_memory) {
      cuda_drop_async(this->d_counter_bits_buffer, streams.stream(0),
                      streams.gpu_index(0));
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(this->h_counter_bits_buffer);
  }
};

/**
 * This structure allocates the most significant memory blocks:
 * - `sbox_internal_workspace`: A large workspace for the complex, parallel
 * evaluation of the S-Box circuit.
 * - `main_bitsliced_states_buffer`: Holds the entire set of AES states in a
 * bitsliced layout, which is optimal for parallel bitwise operations on the
 * GPU.
 * - Other buffers are used for data layout transformations (transposition) and
 * for batching small operations into larger, more efficient launches.
 */
template <typename Torus> struct int_aes_main_workspaces {
  CudaRadixCiphertextFFI *sbox_internal_workspace;
  CudaRadixCiphertextFFI *initial_states_and_jit_key_workspace;
  CudaRadixCiphertextFFI *main_bitsliced_states_buffer;
  CudaRadixCiphertextFFI *tmp_tiled_key_buffer;
  CudaRadixCiphertextFFI *batch_processing_buffer;

  int_aes_main_workspaces(CudaStreams streams, const int_radix_params &params,
                          bool allocate_gpu_memory, uint32_t num_aes_inputs,
                          uint32_t sbox_parallelism, uint64_t &size_tracker) {

    constexpr uint32_t AES_STATE_BITS = 128;
    constexpr uint32_t SBOX_MAX_AND_GATES = 18;
    constexpr uint32_t BATCH_BUFFER_OPERANDS = 3;

    this->sbox_internal_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->sbox_internal_workspace,
        num_aes_inputs * AES_STATE_BITS * sbox_parallelism,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->initial_states_and_jit_key_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->initial_states_and_jit_key_workspace,
        num_aes_inputs * AES_STATE_BITS, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->main_bitsliced_states_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->main_bitsliced_states_buffer, num_aes_inputs * AES_STATE_BITS,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->tmp_tiled_key_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_tiled_key_buffer,
        num_aes_inputs * AES_STATE_BITS, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->batch_processing_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->batch_processing_buffer,
        num_aes_inputs * SBOX_MAX_AND_GATES * BATCH_BUFFER_OPERANDS *
            sbox_parallelism,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->sbox_internal_workspace,
                                   allocate_gpu_memory);
    delete this->sbox_internal_workspace;
    this->sbox_internal_workspace = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->initial_states_and_jit_key_workspace,
                                   allocate_gpu_memory);
    delete this->initial_states_and_jit_key_workspace;
    this->initial_states_and_jit_key_workspace = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->main_bitsliced_states_buffer,
                                   allocate_gpu_memory);
    delete this->main_bitsliced_states_buffer;
    this->main_bitsliced_states_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_tiled_key_buffer,
                                   allocate_gpu_memory);
    delete this->tmp_tiled_key_buffer;
    this->tmp_tiled_key_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->batch_processing_buffer,
                                   allocate_gpu_memory);
    delete this->batch_processing_buffer;
    this->batch_processing_buffer = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * This structure acts as a container, holding instances of all the other buffer
 * management structs. It provides a
 * single object to manage the entire lifecycle of memory needed for a complete
 * AES-CTR encryption operation.
 */
template <typename Torus> struct int_aes_encrypt_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_aes_inputs;
  uint32_t sbox_parallel_instances;

  int_aes_lut_buffers<Torus> *luts;
  int_aes_round_workspaces<Torus> *round_workspaces;
  int_aes_counter_workspaces<Torus> *counter_workspaces;
  int_aes_main_workspaces<Torus> *main_workspaces;

  int_aes_encrypt_buffer(CudaStreams streams, const int_radix_params &params,
                         bool allocate_gpu_memory, uint32_t num_aes_inputs,
                         uint32_t sbox_parallelism, uint64_t &size_tracker) {

    PANIC_IF_FALSE(num_aes_inputs >= 1,
                   "num_aes_inputs should be greater or equal to 1");

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_aes_inputs = num_aes_inputs;
    this->sbox_parallel_instances = sbox_parallelism;

    this->luts = new int_aes_lut_buffers<Torus>(
        streams, params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism,
        size_tracker);

    this->round_workspaces = new int_aes_round_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_aes_inputs, size_tracker);

    this->counter_workspaces = new int_aes_counter_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_aes_inputs, size_tracker);

    this->main_workspaces = new int_aes_main_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism,
        size_tracker);
  }

  void release(CudaStreams streams) {
    luts->release(streams);
    delete luts;
    luts = nullptr;

    round_workspaces->release(streams, allocate_gpu_memory);
    delete round_workspaces;
    round_workspaces = nullptr;

    counter_workspaces->release(streams, allocate_gpu_memory);
    delete counter_workspaces;
    counter_workspaces = nullptr;

    main_workspaces->release(streams, allocate_gpu_memory);
    delete main_workspaces;
    main_workspaces = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * This structure holds the buffer for the 44 words of the expanded key
 * and temporary storage for word manipulations.
 * It contains its own instance of `int_aes_encrypt_buffer` because the
 * key expansion algorithm itself requires using the S-Box.
 * This separation ensures that memory for key expansion can be allocated and
 * freed independently of the main encryption process.
 */
template <typename Torus> struct int_key_expansion_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *words_buffer;

  CudaRadixCiphertextFFI *tmp_word_buffer;
  CudaRadixCiphertextFFI *tmp_rotated_word_buffer;

  int_aes_encrypt_buffer<Torus> *aes_encrypt_buffer;

  int_key_expansion_buffer(CudaStreams streams, const int_radix_params &params,
                           bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    constexpr uint32_t TOTAL_WORDS = 44;
    constexpr uint32_t BITS_PER_WORD = 32;
    constexpr uint32_t TOTAL_BITS = TOTAL_WORDS * BITS_PER_WORD;

    this->words_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->words_buffer, TOTAL_BITS,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->tmp_word_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_word_buffer,
        BITS_PER_WORD, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->tmp_rotated_word_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_rotated_word_buffer,
        BITS_PER_WORD, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->aes_encrypt_buffer = new int_aes_encrypt_buffer<Torus>(
        streams, params, allocate_gpu_memory, 1, 4, size_tracker);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->words_buffer, allocate_gpu_memory);
    delete this->words_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_word_buffer, allocate_gpu_memory);
    delete this->tmp_word_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_rotated_word_buffer,
                                   allocate_gpu_memory);
    delete this->tmp_rotated_word_buffer;

    this->aes_encrypt_buffer->release(streams);
    delete this->aes_encrypt_buffer;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_key_expansion_256_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *words_buffer;

  CudaRadixCiphertextFFI *tmp_word_buffer;
  CudaRadixCiphertextFFI *tmp_rotated_word_buffer;

  int_aes_encrypt_buffer<Torus> *aes_encrypt_buffer;

  int_key_expansion_256_buffer(CudaStreams streams,
                               const int_radix_params &params,
                               bool allocate_gpu_memory,
                               uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    constexpr uint32_t TOTAL_WORDS = 60;
    constexpr uint32_t BITS_PER_WORD = 32;
    constexpr uint32_t TOTAL_BITS = TOTAL_WORDS * BITS_PER_WORD;

    this->words_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->words_buffer, TOTAL_BITS,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->tmp_word_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_word_buffer,
        BITS_PER_WORD, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->tmp_rotated_word_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_rotated_word_buffer,
        BITS_PER_WORD, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->aes_encrypt_buffer = new int_aes_encrypt_buffer<Torus>(
        streams, params, allocate_gpu_memory, 1, 4, size_tracker);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->words_buffer, allocate_gpu_memory);
    delete this->words_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_word_buffer, allocate_gpu_memory);
    delete this->tmp_word_buffer;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_rotated_word_buffer,
                                   allocate_gpu_memory);
    delete this->tmp_rotated_word_buffer;

    this->aes_encrypt_buffer->release(streams);
    delete this->aes_encrypt_buffer;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

#endif
