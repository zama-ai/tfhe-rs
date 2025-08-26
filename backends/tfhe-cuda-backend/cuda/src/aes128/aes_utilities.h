#ifndef AES_UTILITIES
#define AES_UTILITIES
#include "../../include/integer/integer_utilities.h"

template <typename Torus> struct int_aes_lut_buffers {
  int_radix_lut<Torus> *and_lut;
  int_radix_lut<Torus> *flush_lut;
  int_radix_lut<Torus> *carry_lut;

  int_aes_lut_buffers(CudaStreams streams, const int_radix_params &params,
                      bool allocate_gpu_memory, uint32_t num_blocks,
                      uint32_t sbox_parallelism, uint64_t &size_tracker) {

    constexpr uint32_t AES_STATE_BITS = 128;
    constexpr uint32_t SBOX_MAX_AND_GATES = 18;

    this->and_lut = new int_radix_lut<Torus>(
        streams, params, 1, SBOX_MAX_AND_GATES * num_blocks * sbox_parallelism,
        allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus, Torus)> and_lambda =
        [](Torus a, Torus b) -> Torus { return a & b; };
    generate_device_accumulator_bivariate<Torus>(
        streams.stream(0), streams.gpu_index(0), this->and_lut->get_lut(0, 0),
        this->and_lut->get_degree(0), this->and_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, and_lambda, allocate_gpu_memory);
    auto active_streams_and_lut = streams.active_gpu_subset(
        SBOX_MAX_AND_GATES * num_blocks * sbox_parallelism);
    this->and_lut->broadcast_lut(active_streams_and_lut);

    this->flush_lut = new int_radix_lut<Torus>(
        streams, params, 1, AES_STATE_BITS * num_blocks, allocate_gpu_memory,
        size_tracker);
    std::function<Torus(Torus)> flush_lambda = [](Torus x) -> Torus {
      return x & 1;
    };
    generate_device_accumulator(
        streams.stream(0), streams.gpu_index(0), this->flush_lut->get_lut(0, 0),
        this->flush_lut->get_degree(0), this->flush_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, flush_lambda, allocate_gpu_memory);
    auto active_streams_flush_lut =
        streams.active_gpu_subset(AES_STATE_BITS * num_blocks);
    this->flush_lut->broadcast_lut(active_streams_flush_lut);

    this->carry_lut = new int_radix_lut<Torus>(
        streams, params, 1, num_blocks, allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> carry_lambda = [](Torus x) -> Torus {
      return (x >> 1) & 1;
    };
    generate_device_accumulator(
        streams.stream(0), streams.gpu_index(0), this->carry_lut->get_lut(0, 0),
        this->carry_lut->get_degree(0), this->carry_lut->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, carry_lambda, allocate_gpu_memory);
    auto active_streams_carry_lut = streams.active_gpu_subset(num_blocks);
    this->carry_lut->broadcast_lut(active_streams_carry_lut);
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
  }
};

template <typename Torus> struct int_aes_trivial_buffers {
  CudaRadixCiphertextFFI *trivial_1_bit;
  Torus *d_trivial_scalars_zero;
  Torus *h_trivial_scalars_zero;

  int_aes_trivial_buffers(CudaStreams streams, const int_radix_params &params,
                          bool allocate_gpu_memory, uint64_t &size_tracker) {

    constexpr uint32_t NUM_TRIVIAL_BLOCKS = 1;

    Torus h_trivial_one[] = {1};
    Torus *d_trivial_scalars = (Torus *)cuda_malloc_with_size_tracking_async(
        sizeof(Torus), streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);
    if (allocate_gpu_memory) {
      cuda_memcpy_async_to_gpu(d_trivial_scalars, h_trivial_one, sizeof(Torus),
                               streams.stream(0), streams.gpu_index(0));
    }

    this->trivial_1_bit = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->trivial_1_bit,
        NUM_TRIVIAL_BLOCKS, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    if (allocate_gpu_memory) {
      set_trivial_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), this->trivial_1_bit,
          d_trivial_scalars, h_trivial_one, NUM_TRIVIAL_BLOCKS,
          params.message_modulus, params.carry_modulus);
    }
    if (allocate_gpu_memory) {
      cuda_drop_async(d_trivial_scalars, streams.stream(0),
                      streams.gpu_index(0));
    }

    h_trivial_scalars_zero = (Torus *)calloc(NUM_TRIVIAL_BLOCKS, sizeof(Torus));
    d_trivial_scalars_zero = (Torus *)cuda_malloc_with_size_tracking_async(
        sizeof(Torus), streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);
    if (allocate_gpu_memory) {
      cuda_memset_async(d_trivial_scalars_zero, 0, sizeof(Torus),
                        streams.stream(0), streams.gpu_index(0));
    }
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    if (allocate_gpu_memory) {
      cuda_drop_async(this->d_trivial_scalars_zero, streams.stream(0),
                      streams.gpu_index(0));
    }
    free(this->h_trivial_scalars_zero);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->trivial_1_bit, allocate_gpu_memory);
    delete this->trivial_1_bit;
    this->trivial_1_bit = nullptr;
  }
};

template <typename Torus> struct int_aes_round_workspaces {
  CudaRadixCiphertextFFI *mix_columns_col_copy_buffer;
  CudaRadixCiphertextFFI *mix_columns_mul_workspace_buffer;
  CudaRadixCiphertextFFI *tmp_bit_buffer;
  CudaRadixCiphertextFFI *vec_tmp_bit_buffer;
  CudaRadixCiphertextFFI *tmp_carry_buffer;
  CudaRadixCiphertextFFI *tmp_sum_buffer;

  int_aes_round_workspaces(CudaStreams streams, const int_radix_params &params,
                           bool allocate_gpu_memory, uint32_t num_blocks,
                           uint64_t &size_tracker) {

    constexpr uint32_t BITS_PER_BYTE = 8;
    constexpr uint32_t BYTES_PER_COLUMN = 4;
    constexpr uint32_t BITS_PER_COLUMN = BITS_PER_BYTE * BYTES_PER_COLUMN;
    constexpr uint32_t MIX_COLUMNS_MUL_WORKSPACE_BYTES = BYTES_PER_COLUMN + 1;
    constexpr uint32_t SINGLE_BLOCK = 1;

    this->mix_columns_col_copy_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->mix_columns_col_copy_buffer, BITS_PER_COLUMN * num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->mix_columns_mul_workspace_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->mix_columns_mul_workspace_buffer,
        MIX_COLUMNS_MUL_WORKSPACE_BYTES * BITS_PER_BYTE * num_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->tmp_bit_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_bit_buffer,
        SINGLE_BLOCK, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->vec_tmp_bit_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->vec_tmp_bit_buffer,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->tmp_carry_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_carry_buffer,
        SINGLE_BLOCK, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->tmp_sum_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_sum_buffer,
        SINGLE_BLOCK, params.big_lwe_dimension, size_tracker,
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
                                   this->tmp_bit_buffer, allocate_gpu_memory);
    delete this->tmp_bit_buffer;
    this->tmp_bit_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->vec_tmp_bit_buffer,
                                   allocate_gpu_memory);
    delete this->vec_tmp_bit_buffer;
    this->vec_tmp_bit_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_carry_buffer, allocate_gpu_memory);
    delete this->tmp_carry_buffer;
    this->tmp_carry_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_sum_buffer, allocate_gpu_memory);
    delete this->tmp_sum_buffer;
    this->tmp_sum_buffer = nullptr;
  }
};

template <typename Torus> struct int_aes_counter_workspaces {
  CudaRadixCiphertextFFI *vec_tmp_carry_buffer;
  CudaRadixCiphertextFFI *vec_tmp_sum_buffer;
  CudaRadixCiphertextFFI *vec_trivial_b_bits_buffer;
  Torus *h_counter_bits_buffer;
  Torus *d_counter_bits_buffer;

  int_aes_counter_workspaces(CudaStreams streams,
                             const int_radix_params &params,
                             bool allocate_gpu_memory, uint32_t num_blocks,
                             uint64_t &size_tracker) {

    this->vec_tmp_carry_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->vec_tmp_carry_buffer,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->vec_tmp_sum_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->vec_tmp_sum_buffer,
        num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->vec_trivial_b_bits_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->vec_trivial_b_bits_buffer, num_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->h_counter_bits_buffer = (Torus *)malloc(num_blocks * sizeof(Torus));
    size_tracker += num_blocks * sizeof(Torus);
    this->d_counter_bits_buffer = (Torus *)cuda_malloc_with_size_tracking_async(
        num_blocks * sizeof(Torus), streams.stream(0), streams.gpu_index(0),
        size_tracker, allocate_gpu_memory);
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

    free(this->h_counter_bits_buffer);
    if (allocate_gpu_memory) {
      cuda_drop_async(this->d_counter_bits_buffer, streams.stream(0),
                      streams.gpu_index(0));
    }
  }
};

template <typename Torus> struct int_aes_main_workspaces {
  CudaRadixCiphertextFFI *sbox_internal_workspace;
  CudaRadixCiphertextFFI *initial_states_and_jit_key_workspace;
  CudaRadixCiphertextFFI *main_bitsliced_states_buffer;
  CudaRadixCiphertextFFI *tmp_tiled_key_buffer;
  CudaRadixCiphertextFFI *batch_processing_buffer;

  int_aes_main_workspaces(CudaStreams streams, const int_radix_params &params,
                          bool allocate_gpu_memory, uint32_t num_blocks,
                          uint32_t sbox_parallelism, uint64_t &size_tracker) {

    constexpr uint32_t AES_STATE_BITS = 128;
    constexpr uint32_t SBOX_MAX_AND_GATES = 18;
    constexpr uint32_t BATCH_BUFFER_OPERANDS = 3;

    this->sbox_internal_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->sbox_internal_workspace,
        num_blocks * AES_STATE_BITS * sbox_parallelism,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->initial_states_and_jit_key_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->initial_states_and_jit_key_workspace, num_blocks * AES_STATE_BITS,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->main_bitsliced_states_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        this->main_bitsliced_states_buffer, num_blocks * AES_STATE_BITS,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    this->tmp_tiled_key_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_tiled_key_buffer,
        num_blocks * AES_STATE_BITS, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->batch_processing_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->batch_processing_buffer,
        num_blocks * SBOX_MAX_AND_GATES * BATCH_BUFFER_OPERANDS *
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
  }
};

template <typename Torus> struct int_aes_encrypt_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_blocks;
  uint32_t sbox_parallel_instances;

  int_aes_lut_buffers<Torus> *luts;
  int_aes_trivial_buffers<Torus> *trivial;
  int_aes_round_workspaces<Torus> *round_workspaces;
  int_aes_counter_workspaces<Torus> *counter_workspaces;
  int_aes_main_workspaces<Torus> *main_workspaces;

  int_aes_encrypt_buffer(CudaStreams streams, const int_radix_params &params,
                         bool allocate_gpu_memory, uint32_t num_blocks,
                         uint32_t sbox_parallelism, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_blocks = num_blocks;
    this->sbox_parallel_instances = sbox_parallelism;

    this->luts = new int_aes_lut_buffers<Torus>(streams, params,
                                                allocate_gpu_memory, num_blocks,
                                                sbox_parallelism, size_tracker);

    this->trivial = new int_aes_trivial_buffers<Torus>(
        streams, params, allocate_gpu_memory, size_tracker);

    this->round_workspaces = new int_aes_round_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_blocks, size_tracker);

    this->counter_workspaces = new int_aes_counter_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_blocks, size_tracker);

    this->main_workspaces = new int_aes_main_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_blocks, sbox_parallelism,
        size_tracker);
  }

  void release(CudaStreams streams) {
    luts->release(streams);
    delete luts;
    luts = nullptr;

    trivial->release(streams, allocate_gpu_memory);
    delete trivial;
    trivial = nullptr;

    round_workspaces->release(streams, allocate_gpu_memory);
    delete round_workspaces;
    round_workspaces = nullptr;

    counter_workspaces->release(streams, allocate_gpu_memory);
    delete counter_workspaces;
    counter_workspaces = nullptr;

    main_workspaces->release(streams, allocate_gpu_memory);
    delete main_workspaces;
    main_workspaces = nullptr;
  }
};

#endif
