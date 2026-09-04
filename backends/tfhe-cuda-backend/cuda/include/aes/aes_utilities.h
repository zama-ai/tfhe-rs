#ifndef AES_UTILITIES
#define AES_UTILITIES
#include "../integer/integer_utilities.h"

// Dimensions of the AES state, shared by every structure and kernel below.
static constexpr uint32_t AES_BITS_PER_BYTE = 8;
static constexpr uint32_t AES_STATE_BYTES = 16;
static constexpr uint32_t AES_STATE_BITS = AES_STATE_BYTES * AES_BITS_PER_BYTE;

// Wire slots the S-box circuit occupies (22 a, 68 b and 18 c wires). A
// static_assert in the S-box keeps this in sync with the circuit.
static constexpr uint32_t AES_SBOX_WIRE_SLOTS = 108;

// AND gates the S-box circuit evaluates (its c wires): the and_lut capacity
// and the batch staging buffer are sized on it, and the largest AND batch
// fills that capacity exactly. A static_assert in the S-box keeps this in
// sync with the circuit.
static constexpr uint32_t AES_SBOX_AND_GATES = 18;

// FULL_ENCRYPTION serves the CTR loop. SBOX_ONLY trims allocation down to
// what the key schedule's S-box calls actually touch.
enum class aes_buffer_scope { FULL_ENCRYPTION, SBOX_ONLY };

// Slots of int_aes_lut_buffers::state_lut. Slot 0 is the resting one: any
// code selecting another must restore AES_LUT_FLUSH before returning.
static constexpr uint32_t AES_LUT_FLUSH = 0;
// CTR adder, encoding kill=0, propagate=1, generate=2: under that encoding
// the symbol is exactly the levelled a + b, so no symbol-generation
// bootstrap is needed.
static constexpr uint32_t AES_LUT_CTR_SELECT = 1;
static constexpr uint32_t AES_LUT_CTR_SUM = 2;
static constexpr uint32_t AES_NUM_STATE_LUTS = 3;

// Slots of int_aes_lut_buffers::and_lut, same resting-slot convention.
static constexpr uint32_t AES_ANDLUT_AND = 0;
static constexpr uint32_t AES_ANDLUT_FLUSH = 1;
static constexpr uint32_t AES_NUM_ANDLUT_SLOTS = 2;

/**
 * The two multi-slot LUTs the whole encryption bootstraps through:
 * and_lut for the S-box AND gates and wide flushes, state_lut for
 * state-wide flushes and every function of the CTR adder.
 */
template <typename Torus> struct int_aes_lut_buffers {
  int_radix_lut<Torus> *and_lut;
  int_radix_lut<Torus> *state_lut;

  int_aes_lut_buffers(CudaStreams streams, const int_radix_params &params,
                      bool allocate_gpu_memory, uint32_t num_aes_inputs,
                      uint32_t sbox_parallelism, uint64_t &size_tracker) {

    this->and_lut = new int_radix_lut<Torus>(
        streams, params, AES_NUM_ANDLUT_SLOTS,
        AES_SBOX_AND_GATES * num_aes_inputs * sbox_parallelism,
        allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus)> and_lambda = [](Torus x) -> Torus {
      return x == 2 ? 1 : 0;
    };
    std::function<Torus(Torus)> flush_lambda = [](Torus x) -> Torus {
      return x & 1;
    };

    auto active_streams_and_lut = streams.active_gpu_subset(
        AES_SBOX_AND_GATES * num_aes_inputs * sbox_parallelism,
        params.pbs_type);
    this->and_lut->generate_and_broadcast_lut(
        active_streams_and_lut, {AES_ANDLUT_AND, AES_ANDLUT_FLUSH},
        {and_lambda, flush_lambda}, LUT_0_FOR_ALL_BLOCKS);

    this->state_lut = new int_radix_lut<Torus>(
        streams, params, AES_NUM_STATE_LUTS, AES_STATE_BITS * num_aes_inputs,
        allocate_gpu_memory, size_tracker);

    std::function<Torus(Torus, Torus)> select_lambda =
        [](Torus hi, Torus lo) -> Torus { return hi == 1 ? lo : hi; };

    std::function<Torus(Torus, Torus)> sum_lambda = [](Torus p,
                                                       Torus c) -> Torus {
      return (p == 1 ? 1 : 0) ^ (c == 2 ? 1 : 0);
    };

    auto active_streams_state_lut = streams.active_gpu_subset(
        AES_STATE_BITS * num_aes_inputs, params.pbs_type);
    this->state_lut->generate_and_broadcast_lut(active_streams_state_lut,
                                                {AES_LUT_FLUSH}, {flush_lambda},
                                                LUT_0_FOR_ALL_BLOCKS);
    this->state_lut->generate_and_broadcast_bivariate_lut(
        active_streams_state_lut, {AES_LUT_CTR_SELECT, AES_LUT_CTR_SUM},
        {select_lambda, sum_lambda}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    this->and_lut->release(streams);
    delete this->and_lut;
    this->and_lut = nullptr;

    this->state_lut->release(streams);
    delete this->state_lut;
    this->state_lut = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

// Padding for index-table rows that use fewer terms than the table width.
static constexpr uint32_t AES_LINEAR_NO_TERM = 0xFFFFFFFFu;

// malloc with the failure check the tables below all need.
static inline uint32_t *aes_host_alloc_u32(uint32_t len) {
  uint32_t *ptr = (uint32_t *)malloc(sizeof(uint32_t) * len);
  PANIC_IF_FALSE(ptr != nullptr, "Cuda error: host allocation failed");
  return ptr;
}

/**
 * Index tables of the round's fixed GF(2) linear maps (ShiftRows, xtime,
 * MixColumns, S-box reordering), one kernel launch each. Expressed per
 * state bit, hence independent of num_aes_inputs.
 */
struct int_aes_linear_tables {
  static constexpr uint32_t XTIME_BASE = AES_STATE_BITS;
  static constexpr uint32_t XTIME_TERMS = 2;
  static constexpr uint32_t MIX_COLUMNS_TERMS = 5;

  uint32_t *h_shift_rows, *d_shift_rows;
  uint32_t *h_xtime, *d_xtime;
  uint32_t *h_mix_columns, *d_mix_columns;
  uint32_t *h_sbox_gather, *d_sbox_gather;
  uint32_t *h_sbox_scatter, *d_sbox_scatter;

  uint32_t sbox_reorder_len;

  bool has_round_tables;

  int_aes_linear_tables(CudaStreams streams, bool allocate_gpu_memory,
                        uint32_t sbox_parallelism, uint64_t &size_tracker,
                        aes_buffer_scope scope) {

    this->sbox_reorder_len = AES_BITS_PER_BYTE * sbox_parallelism;
    this->has_round_tables = (scope == aes_buffer_scope::FULL_ENCRYPTION);

    if (has_round_tables) {
      const uint32_t shift_rows_map[AES_STATE_BYTES] = {
          0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
      h_shift_rows = aes_host_alloc_u32(AES_STATE_BITS);
      for (uint32_t byte = 0; byte < AES_STATE_BYTES; ++byte)
        for (uint32_t bit = 0; bit < AES_BITS_PER_BYTE; ++bit)
          h_shift_rows[byte * AES_BITS_PER_BYTE + bit] =
              shift_rows_map[byte] * AES_BITS_PER_BYTE + bit;

      h_xtime = aes_host_alloc_u32(AES_STATE_BITS * XTIME_TERMS);
      for (uint32_t byte = 0; byte < AES_STATE_BYTES; ++byte) {
        const uint32_t base = byte * AES_BITS_PER_BYTE;
        for (uint32_t j = 0; j < AES_BITS_PER_BYTE; ++j) {
          uint32_t *row = &h_xtime[(base + j) * XTIME_TERMS];
          row[0] = (j == AES_BITS_PER_BYTE - 1) ? base : base + j + 1;
          const bool reduced = (j == 3 || j == 4 || j == 6);
          row[1] = reduced ? base : AES_LINEAR_NO_TERM;
        }
      }

      h_mix_columns = aes_host_alloc_u32(AES_STATE_BITS * MIX_COLUMNS_TERMS);
      for (uint32_t col = 0; col < 4; ++col) {
        const uint32_t c = col * 4;
        for (uint32_t t = 0; t < AES_BITS_PER_BYTE; ++t) {
          auto orig = [&](uint32_t b) {
            return (c + b) * AES_BITS_PER_BYTE + t;
          };
          auto mul2 = [&](uint32_t b) { return XTIME_BASE + orig(b); };
          const uint32_t rows[4][MIX_COLUMNS_TERMS] = {
              {mul2(0), mul2(1), orig(1), orig(2), orig(3)},
              {orig(0), mul2(1), mul2(2), orig(2), orig(3)},
              {orig(0), orig(1), mul2(2), orig(3), mul2(3)},
              {mul2(0), orig(0), orig(1), orig(2), mul2(3)},
          };
          for (uint32_t b = 0; b < 4; ++b)
            for (uint32_t k = 0; k < MIX_COLUMNS_TERMS; ++k)
              h_mix_columns[orig(b) * MIX_COLUMNS_TERMS + k] = rows[b][k];
        }
      }
    } else {
      h_shift_rows = d_shift_rows = nullptr;
      h_xtime = d_xtime = nullptr;
      h_mix_columns = d_mix_columns = nullptr;
    }

    h_sbox_gather = aes_host_alloc_u32(sbox_reorder_len);
    h_sbox_scatter = aes_host_alloc_u32(sbox_reorder_len);
    for (uint32_t p = 0; p < sbox_parallelism; ++p)
      for (uint32_t j = 0; j < AES_BITS_PER_BYTE; ++j) {
        h_sbox_gather[j * sbox_parallelism + p] = p * AES_BITS_PER_BYTE + j;
        h_sbox_scatter[p * AES_BITS_PER_BYTE + j] = j * sbox_parallelism + p;
      }

    auto upload = [&](uint32_t **d, const uint32_t *h, uint32_t len) {
      *d = (uint32_t *)cuda_malloc_with_size_tracking_async(
          sizeof(uint32_t) * len, streams.stream(0), streams.gpu_index(0),
          size_tracker, allocate_gpu_memory);
      cuda_memcpy_with_size_tracking_async_to_gpu(
          *d, h, sizeof(uint32_t) * len, streams.stream(0),
          streams.gpu_index(0), allocate_gpu_memory);
    };
    if (has_round_tables) {
      upload(&d_shift_rows, h_shift_rows, AES_STATE_BITS);
      upload(&d_xtime, h_xtime, AES_STATE_BITS * XTIME_TERMS);
      upload(&d_mix_columns, h_mix_columns, AES_STATE_BITS * MIX_COLUMNS_TERMS);
    }
    upload(&d_sbox_gather, h_sbox_gather, sbox_reorder_len);
    upload(&d_sbox_scatter, h_sbox_scatter, sbox_reorder_len);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    if (allocate_gpu_memory) {
      if (has_round_tables) {
        cuda_drop_async(d_shift_rows, streams.stream(0), streams.gpu_index(0));
        cuda_drop_async(d_xtime, streams.stream(0), streams.gpu_index(0));
        cuda_drop_async(d_mix_columns, streams.stream(0), streams.gpu_index(0));
      }
      cuda_drop_async(d_sbox_gather, streams.stream(0), streams.gpu_index(0));
      cuda_drop_async(d_sbox_scatter, streams.stream(0), streams.gpu_index(0));
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    if (has_round_tables) {
      free(h_shift_rows);
      free(h_xtime);
      free(h_mix_columns);
    }
    free(h_sbox_gather);
    free(h_sbox_scatter);
  }
};

/**
 * Holds [ShiftRows output | its xtime] in one buffer, so a single index
 * table addresses both operand sets and MixColumns is one launch.
 */
template <typename Torus> struct int_aes_round_workspaces {
  CudaRadixCiphertextFFI *mix_columns_workspace;

  int_aes_round_workspaces(CudaStreams streams, const int_radix_params &params,
                           bool allocate_gpu_memory, uint32_t num_aes_inputs,
                           uint64_t &size_tracker) {

    this->mix_columns_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->mix_columns_workspace,
        2 * AES_STATE_BITS * num_aes_inputs, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->mix_columns_workspace,
                                   allocate_gpu_memory);
    delete this->mix_columns_workspace;
    this->mix_columns_workspace = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * Staging for the plaintext counter bits. The ciphertext workspaces of
 * the CTR adder alias buffers that are idle at that point.
 */
template <typename Torus> struct int_aes_counter_workspaces {
  Torus *h_counter_bits_buffer;
  Torus *d_counter_bits_buffer;

  int_aes_counter_workspaces(CudaStreams streams,
                             const int_radix_params &params,
                             bool allocate_gpu_memory, uint32_t num_aes_inputs,
                             uint64_t &size_tracker) {

    const uint32_t num_bits = AES_STATE_BITS * num_aes_inputs;

    this->h_counter_bits_buffer =
        (Torus *)malloc(safe_mul_sizeof<Torus>(num_bits));
    PANIC_IF_FALSE(this->h_counter_bits_buffer != nullptr,
                   "Cuda error: host allocation failed");
    this->d_counter_bits_buffer = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_bits), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    if (allocate_gpu_memory) {
      cuda_drop_async(this->d_counter_bits_buffer, streams.stream(0),
                      streams.gpu_index(0));
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(this->h_counter_bits_buffer);
  }
};

/**
 * The bulk of the memory: S-box wires, batch staging and the whole-state
 * buffers of the CTR loop. sbox_internal_workspace dominates and scales
 * with the S-box parallelism, which the caller lowers when memory is short.
 */
template <typename Torus> struct int_aes_main_workspaces {
  CudaRadixCiphertextFFI *sbox_internal_workspace;
  CudaRadixCiphertextFFI *ctr_adder_workspace;
  CudaRadixCiphertextFFI *main_bitsliced_states_buffer;
  CudaRadixCiphertextFFI *sbox_input_buffer;
  CudaRadixCiphertextFFI *batch_processing_buffer;

  int_aes_main_workspaces(CudaStreams streams, const int_radix_params &params,
                          bool allocate_gpu_memory, uint32_t num_aes_inputs,
                          uint32_t sbox_parallelism, uint64_t &size_tracker,
                          aes_buffer_scope scope) {

    constexpr uint32_t BATCH_BUFFER_OPERANDS = 3;

    const uint32_t sbox_slots = AES_SBOX_WIRE_SLOTS * sbox_parallelism;
    const uint32_t sbox_workspace_blocks =
        sbox_slots > AES_STATE_BITS ? sbox_slots : AES_STATE_BITS;

    this->sbox_internal_workspace = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->sbox_internal_workspace,
        num_aes_inputs * sbox_workspace_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    if (scope == aes_buffer_scope::FULL_ENCRYPTION) {
      this->ctr_adder_workspace = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), this->ctr_adder_workspace,
          num_aes_inputs * AES_STATE_BITS, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);

      this->main_bitsliced_states_buffer = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          this->main_bitsliced_states_buffer, num_aes_inputs * AES_STATE_BITS,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    } else {
      this->ctr_adder_workspace = nullptr;
      this->main_bitsliced_states_buffer = nullptr;
    }

    uint32_t sbox_input_blocks = AES_BITS_PER_BYTE * sbox_parallelism;
    if (scope == aes_buffer_scope::FULL_ENCRYPTION) {
      const uint32_t ctr_blocks = AES_STATE_BITS + 1;
      if (sbox_input_blocks < ctr_blocks)
        sbox_input_blocks = ctr_blocks;
    }

    this->sbox_input_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->sbox_input_buffer,
        num_aes_inputs * sbox_input_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->batch_processing_buffer = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->batch_processing_buffer,
        num_aes_inputs * AES_SBOX_AND_GATES * BATCH_BUFFER_OPERANDS *
            sbox_parallelism,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->sbox_internal_workspace,
                                   allocate_gpu_memory);
    delete this->sbox_internal_workspace;
    this->sbox_internal_workspace = nullptr;

    if (this->ctr_adder_workspace != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->ctr_adder_workspace,
                                     allocate_gpu_memory);
      delete this->ctr_adder_workspace;
      this->ctr_adder_workspace = nullptr;
    }

    if (this->main_bitsliced_states_buffer != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     this->main_bitsliced_states_buffer,
                                     allocate_gpu_memory);
      delete this->main_bitsliced_states_buffer;
      this->main_bitsliced_states_buffer = nullptr;
    }

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->sbox_input_buffer,
                                   allocate_gpu_memory);
    delete this->sbox_input_buffer;
    this->sbox_input_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->batch_processing_buffer,
                                   allocate_gpu_memory);
    delete this->batch_processing_buffer;
    this->batch_processing_buffer = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * Owns everything one encryption needs, so allocation and release happen
 * once per call rather than per round.
 */
template <typename Torus> struct int_aes_encrypt_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t sbox_parallel_instances;

  int_aes_lut_buffers<Torus> *luts;
  int_aes_linear_tables *linear_tables;
  int_aes_round_workspaces<Torus> *round_workspaces;
  int_aes_counter_workspaces<Torus> *counter_workspaces;
  int_aes_main_workspaces<Torus> *main_workspaces;

  int_aes_encrypt_buffer(
      CudaStreams streams, const int_radix_params &params,
      bool allocate_gpu_memory, uint32_t num_aes_inputs,
      uint32_t sbox_parallelism, uint64_t &size_tracker,
      aes_buffer_scope scope = aes_buffer_scope::FULL_ENCRYPTION) {

    PANIC_IF_FALSE(num_aes_inputs >= 1,
                   "num_aes_inputs should be greater or equal to 1");
    PANIC_IF_FALSE(params.message_modulus == 4 && params.carry_modulus == 4,
                   "Cuda error: the AES circuit is scheduled for 2_2 "
                   "parameters (message_modulus == 4, carry_modulus == 4); "
                   "several levelled chains use the noise budget of 5 these "
                   "parameters provide");

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->sbox_parallel_instances = sbox_parallelism;

    this->luts = new int_aes_lut_buffers<Torus>(
        streams, params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism,
        size_tracker);

    this->linear_tables = new int_aes_linear_tables(
        streams, allocate_gpu_memory, sbox_parallelism, size_tracker, scope);

    if (scope == aes_buffer_scope::FULL_ENCRYPTION) {
      this->round_workspaces = new int_aes_round_workspaces<Torus>(
          streams, params, allocate_gpu_memory, num_aes_inputs, size_tracker);

      this->counter_workspaces = new int_aes_counter_workspaces<Torus>(
          streams, params, allocate_gpu_memory, num_aes_inputs, size_tracker);
    } else {
      this->round_workspaces = nullptr;
      this->counter_workspaces = nullptr;
    }

    this->main_workspaces = new int_aes_main_workspaces<Torus>(
        streams, params, allocate_gpu_memory, num_aes_inputs, sbox_parallelism,
        size_tracker, scope);
  }

  void release(CudaStreams streams) {
    luts->release(streams);
    delete luts;
    luts = nullptr;

    linear_tables->release(streams, allocate_gpu_memory);
    delete linear_tables;
    linear_tables = nullptr;

    if (round_workspaces != nullptr) {
      round_workspaces->release(streams, allocate_gpu_memory);
      delete round_workspaces;
      round_workspaces = nullptr;
    }

    if (counter_workspaces != nullptr) {
      counter_workspaces->release(streams, allocate_gpu_memory);
      delete counter_workspaces;
      counter_workspaces = nullptr;
    }

    main_workspaces->release(streams, allocate_gpu_memory);
    delete main_workspaces;
    main_workspaces = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/**
 * Key schedule state shared by AES-128 (44 words from a 4-word key) and
 * AES-256 (60 words from an 8-word key). It embeds a SBOX_ONLY encrypt
 * buffer sized for four bytes of a single input.
 */
template <typename Torus, uint32_t TOTAL_WORDS, uint32_t KEY_WORDS>
struct int_key_expansion_generic_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  CudaRadixCiphertextFFI *words_buffer;

  CudaRadixCiphertextFFI *tmp_word_buffer;
  CudaRadixCiphertextFFI *tmp_rotated_word_buffer;

  int_aes_encrypt_buffer<Torus> *aes_encrypt_buffer;

  int_key_expansion_generic_buffer(CudaStreams streams,
                                   const int_radix_params &params,
                                   bool allocate_gpu_memory,
                                   uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

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
        streams, params, allocate_gpu_memory, 1, 4, size_tracker,
        aes_buffer_scope::SBOX_ONLY);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->words_buffer, allocate_gpu_memory);
    delete this->words_buffer;
    this->words_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_word_buffer, allocate_gpu_memory);
    delete this->tmp_word_buffer;
    this->tmp_word_buffer = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_rotated_word_buffer,
                                   allocate_gpu_memory);
    delete this->tmp_rotated_word_buffer;
    this->tmp_rotated_word_buffer = nullptr;

    this->aes_encrypt_buffer->release(streams);
    delete this->aes_encrypt_buffer;
    this->aes_encrypt_buffer = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus>
using int_key_expansion_buffer = int_key_expansion_generic_buffer<Torus, 44, 4>;
template <typename Torus>
using int_key_expansion_256_buffer =
    int_key_expansion_generic_buffer<Torus, 60, 8>;

#endif
