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
                      uint32_t sbox_parallelism, uint64_t &size_tracker,
                      aes_buffer_scope scope) {

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

    const bool needs_ctr_luts = (scope == aes_buffer_scope::FULL_ENCRYPTION);
    this->state_lut = new int_radix_lut<Torus>(
        streams, params, needs_ctr_luts ? AES_NUM_STATE_LUTS : 1,
        AES_STATE_BITS * num_aes_inputs, allocate_gpu_memory, size_tracker);

    auto active_streams_state_lut = streams.active_gpu_subset(
        AES_STATE_BITS * num_aes_inputs, params.pbs_type);
    this->state_lut->generate_and_broadcast_lut(active_streams_state_lut,
                                                {AES_LUT_FLUSH}, {flush_lambda},
                                                LUT_0_FOR_ALL_BLOCKS);

    if (needs_ctr_luts) {
      std::function<Torus(Torus, Torus)> select_lambda =
          [](Torus hi, Torus lo) -> Torus { return hi == 1 ? lo : hi; };

      std::function<Torus(Torus, Torus)> sum_lambda = [](Torus p,
                                                         Torus c) -> Torus {
        return (p == 1 ? 1 : 0) ^ (c == 2 ? 1 : 0);
      };

      this->state_lut->generate_and_broadcast_bivariate_lut(
          active_streams_state_lut, {AES_LUT_CTR_SELECT, AES_LUT_CTR_SUM},
          {select_lambda, sum_lambda}, LUT_0_FOR_ALL_BLOCKS);
    }
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

/**
 * The fixed GF(2) maps of a round, as index tables: per output bit, the
 * input bits to sum. The map lives here rather than in a launch schedule
 * spelling out one copy or one addition per wire, so a permutation and a
 * five term sum are the same single launch and neither costs a bootstrap.
 * Pure bit positions, the lane dimension being the map's to replicate, so
 * the tables do not grow with num_aes_inputs.
 */
struct int_aes_linear_tables {
  static constexpr uint32_t XTIME_BASE = AES_STATE_BITS;
  static constexpr uint32_t XTIME_TERMS = 2;
  static constexpr uint32_t MIX_COLUMNS_TERMS = 5;

  // Owns every map below, and releases them
  radix_index_tables<uint32_t> maps;

  radix_index_table<uint32_t> shift_rows;
  radix_index_table<uint32_t> xtime;
  radix_index_table<uint32_t> mix_columns;
  radix_index_table<uint32_t> sbox_gather;
  radix_index_table<uint32_t> sbox_scatter;
  radix_index_table<uint32_t> iv_broadcast;
  radix_index_table<uint32_t> to_blocks;

  uint32_t sbox_reorder_len;

  bool has_round_tables;

  int_aes_linear_tables(CudaStreams streams, bool allocate_gpu_memory,
                        uint32_t num_aes_inputs, uint32_t sbox_parallelism,
                        uint64_t &size_tracker, aes_buffer_scope scope) {

    const uint32_t N = num_aes_inputs;
    this->sbox_reorder_len = AES_BITS_PER_BYTE * sbox_parallelism;
    this->has_round_tables = (scope == aes_buffer_scope::FULL_ENCRYPTION);

    auto build = [&](radix_index_table<uint32_t> &map, uint32_t num_out_bits,
                     uint32_t num_terms,
                     const std::function<uint32_t(uint32_t, uint32_t)> &src) {
      maps.create(streams, allocate_gpu_memory, size_tracker, map, num_out_bits,
                  num_terms, N, N, src);
    };

    if (has_round_tables) {
      // ShiftRows rotates row r of the state left by r bytes:
      //
      //      c=0  c=1  c=2  c=3            c=0  c=1  c=2  c=3
      // r=0 |  0 |  4 |  8 | 12 |     r=0 |  0 |  4 |  8 | 12 |
      // r=1 |  1 |  5 |  9 | 13 |  -> r=1 |  5 |  9 | 13 |  1 |
      // r=2 |  2 |  6 | 10 | 14 |     r=2 | 10 | 14 |  2 |  6 |
      // r=3 |  3 |  7 | 11 | 15 |     r=3 | 15 |  3 |  7 | 11 |
      //
      // Read the right hand state column major and you get the table below:
      //
      build(shift_rows, AES_STATE_BITS, 1, [](uint32_t bit, uint32_t) {
        constexpr uint32_t shift_rows_map[AES_STATE_BYTES] = {
            0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
        return shift_rows_map[bit / AES_BITS_PER_BYTE] * AES_BITS_PER_BYTE +
               bit % AES_BITS_PER_BYTE;
      });

      // xtime multiplies by x in GF(2^8). Bits are MSB first and the modulus
      // x^8 + x^4 + x^3 + x + 1 folds bit 0 back onto j = 3, 4, 6, 7:
      //
      //   out[j] = a[j + 1]     j < 7
      //   out[j] += a[0]        j = 3, 4, 6, 7
      //
      build(xtime, AES_STATE_BITS, XTIME_TERMS,
            [](uint32_t bit, uint32_t term) {
              uint32_t j = bit % AES_BITS_PER_BYTE, base = bit - j;
              if (term == 0)
                return (j == AES_BITS_PER_BYTE - 1) ? base : base + j + 1;
              const bool reduced = (j == 3 || j == 4 || j == 6);
              return reduced ? base : RADIX_INDEX_NO_TERM;
            });

      // MixColumns multiplies each column by a fixed matrix over GF(2^8):
      //
      //   | b0 |   | 2 3 1 1 |   | a0 |
      //   | b1 | = | 1 2 3 1 | * | a1 |
      //   | b2 |   | 1 1 2 3 |   | a2 |
      //   | b3 |   | 3 1 1 2 |   | a3 |
      //
      // With 3a = 2a + a that is five terms at most per output. The
      // workspace holds [shifted | xtime of it], so a doubled term is the
      // same index plus XTIME_BASE and one table covers both halves.
      build(mix_columns, AES_STATE_BITS, MIX_COLUMNS_TERMS,
            [](uint32_t bit, uint32_t term) {
              uint32_t byte = bit / AES_BITS_PER_BYTE;
              uint32_t t = bit % AES_BITS_PER_BYTE;
              uint32_t c = byte & ~3u, b = byte & 3u;
              auto orig = [c, t](uint32_t i) {
                return (c + i) * AES_BITS_PER_BYTE + t;
              };
              auto mul2 = [&orig](uint32_t i) { return XTIME_BASE + orig(i); };
              const uint32_t rows[4][MIX_COLUMNS_TERMS] = {
                  {mul2(0), mul2(1), orig(1), orig(2), orig(3)},
                  {orig(0), mul2(1), mul2(2), orig(2), orig(3)},
                  {orig(0), orig(1), mul2(2), orig(3), mul2(3)},
                  {mul2(0), orig(0), orig(1), orig(2), mul2(3)},
              };
              return rows[b][term];
            });

      // The IV is one state the whole batch starts from, so it has no lane
      // of its own: every input reads the same bit.
      maps.create(streams, allocate_gpu_memory, size_tracker, iv_broadcast,
                  AES_STATE_BITS, 1, N, 1,
                  [](uint32_t bit, uint32_t) { return bit; });

      // Leaving the bitsliced layout is the one map that crosses lanes, so
      // it is the one spelled out block by block.
      maps.create(streams, allocate_gpu_memory, size_tracker, to_blocks,
                  AES_STATE_BITS * N, 1, 1, 1, [N](uint32_t o, uint32_t) {
                    uint32_t input = o / AES_STATE_BITS;
                    uint32_t bit = o % AES_STATE_BITS;
                    return bit * N + input;
                  });
    }

    // A bootstrap batch addresses one run per bit position, the state stores
    // whole bytes, hence this transposition and its inverse:
    //
    //   state      | byte 0: b0 b1 ... b7 | byte 1: b0 b1 ... b7 | ...
    //   gathered   | b0 of every byte | b1 of every byte | ...
    //
    build(sbox_gather, sbox_reorder_len, 1,
          [sbox_parallelism](uint32_t o, uint32_t) {
            return (o % sbox_parallelism) * AES_BITS_PER_BYTE +
                   o / sbox_parallelism;
          });
    build(sbox_scatter, sbox_reorder_len, 1,
          [sbox_parallelism](uint32_t o, uint32_t) {
            return (o % AES_BITS_PER_BYTE) * sbox_parallelism +
                   o / AES_BITS_PER_BYTE;
          });
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    maps.release(streams, allocate_gpu_memory);
  }
};

/**
 * Holds [ShiftRows output | its xtime] in one buffer, so a single index
 * table addresses both operand sets and MixColumns is one launch. It spans
 * the whole state, not one column, which is what lets the four columns
 * share a single flush.
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
        size_tracker, scope);

    this->linear_tables =
        new int_aes_linear_tables(streams, allocate_gpu_memory, num_aes_inputs,
                                  sbox_parallelism, size_tracker, scope);

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
