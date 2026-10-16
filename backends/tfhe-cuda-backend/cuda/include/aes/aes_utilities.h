#ifndef AES_UTILITIES
#define AES_UTILITIES
#include "../integer/integer_utilities.h"

// AES state dimensions

/// @brief Bits per state byte
static constexpr uint32_t AES_BITS_PER_BYTE = 8;
/// @brief State bytes
static constexpr uint32_t AES_STATE_BYTES = 16;
/// @brief State bits, one radix block each once bitsliced
static constexpr uint32_t AES_STATE_BITS = AES_STATE_BYTES * AES_BITS_PER_BYTE;

/// @brief S-box wires (22 a, 68 b, 18 c), sizes the S-box workspace. Kept in
/// sync with the circuit by a static_assert in the S-box
static constexpr uint32_t AES_SBOX_WIRE_SLOTS = 108;

/// @brief ANDs in the widest S-box layer (the c wires), sizes and_lut and the
/// batch staging buffer. Also checked by a static_assert in the S-box
static constexpr uint32_t AES_SBOX_AND_GATES = 18;

/// @brief What an int_aes_encrypt_buffer is for. FULL_ENCRYPTION for the CTR
/// loop, SBOX_ONLY for the key schedule which only needs the S-box
enum class aes_buffer_scope { FULL_ENCRYPTION, SBOX_ONLY };

// state_lut slots. Slot 0 is the resting one, whoever picks another must put
// AES_LUT_FLUSH back before returning

/// @brief Flush, x & 1, resting slot
static constexpr uint32_t AES_LUT_FLUSH = 0;
/// @brief Carry combine of the CTR adder on kill 0, propagate 1, generate 2.
/// With that encoding the symbol is just a + b, no PBS needed to build it
static constexpr uint32_t AES_LUT_CTR_SELECT = 1;
/// @brief Sum bit of the CTR adder, propagate xor carry
static constexpr uint32_t AES_LUT_CTR_SUM = 2;
/// @brief state_lut slots under FULL_ENCRYPTION
static constexpr uint32_t AES_NUM_STATE_LUTS = 3;

// and_lut slots, same resting slot rule

/// @brief AND on a levelled sum, x == 2, resting slot
static constexpr uint32_t AES_ANDLUT_AND = 0;
/// @brief Flush, for batches too wide for state_lut
static constexpr uint32_t AES_ANDLUT_FLUSH = 1;
/// @brief and_lut slots
static constexpr uint32_t AES_NUM_ANDLUT_SLOTS = 2;

/// @brief The two multi slot LUTs every PBS of the encryption goes through.
/// and_lut for the S-box ANDs and wide flushes, state_lut for state wide
/// flushes and the CTR adder.
template <typename Torus> struct int_aes_lut_buffers {
  /// @brief Sized for the widest AND layer, AES_SBOX_AND_GATES *
  /// num_aes_inputs * sbox_parallelism blocks
  int_radix_lut<Torus> *and_lut;
  /// @brief One state worth of blocks, AES_STATE_BITS * num_aes_inputs. Only
  /// the flush slot under SBOX_ONLY
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

/// @brief The fixed GF(2) maps of AES as index tables, each one a single
/// levelled launch through host_radix_gather_sum.
///
/// A permutation or a 5 term sum costs the same, one launch and no PBS.
/// Written in bit positions, the lanes are replicated by the table, so they
/// don't grow with num_aes_inputs.
struct int_aes_linear_tables {
  /// @brief Where the xtime half starts in the MixColumns workspace, i +
  /// XTIME_BASE is bit i doubled
  static constexpr uint32_t XTIME_BASE = AES_STATE_BITS;
  /// @brief Terms per xtime output bit, the shifted bit plus bit 0 where the
  /// modulus folds back
  static constexpr uint32_t XTIME_TERMS = 2;
  /// @brief Terms per MixColumns output bit, 3a = 2a + a expanded
  static constexpr uint32_t MIX_COLUMNS_TERMS = 5;

  /// @brief Owner of the maps below
  radix_index_tables<uint32_t> maps;

  /// @brief ShiftRows, a permutation of the state bits. Round tables only
  radix_index_table<uint32_t> shift_rows;
  /// @brief xtime of every state byte. Round tables only
  radix_index_table<uint32_t> xtime;
  /// @brief MixColumns over [shifted | xtime of shifted], the four columns at
  /// once. Round tables only
  radix_index_table<uint32_t> mix_columns;
  /// @brief Byte major to bit major, so the S-box sees one contiguous run per
  /// bit
  radix_index_table<uint32_t> sbox_gather;
  /// @brief Back from bit major once the S-box is done
  radix_index_table<uint32_t> sbox_scatter;
  /// @brief Copies the IV to every lane. Round tables only
  radix_index_table<uint32_t> iv_broadcast;
  /// @brief Bitsliced back to the block order callers expect. Round tables
  /// only
  radix_index_table<uint32_t> to_blocks;

  /// @brief Rows of sbox_gather and sbox_scatter, 8 * sbox_parallelism
  uint32_t sbox_reorder_len;

  /// @brief Whether the round tables were built (FULL_ENCRYPTION)
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
      // ShiftRows rotates row r left by r bytes
      //
      //      c=0  c=1  c=2  c=3            c=0  c=1  c=2  c=3
      // r=0 |  0 |  4 |  8 | 12 |     r=0 |  0 |  4 |  8 | 12 |
      // r=1 |  1 |  5 |  9 | 13 |  -> r=1 |  5 |  9 | 13 |  1 |
      // r=2 |  2 |  6 | 10 | 14 |     r=2 | 10 | 14 |  2 |  6 |
      // r=3 |  3 |  7 | 11 | 15 |     r=3 | 15 |  3 |  7 | 11 |
      //
      // Reading the right side column major gives the table below
      //
      build(shift_rows, AES_STATE_BITS, 1, [](uint32_t bit, uint32_t) {
        constexpr uint32_t shift_rows_map[AES_STATE_BYTES] = {
            0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
        return shift_rows_map[bit / AES_BITS_PER_BYTE] * AES_BITS_PER_BYTE +
               bit % AES_BITS_PER_BYTE;
      });

      // xtime multiplies by x in GF(2^8). Bits are MSB first and the modulus
      // x^8 + x^4 + x^3 + x + 1 folds bit 0 back onto j = 3, 4, 6, 7
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

      // MixColumns multiplies each column by a fixed matrix over GF(2^8)
      //
      //   | b0 |   | 2 3 1 1 |   | a0 |
      //   | b1 | = | 1 2 3 1 | * | a1 |
      //   | b2 |   | 1 1 2 3 |   | a2 |
      //   | b3 |   | 3 1 1 2 |   | a3 |
      //
      // With 3a = 2a + a that's 5 terms per output. The workspace holds
      // [shifted | xtime of it], so a doubled term is just index + XTIME_BASE
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

      // One IV for the whole batch, every lane reads the same bit
      maps.create(streams, allocate_gpu_memory, size_tracker, iv_broadcast,
                  AES_STATE_BITS, 1, N, 1,
                  [](uint32_t bit, uint32_t) { return bit; });

      // Crosses lanes, so listed block by block
      maps.create(streams, allocate_gpu_memory, size_tracker, to_blocks,
                  AES_STATE_BITS * N, 1, 1, 1, [N](uint32_t o, uint32_t) {
                    uint32_t input = o / AES_STATE_BITS;
                    uint32_t bit = o % AES_STATE_BITS;
                    return bit * N + input;
                  });
    }

    // The state stores whole bytes but the S-box wants one run per bit
    // position, hence this transposition and its inverse
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
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/// @brief Staging for the plaintext counter bits. The ciphertext temporaries
/// of the CTR adder borrow buffers that are idle at that point.
template <typename Torus> struct int_aes_counter_workspaces {
  /// @brief Counter bits on the host, bitsliced and MSB first
  Torus *h_counter_bits_buffer;
  /// @brief Device copy of h_counter_bits_buffer
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

/// @brief Most of the memory, S-box wires, batch staging and the state
/// buffers. sbox_internal_workspace dominates and scales with
/// sbox_parallelism, which is what the caller lowers when memory is short.
template <typename Torus> struct int_aes_main_workspaces {
  /// @brief S-box wires, AES_SBOX_WIRE_SLOTS * sbox_parallelism of
  /// num_aes_inputs blocks each. At least a state worth so the Sklansky scan
  /// of the CTR adder can borrow it
  CudaRadixCiphertextFFI sbox_internal_workspace;
  /// @brief Whether the next three buffers exist, SBOX_ONLY never uses them
  bool has_full_encryption_buffers;
  /// @brief Kill, propagate, generate symbols of the CTR adder, one state
  /// worth
  CudaRadixCiphertextFFI ctr_adder_workspace;
  /// @brief Bitsliced states of the whole batch, what the rounds run on
  CudaRadixCiphertextFFI main_bitsliced_states_buffer;
  /// @brief [ShiftRows output | its xtime] side by side, so one table reads
  /// both and MixColumns is one launch. Covers the whole state so the four
  /// columns share one flush
  CudaRadixCiphertextFFI mix_columns_workspace;
  /// @brief S-box input in bit major order, 8 * sbox_parallelism *
  /// num_aes_inputs. Under FULL_ENCRYPTION at least AES_STATE_BITS + 1 per
  /// input, the CTR adder keeps its carries there
  CudaRadixCiphertextFFI sbox_input_buffer;
  /// @brief Staging for the AND and flush batches, 3 operand sets of
  /// AES_SBOX_AND_GATES * sbox_parallelism * num_aes_inputs
  CudaRadixCiphertextFFI batch_processing_buffer;

  int_aes_main_workspaces(CudaStreams streams, const int_radix_params &params,
                          bool allocate_gpu_memory, uint32_t num_aes_inputs,
                          uint32_t sbox_parallelism, uint64_t &size_tracker,
                          aes_buffer_scope scope) {

    constexpr uint32_t BATCH_BUFFER_OPERANDS = 3;

    const uint32_t sbox_slots = AES_SBOX_WIRE_SLOTS * sbox_parallelism;
    const uint32_t sbox_workspace_blocks =
        sbox_slots > AES_STATE_BITS ? sbox_slots : AES_STATE_BITS;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->sbox_internal_workspace,
        num_aes_inputs * sbox_workspace_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    this->has_full_encryption_buffers =
        (scope == aes_buffer_scope::FULL_ENCRYPTION);
    if (this->has_full_encryption_buffers) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &this->ctr_adder_workspace,
          num_aes_inputs * AES_STATE_BITS, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &this->main_bitsliced_states_buffer, num_aes_inputs * AES_STATE_BITS,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &this->mix_columns_workspace,
          2 * AES_STATE_BITS * num_aes_inputs, params.big_lwe_dimension,
          size_tracker, allocate_gpu_memory);
    }

    uint32_t sbox_input_blocks = AES_BITS_PER_BYTE * sbox_parallelism;
    if (scope == aes_buffer_scope::FULL_ENCRYPTION) {
      const uint32_t ctr_blocks = AES_STATE_BITS + 1;
      if (sbox_input_blocks < ctr_blocks)
        sbox_input_blocks = ctr_blocks;
    }
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->sbox_input_buffer,
        num_aes_inputs * sbox_input_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->batch_processing_buffer,
        num_aes_inputs * AES_SBOX_AND_GATES * BATCH_BUFFER_OPERANDS *
            sbox_parallelism,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams, bool allocate_gpu_memory) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->sbox_internal_workspace,
                                   allocate_gpu_memory);

    if (this->has_full_encryption_buffers) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->ctr_adder_workspace,
                                     allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->main_bitsliced_states_buffer,
                                     allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &this->mix_columns_workspace,
                                     allocate_gpu_memory);
    }

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->sbox_input_buffer,
                                   allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->batch_processing_buffer,
                                   allocate_gpu_memory);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/// @brief Owns everything one encryption needs, so allocation happens once per
/// call and not per round.
template <typename Torus> struct int_aes_encrypt_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// @brief State bytes per S-box pass, divides 16
  uint32_t sbox_parallel_instances;

  /// @brief The two multi slot LUTs
  int_aes_lut_buffers<Torus> *luts;
  /// @brief Index tables of the linear layers
  int_aes_linear_tables *linear_tables;
  /// @brief Counter staging, FULL_ENCRYPTION only, nullptr otherwise
  int_aes_counter_workspaces<Torus> *counter_workspaces;
  /// @brief Ciphertext workspaces
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
      this->counter_workspaces = new int_aes_counter_workspaces<Torus>(
          streams, params, allocate_gpu_memory, num_aes_inputs, size_tracker);
    } else {
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

/// @brief Word counts of the AES-128 key schedule
struct aes128_key_schedule {
  /// @brief Words of the expanded key, 4 per round key
  static constexpr uint32_t TOTAL_WORDS = 44;
  /// @brief Words of the input key
  static constexpr uint32_t KEY_WORDS = 4;
};

/// @brief Word counts of the AES-256 key schedule
struct aes256_key_schedule {
  /// @brief Words of the expanded key, 4 per round key
  static constexpr uint32_t TOTAL_WORDS = 60;
  /// @brief Words of the input key
  static constexpr uint32_t KEY_WORDS = 8;
};

/// @brief Key schedule state, shared by AES-128 (44 words from 4) and
/// AES-256 (60 from 8). SubWord reuses the encryption S-box through a
/// SBOX_ONLY buffer sized for one word of one input.
///
/// @tparam Schedule aes128_key_schedule or aes256_key_schedule
template <typename Torus, typename Schedule>
struct int_key_expansion_generic_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  /// @brief Expanded key being built, TOTAL_WORDS * 32 blocks
  CudaRadixCiphertextFFI words_buffer;

  /// @brief Word being derived, 32 blocks
  CudaRadixCiphertextFFI tmp_word_buffer;
  /// @brief RotWord of the previous word, SubWord and rcon apply to it, 32
  /// blocks
  CudaRadixCiphertextFFI tmp_rotated_word_buffer;

  /// @brief SBOX_ONLY buffer for SubWord and the flushes
  int_aes_encrypt_buffer<Torus> *aes_encrypt_buffer;

  int_key_expansion_generic_buffer(CudaStreams streams,
                                   const int_radix_params &params,
                                   bool allocate_gpu_memory,
                                   uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    constexpr uint32_t BITS_PER_WORD = 32;
    constexpr uint32_t TOTAL_BITS = Schedule::TOTAL_WORDS * BITS_PER_WORD;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->words_buffer,
        TOTAL_BITS, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_word_buffer,
        BITS_PER_WORD, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &this->tmp_rotated_word_buffer,
        BITS_PER_WORD, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    this->aes_encrypt_buffer = new int_aes_encrypt_buffer<Torus>(
        streams, params, allocate_gpu_memory, 1, 4, size_tracker,
        aes_buffer_scope::SBOX_ONLY);
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->words_buffer, allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_word_buffer, allocate_gpu_memory);

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &this->tmp_rotated_word_buffer,
                                   allocate_gpu_memory);

    this->aes_encrypt_buffer->release(streams);
    delete this->aes_encrypt_buffer;
    this->aes_encrypt_buffer = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/// @brief AES-128 key schedule, 44 words from 4
template <typename Torus>
using int_key_expansion_buffer =
    int_key_expansion_generic_buffer<Torus, aes128_key_schedule>;
/// @brief AES-256 key schedule, 60 words from 8
template <typename Torus>
using int_key_expansion_256_buffer =
    int_key_expansion_generic_buffer<Torus, aes256_key_schedule>;

#endif
