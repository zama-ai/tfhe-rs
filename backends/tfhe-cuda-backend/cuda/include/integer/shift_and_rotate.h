#pragma once
#include "integer/comparison.h"
#include "integer_utilities.h"

/// @brief Buffers and LUTs of the bit-level barrel shifter, which explodes
/// both operands into one-bit ciphertexts and runs one cmux per bit per round.
/// Used for every parameter set the block-level path does not support.
template <typename Torus> struct int_shift_and_rotate_by_bits_buffer {
  int_radix_params params;
  bool gpu_memory_allocated;

  /// @brief The value being shifted, exploded into one ciphertext per bit.
  CudaRadixCiphertextFFI *tmp_bits;
  /// @brief The shift amount's low bits, one per barrel round, each already
  /// aligned on the cmux control position.
  CudaRadixCiphertextFFI *tmp_shift_bits;
  /// @brief Destination of a round's bit rotation, which is not in-place.
  CudaRadixCiphertextFFI *tmp_rotated;
  /// @brief Bit array carrying the result, updated in place every round.
  CudaRadixCiphertextFFI *tmp_input_bits_a;
  /// @brief Copy of that array the rotation reads from, so the cmux can pick
  /// between the shifted and unshifted bit.
  CudaRadixCiphertextFFI *tmp_input_bits_b;
  /// @brief Packs control | shifted | unshifted into one block per bit, the
  /// input of the mux LUT.
  CudaRadixCiphertextFFI *tmp_mux_inputs;

  /// @brief Explodes the value into its individual bits.
  int_bit_extract_luts_buffer<Torus> *bit_extract_luts;
  /// @brief Explodes the shift amount into bits, each placed on plaintext
  /// position 2 where the mux LUT expects its control bit.
  int_bit_extract_luts_buffer<Torus> *bit_extract_luts_with_offset_2;
  /// @brief The cmux itself: returns the shifted bit when the control bit is
  /// set, the unshifted one otherwise.
  int_radix_lut<Torus> *mux_lut;

  int_shift_and_rotate_by_bits_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_radix_blocks,
      uint32_t bits_per_block, uint32_t max_num_bits_that_tell_shift,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    bit_extract_luts = new int_bit_extract_luts_buffer<Torus>(
        streams, params, bits_per_block, num_radix_blocks, allocate_gpu_memory,
        size_tracker);
    bit_extract_luts_with_offset_2 = new int_bit_extract_luts_buffer<Torus>(
        streams, params, bits_per_block, 2, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    mux_lut = new int_radix_lut<Torus>(streams, params, 1,
                                       bits_per_block * num_radix_blocks,
                                       allocate_gpu_memory, size_tracker);

    tmp_bits = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_bits,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_shift_bits = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_shift_bits,
        max_num_bits_that_tell_shift * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tmp_rotated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_rotated,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_input_bits_a = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_input_bits_a,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_input_bits_b = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_input_bits_b,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_mux_inputs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_mux_inputs,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    auto mux_lut_f = [](Torus x) -> Torus {
      // x is expected to be x = 0bcba
      // where
      // - c is the control bit
      // - b the bit value returned if c is 1
      // - a the bit value returned if c is 0
      // (any bit above c is ignored)
      x = x & 7;
      auto control_bit = x >> 2;
      auto previous_bit = (x & 2) >> 1;
      auto current_bit = x & 1;

      if (control_bit == 1)
        return previous_bit;
      else
        return current_bit;
    };
    auto active_gpu_count_mux = streams.active_gpu_subset(
        bits_per_block * num_radix_blocks, params.pbs_type);

    mux_lut->generate_and_broadcast_lut(active_gpu_count_mux, {0}, {mux_lut_f},
                                        LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    auto drop_ct = [&](CudaRadixCiphertextFFI *ct) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, gpu_memory_allocated);
      delete ct;
    };
    drop_ct(tmp_bits);
    drop_ct(tmp_shift_bits);
    drop_ct(tmp_rotated);
    drop_ct(tmp_input_bits_a);
    drop_ct(tmp_input_bits_b);
    drop_ct(tmp_mux_inputs);

    bit_extract_luts->release(streams);
    delete bit_extract_luts;
    bit_extract_luts_with_offset_2->release(streams);
    delete bit_extract_luts_with_offset_2;
    mux_lut->release(streams);
    delete mux_lut;
  }
};

/// @brief Buffers and LUTs of the block-level barrel shifter, which works on
/// whole blocks instead of individual bits and costs about half the PBS.
///
/// The shift amount is split as `amount = 2 * t + s + 4 * rest`, where `s` is
/// the shift inside a block and `t` a shift by one block; both live in amount
/// block 0 and are consumed by the fused first round. `rest` drives the
/// remaining `num_rounds` rounds, each shifting by `1 << d` blocks.
template <typename Torus> struct int_shift_and_rotate_by_block_buffer {
  int_radix_params params;
  /// @brief Which of the four operations is being performed.
  SHIFT_OR_ROTATE_TYPE shift_type;
  /// @brief Whether the value being shifted is signed; with a right shift
  /// this makes the shift arithmetic.
  bool is_signed;
  bool gpu_memory_allocated;

  /// @brief Result being built: what each block keeps of its own value,
  /// accumulated with the two donor arrays below.
  CudaRadixCiphertextFFI *messages;
  /// @brief What each block hands to the block one position away.
  CudaRadixCiphertextFFI *next;
  /// @brief What each block hands to the block two positions away.
  CudaRadixCiphertextFFI *next_next;
  /// @brief Destination of the block rotations, which are not in-place.
  CudaRadixCiphertextFFI *rotate_tmp;
  /// @brief Holds (input block) * message_modulus + (amount block 0) for the
  /// three bivariate LUTs of the first round.
  CudaRadixCiphertextFFI *pack_tmp;
  /// @brief Many-LUT output of a barrel round: messages in [0, num_blocks),
  /// carries in [num_blocks, 2 * num_blocks).
  CudaRadixCiphertextFFI *many_out;
  /// @brief Shift-amount bits 2.. , one per remaining barrel round, already
  /// aligned on the control-bit position.
  CudaRadixCiphertextFFI *shift_bits;
  /// @brief Sign bit of the original input (arithmetic right shift only).
  CudaRadixCiphertextFFI *sign_block;
  /// @brief Sign-extension block filling the slots that wrap around during an
  /// arithmetic right shift, recomputed every round.
  CudaRadixCiphertextFFI *padding_block;
  /// @brief Input of the padding LUT: the saved top block plus the round's
  /// shift bit.
  CudaRadixCiphertextFFI *padding_block_in;
  /// @brief Copy of the top block after the first round; the sign source for
  /// padding_block, kept because `messages` is overwritten each round.
  CudaRadixCiphertextFFI *saved_top_block;

  /// @brief Extracts the rounds' shift bits onto the control-bit position.
  int_bit_extract_luts_buffer<Torus> *shift_bit_extract_luts;
  /// @brief First round, bivariate against amount block 0: what a block
  /// keeps. Holds a sign-extended variant for the top block when arithmetic.
  int_radix_lut<Torus> *msg_lut;
  /// @brief First round: what a block hands one position away. Also has a
  /// sign-extended variant for the top block when arithmetic.
  int_radix_lut<Torus> *next_lut;
  /// @brief First round: what a block hands two positions away.
  int_radix_lut<Torus> *next_next_lut;
  /// @brief Barrel round many-LUT, splitting a block into the part it keeps
  /// and the part it hands `1 << d` blocks away.
  int_radix_lut<Torus> *round_lut;
  /// @brief Extracts the input's sign bit from its top block.
  int_radix_lut<Torus> *sign_lut;
  /// @brief Builds a round's sign-extension block from the saved top block.
  int_radix_lut<Torus> *padding_lut;

  /// @brief Number of barrel rounds left after the fused first round.
  uint32_t num_rounds;
  /// @brief Number of amount blocks, starting at block 1, the rounds' shift
  /// bits are extracted from.
  uint32_t num_amount_blocks;
  /// @brief Distance between the two sub-LUTs packed in round_lut.
  uint32_t lut_stride;

  int_shift_and_rotate_by_block_buffer(
      CudaStreams streams, SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
      int_radix_params params, uint32_t num_radix_blocks,
      uint32_t bits_per_block, uint32_t max_num_bits_that_tell_shift,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->shift_type = shift_type;
    this->is_signed = is_signed;
    gpu_memory_allocated = allocate_gpu_memory;

    auto message_modulus = params.message_modulus;
    bool is_left = (shift_type == LEFT_SHIFT || shift_type == LEFT_ROTATE);
    // An arithmetic shift is a right shift of a signed value: it pads with
    // copies of the sign bit instead of zeros so the result keeps the input's
    // sign. Left shifts and rotations never do this. It needs two extra LUT
    // variants for the block that holds the sign, plus the sign and padding
    // machinery allocated at the end of this constructor.
    bool arithmetic = is_signed && (shift_type == RIGHT_SHIFT);

    // Amount block 0 carries the first log2(bits_per_block) + 1 shift bits,
    // consumed by the fused first round.
    uint32_t bits_done_by_first_round = log2_int(bits_per_block) + 1;
    num_rounds = (max_num_bits_that_tell_shift > bits_done_by_first_round)
                     ? max_num_bits_that_tell_shift - bits_done_by_first_round
                     : 0;
    // Rounds read their bit from amount blocks 1.. , as the bits of block 0
    // are already spent.
    num_amount_blocks =
        std::max(1u, (num_rounds + bits_per_block - 1) / bits_per_block);
    GPU_ASSERT(num_amount_blocks <= num_radix_blocks - 1,
               "Cuda error: not enough shift amount blocks for the block "
               "barrel shifter");

    uint32_t block_modulus = message_modulus * params.carry_modulus;
    uint32_t box_size = params.polynomial_size / block_modulus;
    lut_stride = (block_modulus / 2) * box_size;

    auto alloc = [&](CudaRadixCiphertextFFI **ct, uint32_t n) {
      *ct = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), *ct, n,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    };
    alloc(&messages, num_radix_blocks);
    alloc(&next, num_radix_blocks);
    alloc(&next_next, num_radix_blocks);
    alloc(&rotate_tmp, num_radix_blocks);
    alloc(&pack_tmp, num_radix_blocks);
    alloc(&many_out, 2 * num_radix_blocks);
    alloc(&shift_bits, std::max(1u, num_rounds));

    // Shift bits are extracted onto plaintext position bits_per_block, which
    // is where the round LUT expects the control bit.
    shift_bit_extract_luts = new int_bit_extract_luts_buffer<Torus>(
        streams, params, bits_per_block, bits_per_block, num_amount_blocks,
        allocate_gpu_memory, size_tracker);

    // ---- first round: three bivariate LUTs over (block, amount block 0) ----
    // The packed input is x = block * message_modulus + a0.
    auto split_amount = [message_modulus, bits_per_block](Torus x, Torus &s,
                                                          Torus &t) {
      Torus a0 = x % message_modulus;
      s = a0 % bits_per_block;
      t = (a0 / bits_per_block) % 2;
    };

    // What a block keeps of its own value.
    auto f_msg = [=](Torus x) -> Torus {
      Torus s, t;
      split_amount(x, s, t);
      Torus blk = x / message_modulus;
      if (t == 1)
        return 0; // the whole block moved to a neighbour
      return is_left ? ((blk << s) % message_modulus) : (blk >> s);
    };
    // Same, for the block holding the sign: the value is first extended with
    // sign bits so that shifting in from above brings in the sign.
    auto f_msg_signed = [=](Torus x) -> Torus {
      Torus s, t;
      split_amount(x, s, t);
      Torus blk = x / message_modulus;
      Torus sign = (blk >> (bits_per_block - 1)) & 1;
      Torus pad = (message_modulus - 1) * sign;
      if (t == 1)
        return pad;
      return (((pad << bits_per_block) | blk) >> s) % message_modulus;
    };
    // What a block hands to the block one position away: its message part when
    // the amount also moves a whole block, its overflowing part otherwise.
    auto f_next = [=](Torus x) -> Torus {
      Torus s, t;
      split_amount(x, s, t);
      Torus prev = x / message_modulus;
      if (t == 1)
        return is_left ? ((prev << s) % message_modulus) : (prev >> s);
      return is_left ? (prev >> (bits_per_block - s))
                     : ((prev << (bits_per_block - s)) % message_modulus);
    };
    auto f_next_signed = [=](Torus x) -> Torus {
      Torus s, t;
      split_amount(x, s, t);
      Torus prev = x / message_modulus;
      Torus sign = (prev >> (bits_per_block - 1)) & 1;
      Torus pad = (message_modulus - 1) * sign;
      if (t == 1)
        return (((pad << bits_per_block) | prev) >> s) % message_modulus;
      return (prev << (bits_per_block - s)) % message_modulus;
    };
    // What a block hands two positions away: only its overflowing part, and
    // only when the amount also moves a whole block.
    auto f_next_next = [=](Torus x) -> Torus {
      Torus s, t;
      split_amount(x, s, t);
      Torus pp = x / message_modulus;
      if (t == 0)
        return 0;
      return is_left ? (pp >> (bits_per_block - s))
                     : ((pp << (bits_per_block - s)) % message_modulus);
    };

    // Only the top block holds the sign, so only it needs the sign-extended
    // LUT variants: bits shifted into it come from outside the ciphertext and
    // must read as sign copies. Every other block receives real bits from its
    // neighbour above and uses LUT 0. This per-block index map selects LUT 1
    // for the top block alone.
    auto last_block_uses_lut_1 = [num_radix_blocks](Torus *h_lut_indexes,
                                                    uint32_t) {
      for (uint32_t i = 0; i < num_radix_blocks; i++)
        h_lut_indexes[i] = (i == num_radix_blocks - 1) ? 1 : 0;
    };
    auto active_streams =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);

    // Two LUTs (normal + sign-extended) only when the sign-extended variant
    // is actually needed; a logical shift or a rotation uses one for all
    // blocks.
    uint32_t num_first_round_luts = arithmetic ? 2 : 1;
    msg_lut = new int_radix_lut<Torus>(streams, params, num_first_round_luts,
                                       num_radix_blocks, allocate_gpu_memory,
                                       size_tracker);
    next_lut = new int_radix_lut<Torus>(streams, params, num_first_round_luts,
                                        num_radix_blocks, allocate_gpu_memory,
                                        size_tracker);
    next_next_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    if (arithmetic) {
      // Fill both LUT slots and hand over the index map, so the top block
      // picks the sign-extended variant and the rest keep the plain one. A
      // logical shift or a rotation has a single variant for every block.
      msg_lut->generate_and_broadcast_lut(
          active_streams, {0, 1}, {f_msg, f_msg_signed}, last_block_uses_lut_1);
      next_lut->generate_and_broadcast_lut(active_streams, {0, 1},
                                           {f_next, f_next_signed},
                                           last_block_uses_lut_1);
    } else {
      msg_lut->generate_and_broadcast_lut(active_streams, {0}, {f_msg},
                                          LUT_0_FOR_ALL_BLOCKS);
      next_lut->generate_and_broadcast_lut(active_streams, {0}, {f_next},
                                           LUT_0_FOR_ALL_BLOCKS);
    }
    next_next_lut->generate_and_broadcast_lut(
        active_streams, {0}, {f_next_next}, LUT_0_FOR_ALL_BLOCKS);

    // ---- barrel rounds: one many-LUT splitting message and carry ----
    // Input is (block + shift_bit << bits_per_block): when the round's shift
    // bit is set the whole block moves, otherwise it stays.
    auto f_round_message = [=](Torus x) -> Torus {
      Torus control = (x >> bits_per_block) % 2;
      return control == 1 ? 0 : (x % message_modulus);
    };
    auto f_round_carry = [=](Torus x) -> Torus {
      Torus control = (x >> bits_per_block) % 2;
      return control == 1 ? (x % message_modulus) : 0;
    };
    round_lut = new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                         2, allocate_gpu_memory, size_tracker);
    round_lut->generate_and_broadcast_many_lut(
        active_streams, {0}, {{f_round_message, f_round_carry}},
        LUT_0_FOR_ALL_BLOCKS);

    // ---- arithmetic right shift extras ----
    if (arithmetic) {
      alloc(&sign_block, 1);
      alloc(&padding_block, 1);
      alloc(&padding_block_in, 1);
      alloc(&saved_top_block, 1);

      auto active_streams_single =
          streams.active_gpu_subset(1, params.pbs_type);
      // Extracts the input's sign bit (the MSB of its top block). The
      // overshift fixup needs it to decide between -1 and 0 when the shift
      // amount is >= the bit width.
      auto f_sign = [bits_per_block](Torus x) -> Torus {
        return (x >> (bits_per_block - 1)) & 1;
      };
      sign_lut = new int_radix_lut<Torus>(streams, params, 1, 1,
                                          allocate_gpu_memory, size_tracker);
      sign_lut->generate_and_broadcast_lut(active_streams_single, {0}, {f_sign},
                                           LUT_0_FOR_ALL_BLOCKS);

      // Builds the padding block a round uses to refill the slots that wrap
      // off the top. Input packs the round's shift bit on the control
      // position with the (sign-holding) top block: when the bit is set the
      // result is the sign replicated across the whole block, otherwise the
      // round shifts nothing and the padding is zero.
      auto f_padding = [=](Torus x) -> Torus {
        Torus control = (x >> bits_per_block) % 2;
        Torus last = x % message_modulus;
        Torus sign = (last >> (bits_per_block - 1)) & 1;
        return control == 1 ? (message_modulus - 1) * sign : 0;
      };
      padding_lut = new int_radix_lut<Torus>(streams, params, 1, 1,
                                             allocate_gpu_memory, size_tracker);
      padding_lut->generate_and_broadcast_lut(
          active_streams_single, {0}, {f_padding}, LUT_0_FOR_ALL_BLOCKS);
    } else {
      sign_block = nullptr;
      padding_block = nullptr;
      padding_block_in = nullptr;
      saved_top_block = nullptr;
      sign_lut = nullptr;
      padding_lut = nullptr;
    }
  }

  void release(CudaStreams streams) {
    auto drop_ct = [&](CudaRadixCiphertextFFI *ct) {
      if (ct == nullptr)
        return;
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, gpu_memory_allocated);
      delete ct;
    };
    auto drop_lut = [&](int_radix_lut<Torus> *lut) {
      if (lut == nullptr)
        return;
      lut->release(streams);
      delete lut;
    };

    drop_ct(messages);
    drop_ct(next);
    drop_ct(next_next);
    drop_ct(rotate_tmp);
    drop_ct(pack_tmp);
    drop_ct(many_out);
    drop_ct(shift_bits);
    // Allocated only for an arithmetic right shift.
    drop_ct(sign_block);
    drop_ct(padding_block);
    drop_ct(padding_block_in);
    drop_ct(saved_top_block);

    shift_bit_extract_luts->release(streams);
    delete shift_bit_extract_luts;
    drop_lut(msg_lut);
    drop_lut(next_lut);
    drop_lut(next_next_lut);
    drop_lut(round_lut);
    drop_lut(sign_lut);
    drop_lut(padding_lut);
  }
};

/// @brief Scratch for a shift or rotation by an encrypted amount.
///
/// Holds what both algorithms share -- the cleaning LUT and the overshift
/// fixup -- and delegates the shift itself to whichever of the two sub-buffers
/// `use_block_path` selects.
template <typename Torus> struct int_shift_and_rotate_buffer {
  int_radix_params params;
  /// @brief Which of the four operations is being performed.
  SHIFT_OR_ROTATE_TYPE shift_type;
  /// @brief Whether the value being shifted is signed; with a right shift
  /// this makes the shift arithmetic.
  bool is_signed;

  /// @brief Selects the algorithm: the block-level barrel shifter
  /// (host_block_shift_and_rotate_inplace) when true, the bit-level one
  /// (host_shift_and_rotate_inplace) otherwise. Exactly one of block_mem and
  /// bits_mem is non-null, the one this flag selects.
  bool use_block_path;
  /// @brief Block-level path scratch; null unless use_block_path.
  int_shift_and_rotate_by_block_buffer<Torus> *block_mem;
  /// @brief Bit-level path scratch; null when use_block_path.
  int_shift_and_rotate_by_bits_buffer<Torus> *bits_mem;

  /// @brief Refreshes a block's noise and drops its carries. Shared by both
  /// paths, and the final step of a rotation.
  int_radix_lut<Torus> *cleaning_lut;

  // Overshift handling: shifting by >= the integer's bit width yields 0, or the
  // sign (0 / -1) for an arithmetic right shift.

  /// @brief true for shifts (left/right), false for rotations.
  bool handle_overshift;
  /// @brief Scratch for the comparison "shift amount >= total_nb_bits".
  int_comparison_buffer<Torus> *overshift_compare_mem;
  /// @brief One-block ct reused by the fixup: first the boolean predicate,
  /// then the per-block condition packed into the carry.
  CudaRadixCiphertextFFI *tmp_overshift;
  /// @brief Zero-padded copy of the shift amount, used when the block count is
  /// odd (the comparison needs an even count, or one). Null when not padding.
  CudaRadixCiphertextFFI *tmp_padded_shift;
  /// @brief Number of blocks the comparison runs on: the input block count
  /// rounded up to even (or 1).
  uint32_t overshift_compare_num_blocks;
  /// @brief Constant the shift amount is compared against: total_nb_bits split
  /// into blocks, on the host.
  Torus *h_overshift_scalar_blocks;
  /// @brief Device copy of the scalar blocks.
  Torus *d_overshift_scalar_blocks;
  /// @brief Number of digits in the total_nb_bits decomposition.
  uint32_t num_overshift_scalar_blocks;
  /// @brief Moves the small condition into a block's carry
  /// (x -> (x % message_modulus) * message_modulus) so it can be added per
  /// block.
  int_radix_lut<Torus> *overshift_pack_lut;
  /// @brief Per-block finalizer: reads the packed condition and keeps the
  /// shifted value or replaces it with 0 / the sign, refreshing noise in the
  /// same PBS.
  int_radix_lut<Torus> *overshift_cleanup_lut;

  /// @brief Bit index the bit-level barrel shifter counts its rotations
  /// from: 0 for a left shift, the bit width otherwise.
  Torus offset;
  bool gpu_memory_allocated;

  int_shift_and_rotate_buffer(CudaStreams streams,
                              SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
                              int_radix_params params,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->shift_type = shift_type;
    this->is_signed = is_signed;
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    uint32_t bits_per_block = std::log2(params.message_modulus);
    uint32_t total_nb_bits =
        std::log2(params.message_modulus) * num_radix_blocks;
    uint32_t max_num_bits_that_tell_shift = std::log2(total_nb_bits);

    auto is_power_of_two = [](uint32_t n) {
      return (n > 0) && ((n & (n - 1)) == 0);
    };

    if (!is_power_of_two(total_nb_bits))
      max_num_bits_that_tell_shift += 1;

    offset = (shift_type == LEFT_SHIFT ? 0 : total_nb_bits);

    // The block-level barrel shifter costs roughly half the PBS of the
    // bit-level one, but it requires blocks holding a power-of-two number of
    // message bits and a noise budget of three additions before a PBS. Only
    // 2_2 is enabled for now; every other parameter set keeps the bit-level
    // path. A single block is excluded because the fused first round needs a
    // neighbour to hand its overflow to.
    use_block_path = (params.message_modulus == 4 &&
                      params.carry_modulus == 4 && num_radix_blocks > 1);

    cleaning_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    auto cleaning_lut_f = [params](Torus x) -> Torus {
      return x % params.message_modulus;
    };
    auto active_gpu_count_cleaning =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    cleaning_lut->generate_and_broadcast_lut(
        active_gpu_count_cleaning, {0}, {cleaning_lut_f}, LUT_0_FOR_ALL_BLOCKS);

    block_mem = nullptr;
    bits_mem = nullptr;
    if (use_block_path) {
      block_mem = new int_shift_and_rotate_by_block_buffer<Torus>(
          streams, shift_type, is_signed, params, num_radix_blocks,
          bits_per_block, max_num_bits_that_tell_shift, allocate_gpu_memory,
          size_tracker);
    } else {
      bits_mem = new int_shift_and_rotate_by_bits_buffer<Torus>(
          streams, params, num_radix_blocks, bits_per_block,
          max_num_bits_that_tell_shift, allocate_gpu_memory, size_tracker);
    }

    // ---- Overshift handling (shifts only, not rotations) ----
    setup_handle_overshift(streams, num_radix_blocks, total_nb_bits,
                           allocate_gpu_memory, size_tracker);
  }

  /// @brief Allocates and initializes the buffers and LUTs used to fix up the
  /// result when the shift amount is >= the integer's bit width (overshift).
  /// Only shifts (not rotations) need this; for rotations it just resets the
  /// members to their null/zero defaults.
  /// @param num_radix_blocks Number of radix blocks of the value being shifted.
  /// @param total_nb_bits Bit width of the value, i.e. the overshift threshold.
  void setup_handle_overshift(CudaStreams streams, uint32_t num_radix_blocks,
                              uint32_t total_nb_bits, bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    handle_overshift = (shift_type == LEFT_SHIFT || shift_type == RIGHT_SHIFT);
    overshift_compare_mem = nullptr;
    tmp_overshift = nullptr;
    tmp_padded_shift = nullptr;
    overshift_compare_num_blocks = 0;
    d_overshift_scalar_blocks = nullptr;
    h_overshift_scalar_blocks = nullptr;
    num_overshift_scalar_blocks = 0;
    overshift_pack_lut = nullptr;
    overshift_cleanup_lut = nullptr;

    if (handle_overshift) {
      auto message_modulus = params.message_modulus;

      // The unsigned scalar comparison requires an even number of blocks (or
      // exactly 1), so pad the comparison block count when needed.
      overshift_compare_num_blocks = num_radix_blocks;
      if (num_radix_blocks > 1 && (num_radix_blocks % 2 != 0))
        overshift_compare_num_blocks = num_radix_blocks + 1;

      overshift_compare_mem = new int_comparison_buffer<Torus>(
          streams, COMPARISON_TYPE::GE, params, overshift_compare_num_blocks,
          /*is_signed=*/false, allocate_gpu_memory, size_tracker);

      tmp_overshift = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), tmp_overshift, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      if (overshift_compare_num_blocks != num_radix_blocks) {
        tmp_padded_shift = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), tmp_padded_shift,
            overshift_compare_num_blocks, params.big_lwe_dimension,
            size_tracker, allocate_gpu_memory);
      }

      // Decompose total_nb_bits into base-message_modulus digits
      // (little-endian)
      std::vector<Torus> digits;
      {
        uint32_t v = total_nb_bits;
        while (v > 0) {
          digits.push_back((Torus)(v % message_modulus));
          v /= message_modulus;
        }
        if (digits.empty())
          digits.push_back((Torus)0);
      }
      num_overshift_scalar_blocks = (uint32_t)digits.size();
      h_overshift_scalar_blocks =
          (Torus *)malloc(num_overshift_scalar_blocks * sizeof(Torus));
      for (uint32_t i = 0; i < num_overshift_scalar_blocks; i++)
        h_overshift_scalar_blocks[i] = digits[i];
      d_overshift_scalar_blocks = (Torus *)cuda_malloc_with_size_tracking_async(
          num_overshift_scalar_blocks * sizeof(Torus), streams.stream(0),
          streams.gpu_index(0), size_tracker, allocate_gpu_memory);
      cuda_memcpy_with_size_tracking_async_to_gpu(
          d_overshift_scalar_blocks, h_overshift_scalar_blocks,
          num_overshift_scalar_blocks * sizeof(Torus), streams.stream(0),
          streams.gpu_index(0), allocate_gpu_memory);

      // An arithmetic right shift saturates towards the sign rather than
      // towards zero, so its overshift result depends on the input's sign and
      // the condition carries one extra bit (see cleanup_f below).
      bool arithmetic = is_signed && (shift_type == RIGHT_SHIFT);

      // Pack LUT: moves the small condition value into the carry space, clean.
      overshift_pack_lut = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);
      auto pack_f = [message_modulus](Torus x) -> Torus {
        return (x % message_modulus) * message_modulus;
      };
      auto active_streams_pack = streams.active_gpu_subset(1, params.pbs_type);
      overshift_pack_lut->generate_and_broadcast_lut(
          active_streams_pack, {0}, {pack_f}, LUT_0_FOR_ALL_BLOCKS);

      // Cleanup LUT: applied per result block, reads `cond` from the carry.
      overshift_cleanup_lut =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);
      std::function<Torus(Torus)> cleanup_f;
      if (arithmetic) {
        // `cond` packs two bits: overshift in bit 1, the input's sign in bit
        // 0. Shifting a negative value right by more than its width saturates
        // to -1, a positive one to 0, so both bits are needed to choose.
        cleanup_f = [message_modulus](Torus x) -> Torus {
          Torus c = x / message_modulus; // c == (overshift << 1) | is_neg
          Torus v = x % message_modulus;
          if (c == 3)
            return message_modulus - 1; // overshift & negative -> -1
          if (c == 2)
            return (Torus)0; // overshift & positive -> 0
          return v;          // in range -> shifted value
        };
      } else {
        cleanup_f = [message_modulus](Torus x) -> Torus {
          Torus c = x / message_modulus; // c == overshift
          Torus v = x % message_modulus;
          return (c >= 1) ? (Torus)0 : v;
        };
      }
      auto active_streams_cleanup =
          streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
      overshift_cleanup_lut->generate_and_broadcast_lut(
          active_streams_cleanup, {0}, {cleanup_f}, LUT_0_FOR_ALL_BLOCKS);
    }
  }

  void release(CudaStreams streams) {
    if (block_mem != nullptr) {
      block_mem->release(streams);
      delete block_mem;
    }
    if (bits_mem != nullptr) {
      bits_mem->release(streams);
      delete bits_mem;
    }

    cleaning_lut->release(streams);
    delete cleaning_lut;

    if (handle_overshift)
      release_handle_overshift(streams);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }

  /// @brief Releases the buffers and LUTs allocated by
  /// setup_handle_overshift. A no-op when overshift handling is disabled
  /// (rotations), since all members are then null.
  void release_handle_overshift(CudaStreams streams) {

    if (overshift_compare_mem) {
      overshift_compare_mem->release(streams);
      delete overshift_compare_mem;
    }
    if (tmp_overshift) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_overshift, gpu_memory_allocated);
      delete tmp_overshift;
    }
    if (tmp_padded_shift) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_padded_shift, gpu_memory_allocated);
      delete tmp_padded_shift;
    }
    if (overshift_pack_lut) {
      overshift_pack_lut->release(streams);
      delete overshift_pack_lut;
    }
    if (overshift_cleanup_lut) {
      overshift_cleanup_lut->release(streams);
      delete overshift_cleanup_lut;
    }
    if (d_overshift_scalar_blocks)
      cuda_drop_with_size_tracking_async(
          d_overshift_scalar_blocks, streams.stream(0), streams.gpu_index(0),
          gpu_memory_allocated);
    if (h_overshift_scalar_blocks)
      free(h_overshift_scalar_blocks);
  }
};
