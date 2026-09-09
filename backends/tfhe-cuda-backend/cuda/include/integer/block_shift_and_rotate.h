#pragma once
#include "integer_utilities.h"

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
  /// @brief True for a right shift of a signed value, the only case that pads
  /// with the sign. Tells release() whether the sign and padding members below
  /// hold anything.
  bool arithmetic;
  bool gpu_memory_allocated;

  /// @brief Result being built: what each block keeps of its own value,
  /// accumulated with the two donor arrays below.
  CudaRadixCiphertextFFI messages;
  /// @brief What each block hands to the block one position away.
  CudaRadixCiphertextFFI next;
  /// @brief What each block hands to the block two positions away.
  CudaRadixCiphertextFFI next_next;
  /// @brief Destination of the block rotations, which are not in-place.
  CudaRadixCiphertextFFI rotate_tmp;
  /// @brief Holds (input block) * message_modulus + (amount block 0) for the
  /// three bivariate LUTs of the first round.
  CudaRadixCiphertextFFI pack_tmp;
  /// @brief Many-LUT output of a barrel round: messages in [0, num_blocks),
  /// carries in [num_blocks, 2 * num_blocks).
  CudaRadixCiphertextFFI many_out;
  /// @brief Shift-amount bits 2.. , one per remaining barrel round, already
  /// aligned on the control-bit position.
  CudaRadixCiphertextFFI shift_bits;
  /// @brief Sign bit of the original input (arithmetic right shift only).
  CudaRadixCiphertextFFI sign_block;
  /// @brief Sign-extension block filling the slots that wrap around during an
  /// arithmetic right shift, recomputed every round.
  CudaRadixCiphertextFFI padding_block;
  /// @brief Input of the padding LUT: the saved top block plus the round's
  /// shift bit.
  CudaRadixCiphertextFFI padding_block_in;
  /// @brief Copy of the top block after the first round; the sign source for
  /// padding_block, kept because `messages` is overwritten each round.
  CudaRadixCiphertextFFI saved_top_block;

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
    arithmetic = is_signed && (shift_type == RIGHT_SHIFT);

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

    auto create_zero = [&](CudaRadixCiphertextFFI *ct, uint32_t n) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), ct, n,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    };
    create_zero(&messages, num_radix_blocks);
    create_zero(&next, num_radix_blocks);
    create_zero(&next_next, num_radix_blocks);
    create_zero(&rotate_tmp, num_radix_blocks);
    create_zero(&pack_tmp, num_radix_blocks);
    create_zero(&many_out, 2 * num_radix_blocks);
    create_zero(&shift_bits, std::max(1u, num_rounds));

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
      create_zero(&sign_block, 1);
      create_zero(&padding_block, 1);
      create_zero(&padding_block_in, 1);
      create_zero(&saved_top_block, 1);

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
      // The sign and padding members are left untouched; `arithmetic` is what
      // tells release() that they hold nothing.
      sign_lut = nullptr;
      padding_lut = nullptr;
    }
  }

  void release(CudaStreams streams) {
    auto drop_ct = [&](CudaRadixCiphertextFFI *ct) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, gpu_memory_allocated);
    };
    auto drop_lut = [&](int_radix_lut<Torus> *lut) {
      if (lut == nullptr)
        return;
      lut->release(streams);
      delete lut;
    };

    drop_ct(&messages);
    drop_ct(&next);
    drop_ct(&next_next);
    drop_ct(&rotate_tmp);
    drop_ct(&pack_tmp);
    drop_ct(&many_out);
    drop_ct(&shift_bits);
    // Allocated only for an arithmetic right shift.
    if (arithmetic) {
      drop_ct(&sign_block);
      drop_ct(&padding_block);
      drop_ct(&padding_block_in);
      drop_ct(&saved_top_block);
    }

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
