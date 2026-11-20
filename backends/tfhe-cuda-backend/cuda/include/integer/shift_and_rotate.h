#pragma once
#include "integer/block_shift_and_rotate.h"
#include "integer/comparison.h"
#include "integer/scalar_div.h"
#include "integer_utilities.h"

/// @brief Buffers and LUTs of the bit-level barrel shifter, which explodes
/// both operands into one-bit ciphertexts and runs one cmux per bit per round.
/// Used for every parameter set the block-level path does not support.
template <typename Torus> struct int_shift_and_rotate_by_bits_buffer {
  int_radix_params params;
  bool gpu_memory_allocated;

  /// @brief The value being shifted, exploded into one ciphertext per bit.
  CudaRadixCiphertextFFI tmp_bits;
  /// @brief The shift amount's low bits, one per barrel round, each already
  /// aligned on the cmux control position.
  CudaRadixCiphertextFFI tmp_shift_bits;
  /// @brief Destination of a round's bit rotation, which is not in-place.
  CudaRadixCiphertextFFI tmp_rotated;
  /// @brief Bit array carrying the result, updated in place every round.
  CudaRadixCiphertextFFI tmp_input_bits_a;
  /// @brief Copy of that array the rotation reads from, so the cmux can pick
  /// between the shifted and unshifted bit.
  CudaRadixCiphertextFFI tmp_input_bits_b;
  /// @brief Packs control | shifted | unshifted into one block per bit, the
  /// input of the mux LUT.
  CudaRadixCiphertextFFI tmp_mux_inputs;

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

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &tmp_bits,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &tmp_shift_bits,
        max_num_bits_that_tell_shift * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &tmp_rotated,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &tmp_input_bits_a,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &tmp_input_bits_b,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &tmp_mux_inputs,
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
        bits_per_block * num_radix_blocks, params.pbs_type());

    mux_lut->generate_and_broadcast_lut(active_gpu_count_mux, {0}, {mux_lut_f},
                                        LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    auto drop_ct = [&](CudaRadixCiphertextFFI *ct) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, gpu_memory_allocated);
    };
    drop_ct(&tmp_bits);
    drop_ct(&tmp_shift_bits);
    drop_ct(&tmp_rotated);
    drop_ct(&tmp_input_bits_a);
    drop_ct(&tmp_input_bits_b);
    drop_ct(&tmp_mux_inputs);

    bit_extract_luts->release(streams);
    delete bit_extract_luts;
    bit_extract_luts_with_offset_2->release(streams);
    delete bit_extract_luts_with_offset_2;
    mux_lut->release(streams);
    delete mux_lut;
  }
};

/// @brief Tells whether n has a single bit set.
/// @param n Value to test.
inline bool is_power_of_two(uint32_t n) { return n > 0 && (n & (n - 1)) == 0; }

/// @brief Scratch of the barrel shifter that shifts and rotations by an
/// encrypted amount both run on.
///
/// The shifter only moves bits by the low bits of the amount. What an amount
/// of the bit width or more means is the business of its two owners,
/// int_shift_buffer and int_rotate_buffer.
template <typename Torus> struct int_barrel_shifter_buffer {
  int_radix_params params;
  /// @brief Which of the four operations is being performed.
  SHIFT_OR_ROTATE_TYPE shift_type;
  /// @brief Whether the value being shifted is signed. With a right shift
  /// this makes the shift arithmetic.
  bool is_signed;
  /// @brief Number of low bits of the amount the shifter reads, one per round:
  /// ceil(log2(bit width)).
  uint32_t max_num_bits_that_tell_shift;

  /// @brief Selects the algorithm: the block-level barrel shifter
  /// (host_block_shift_and_rotate, in block_shift_and_rotate.cuh) when true,
  /// the bit-level one otherwise. Both are dispatched from
  /// host_barrel_shift_rounds. Exactly one of block_mem and bits_mem is
  /// non-null, the one this flag selects.
  bool use_block_path;
  /// @brief Block-level path scratch, null unless use_block_path.
  int_shift_and_rotate_by_block_buffer<Torus> *block_mem;
  /// @brief Bit-level path scratch, null when use_block_path.
  int_shift_and_rotate_by_bits_buffer<Torus> *bits_mem;

  /// @brief Refreshes a block's noise and drops its carries. Shared by both
  /// paths, and the final step of a rotation.
  int_radix_lut<Torus> *cleaning_lut;

  int_barrel_shifter_buffer(CudaStreams streams,
                            SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
                            int_radix_params params, uint32_t num_radix_blocks,
                            bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->shift_type = shift_type;
    this->is_signed = is_signed;
    this->params = params;

    uint32_t bits_per_block = std::log2(params.message_modulus);
    uint32_t total_nb_bits = bits_per_block * num_radix_blocks;
    max_num_bits_that_tell_shift = std::log2(total_nb_bits);
    if (!is_power_of_two(total_nb_bits))
      max_num_bits_that_tell_shift += 1;

    // The block-level barrel shifter costs roughly half the PBS of the
    // bit-level one, but it requires blocks holding a power-of-two number of
    // message bits and a noise budget of three additions before a PBS. Only
    // 2_2 is enabled for now, every other parameter set keeps the bit-level
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
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type());
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
  }
};

/// @brief Scratch of a shift by an encrypted amount.
///
/// On top of the barrel shifter it holds the overshift fixup. Shifting by the
/// bit width or more yields 0, or the sign (0 / -1) for an arithmetic right
/// shift, which the shifter cannot tell as it only reads the low bits of the
/// amount.
template <typename Torus> struct int_shift_buffer {
  int_radix_params params;
  bool gpu_memory_allocated;

  /// @brief Moves the bits, see host_barrel_shift_rounds.
  int_barrel_shifter_buffer<Torus> *shifter_mem;

  /// @brief True for a right shift of a signed value, whose overshift result
  /// is the sign of the input instead of 0.
  bool arithmetic;
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

  int_shift_buffer(CudaStreams streams, SHIFT_OR_ROTATE_TYPE shift_type,
                   bool is_signed, int_radix_params params,
                   uint32_t num_radix_blocks, bool allocate_gpu_memory,
                   uint64_t &size_tracker) {
    GPU_ASSERT(shift_type == LEFT_SHIFT || shift_type == RIGHT_SHIFT,
               "Cuda error: a shift buffer cannot run a rotation");
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    shifter_mem = new int_barrel_shifter_buffer<Torus>(
        streams, shift_type, is_signed, params, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    auto message_modulus = params.message_modulus;
    uint32_t total_nb_bits = log2_int(message_modulus) * num_radix_blocks;

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

    tmp_padded_shift = nullptr;
    if (overshift_compare_num_blocks != num_radix_blocks) {
      tmp_padded_shift = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), tmp_padded_shift,
          overshift_compare_num_blocks, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);
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
    arithmetic = is_signed && (shift_type == RIGHT_SHIFT);

    // Pack LUT: moves the small condition value into the carry space, clean.
    overshift_pack_lut = new int_radix_lut<Torus>(
        streams, params, 1, 1, allocate_gpu_memory, size_tracker);
    auto pack_f = [message_modulus](Torus x) -> Torus {
      return (x % message_modulus) * message_modulus;
    };
    auto active_streams_pack = streams.active_gpu_subset(1, params.pbs_type());
    overshift_pack_lut->generate_and_broadcast_lut(
        active_streams_pack, {0}, {pack_f}, LUT_0_FOR_ALL_BLOCKS);

    // Cleanup LUT: applied per result block, reads cond from the carry.
    overshift_cleanup_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> cleanup_f;
    if (arithmetic) {
      // cond packs two bits: overshift in bit 1, the input's sign in bit
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
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type());
    overshift_cleanup_lut->generate_and_broadcast_lut(
        active_streams_cleanup, {0}, {cleanup_f}, LUT_0_FOR_ALL_BLOCKS);
  }

  void release(CudaStreams streams) {
    shifter_mem->release(streams);
    delete shifter_mem;

    overshift_compare_mem->release(streams);
    delete overshift_compare_mem;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_overshift, gpu_memory_allocated);
    delete tmp_overshift;
    if (tmp_padded_shift != nullptr) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_padded_shift, gpu_memory_allocated);
      delete tmp_padded_shift;
    }

    overshift_pack_lut->release(streams);
    delete overshift_pack_lut;
    overshift_cleanup_lut->release(streams);
    delete overshift_cleanup_lut;

    cuda_drop_with_size_tracking_async(d_overshift_scalar_blocks,
                                       streams.stream(0), streams.gpu_index(0),
                                       gpu_memory_allocated);
    free(h_overshift_scalar_blocks);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

/// @brief Scratch of the remainder amount % total_nb_bits a rotation runs
/// before its barrel shifter, see host_reduce_rotation_amount.
template <typename Torus> struct int_rotation_amount_reduction_buffer {
  bool gpu_memory_allocated;

  /// @brief Scratch of the scalar division by total_nb_bits.
  int_unsigned_scalar_div_rem_buffer<Torus> *div_rem_mem;
  /// @brief The division works in place: holds the amount on entry and its
  /// quotient on exit, which nothing reads.
  CudaRadixCiphertextFFI quotient;
  /// @brief The amount modulo total_nb_bits, what the barrel shifter reads.
  CudaRadixCiphertextFFI reduced_amount;

  int_rotation_amount_reduction_buffer(
      CudaStreams streams, int_radix_params params, uint32_t num_radix_blocks,
      const CudaScalarDivisorFFI *scalar_divisor_ffi,
      uint32_t active_bits_divisor, bool allocate_gpu_memory,
      uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;

    div_rem_mem = new int_unsigned_scalar_div_rem_buffer<Torus>(
        streams, params, num_radix_blocks, scalar_divisor_ffi,
        active_bits_divisor, allocate_gpu_memory, size_tracker);

    for (auto ct : {&quotient, &reduced_amount})
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), ct, num_radix_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    div_rem_mem->release(streams);
    delete div_rem_mem;

    for (auto ct : {&quotient, &reduced_amount})
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     ct, gpu_memory_allocated);
  }
};

/// @brief Scratch of a rotation by an encrypted amount.
///
/// A rotation is periodic in its amount, with the bit width as period. The
/// barrel shifter gets that for free when the bit width is a power of two, as
/// dropping the high bits of the amount is then the reduction. Any other bit
/// width has to reduce the amount before the shifter reads it.
template <typename Torus> struct int_rotate_buffer {
  /// @brief Moves the bits, see host_barrel_shift_rounds.
  int_barrel_shifter_buffer<Torus> *shifter_mem;
  /// @brief Reduces the amount modulo the bit width before the shifter runs.
  /// Null when the bit width is a power of two.
  int_rotation_amount_reduction_buffer<Torus> *amount_reduction_mem;

  int_rotate_buffer(CudaStreams streams, SHIFT_OR_ROTATE_TYPE rotate_type,
                    int_radix_params params, uint32_t num_radix_blocks,
                    const CudaScalarDivisorFFI *scalar_divisor_ffi,
                    uint32_t active_bits_divisor, bool allocate_gpu_memory,
                    uint64_t &size_tracker) {
    GPU_ASSERT(rotate_type == LEFT_ROTATE || rotate_type == RIGHT_ROTATE,
               "Cuda error: a rotate buffer cannot run a shift");

    // A rotation loses no bit, so the sign of the value has no say in it
    shifter_mem = new int_barrel_shifter_buffer<Torus>(
        streams, rotate_type, /*is_signed=*/false, params, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    amount_reduction_mem = nullptr;
    uint32_t total_nb_bits =
        log2_int(params.message_modulus) * num_radix_blocks;
    if (!is_power_of_two(total_nb_bits)) {
      GPU_ASSERT(scalar_divisor_ffi != nullptr,
                 "Cuda error: rotating a bit width that is not a power of two "
                 "requires the scalar divisor of that bit width");
      amount_reduction_mem = new int_rotation_amount_reduction_buffer<Torus>(
          streams, params, num_radix_blocks, scalar_divisor_ffi,
          active_bits_divisor, allocate_gpu_memory, size_tracker);
    }
  }

  void release(CudaStreams streams) {
    shifter_mem->release(streams);
    delete shifter_mem;

    if (amount_reduction_mem != nullptr) {
      amount_reduction_mem->release(streams);
      delete amount_reduction_mem;
    }

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
