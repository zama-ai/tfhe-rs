#pragma once
#include "cmux.h"
#include "comparison.h"
#include "ilog2.h"
#include "integer_utilities.h"
#include "mul_add_fixed_point.h"
#include "multiplication.h"
#include "shift_and_rotate.h"
#include "vector_find.h"

// ---------------------------------------------------------------------------
// Goldschmidt division
// ---------------------------------------------------------------------------
//
// Divides two n-block unsigned radix integers by iterating a fixed-point
// reciprocal instead of doing long division, so the work is a handful of wide
// multiplications rather than one sequential step per bit.
//
// Everything runs in a fixed point two blocks wider than the operands
// (68 bits for a 64-bit division), in two different scalings:
//
//     d  =  Q0.68   normalised into [1/2, 1)   -- the MSB of the field is set
//     n  =  Q64.4   the numerator, rescaled by the same factor as d
//
//     bit  67                                    4  3      0
//          +-------------------------------------+--+------+
//     d    |0. 1 d62 d61 ................... d0  |  0 ...  |   d in [1/2, 1)
//          +-------------------------------------+--+------+
//          +----------------------------------------+------+
//     n    | floor(N * 2^lz / 2^60)                 | .frac|   n = N/D * 2^4
//          +----------------------------------------+------+
//
// The iteration multiplies both by the same factor until d converges to 1, at
// which point n holds the quotient:
//
//     d <- d * (1 + x),   n <- n * (1 + x)     with x = 1 - d
//
// so that d becomes 1 - x^2 and the number of correct bits doubles each round.
// Three rounds after a 9-bit seed cover 64 bits. The seed comes from a
// 512-entry lookup table on d's top 10 bits, chosen so that (1 + x0) * d < 1 --
// keeping every intermediate below 1 means the quotient only ever approaches
// the true value from below, so a single +1 correction at the end suffices.
//
// The per-round truncation schedule is the one the correctness proof pins down:
// round i takes x from `s` significant blocks whose LSB weighs beta^-t, and the
// multiplication drops everything below one ulp of the output.
//
//     round | s (blocks of x) | t (x's LSB weight) | x's leading zero blocks
//     ------+-----------------+--------------------+------------------------
//     seed  |        5        |         5          |           0
//       0   |        5        |         9          |           4
//       1   |        9        |        17          |           8
//       2   |       16        |        32          |          16
//
// x is a true negation of d, carry propagated. The tempting shortcut - read the
// bitwise complement and skip the +1, since only the top blocks are ever used -
// is wrong: it lowers x by one ulp exactly when 1 - d is representable at x's
// scale, which for a power-of-two denominator is every single round. The losses
// compound to two ulps of quotient, one more than the final correction can
// absorb, and u64::MAX / 1 comes out short.
#define GOLDSCHMIDT_ITERATIONS 3u
#define GOLDSCHMIDT_LUT_PRECISION 9u

/// @brief Scratch for the Goldschmidt division: the truncation schedule, the
/// fixed-point iteration state, the seed table, and the sub-buffers of every
/// step (normalisation, seed lookup, the four multiply-adds, and the
/// remainder-based correction). See the file banner above for the algorithm.
template <typename Torus> struct int_goldschmidt_division_buffer {
  int_radix_params params;
  bool gpu_memory_allocated;

  /// @brief Operand width, 32 for a 64-bit division.
  uint32_t num_blocks;
  /// @brief Fixed-point width, num_blocks + 2.
  uint32_t fp_blocks;
  /// @brief Significant blocks of the seed factor x0.
  uint32_t x0_blocks;
  /// @brief Width of the leading-zero counter, enough to hold the bit count.
  uint32_t counter_blocks;

  /// @brief Per-round significant blocks of x (the `s` of the schedule).
  uint32_t x_blocks[GOLDSCHMIDT_ITERATIONS];
  /// @brief Per-round leading zero blocks of x. The LSB of x weighs
  /// beta^-(x_zero_blocks + x_blocks), which is the `t` of the schedule.
  uint32_t x_zero_blocks[GOLDSCHMIDT_ITERATIONS];

  /// @brief Numerator of the current round, fp_blocks. Swaps with next_n
  /// every round.
  CudaRadixCiphertextFFI current_n;
  /// @brief Denominator of the current round, fp_blocks. Swaps with next_d
  /// every round.
  CudaRadixCiphertextFFI current_d;
  /// @brief Output of the numerator multiply-add of the current round.
  CudaRadixCiphertextFFI next_n;
  /// @brief Output of the denominator multiply-add of the current round.
  CudaRadixCiphertextFFI next_d;

  /// @brief The denominator at operand width, shifted by the leading-zero
  /// count.
  CudaRadixCiphertextFFI shifted_d;
  /// @brief The numerator widened to twice the operand width, so the same
  /// shift cannot lose its top bits.
  CudaRadixCiphertextFFI wide_n;
  /// @brief Leading-zero count of the denominator, counter_blocks.
  CudaRadixCiphertextFFI leading_zeros;
  /// @brief leading_zeros zero-extended to the width of the value it shifts.
  CudaRadixCiphertextFFI shift_amount;
  /// @brief Boolean block set when the denominator is zero.
  CudaRadixCiphertextFFI d_is_zero;

  /// @brief The seed factor x0 read from the table.
  CudaRadixCiphertextFFI seed_factor;
  /// @brief Match flag of the table lookup; unused but required by it.
  CudaRadixCiphertextFFI seed_found;
  /// @brief 1 - d at full fixed-point width; each round's x is a window into
  /// it.
  CudaRadixCiphertextFFI factor_x;

  /// @brief Integer part of the fixed-point quotient, before correction.
  CudaRadixCiphertextFFI quotient_tmp;
  /// @brief [bitnot(numerator) | trivial one], the mul-low's two addends.
  CudaRadixCiphertextFFI extra_terms;
  /// @brief q * d + bitnot(n) + 1 = q * d - n, carries left unpropagated.
  CudaRadixCiphertextFFI term_sum;
  /// @brief [!message | !carry] of term_sum.
  CudaRadixCiphertextFFI inverted;
  /// @brief The !carry half moved up one block, as the carries weigh.
  CudaRadixCiphertextFFI carry_shifted;
  /// @brief r = n - q * d, recovered from the inverted halves.
  CudaRadixCiphertextFFI remainder_tmp;
  /// @brief Borrow out of r - d: set when r did not reach d.
  CudaRadixCiphertextFFI overflow_block;
  /// @brief [q | r], the branch kept when q is already exact. Reused
  /// afterwards as the division-by-zero branch.
  CudaRadixCiphertextFFI no_correction;
  /// @brief [q + 1 | r - d] for the correction cmux, then the function's
  /// final output.
  CudaRadixCiphertextFFI final_result;
  /// @brief Output of the r < d correction cmux, before the division-by-zero
  /// decision.
  CudaRadixCiphertextFFI correction_output;
  /// @brief Trivial 1 at operand width.
  CudaRadixCiphertextFFI trivial_one;
  /// @brief Trivial 2 at operand width.
  CudaRadixCiphertextFFI trivial_two;
  /// @brief Trivial all-ones, the quotient of a division by zero.
  CudaRadixCiphertextFFI trivial_max;

  /// @brief Seed table inputs: 512 entries of x0_blocks base-beta digits.
  uint64_t *h_lut_inputs;
  /// @brief Seed table outputs, packed two base-beta digits per block.
  uint64_t *h_lut_outputs;
  /// @brief All-zero scalar the denominator is compared against, on device.
  Torus *d_zero_scalar;

  /// @brief Scratch for the leading-zero count of the denominator.
  int_count_of_consecutive_bits_buffer<Torus> *leading_zeros_mem;
  /// @brief Scratch for the denominator == 0 check.
  int_comparison_buffer<Torus> *is_zero_mem;
  /// @brief Shifter for the denominator, at operand width.
  int_shift_and_rotate_buffer<Torus> *shift_d_mem;
  /// @brief Shifter for the widened numerator, at twice the operand width.
  int_shift_and_rotate_buffer<Torus> *shift_n_mem;
  /// @brief Scratch for the seed table lookup.
  int_unchecked_match_buffer<Torus> *seed_lut_mem;
  /// @brief One multiply-add per shape: the seed step plus the three rounds.
  /// Each is used twice (numerator and denominator) except the last, which
  /// only updates the numerator.
  int_mul_add_fixed_point_memory<Torus>
      *mul_add_mem[1 + GOLDSCHMIDT_ITERATIONS];
  /// @brief Mul-low computing q * d plus the two addends of extra_terms.
  int_mul_add_fixed_point_memory<Torus> *mul_low_mem;
  /// @brief {!message, !carry} LUTs applied to the two halves of inverted.
  int_radix_lut<Torus> *invert_lut;
  /// @brief Carry propagation at operand width.
  int_sc_prop_memory<Torus> *sc_prop_mem;
  /// @brief Carry propagation for the negation that produces x, at
  /// fixed-point width.
  int_sc_prop_memory<Torus> *sc_prop_fp_mem;
  /// @brief Borrow propagation for r - d.
  int_borrow_prop_memory<Torus> *borrow_mem;
  /// @brief Cmux over [q | r] pairs, shared by both final selections.
  int_cmux_buffer<Torus> *cmux_mem;

  int_goldschmidt_division_buffer(CudaStreams streams, int_radix_params params,
                                  uint32_t num_blocks, uint32_t iterations,
                                  uint32_t lut_precision,
                                  bool allocate_gpu_memory,
                                  uint64_t &size_tracker) {
    this->params = params;
    this->gpu_memory_allocated = allocate_gpu_memory;
    this->num_blocks = num_blocks;

    auto message_modulus = params.message_modulus;
    uint32_t bits_per_block = log2_int(message_modulus);

    // The schedule below is tabulated for a 2-bit block, a 9-bit seed and three
    // rounds; nothing else has a correctness proof behind it.
    PANIC_IF_FALSE(bits_per_block == 2,
                   "Cuda error (goldschmidt division): only 2 bits per block "
                   "are supported");
    PANIC_IF_FALSE(iterations == GOLDSCHMIDT_ITERATIONS,
                   "Cuda error (goldschmidt division): only 3 iterations are "
                   "supported");
    PANIC_IF_FALSE(lut_precision == GOLDSCHMIDT_LUT_PRECISION,
                   "Cuda error (goldschmidt division): only a 9-bit seed is "
                   "supported");
    PANIC_IF_FALSE(num_blocks * bits_per_block == 64,
                   "Cuda error (goldschmidt division): only 64-bit operands "
                   "are supported");

    this->fp_blocks = num_blocks + 2;
    this->x0_blocks = (lut_precision + 1) / bits_per_block;
    this->counter_blocks = ((uint32_t)std::log2(num_blocks * bits_per_block) +
                            1 + bits_per_block - 1) /
                           bits_per_block;

    uint32_t schedule_x_blocks[GOLDSCHMIDT_ITERATIONS] = {5, 9, 16};
    uint32_t schedule_x_zero_blocks[GOLDSCHMIDT_ITERATIONS] = {4, 8, 16};
    std::memcpy(x_blocks, schedule_x_blocks, sizeof(schedule_x_blocks));
    std::memcpy(x_zero_blocks, schedule_x_zero_blocks,
                sizeof(schedule_x_zero_blocks));

    auto new_ct = [&](CudaRadixCiphertextFFI &ct, uint32_t blocks) {
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &ct, blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
    };

    new_ct(current_n, fp_blocks);
    new_ct(current_d, fp_blocks);
    new_ct(next_n, fp_blocks);
    new_ct(next_d, fp_blocks);
    new_ct(shifted_d, num_blocks);
    new_ct(wide_n, 2 * num_blocks);
    new_ct(leading_zeros, counter_blocks);
    new_ct(shift_amount, 2 * num_blocks);
    new_ct(d_is_zero, 1);
    new_ct(seed_factor, x0_blocks);
    new_ct(seed_found, 1);
    new_ct(factor_x, fp_blocks);
    new_ct(quotient_tmp, num_blocks);
    new_ct(extra_terms, 2 * num_blocks);
    new_ct(term_sum, num_blocks);
    new_ct(inverted, 2 * num_blocks);
    new_ct(carry_shifted, num_blocks);
    new_ct(remainder_tmp, num_blocks);
    new_ct(overflow_block, 1);
    new_ct(no_correction, 2 * num_blocks);
    new_ct(final_result, 2 * num_blocks);
    new_ct(correction_output, 2 * num_blocks);
    new_ct(trivial_one, num_blocks);
    new_ct(trivial_two, num_blocks);
    new_ct(trivial_max, num_blocks);

    if (allocate_gpu_memory) {
      set_single_scalar_trivial_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &trivial_one, 1,
          message_modulus, params.carry_modulus);
      set_single_scalar_trivial_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &trivial_two, 2,
          message_modulus, params.carry_modulus);
      // All blocks at message_modulus - 1, i.e. the all-ones quotient a
      // division by zero returns.
      std::vector<Torus> h_max(num_blocks, message_modulus - 1);
      Torus *d_max = (Torus *)cuda_malloc_with_size_tracking_async(
          safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
          streams.gpu_index(0), size_tracker, allocate_gpu_memory);
      cuda_memcpy_async_to_gpu(d_max, h_max.data(),
                               safe_mul_sizeof<Torus>(num_blocks),
                               streams.stream(0), streams.gpu_index(0));
      set_trivial_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &trivial_max, d_max,
          h_max.data(), num_blocks, message_modulus, params.carry_modulus);
      cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
      cuda_drop_with_size_tracking_async(
          d_max, streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
    }

    // The scalar the denominator is compared against, all-zero blocks.
    d_zero_scalar = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(num_blocks), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    if (allocate_gpu_memory)
      cuda_memset_with_size_tracking_async(
          d_zero_scalar, 0, safe_mul_sizeof<Torus>(num_blocks),
          streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);

    leading_zeros_mem = new int_count_of_consecutive_bits_buffer<Torus>(
        streams, params, num_blocks, counter_blocks, Leading, Zero,
        allocate_gpu_memory, size_tracker);
    is_zero_mem = new int_comparison_buffer<Torus>(
        streams, COMPARISON_TYPE::EQ, params, num_blocks, false,
        allocate_gpu_memory, size_tracker);
    // Two shifters: the denominator stays at operand width, the numerator is
    // widened first so that shifting it left cannot lose its top bits.
    shift_d_mem = new int_shift_and_rotate_buffer<Torus>(
        streams, LEFT_SHIFT, false, params, num_blocks, allocate_gpu_memory,
        size_tracker);
    shift_n_mem = new int_shift_and_rotate_buffer<Torus>(
        streams, LEFT_SHIFT, false, params, 2 * num_blocks, allocate_gpu_memory,
        size_tracker);

    // Seed table: for d's top (lut_precision + 1) bits, x0 such that
    // (1 + x0) * d < 1 and 1 + x0 approximates 1/d to lut_precision bits.
    // Outputs are packed two base-beta digits to a block, which is the format
    // the one-hot aggregation reduces in.
    uint32_t num_matches = 1u << lut_precision;
    uint32_t packed_blocks = (x0_blocks + 1) / 2;
    h_lut_inputs = new uint64_t[(size_t)num_matches * x0_blocks];
    h_lut_outputs = new uint64_t[(size_t)num_matches * packed_blocks];
    uint32_t bits_per_packed = 2 * bits_per_block;
    uint64_t packed_mask = (1ull << bits_per_packed) - 1;
    for (uint32_t i = 0; i < num_matches; i++) {
      uint64_t input = (1ull << lut_precision) + i;
      uint64_t output = ((1ull << (2 + 2 * lut_precision)) / (input + 1)) -
                        (1ull << (lut_precision + 1));
      for (uint32_t b = 0; b < x0_blocks; b++)
        h_lut_inputs[(size_t)i * x0_blocks + b] =
            (input >> (b * bits_per_block)) & (message_modulus - 1);
      for (uint32_t b = 0; b < packed_blocks; b++)
        h_lut_outputs[(size_t)i * packed_blocks + b] =
            (output >> (b * bits_per_packed)) & packed_mask;
    }
    seed_lut_mem = new int_unchecked_match_buffer<Torus>(
        streams, params, num_matches, x0_blocks, packed_blocks, false,
        allocate_gpu_memory, size_tracker);

    // One multiplication buffer per shape. The seed multiplies by x0 with no
    // rescaling; round i rescales by x's leading zero blocks and truncates
    // everything below one ulp of a beta^-t output.
    mul_add_mem[0] = new int_mul_add_fixed_point_memory<Torus>(
        streams, params, MUL_ADD_MODE_FIXED_POINT, fp_blocks, x0_blocks, 0,
        bits_per_block * x0_blocks, 0, allocate_gpu_memory, size_tracker);
    for (uint32_t i = 0; i < iterations; i++) {
      uint32_t t = x_zero_blocks[i] + x_blocks[i];
      mul_add_mem[1 + i] = new int_mul_add_fixed_point_memory<Torus>(
          streams, params, MUL_ADD_MODE_FIXED_POINT, fp_blocks, x_blocks[i],
          x_zero_blocks[i], bits_per_block * t, 0, allocate_gpu_memory,
          size_tracker);
    }
    // The remainder needs q * d plus two addends, and keeps the carries so the
    // message/carry inversion below can negate the sum in place.
    mul_low_mem = new int_mul_add_fixed_point_memory<Torus>(
        streams, params, MUL_ADD_MODE_MUL_LOW, num_blocks, num_blocks, 0, 0, 2,
        allocate_gpu_memory, size_tracker);

    // r = -(q*d - n) is built from the term sum's own blocks: with
    // sum = M + C (message halves plus carry halves shifted up one block),
    // -sum = (!M + 1) + (!C + 1) = !M + !C + 2.
    invert_lut = new int_radix_lut<Torus>(streams, params, 2, 2 * num_blocks,
                                          allocate_gpu_memory, size_tracker);
    auto invert_message_f = [message_modulus](Torus x) -> Torus {
      return (message_modulus - 1) - (x % message_modulus);
    };
    auto invert_carry_f = [message_modulus](Torus x) -> Torus {
      return (message_modulus - 1) - ((x / message_modulus) % message_modulus);
    };
    auto blocks = num_blocks;
    auto invert_index_generator = [blocks](Torus *h_lut_indexes,
                                           uint32_t num_indexes) {
      for (uint32_t i = 0; i < num_indexes; i++)
        h_lut_indexes[i] = (i < blocks) ? 0 : 1;
    };
    auto active_streams =
        streams.active_gpu_subset(2 * num_blocks, params.pbs_type);
    invert_lut->generate_and_broadcast_lut(active_streams, {0, 1},
                                           {invert_message_f, invert_carry_f},
                                           invert_index_generator);

    sc_prop_mem = new int_sc_prop_memory<Torus>(
        streams, params, num_blocks, outputFlag::FLAG_NONE, allocate_gpu_memory,
        size_tracker);
    sc_prop_fp_mem = new int_sc_prop_memory<Torus>(
        streams, params, fp_blocks, outputFlag::FLAG_NONE, allocate_gpu_memory,
        size_tracker);
    borrow_mem = new int_borrow_prop_memory<Torus>(
        streams, params, num_blocks, outputFlag::FLAG_OVERFLOW,
        allocate_gpu_memory, size_tracker);
    std::function<Torus(Torus)> cmux_predicate_f = [](Torus x) -> Torus {
      return x == 1;
    };
    cmux_mem = new int_cmux_buffer<Torus>(streams, cmux_predicate_f, params,
                                          2 * num_blocks, allocate_gpu_memory,
                                          size_tracker);
  }

  void release(CudaStreams streams) {
    auto drop_ct = [&](CudaRadixCiphertextFFI &ct) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &ct, gpu_memory_allocated);
    };
    drop_ct(current_n);
    drop_ct(current_d);
    drop_ct(next_n);
    drop_ct(next_d);
    drop_ct(shifted_d);
    drop_ct(wide_n);
    drop_ct(leading_zeros);
    drop_ct(shift_amount);
    drop_ct(d_is_zero);
    drop_ct(seed_factor);
    drop_ct(seed_found);
    drop_ct(factor_x);
    drop_ct(quotient_tmp);
    drop_ct(extra_terms);
    drop_ct(term_sum);
    drop_ct(inverted);
    drop_ct(carry_shifted);
    drop_ct(remainder_tmp);
    drop_ct(overflow_block);
    drop_ct(no_correction);
    drop_ct(final_result);
    drop_ct(correction_output);
    drop_ct(trivial_one);
    drop_ct(trivial_two);
    drop_ct(trivial_max);

    cuda_drop_with_size_tracking_async(d_zero_scalar, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);

    leading_zeros_mem->release(streams);
    is_zero_mem->release(streams);
    shift_d_mem->release(streams);
    shift_n_mem->release(streams);
    seed_lut_mem->release(streams);
    for (uint32_t i = 0; i < 1 + GOLDSCHMIDT_ITERATIONS; i++) {
      mul_add_mem[i]->release(streams);
      delete mul_add_mem[i];
    }
    mul_low_mem->release(streams);
    invert_lut->release(streams);
    sc_prop_mem->release(streams);
    sc_prop_fp_mem->release(streams);
    borrow_mem->release(streams);
    cmux_mem->release(streams);

    delete leading_zeros_mem;
    delete is_zero_mem;
    delete shift_d_mem;
    delete shift_n_mem;
    delete seed_lut_mem;
    delete mul_low_mem;
    delete invert_lut;
    delete sc_prop_mem;
    delete sc_prop_fp_mem;
    delete borrow_mem;
    delete cmux_mem;
    delete[] h_lut_inputs;
    delete[] h_lut_outputs;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
