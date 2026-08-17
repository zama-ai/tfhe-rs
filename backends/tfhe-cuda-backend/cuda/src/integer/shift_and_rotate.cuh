#ifndef CUDA_INTEGER_SHIFT_OPS_CUH
#define CUDA_INTEGER_SHIFT_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/scalar_comparison.cuh"
#include "integer/shift_and_rotate.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "scalar_mul.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_shift_and_rotate(
    CudaStreams streams, int_shift_and_rotate_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_shift_and_rotate_buffer<Torus>(
      streams, shift_type, is_signed, params, num_radix_blocks,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/**
 * @brief Computes the overshift condition (shift_amount >= total_nb_bits) and
 * packs it into the carry of mem->tmp_overshift, so it can later be fused into
 * the final cleaning PBS of the reassembly at no extra per-block PBS cost. For
 * an arithmetic right shift the condition also encodes the input's sign.
 * @param lwe_shift Encrypted shift amount to compare against the bit width.
 * @param last_bit Input's original sign bit, used for the arithmetic case.
 * @param mem Scratch buffer holding the comparison memory, scalar and LUTs.
 */
template <typename Torus, typename KSTorus>
__host__ void
host_compute_overshift_condition(CudaStreams streams,
                                 CudaRadixCiphertextFFI const *lwe_shift,
                                 CudaRadixCiphertextFFI const *last_bit,
                                 int_shift_and_rotate_buffer<Torus> *mem,
                                 void *const *bsks, KSTorus *const *ksks) {
  auto message_modulus = mem->params.message_modulus;
  auto carry_modulus = mem->params.carry_modulus;

  auto num_radix_blocks = lwe_shift->num_radix_blocks;
  CudaRadixCiphertextFFI const *compare_in;
  if (mem->tmp_padded_shift != nullptr) {
    // Pad the shift amount to an even number of blocks (high block is 0).
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem->tmp_padded_shift, 0,
        mem->tmp_padded_shift->num_radix_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem->tmp_padded_shift, 0,
        num_radix_blocks, lwe_shift, 0, num_radix_blocks);
    compare_in = mem->tmp_padded_shift;
  } else {
    compare_in = lwe_shift;
  }
  integer_radix_unsigned_scalar_difference_check<Torus>(
      streams, mem->tmp_overshift, compare_in, mem->d_overshift_scalar_blocks,
      mem->h_overshift_scalar_blocks, mem->overshift_compare_mem,
      mem->overshift_compare_mem->diff_buffer->operator_f, bsks, ksks,
      mem->overshift_compare_num_blocks, mem->num_overshift_scalar_blocks);

  if (mem->is_signed && (mem->shift_type == RIGHT_SHIFT)) {
    // cond = 2 * overshift + is_neg, where is_neg is the input's sign bit
    // (`last_bit`, still the original sign bit since the loop reads a copy).
    host_integer_small_scalar_mul_radix<Torus>(streams, mem->tmp_overshift,
                                               mem->tmp_overshift, 2,
                                               message_modulus, carry_modulus);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                         mem->tmp_overshift, mem->tmp_overshift, last_bit, 1,
                         message_modulus, carry_modulus);
  }
  // Move cond into the carry space (clean output).
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->tmp_overshift, mem->tmp_overshift, bsks, ksks,
      mem->overshift_pack_lut, 1);
}

/**
 * @brief Applies the overshift selection: adds the packed condition from
 * mem->tmp_overshift to every block and runs the overshift cleanup LUT, which
 * both refreshes the noise and selects the overshift result (0 / the sign) in a
 * single PBS.
 * @param output Destination of the selection; may alias shifted_ct.
 * @param shifted_ct Shift result, updated in place by the condition addition.
 * @param mem Scratch buffer holding tmp_overshift and the cleanup LUT.
 */
template <typename Torus, typename KSTorus>
__host__ void host_apply_overshift_cleanup(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI *shifted_ct, int_shift_and_rotate_buffer<Torus> *mem,
    void *const *bsks, KSTorus *const *ksks) {
  auto num_radix_blocks = output->num_radix_blocks;
  host_add_the_same_block_to_all_blocks<Torus>(
      streams.stream(0), streams.gpu_index(0), shifted_ct, shifted_ct,
      mem->tmp_overshift, mem->params.message_modulus,
      mem->params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, output, shifted_ct, bsks, ksks, mem->overshift_cleanup_lut,
      num_radix_blocks);
}

/**
 * @brief Block-level barrel shifter: shift/rotate by an encrypted amount
 * without ever splitting the ciphertext into one-bit ciphertexts.
 *
 * Writing the amount as `2*t + s + 4*rest` (for 2 message bits per block), the
 * first round consumes `s` (the shift inside a block) and `t` (a shift by one
 * block) at once with three bivariate LUTs, and the remaining rounds form a
 * barrel shifter over blocks, each shifting by `1 << d` blocks.
 *
 * First round, for a left shift. Three bivariate LUTs read every block
 * together with amount block 0, producing what each block keeps and what it
 * hands over; the donor arrays are then rotated into place and summed. Only
 * one of the three terms is non-zero for a given block, which is what keeps
 * the sum inside the message space.
 *
 *      input       b0        b1        b2        b3
 *                  |         |         |         |
 *      msg        m0        m1        m2        m3         stays in place
 *      next       n0 -.     n1 -.     n2 -.     n3 -x      +1 block
 *      next_next  p0 --.    p1 --.    p2 -x     p3 -x      +2 blocks
 *                      |         |         |         |
 *      result     m0   m1+n0   m2+n1+p0  m3+n2+p1
 *                      (n3, p2, p3 wrapped: dropped for a shift,
 *                       kept for a rotation)
 *
 * Then, for d = 1 .. num_rounds, one many-LUT per block splits it into
 * (message kept, carry handed `1 << d` blocks away), selected by that round's
 * shift bit.
 *
 * This costs about half the PBS of host_shift_and_rotate_inplace; see
 * int_shift_and_rotate_buffer::use_block_path for when it is selected.
 *
 * @param lwe_array Value to shift, overwritten with the result.
 * @param lwe_shift Encrypted shift amount, same block count as lwe_array.
 */
template <typename Torus, typename KSTorus>
__host__ void
host_block_shift_and_rotate_inplace(CudaStreams streams,
                                    CudaRadixCiphertextFFI *lwe_array,
                                    CudaRadixCiphertextFFI const *lwe_shift,
                                    int_shift_and_rotate_buffer<Torus> *mem,
                                    void *const *bsks, KSTorus *const *ksks) {
  cuda_set_device(streams.gpu_index(0));
  auto params = mem->params;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;
  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  uint32_t bits_per_block = log2_int(message_modulus);
  auto num_blocks = lwe_array->num_radix_blocks;

  if (lwe_array->num_radix_blocks != lwe_shift->num_radix_blocks)
    PANIC("Cuda error: lwe_shift and lwe_array num radix blocks must be "
          "the same")
  if (lwe_array->lwe_dimension != lwe_shift->lwe_dimension)
    PANIC("Cuda error: lwe_shift and lwe_array lwe_dimension must be "
          "the same")

  bool is_left =
      (mem->shift_type == LEFT_SHIFT || mem->shift_type == LEFT_ROTATE);
  bool is_rotate =
      (mem->shift_type == LEFT_ROTATE || mem->shift_type == RIGHT_ROTATE);
  // Only a right shift of a signed value pads with the sign instead of zeros.
  bool arithmetic = mem->is_signed && (mem->shift_type == RIGHT_SHIFT);

  // The input's sign bit feeds the overshift condition, so read it before
  // lwe_array is overwritten.
  if (arithmetic) {
    CudaRadixCiphertextFFI top_block;
    as_radix_ciphertext_slice<Torus>(&top_block, lwe_array, num_blocks - 1,
                                     num_blocks);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, mem->blk_sign, &top_block, bsks, ksks, mem->blk_sign_lut, 1);
  }

  // ---- first round ----
  // The three LUTs share the same bivariate input, so pack it once.
  CudaRadixCiphertextFFI amount_block_0;
  as_radix_ciphertext_slice<Torus>(&amount_block_0, lwe_shift, 0, 1);

  auto packed = mem->blk_pack_tmp;
  host_pack_bivariate_blocks_with_single_block<Torus>(
      streams, packed, mem->blk_msg_lut->lwe_indexes_in, lwe_array,
      &amount_block_0, mem->blk_msg_lut->lwe_indexes_in, message_modulus,
      num_blocks);
  for (uint32_t i = 0; i < num_blocks; i++) {
    packed->degrees[i] =
        lwe_array->degrees[i] * message_modulus + amount_block_0.degrees[0];
    packed->noise_levels[i] = lwe_array->noise_levels[i] * message_modulus +
                              amount_block_0.noise_levels[0];
    CHECK_NOISE_LEVEL(packed->noise_levels[i], message_modulus, carry_modulus);
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->blk_messages, packed, bsks, ksks, mem->blk_msg_lut,
      num_blocks);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->blk_next, packed, bsks, ksks, mem->blk_next_lut,
      num_blocks);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->blk_next_next, packed, bsks, ksks, mem->blk_next_next_lut,
      num_blocks);

  // Moves a donor array `rotations` blocks along and accumulates it into the
  // result. Blocks are little endian, so a left shift of the value moves
  // blocks towards higher indexes. The slots that wrap around are dropped for
  // a shift; the sign extension of an arithmetic right shift is already baked
  // into the LUTs of this round.
  auto accumulate_donor = [&](CudaRadixCiphertextFFI *donor,
                              uint32_t rotations) {
    if (is_left)
      host_radix_blocks_rotate_right<Torus>(streams, mem->blk_rotate_tmp, donor,
                                            rotations, num_blocks);
    else
      host_radix_blocks_rotate_left<Torus>(streams, mem->blk_rotate_tmp, donor,
                                           rotations, num_blocks);
    if (!is_rotate) {
      uint32_t start = is_left ? 0 : num_blocks - rotations;
      uint32_t end = is_left ? rotations : num_blocks;
      set_zero_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, mem->blk_rotate_tmp, start, end);
    }
    host_addition<Torus>(stream, gpu_index, mem->blk_messages,
                         mem->blk_messages, mem->blk_rotate_tmp, num_blocks,
                         message_modulus, carry_modulus);
  };
  accumulate_donor(mem->blk_next, 1);
  accumulate_donor(mem->blk_next_next, 2);
  // At most one of the three contributions is non-zero for a given block, so
  // the sum still fits in the message space.
  for (uint32_t i = 0; i < num_blocks; i++)
    mem->blk_messages->degrees[i] = message_modulus - 1;

  // ---- remaining barrel rounds ----
  if (mem->blk_num_rounds > 0) {
    if (arithmetic) {
      // The sign stays in the top block's MSB through every round, so this
      // copy is a valid sign source for all of them.
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, mem->blk_saved_top, 0, 1, mem->blk_messages,
          num_blocks - 1, num_blocks);
    }

    // Bits 0..1 of the amount were spent by the first round, so the rounds
    // read theirs from amount block 1 onwards.
    CudaRadixCiphertextFFI amount_high;
    as_radix_ciphertext_slice<Torus>(&amount_high, lwe_shift, 1,
                                     1 + mem->blk_num_amount_blocks);
    extract_n_bits<Torus>(streams, mem->blk_shift_bits, &amount_high, bsks,
                          ksks, mem->blk_num_rounds, mem->blk_num_amount_blocks,
                          mem->bit_extract_luts_with_offset_2);
  }

  for (uint32_t d = 1; d <= mem->blk_num_rounds; d++) {
    CudaRadixCiphertextFFI shift_bit;
    as_radix_ciphertext_slice<Torus>(&shift_bit, mem->blk_shift_bits, d - 1, d);

    if (arithmetic) {
      // Sign-extension block for this round: the sign repeated, or 0 when this
      // round does not shift.
      host_addition<Torus>(stream, gpu_index, mem->blk_padding_in,
                           mem->blk_saved_top, &shift_bit, 1, message_modulus,
                           carry_modulus);
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, mem->blk_padding, mem->blk_padding_in, bsks, ksks,
          mem->blk_padding_lut, 1);
    }

    // The shift bit sits on the control position, so a single many-LUT splits
    // every block into "what it keeps" and "what it hands over".
    host_add_the_same_block_to_all_blocks<Torus>(
        stream, gpu_index, mem->blk_messages, mem->blk_messages, &shift_bit,
        message_modulus, carry_modulus);
    integer_radix_apply_many_univariate_lookup_table<Torus>(
        streams, mem->blk_many_out, mem->blk_messages, bsks, ksks,
        mem->blk_round_lut, 2, mem->blk_lut_stride);

    copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index,
                                             mem->blk_messages, 0, num_blocks,
                                             mem->blk_many_out, 0, num_blocks);
    CudaRadixCiphertextFFI carries;
    as_radix_ciphertext_slice<Torus>(&carries, mem->blk_many_out, num_blocks,
                                     2 * num_blocks);

    uint32_t rotations = 1u << d;
    if (is_left)
      host_radix_blocks_rotate_right<Torus>(streams, mem->blk_rotate_tmp,
                                            &carries, rotations, num_blocks);
    else
      host_radix_blocks_rotate_left<Torus>(streams, mem->blk_rotate_tmp,
                                           &carries, rotations, num_blocks);

    if (!is_rotate) {
      uint32_t start = is_left ? 0 : num_blocks - rotations;
      uint32_t end = is_left ? rotations : num_blocks;
      if (arithmetic) {
        for (uint32_t i = start; i < end; i++)
          copy_radix_ciphertext_slice_async<Torus>(
              stream, gpu_index, mem->blk_rotate_tmp, i, i + 1,
              mem->blk_padding, 0, 1);
      } else {
        set_zero_radix_ciphertext_slice_async<Torus>(
            stream, gpu_index, mem->blk_rotate_tmp, start, end);
      }
    }

    host_addition<Torus>(stream, gpu_index, mem->blk_messages,
                         mem->blk_messages, mem->blk_rotate_tmp, num_blocks,
                         message_modulus, carry_modulus);
    for (uint32_t i = 0; i < num_blocks; i++)
      mem->blk_messages->degrees[i] = message_modulus - 1;
  }

  // ---- finalize ----
  // The result still carries the accumulated noise, so a cleaning PBS is due
  // anyway; for a shift it also applies the overshift selection for free.
  if (is_rotate) {
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, lwe_array, mem->blk_messages, bsks, ksks, mem->cleaning_lut,
        num_blocks);
  } else {
    host_compute_overshift_condition<Torus, KSTorus>(
        streams, lwe_shift, mem->blk_sign, mem, bsks, ksks);
    host_apply_overshift_cleanup<Torus, KSTorus>(
        streams, lwe_array, mem->blk_messages, mem, bsks, ksks);
  }
}

template <typename Torus, typename KSTorus>
__host__ void
host_shift_and_rotate_inplace(CudaStreams streams,
                              CudaRadixCiphertextFFI *lwe_array,
                              CudaRadixCiphertextFFI const *lwe_shift,
                              int_shift_and_rotate_buffer<Torus> *mem,
                              void *const *bsks, KSTorus *const *ksks) {
  if (mem->use_block_path) {
    host_block_shift_and_rotate_inplace<Torus, KSTorus>(
        streams, lwe_array, lwe_shift, mem, bsks, ksks);
    return;
  }
  cuda_set_device(streams.gpu_index(0));
  // The barrel shifter packs three bits (control | previous | current) into a
  // single block for the mux LUT, so it needs the control bit at plaintext
  // position 2 (value 4). This only fits when a block holds at least 3 bits.
  if (mem->params.message_modulus * mem->params.carry_modulus < 8)
    PANIC("Cuda error: shift/rotate by an encrypted amount requires "
          "message_modulus * carry_modulus >= 8 (1_1 parameters are not "
          "supported)")
  if (lwe_array->num_radix_blocks != lwe_shift->num_radix_blocks)
    PANIC("Cuda error: lwe_shift and lwe_array num radix blocks must be "
          "the same")

  if (lwe_array->lwe_dimension != lwe_shift->lwe_dimension)
    PANIC("Cuda error: lwe_shift and lwe_array lwe_dimension must be "
          "the same")

  auto num_radix_blocks = lwe_array->num_radix_blocks;

  uint32_t bits_per_block = log2_int(mem->params.message_modulus);
  uint32_t total_nb_bits = bits_per_block * num_radix_blocks;
  if (total_nb_bits == 0)
    return;

  auto big_lwe_dimension = mem->params.big_lwe_dimension;

  if (lwe_array->lwe_dimension != big_lwe_dimension)
    PANIC("Cuda error: lwe_shift lwe_dimension must be equal to "
          "big_lwe_dimension")

  // Extract all bits
  auto bits = mem->tmp_bits;
  extract_n_bits<Torus>(streams, bits, lwe_array, bsks, ksks,
                        num_radix_blocks * bits_per_block, num_radix_blocks,
                        mem->bit_extract_luts);

  // Extract shift bits
  auto shift_bits = mem->tmp_shift_bits;
  auto is_power_of_two = [](uint32_t n) {
    return (n > 0) && ((n & (n - 1)) == 0);
  };

  // This effectively means, that if the block parameters
  // give a total_nb_bits that is not a power of two,
  // then the behaviour of shifting won't be the same
  // if shift >= total_nb_bits compared to when total_nb_bits
  // is a power of two, as will 'capture' more bits in `shift_bits`
  uint32_t max_num_bits_that_tell_shift = log2_int(total_nb_bits);
  if (!is_power_of_two(total_nb_bits))
    max_num_bits_that_tell_shift += 1;
  // Extracts bits and put them in the bit index 2 (=> bit number 3)
  // so that it is already aligned to the correct position of the cmux input
  // and we reduce noise growth
  extract_n_bits<Torus>(streams, shift_bits, lwe_shift, bsks, ksks,
                        max_num_bits_that_tell_shift, num_radix_blocks,
                        mem->bit_extract_luts_with_offset_2);

  // If signed, do an "arithmetic shift" by padding with the sign bit
  CudaRadixCiphertextFFI last_bit;
  as_radix_ciphertext_slice<Torus>(&last_bit, bits, (total_nb_bits - 1),
                                   total_nb_bits);

  // Apply op
  auto rotated_input = mem->tmp_rotated;
  auto input_bits_a = mem->tmp_input_bits_a;
  auto input_bits_b = mem->tmp_input_bits_b;
  auto mux_lut = mem->mux_lut;
  auto mux_inputs = mem->tmp_mux_inputs;

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     input_bits_a, bits);
  for (int d = 0; d < max_num_bits_that_tell_shift; d++) {
    CudaRadixCiphertextFFI shift_bit;
    as_radix_ciphertext_slice<Torus>(&shift_bit, shift_bits, d, d + 1);

    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       input_bits_b, input_bits_a);
    auto rotations = 1 << d;
    switch (mem->shift_type) {
    case LEFT_SHIFT:
      // rotate right as the blocks are from LSB to MSB
      if (input_bits_b->num_radix_blocks != total_nb_bits)
        PANIC("Cuda error: incorrect number of blocks")
      host_radix_blocks_rotate_right<Torus>(
          streams, rotated_input, input_bits_b, rotations, total_nb_bits);

      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), rotated_input, 0, rotations);
      break;
    case RIGHT_SHIFT:
      // rotate left as the blocks are from LSB to MSB
      if (input_bits_b->num_radix_blocks != total_nb_bits)
        PANIC("Cuda error: incorrect number of blocks")
      host_radix_blocks_rotate_left<Torus>(streams, rotated_input, input_bits_b,
                                           rotations, total_nb_bits);

      if (mem->is_signed)
        for (int i = 0; i < rotations; i++) {
          copy_radix_ciphertext_slice_async<Torus>(
              streams.stream(0), streams.gpu_index(0), rotated_input,
              total_nb_bits - rotations + i, total_nb_bits - rotations + i + 1,
              &last_bit, 0, 1);
        }
      else {
        set_zero_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0), rotated_input,
            total_nb_bits - rotations, total_nb_bits);
      }
      break;
    case LEFT_ROTATE:
      // rotate right as the blocks are from LSB to MSB
      host_radix_blocks_rotate_right<Torus>(
          streams, rotated_input, input_bits_b, rotations, total_nb_bits);
      break;
    case RIGHT_ROTATE:
      // rotate left as the blocks are from LSB to MSB
      host_radix_blocks_rotate_left<Torus>(streams, rotated_input, input_bits_b,
                                           rotations, total_nb_bits);
      break;
    default:
      PANIC("Unknown operation")
    }

    // host_pack bits into one block so that we have
    // control_bit|b|a
    host_pack_bivariate_blocks<Torus>(
        streams, mux_inputs, mux_lut->lwe_indexes_out, rotated_input,
        input_bits_a, mux_lut->lwe_indexes_in, 2, total_nb_bits,
        mem->params.message_modulus, mem->params.carry_modulus);

    // The shift bit is already properly aligned/positioned
    host_add_the_same_block_to_all_blocks<Torus>(
        streams.stream(0), streams.gpu_index(0), mux_inputs, mux_inputs,
        &shift_bit, mem->params.message_modulus, mem->params.carry_modulus);

    // we have
    // control_bit|b|a
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, input_bits_a, mux_inputs, bsks, ksks, mux_lut, total_nb_bits);
  }

  if (mem->handle_overshift) {
    // lwe array number of blocks is the same as the shift amount number of
    // blocks
    host_compute_overshift_condition<Torus, KSTorus>(
        streams, lwe_shift, &last_bit, mem, bsks, ksks);
  }

  // Initializes the output
  // Copy the last bit for each radix block
  for (int i = 0; i < num_radix_blocks; i++) {
    auto last_bit_index = (bits_per_block - 1) + i * bits_per_block;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, i, i + 1,
        input_bits_a, last_bit_index, last_bit_index + 1);
  }

  // Bitshift and add the other bits
  for (int i = bits_per_block - 2; i >= 0; i--) {
    host_integer_small_scalar_mul_radix<Torus>(streams, lwe_array, lwe_array, 2,
                                               mem->params.message_modulus,
                                               mem->params.carry_modulus);
    for (int j = 0; j < num_radix_blocks; j++) {
      CudaRadixCiphertextFFI block;
      CudaRadixCiphertextFFI bit_to_add;
      as_radix_ciphertext_slice<Torus>(&block, lwe_array, j, j + 1);
      as_radix_ciphertext_slice<Torus>(&bit_to_add, input_bits_a,
                                       i + j * bits_per_block,
                                       i + j * bits_per_block + 1);
      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &block,
                           &block, &bit_to_add, 1, mem->params.message_modulus,
                           mem->params.carry_modulus);
    }

    // To give back a clean ciphertext.
    // For a shift (not a rotation), the final cleaning PBS also applies the
    // overshift selection: we add `cond` (packed in the carry) to every block
    // and use the overshift cleanup LUT, which both resets the noise and
    // selects the overshift result in a single PBS (no extra PBS round).
    if (i == 0 && mem->handle_overshift) {
      host_apply_overshift_cleanup<Torus, KSTorus>(streams, lwe_array,
                                                   lwe_array, mem, bsks, ksks);
    } else {
      auto cleaning_lut = mem->cleaning_lut;
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, lwe_array, lwe_array, bsks, ksks, cleaning_lut,
          num_radix_blocks);
    }
  }

  // 1-bit-message blocks: the reassembly loop above does not run, so the
  // overshift selection could not be fused into a cleaning PBS; apply it as a
  // standalone step instead.
  if (bits_per_block == 1 && mem->handle_overshift) {
    host_apply_overshift_cleanup<Torus, KSTorus>(streams, lwe_array, lwe_array,
                                                 mem, bsks, ksks);
  }
}
#endif
