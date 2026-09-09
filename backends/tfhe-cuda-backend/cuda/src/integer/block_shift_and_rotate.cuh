#ifndef CUDA_INTEGER_BLOCK_SHIFT_AND_ROTATE_CUH
#define CUDA_INTEGER_BLOCK_SHIFT_AND_ROTATE_CUH

#include "device.h"
#include "integer.cuh"
#include "integer/block_shift_and_rotate.h"

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
 * This costs about half the PBS of the bit-level barrel shifter; see
 * int_shift_and_rotate_buffer::use_block_path for when it is selected.
 *
 * Only the rounds live here. The result is left in mem->messages, uncleaned,
 * and host_shift_and_rotate_inplace finishes it with the one PBS both paths
 * share: the cleaning LUT for a rotation, the overshift selection for a shift.
 * For an arithmetic right shift the input's sign bit is left in
 * mem->sign_block, which that overshift selection reads.
 *
 * @param lwe_array Value to shift; read only, the caller writes the result.
 * @param lwe_shift Encrypted shift amount, same block count as lwe_array.
 * @param mem Scratch holding the block-path buffers and LUTs.
 */
template <typename Torus, typename KSTorus>
__host__ void
host_block_shift_and_rotate(CudaStreams streams,
                            CudaRadixCiphertextFFI const *lwe_array,
                            CudaRadixCiphertextFFI const *lwe_shift,
                            int_shift_and_rotate_by_block_buffer<Torus> *mem,
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
  // An arithmetic shift is a right shift of a signed value: the bits entering
  // at the top are copies of the sign bit instead of zeros, so the result
  // keeps the input's sign (-8 >> 1 is -4, not a large positive). A left shift
  // is never arithmetic, and a rotation loses nothing so it never pads at all.
  bool arithmetic = mem->is_signed && (mem->shift_type == RIGHT_SHIFT);

  // The shift amount is encrypted, so nothing stops it from being larger
  // than the width of the value being shifted. That case is called an
  // overshift, and the caller corrects it once, after all the rounds. What the
  // correct answer is depends on the sign: shifting a negative value right
  // past its own width leaves nothing but sign bits, which is -1, whereas a
  // positive value leaves 0.
  //
  // So extract that sign bit -- the MSB of the top block -- into a one-block
  // ciphertext for host_compute_overshift_condition to consume at the very
  // end. It is read straight from the unshifted input.
  if (arithmetic) {
    CudaRadixCiphertextFFI top_block;
    as_radix_ciphertext_slice<Torus>(&top_block, lwe_array, num_blocks - 1,
                                     num_blocks);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, &mem->sign_block, &top_block, bsks, ksks, mem->sign_lut, 1);
  }

  // first round
  // The three LUTs share the same bivariate input, so pack it once.
  CudaRadixCiphertextFFI amount_block_0;
  as_radix_ciphertext_slice<Torus>(&amount_block_0, lwe_shift, 0, 1);

  auto packed = &mem->pack_tmp;
  host_pack_bivariate_blocks_with_single_block<Torus>(
      streams, packed, mem->msg_lut->lwe_indexes_in, lwe_array, &amount_block_0,
      mem->msg_lut->lwe_indexes_in, message_modulus, num_blocks,
      message_modulus, carry_modulus);

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &mem->messages, packed, bsks, ksks, mem->msg_lut, num_blocks);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &mem->next, packed, bsks, ksks, mem->next_lut, num_blocks);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &mem->next_next, packed, bsks, ksks, mem->next_next_lut,
      num_blocks);

  // Moves a donor array `rotations` blocks along and accumulates it into the
  // result. Blocks are little endian, so a left shift of the value moves
  // blocks towards higher indexes. The slots that wrap around are dropped for
  // a shift; the sign extension of an arithmetic right shift is already applied
  // into the LUTs of this round.
  auto accumulate_donor = [&](CudaRadixCiphertextFFI *donor,
                              uint32_t rotations) {
    if (is_left)
      host_radix_blocks_rotate_right<Torus>(streams, &mem->rotate_tmp, donor,
                                            rotations, num_blocks);
    else
      host_radix_blocks_rotate_left<Torus>(streams, &mem->rotate_tmp, donor,
                                           rotations, num_blocks);
    if (!is_rotate) {
      uint32_t start = is_left ? 0 : num_blocks - rotations;
      uint32_t end = is_left ? rotations : num_blocks;
      set_zero_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, &mem->rotate_tmp, start, end);
    }
    host_addition<Torus>(stream, gpu_index, &mem->messages, &mem->messages,
                         &mem->rotate_tmp, num_blocks, message_modulus,
                         carry_modulus);
  };
  accumulate_donor(&mem->next, 1);
  accumulate_donor(&mem->next_next, 2);
  // At most one of the three contributions is non-zero for a given block, so
  // the sum still fits in the message space.
  for (uint32_t i = 0; i < num_blocks; i++)
    mem->messages.degrees[i] = message_modulus - 1;

  if (mem->num_rounds > 0) {
    if (arithmetic) {
      // Every round's padding is derived from the sign, and the sign is
      // always the MSB of the top block: the first round's sign-extended LUT
      // put it there, and each round below shifts sign bits into the top
      // block, so that MSB never changes.
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, &mem->saved_top_block, 0, 1, &mem->messages,
          num_blocks - 1, num_blocks);
    }

    // Bits 0..1 of the amount were spent by the first round, so the rounds
    // read theirs from amount block 1 onwards.
    CudaRadixCiphertextFFI amount_high;
    as_radix_ciphertext_slice<Torus>(&amount_high, lwe_shift, 1,
                                     1 + mem->num_amount_blocks);
    extract_n_bits<Torus>(streams, &mem->shift_bits, &amount_high, bsks, ksks,
                          mem->num_rounds, mem->num_amount_blocks,
                          mem->shift_bit_extract_luts);
  }

  for (uint32_t d = 1; d <= mem->num_rounds; d++) {
    CudaRadixCiphertextFFI shift_bit;
    as_radix_ciphertext_slice<Torus>(&shift_bit, &mem->shift_bits, d - 1, d);

    if (arithmetic) {
      // Rebuild the padding for this round: a block whose bits are
      // all copies of the sign. It is gated on this round's shift bit, so a
      // round whose bit is 0 shifts nothing and contributes a zero padding
      // block. The LUT reads the sign from the saved top block and the gate
      // from the shift bit, which already sits on the control position, so
      // the two can simply be added together first.
      host_addition<Torus>(stream, gpu_index, &mem->padding_block_in,
                           &mem->saved_top_block, &shift_bit, 1,
                           message_modulus, carry_modulus);
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, &mem->padding_block, &mem->padding_block_in, bsks, ksks,
          mem->padding_lut, 1);
    }

    // The shift bit sits on the control position, so a single many-LUT splits
    // every block into "what it keeps" and "what it hands over".
    host_add_the_same_block_to_all_blocks<Torus>(
        stream, gpu_index, &mem->messages, &mem->messages, &shift_bit,
        message_modulus, carry_modulus);
    integer_radix_apply_many_univariate_lookup_table<Torus>(
        streams, &mem->many_out, &mem->messages, bsks, ksks, mem->round_lut, 2,
        mem->lut_stride);

    copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, &mem->messages,
                                             0, num_blocks, &mem->many_out, 0,
                                             num_blocks);
    CudaRadixCiphertextFFI carries;
    as_radix_ciphertext_slice<Torus>(&carries, &mem->many_out, num_blocks,
                                     2 * num_blocks);

    uint32_t rotations = 1u << d;
    if (is_left)
      host_radix_blocks_rotate_right<Torus>(streams, &mem->rotate_tmp, &carries,
                                            rotations, num_blocks);
    else
      host_radix_blocks_rotate_left<Torus>(streams, &mem->rotate_tmp, &carries,
                                           rotations, num_blocks);

    if (!is_rotate) {
      uint32_t start = is_left ? 0 : num_blocks - rotations;
      uint32_t end = is_left ? rotations : num_blocks;
      if (arithmetic) {
        // An arithmetic one refills them with sign
        // bits, which is what sign-extends the vacated high end.
        for (uint32_t i = start; i < end; i++)
          copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index,
                                                   &mem->rotate_tmp, i, i + 1,
                                                   &mem->padding_block, 0, 1);
      } else {
        set_zero_radix_ciphertext_slice_async<Torus>(
            stream, gpu_index, &mem->rotate_tmp, start, end);
      }
    }

    host_addition<Torus>(stream, gpu_index, &mem->messages, &mem->messages,
                         &mem->rotate_tmp, num_blocks, message_modulus,
                         carry_modulus);
    for (uint32_t i = 0; i < num_blocks; i++)
      mem->messages.degrees[i] = message_modulus - 1;
  }
}
#endif
