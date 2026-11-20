#ifndef CUDA_INTEGER_SHIFT_OPS_CUH
#define CUDA_INTEGER_SHIFT_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/block_shift_and_rotate.cuh"
#include "integer/integer_utilities.h"
#include "integer/scalar_comparison.cuh"
#include "integer/scalar_div.cuh"
#include "integer/shift_and_rotate.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "scalar_mul.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_shift(CudaStreams streams,
                                     int_shift_buffer<Torus> **mem_ptr,
                                     uint32_t num_radix_blocks,
                                     int_radix_params params,
                                     SHIFT_OR_ROTATE_TYPE shift_type,
                                     bool is_signed, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_shift_buffer<Torus>(streams, shift_type, is_signed, params,
                                         num_radix_blocks, allocate_gpu_memory,
                                         size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ uint64_t
scratch_cuda_rotate(CudaStreams streams, int_rotate_buffer<Torus> **mem_ptr,
                    uint32_t num_radix_blocks, int_radix_params params,
                    SHIFT_OR_ROTATE_TYPE rotate_type,
                    const CudaScalarDivisorFFI *scalar_divisor_ffi,
                    uint32_t active_bits_divisor, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_rotate_buffer<Torus>(
      streams, rotate_type, params, num_radix_blocks, scalar_divisor_ffi,
      active_bits_divisor, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/**
 * @brief Checks the operands of a shift or rotation by an encrypted amount,
 * before anything reads them.
 *
 * @param lwe_array Value to shift or rotate.
 * @param lwe_shift Encrypted amount.
 */
template <typename Torus>
__host__ void
assert_barrel_shifter_operands(CudaRadixCiphertextFFI const *lwe_array,
                               CudaRadixCiphertextFFI const *lwe_shift,
                               int_barrel_shifter_buffer<Torus> *mem_ptr) {
  auto params = mem_ptr->params;
  // The mux of the bit-level shifter packs control | previous | current into
  // a single block, with the control bit at plaintext position 2. This only
  // fits when a block holds at least 3 bits.
  GPU_ASSERT(params.message_modulus * params.carry_modulus >= 8,
             "Cuda error: shift/rotate by an encrypted amount requires "
             "message_modulus * carry_modulus >= 8 (1_1 parameters are not "
             "supported)");
  GPU_ASSERT(lwe_array->num_radix_blocks == lwe_shift->num_radix_blocks,
             "Cuda error: lwe_shift and lwe_array num radix blocks must be "
             "the same");
  GPU_ASSERT(lwe_array->lwe_dimension == lwe_shift->lwe_dimension,
             "Cuda error: lwe_shift and lwe_array lwe_dimension must be "
             "the same");
  GPU_ASSERT(lwe_array->lwe_dimension == params.big_lwe_dimension,
             "Cuda error: lwe_array lwe_dimension must be equal to "
             "big_lwe_dimension");
}

/**
 * @brief Runs the rounds of the barrel shifter: round d moves the value by
 * 2^d bit positions when bit d of the amount is set.
 *
 * Only the low bits of the amount are read, so the caller decides what a
 * larger amount means. The result stays in the scratch until
 * host_barrel_shift_finish writes it to lwe_array: noisy blocks on the
 * block-level path, clean bits still to pack on the bit-level one.
 *
 * @param lwe_array Value to shift or rotate, read only.
 * @param lwe_shift Encrypted amount, same block count as lwe_array.
 */
template <typename Torus, typename KSTorus>
__host__ void
host_barrel_shift_rounds(CudaStreams streams,
                         CudaRadixCiphertextFFI const *lwe_array,
                         CudaRadixCiphertextFFI const *lwe_shift,
                         int_barrel_shifter_buffer<Torus> *mem_ptr,
                         void *const *bsks, KSTorus *const *ksks) {
  if (mem_ptr->use_block_path) {
    host_block_shift_and_rotate<Torus, KSTorus>(streams, lwe_array, lwe_shift,
                                                mem_ptr->block_mem, bsks, ksks);
    return;
  }
  cuda_set_device(streams.gpu_index(0));
  auto bits_mem = mem_ptr->bits_mem;
  auto params = mem_ptr->params;
  auto num_radix_blocks = lwe_array->num_radix_blocks;
  uint32_t bits_per_block = log2_int(params.message_modulus);
  uint32_t total_nb_bits = bits_per_block * num_radix_blocks;
  uint32_t max_num_bits_that_tell_shift = mem_ptr->max_num_bits_that_tell_shift;

  // Extract all bits
  auto bits = &bits_mem->tmp_bits;
  extract_n_bits<Torus>(streams, bits, lwe_array, bsks, ksks, total_nb_bits,
                        num_radix_blocks, bits_mem->bit_extract_luts);

  // Extracts bits and put them in the bit index 2 (=> bit number 3)
  // so that it is already aligned to the correct position of the cmux input
  // and we reduce noise growth
  auto shift_bits = &bits_mem->tmp_shift_bits;
  extract_n_bits<Torus>(streams, shift_bits, lwe_shift, bsks, ksks,
                        max_num_bits_that_tell_shift, num_radix_blocks,
                        bits_mem->bit_extract_luts_with_offset_2);

  // If signed, do an "arithmetic shift" by padding with the sign bit
  CudaRadixCiphertextFFI last_bit;
  as_radix_ciphertext_slice<Torus>(&last_bit, bits, (total_nb_bits - 1),
                                   total_nb_bits);

  // Apply op
  auto rotated_input = &bits_mem->tmp_rotated;
  auto input_bits_a = &bits_mem->tmp_input_bits_a;
  auto input_bits_b = &bits_mem->tmp_input_bits_b;
  auto mux_lut = bits_mem->mux_lut;
  auto mux_inputs = &bits_mem->tmp_mux_inputs;

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     input_bits_a, bits);
  GPU_ASSERT(input_bits_a->num_radix_blocks == total_nb_bits,
             "Cuda error: incorrect number of blocks");
  for (int d = 0; d < max_num_bits_that_tell_shift; d++) {
    CudaRadixCiphertextFFI shift_bit;
    as_radix_ciphertext_slice<Torus>(&shift_bit, shift_bits, d, d + 1);

    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       input_bits_b, input_bits_a);
    auto rotations = 1 << d;
    switch (mem_ptr->shift_type) {
    case LEFT_SHIFT:
      // rotate right as the blocks are from LSB to MSB
      host_radix_blocks_rotate_right<Torus>(
          streams, rotated_input, input_bits_b, rotations, total_nb_bits);

      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), rotated_input, 0, rotations);
      break;
    case RIGHT_SHIFT:
      // rotate left as the blocks are from LSB to MSB
      host_radix_blocks_rotate_left<Torus>(streams, rotated_input, input_bits_b,
                                           rotations, total_nb_bits);

      if (mem_ptr->is_signed)
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
        params.message_modulus, params.carry_modulus);

    // The shift bit is already properly aligned/positioned
    host_add_the_same_block_to_all_blocks<Torus>(
        streams.stream(0), streams.gpu_index(0), mux_inputs, mux_inputs,
        &shift_bit, params.message_modulus, params.carry_modulus);

    // we have
    // control_bit|b|a
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, input_bits_a, mux_inputs, bsks, ksks, mux_lut, total_nb_bits);
  }
}

/**
 * @brief Packs the bits the bit-level rounds shifted back into the blocks of
 * lwe_array, most significant bit of each block first.
 *
 * Every bit appended but the last is followed by a cleaning PBS. The last one
 * is left to host_barrel_shift_finish, so blocks of more than one bit come
 * out noisy.
 *
 * @param lwe_array Destination of the blocks.
 */
template <typename Torus, typename KSTorus>
__host__ void
host_reassemble_shifted_bits(CudaStreams streams,
                             CudaRadixCiphertextFFI *lwe_array,
                             int_barrel_shifter_buffer<Torus> *mem_ptr,
                             void *const *bsks, KSTorus *const *ksks) {
  auto params = mem_ptr->params;
  auto shifted_bits = &mem_ptr->bits_mem->tmp_input_bits_a;
  auto num_radix_blocks = lwe_array->num_radix_blocks;
  uint32_t bits_per_block = log2_int(params.message_modulus);

  // Initializes the output
  // Copy the last bit for each radix block
  for (int i = 0; i < num_radix_blocks; i++) {
    auto last_bit_index = (bits_per_block - 1) + i * bits_per_block;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, i, i + 1,
        shifted_bits, last_bit_index, last_bit_index + 1);
  }

  // Bitshift and add the other bits
  for (int i = bits_per_block - 2; i >= 0; i--) {
    host_integer_small_scalar_mul_radix<Torus>(streams, lwe_array, lwe_array, 2,
                                               params.message_modulus,
                                               params.carry_modulus);
    for (int j = 0; j < num_radix_blocks; j++) {
      CudaRadixCiphertextFFI block;
      CudaRadixCiphertextFFI bit_to_add;
      as_radix_ciphertext_slice<Torus>(&block, lwe_array, j, j + 1);
      as_radix_ciphertext_slice<Torus>(&bit_to_add, shifted_bits,
                                       i + j * bits_per_block,
                                       i + j * bits_per_block + 1);
      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &block,
                           &block, &bit_to_add, 1, params.message_modulus,
                           params.carry_modulus);
    }

    if (i > 0)
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, lwe_array, lwe_array, bsks, ksks, mem_ptr->cleaning_lut,
          num_radix_blocks);
  }
}

/**
 * @brief Writes the value the rounds shifted to lwe_array, through the last
 * PBS of the shifter.
 *
 * The blocks get here noisy, from the rounds on the block-level path and from
 * packing the bits back on the bit-level one. This PBS has to refresh them
 * anyway, so the caller picks its LUT and gets a selection on the result at
 * no extra cost. With carry_condition added to every block, final_lut finds
 * it in the carry, next to the shifted message.
 *
 * @param lwe_array Destination of the result.
 * @param final_lut LUT of the last PBS, one per block of lwe_array.
 * @param carry_condition Single block holding a value in the carry space, for
 * final_lut to select on. Null when final_lut reads the message alone.
 */
template <typename Torus, typename KSTorus>
__host__ void
host_barrel_shift_finish(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array,
                         int_barrel_shifter_buffer<Torus> *mem_ptr,
                         int_radix_lut<Torus> *final_lut,
                         CudaRadixCiphertextFFI const *carry_condition,
                         void *const *bsks, KSTorus *const *ksks) {
  auto params = mem_ptr->params;

  CudaRadixCiphertextFFI *shifted;
  if (mem_ptr->use_block_path) {
    shifted = &mem_ptr->block_mem->messages;
  } else {
    host_reassemble_shifted_bits<Torus, KSTorus>(streams, lwe_array, mem_ptr,
                                                 bsks, ksks);
    shifted = lwe_array;
    // Blocks of a single bit come out of the mux clean, so without a
    // selection to apply there is nothing a PBS would add
    if (params.message_modulus == 2 && carry_condition == nullptr)
      return;
  }

  if (carry_condition != nullptr)
    host_add_the_same_block_to_all_blocks<Torus>(
        streams.stream(0), streams.gpu_index(0), shifted, shifted,
        carry_condition, params.message_modulus, params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, lwe_array, shifted, bsks, ksks, final_lut,
      lwe_array->num_radix_blocks);
}

/**
 * @brief Points sign_bit at the sign bit of the value the rounds just
 * shifted, as it was before them.
 *
 * Both paths have it at hand after the rounds of an arithmetic right shift,
 * which pads with it. The overshift selection reads it there instead of
 * paying a PBS to extract it again.
 *
 * @param sign_bit View to set, it owns no memory.
 */
template <typename Torus>
__host__ void
barrel_shifter_input_sign_bit(CudaRadixCiphertextFFI *sign_bit,
                              int_barrel_shifter_buffer<Torus> *mem_ptr) {
  if (mem_ptr->use_block_path) {
    as_radix_ciphertext_slice<Torus>(sign_bit, &mem_ptr->block_mem->sign_block,
                                     0, 1);
    return;
  }
  auto bits = &mem_ptr->bits_mem->tmp_bits;
  as_radix_ciphertext_slice<Torus>(sign_bit, bits, bits->num_radix_blocks - 1,
                                   bits->num_radix_blocks);
}

/**
 * @brief Computes the overshift condition (shift_amount >= total_nb_bits) and
 * packs it into the carry of mem_ptr->tmp_overshift, so it can later be fused
 * into the last PBS of the barrel shifter at no extra per-block PBS cost. For
 * an arithmetic right shift the condition also encodes the input's sign.
 *
 * Runs after the rounds of the shifter, which leave that sign behind.
 *
 * @param lwe_shift Encrypted shift amount to compare against the bit width.
 */
template <typename Torus, typename KSTorus>
__host__ void host_compute_overshift_condition(
    CudaStreams streams, CudaRadixCiphertextFFI const *lwe_shift,
    int_shift_buffer<Torus> *mem_ptr, void *const *bsks, KSTorus *const *ksks) {
  auto message_modulus = mem_ptr->params.message_modulus;
  auto carry_modulus = mem_ptr->params.carry_modulus;

  auto num_radix_blocks = lwe_shift->num_radix_blocks;
  CudaRadixCiphertextFFI const *compare_in;
  if (mem_ptr->tmp_padded_shift != nullptr) {
    // Pad the shift amount to an even number of blocks (high block is 0).
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_padded_shift, 0,
        mem_ptr->tmp_padded_shift->num_radix_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_padded_shift, 0,
        num_radix_blocks, lwe_shift, 0, num_radix_blocks);
    compare_in = mem_ptr->tmp_padded_shift;
  } else {
    compare_in = lwe_shift;
  }
  integer_radix_unsigned_scalar_difference_check<Torus>(
      streams, mem_ptr->tmp_overshift, compare_in,
      mem_ptr->d_overshift_scalar_blocks, mem_ptr->h_overshift_scalar_blocks,
      mem_ptr->overshift_compare_mem,
      mem_ptr->overshift_compare_mem->diff_buffer->operator_f, bsks, ksks,
      mem_ptr->overshift_compare_num_blocks,
      mem_ptr->num_overshift_scalar_blocks);

  if (mem_ptr->arithmetic) {
    // cond = 2 * overshift + is_neg, where is_neg is the input's sign bit
    CudaRadixCiphertextFFI sign_bit;
    barrel_shifter_input_sign_bit<Torus>(&sign_bit, mem_ptr->shifter_mem);
    host_integer_small_scalar_mul_radix<Torus>(streams, mem_ptr->tmp_overshift,
                                               mem_ptr->tmp_overshift, 2,
                                               message_modulus, carry_modulus);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0),
                         mem_ptr->tmp_overshift, mem_ptr->tmp_overshift,
                         &sign_bit, 1, message_modulus, carry_modulus);
  }
  // Move cond into the carry space (clean output).
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem_ptr->tmp_overshift, mem_ptr->tmp_overshift, bsks, ksks,
      mem_ptr->overshift_pack_lut, 1);
}

/**
 * @brief Shifts lwe_array in place by the encrypted amount lwe_shift.
 *
 * An amount of the bit width or more yields 0, or the sign of the input for
 * an arithmetic right shift.
 *
 * @param lwe_array Value to shift, without carries.
 * @param lwe_shift Encrypted amount, same block count as lwe_array.
 */
template <typename Torus, typename KSTorus>
__host__ void host_shift_inplace(CudaStreams streams,
                                 CudaRadixCiphertextFFI *lwe_array,
                                 CudaRadixCiphertextFFI const *lwe_shift,
                                 int_shift_buffer<Torus> *mem_ptr,
                                 void *const *bsks, KSTorus *const *ksks) {
  auto shifter_mem = mem_ptr->shifter_mem;
  assert_barrel_shifter_operands<Torus>(lwe_array, lwe_shift, shifter_mem);
  if (lwe_array->num_radix_blocks == 0)
    return;

  host_barrel_shift_rounds<Torus, KSTorus>(streams, lwe_array, lwe_shift,
                                           shifter_mem, bsks, ksks);
  // The overshift selection rides on the last PBS of the shifter
  host_compute_overshift_condition<Torus, KSTorus>(streams, lwe_shift, mem_ptr,
                                                   bsks, ksks);
  host_barrel_shift_finish<Torus, KSTorus>(streams, lwe_array, shifter_mem,
                                           mem_ptr->overshift_cleanup_lut,
                                           mem_ptr->tmp_overshift, bsks, ksks);
}

/**
 * @brief Reduces the amount of a rotation modulo the bit width of the rotated
 * value, into mem_ptr->reduced_amount.
 *
 * The barrel shifter only reads the low ceil(log2(total_nb_bits)) bits of the
 * amount. That truncation is the reduction a rotation expects when
 * total_nb_bits is a power of two, and another one otherwise: rotating 6 bits
 * by 8 would rotate by 8 % 8 = 0 instead of 8 % 6 = 2.
 *
 * The caller prepares the clear operands of that division, as its magic
 * numbers need integers twice as wide as the amount, which the backend does
 * not have.
 *
 * @param lwe_shift Encrypted rotation amount, without carries.
 * @param scalar_divisor_ffi Magic numbers of the division by total_nb_bits,
 * for a numerator as wide as the amount.
 * @param divisor_has_at_least_one_set For each bit position inside a block,
 * whether total_nb_bits has a bit set there in any of its blocks.
 * @param decomposed_divisor Bits of total_nb_bits, least significant first.
 * @param num_scalars_divisor Length of decomposed_divisor.
 */
template <typename Torus, typename KSTorus>
__host__ void host_reduce_rotation_amount(
    CudaStreams streams, CudaRadixCiphertextFFI const *lwe_shift,
    int_rotation_amount_reduction_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint64_t const *divisor_has_at_least_one_set,
    uint64_t const *decomposed_divisor, uint32_t num_scalars_divisor) {
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     &mem_ptr->quotient, lwe_shift);
  // The clear blocks only serve power of two divisors, which the barrel
  // shifter handles without this reduction
  host_integer_unsigned_scalar_div_rem_radix<Torus, KSTorus>(
      streams, &mem_ptr->quotient, &mem_ptr->reduced_amount,
      mem_ptr->div_rem_mem, bsks, ksks, scalar_divisor_ffi,
      divisor_has_at_least_one_set, decomposed_divisor, num_scalars_divisor,
      nullptr, nullptr, 0);
}

/**
 * @brief Rotates lwe_array in place by the encrypted amount lwe_shift.
 *
 * The four divisor parameters are the clear operands of the reduction of the
 * amount, see host_reduce_rotation_amount. Bit widths that are a power of two
 * skip that reduction and never read them, null pointers and 0 are fine there.
 *
 * @param lwe_array Value to rotate, without carries.
 * @param lwe_shift Encrypted amount, same block count as lwe_array.
 * @param scalar_divisor_ffi Magic numbers of the division by total_nb_bits.
 * @param divisor_has_at_least_one_set Bit positions inside a block where
 * total_nb_bits has a bit set.
 * @param decomposed_divisor Bits of total_nb_bits, least significant first.
 * @param num_scalars_divisor Length of decomposed_divisor.
 */
template <typename Torus, typename KSTorus>
__host__ void host_rotate_inplace(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array,
    CudaRadixCiphertextFFI const *lwe_shift, int_rotate_buffer<Torus> *mem_ptr,
    void *const *bsks, KSTorus *const *ksks,
    const CudaScalarDivisorFFI *scalar_divisor_ffi,
    uint64_t const *divisor_has_at_least_one_set,
    uint64_t const *decomposed_divisor, uint32_t num_scalars_divisor) {
  auto shifter_mem = mem_ptr->shifter_mem;
  assert_barrel_shifter_operands<Torus>(lwe_array, lwe_shift, shifter_mem);
  if (lwe_array->num_radix_blocks == 0)
    return;

  if (mem_ptr->amount_reduction_mem != nullptr) {
    host_reduce_rotation_amount<Torus, KSTorus>(
        streams, lwe_shift, mem_ptr->amount_reduction_mem, bsks, ksks,
        scalar_divisor_ffi, divisor_has_at_least_one_set, decomposed_divisor,
        num_scalars_divisor);
    lwe_shift = &mem_ptr->amount_reduction_mem->reduced_amount;
  }

  host_barrel_shift_rounds<Torus, KSTorus>(streams, lwe_array, lwe_shift,
                                           shifter_mem, bsks, ksks);
  host_barrel_shift_finish<Torus, KSTorus>(streams, lwe_array, shifter_mem,
                                           shifter_mem->cleaning_lut, nullptr,
                                           bsks, ksks);
}
#endif
