#ifndef TFHE_RS_DIV_REM_CUH
#define TFHE_RS_DIV_REM_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer/abs.cuh"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/negation.cuh"
#include "integer/scalar_shifts.cuh"
#include "linear_algebra.h"
#include "pbs/programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_div_rem_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, bool is_signed, int_div_rem_memory<Torus> **mem_ptr,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_div_rem_memory<Torus>(streams, gpu_indexes, gpu_count,
                                           params, is_signed, num_blocks,
                                           allocate_gpu_memory, &size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ void host_unsigned_integer_div_rem_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, CudaRadixCiphertextFFI const *numerator,
    CudaRadixCiphertextFFI const *divisor, void *const *bsks,
    uint64_t *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    unsigned_int_div_rem_memory<uint64_t> *mem_ptr) {

  if (remainder->num_radix_blocks != numerator->num_radix_blocks ||
      remainder->num_radix_blocks != divisor->num_radix_blocks ||
      remainder->num_radix_blocks != quotient->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be equal")
  if (remainder->lwe_dimension != numerator->lwe_dimension ||
      remainder->lwe_dimension != divisor->lwe_dimension ||
      remainder->lwe_dimension != quotient->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimension must be equal")
  auto radix_params = mem_ptr->params;
  auto num_blocks = quotient->num_radix_blocks;

  uint32_t message_modulus = radix_params.message_modulus;
  uint32_t num_bits_in_message = 31 - __builtin_clz(message_modulus);

  uint32_t total_bits = num_bits_in_message * num_blocks;

  // put temporary buffers in lwe_ciphertext_list for easy use
  auto remainder1 = mem_ptr->remainder1;
  auto remainder2 = mem_ptr->remainder2;
  auto numerator_block_stack = mem_ptr->numerator_block_stack;
  auto interesting_remainder1 = mem_ptr->interesting_remainder1;
  auto interesting_remainder2 = mem_ptr->interesting_remainder2;
  auto interesting_divisor = mem_ptr->interesting_divisor;
  auto divisor_ms_blocks = mem_ptr->divisor_ms_blocks;
  auto new_remainder = mem_ptr->new_remainder;
  auto subtraction_overflowed = mem_ptr->subtraction_overflowed;
  auto overflow_sum = mem_ptr->overflow_sum;
  auto overflow_sum_radix = mem_ptr->overflow_sum_radix;
  auto at_least_one_upper_block_is_non_zero =
      mem_ptr->at_least_one_upper_block_is_non_zero;
  auto cleaned_merged_interesting_remainder =
      mem_ptr->cleaned_merged_interesting_remainder;

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                     numerator_block_stack, numerator);
  set_zero_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                               quotient, 0, num_blocks);

  for (int i = total_bits - 1; i >= 0; i--) {
    uint32_t pos_in_block = i % num_bits_in_message;
    uint32_t msb_bit_set = total_bits - 1 - i;
    uint32_t last_non_trivial_block = msb_bit_set / num_bits_in_message;

    // Index to the first block of the remainder that is fully trivial 0
    // and all blocks after it are also trivial zeros
    // This number is in range 1..=num_bocks -1
    uint32_t first_trivial_block = last_non_trivial_block + 1;
    reset_radix_ciphertext_blocks(interesting_remainder1, first_trivial_block);
    reset_radix_ciphertext_blocks(interesting_remainder2, first_trivial_block);
    reset_radix_ciphertext_blocks(interesting_divisor, first_trivial_block);
    reset_radix_ciphertext_blocks(divisor_ms_blocks,
                                  num_blocks -
                                      (msb_bit_set + 1) / num_bits_in_message);

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], interesting_remainder1, 0,
        first_trivial_block, remainder1, 0, first_trivial_block);
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], interesting_remainder2, 0,
        first_trivial_block, remainder2, 0, first_trivial_block);
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], interesting_divisor, 0, first_trivial_block,
        divisor, 0, first_trivial_block);
    if ((msb_bit_set + 1) / num_bits_in_message < num_blocks)
      copy_radix_ciphertext_slice_async<Torus>(
          streams[0], gpu_indexes[0], divisor_ms_blocks, 0,
          num_blocks - (msb_bit_set + 1) / num_bits_in_message, divisor,
          (msb_bit_set + 1) / num_bits_in_message, num_blocks);

    // We split the divisor at a block position, when in reality the split
    // should be at a bit position meaning that potentially (depending on
    // msb_bit_set) the split versions share some bits they should not. So we do
    // one PBS on the last block of the interesting_divisor, and first block of
    // divisor_ms_blocks to trim out bits which should not be there
    auto trim_last_interesting_divisor_bits = [&](cudaStream_t const *streams,
                                                  uint32_t const *gpu_indexes,
                                                  uint32_t gpu_count) {
      if ((msb_bit_set + 1) % num_bits_in_message == 0) {
        return;
      }
      // The last block of the interesting part of the remainder
      // can contain bits which we should not account for
      // we have to zero them out.

      // Where the msb is set in the block
      uint32_t pos_in_block = msb_bit_set % num_bits_in_message;

      // e.g 2 bits in message:
      // if pos_in_block is 0, then we want to keep only first bit (right
      // shift
      // mask by 1) if pos_in_block is 1, then we want to keep the two
      // bits
      // (right shift mask by 0)
      uint32_t shift_amount = num_bits_in_message - (pos_in_block + 1);

      // Create mask of 1s on the message part, 0s in the carries
      uint32_t full_message_mask = message_modulus - 1;

      // Shift the mask so that we will only keep bits we should
      uint32_t shifted_mask = full_message_mask >> shift_amount;

      CudaRadixCiphertextFFI last_interesting_divisor_block;
      as_radix_ciphertext_slice<Torus>(
          &last_interesting_divisor_block, interesting_divisor,
          interesting_divisor->num_radix_blocks - 1,
          interesting_divisor->num_radix_blocks);
      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count, &last_interesting_divisor_block,
          &last_interesting_divisor_block, bsks, ksks, ms_noise_reduction_key,
          mem_ptr->masking_luts_1[shifted_mask], 1);
    }; // trim_last_interesting_divisor_bits

    auto trim_first_divisor_ms_bits = [&](cudaStream_t const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count) {
      if (divisor_ms_blocks->num_radix_blocks == 0 ||
          ((msb_bit_set + 1) % num_bits_in_message) == 0) {
        return;
      }
      // Where the msb is set in the block
      uint32_t pos_in_block = msb_bit_set % num_bits_in_message;

      // e.g 2 bits in message:
      // if pos_in_block is 0, then we want to discard the first bit (left
      // shift mask by 1) if pos_in_block is 1, then we want to discard the
      // two bits (left shift mask by 2) let shift_amount =
      // num_bits_in_message - pos_in_block
      uint32_t shift_amount = pos_in_block + 1;
      uint32_t full_message_mask = message_modulus - 1;
      uint32_t shifted_mask = full_message_mask << shift_amount;

      // Keep the mask within the range of message bits, so that
      // the estimated degree of the output is < msg_modulus
      shifted_mask = shifted_mask & full_message_mask;

      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count, divisor_ms_blocks, divisor_ms_blocks,
          bsks, ksks, ms_noise_reduction_key,
          mem_ptr->masking_luts_2[shifted_mask], 1);
    }; // trim_first_divisor_ms_bits

    // This does
    //  R := R << 1; R(0) := N(i)
    //
    // We could to that by left shifting, R by one, then unchecked_add the
    // correct numerator bit.
    //
    // However, to keep the remainder clean (noise wise), what we do is that we
    // put the remainder block from which we need to extract the bit, as the LSB
    // of the Remainder, so that left shifting will pull the bit we need.
    auto left_shift_interesting_remainder1 = [&](cudaStream_t const *streams,
                                                 uint32_t const *gpu_indexes,
                                                 uint32_t gpu_count) {
      pop_radix_ciphertext_block_async<Torus>(streams[0], gpu_indexes[0],
                                              mem_ptr->numerator_block_1,
                                              numerator_block_stack);
      insert_block_in_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                                    mem_ptr->numerator_block_1,
                                                    interesting_remainder1, 0);

      host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
          streams, gpu_indexes, gpu_count, interesting_remainder1, 1,
          mem_ptr->shift_mem_1, bsks, ksks, ms_noise_reduction_key,
          interesting_remainder1->num_radix_blocks);

      reset_radix_ciphertext_blocks(mem_ptr->tmp_radix,
                                    interesting_remainder1->num_radix_blocks);
      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                         mem_ptr->tmp_radix,
                                         interesting_remainder1);

      host_radix_blocks_rotate_left<Torus>(
          streams, gpu_indexes, gpu_count, interesting_remainder1,
          mem_ptr->tmp_radix, 1, interesting_remainder1->num_radix_blocks);

      pop_radix_ciphertext_block_async<Torus>(streams[0], gpu_indexes[0],
                                              mem_ptr->numerator_block_1,
                                              interesting_remainder1);

      if (pos_in_block != 0) {
        // We have not yet extracted all the bits from this numerator
        // so, we put it back on the front so that it gets taken next
        // iteration
        push_block_to_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                                    mem_ptr->numerator_block_1,
                                                    numerator_block_stack);
      }
    }; // left_shift_interesting_remainder1

    auto left_shift_interesting_remainder2 = [&](cudaStream_t const *streams,
                                                 uint32_t const *gpu_indexes,
                                                 uint32_t gpu_count) {
      host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
          streams, gpu_indexes, gpu_count, interesting_remainder2, 1,
          mem_ptr->shift_mem_2, bsks, ksks, ms_noise_reduction_key,
          interesting_remainder2->num_radix_blocks);
    }; // left_shift_interesting_remainder2

    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }
    // interesting_divisor
    trim_last_interesting_divisor_bits(mem_ptr->sub_streams_1, gpu_indexes,
                                       gpu_count);
    // divisor_ms_blocks
    trim_first_divisor_ms_bits(mem_ptr->sub_streams_2, gpu_indexes, gpu_count);
    // interesting_remainder1
    // numerator_block_stack
    left_shift_interesting_remainder1(mem_ptr->sub_streams_3, gpu_indexes,
                                      gpu_count);
    // interesting_remainder2
    left_shift_interesting_remainder2(mem_ptr->sub_streams_4, gpu_indexes,
                                      gpu_count);
    for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(mem_ptr->sub_streams_2[j], gpu_indexes[j]);
      cuda_synchronize_stream(mem_ptr->sub_streams_3[j], gpu_indexes[j]);
      cuda_synchronize_stream(mem_ptr->sub_streams_4[j], gpu_indexes[j]);
    }

    // if interesting_remainder1 != 0 -> interesting_remainder2 == 0
    // if interesting_remainder1 == 0 -> interesting_remainder2 != 0
    // In practice interesting_remainder1 contains the numerator bit,
    // but in that position, interesting_remainder2 always has a 0
    auto merged_interesting_remainder = interesting_remainder1;

    host_addition<Torus>(streams[0], gpu_indexes[0],
                         merged_interesting_remainder,
                         merged_interesting_remainder, interesting_remainder2,
                         merged_interesting_remainder->num_radix_blocks);

    // after create_clean_version_of_merged_remainder
    // `merged_interesting_remainder` will be reused as
    // `cleaned_merged_interesting_remainder`
    reset_radix_ciphertext_blocks(
        cleaned_merged_interesting_remainder,
        merged_interesting_remainder->num_radix_blocks);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       cleaned_merged_interesting_remainder,
                                       merged_interesting_remainder);

    if (merged_interesting_remainder->num_radix_blocks !=
        interesting_divisor->num_radix_blocks)
      PANIC("Cuda error: merged interesting remainder and interesting divisor "
            "should have the same number of blocks")

    // `new_remainder` is not initialized yet, so need to set length
    reset_radix_ciphertext_blocks(
        new_remainder, merged_interesting_remainder->num_radix_blocks);

    // fills:
    //  `new_remainder` - radix ciphertext
    //  `subtraction_overflowed` - single ciphertext
    auto do_overflowing_sub = [&](cudaStream_t const *streams,
                                  uint32_t const *gpu_indexes,
                                  uint32_t gpu_count) {
      uint32_t compute_borrow = 1;
      uint32_t uses_input_borrow = 0;
      auto first_indexes =
          mem_ptr->first_indexes_for_overflow_sub
              [merged_interesting_remainder->num_radix_blocks - 1];
      auto second_indexes =
          mem_ptr->second_indexes_for_overflow_sub
              [merged_interesting_remainder->num_radix_blocks - 1];
      auto scalar_indexes =
          mem_ptr->scalars_for_overflow_sub
              [merged_interesting_remainder->num_radix_blocks - 1];
      mem_ptr->overflow_sub_mem->update_lut_indexes(
          streams, gpu_indexes, first_indexes, second_indexes, scalar_indexes,
          merged_interesting_remainder->num_radix_blocks);
      host_integer_overflowing_sub<uint64_t>(
          streams, gpu_indexes, gpu_count, new_remainder,
          merged_interesting_remainder, interesting_divisor,
          subtraction_overflowed, (const CudaRadixCiphertextFFI *)nullptr,
          mem_ptr->overflow_sub_mem, bsks, ksks, ms_noise_reduction_key,
          compute_borrow, uses_input_borrow);
    };

    // fills:
    //  `at_least_one_upper_block_is_non_zero` - single ciphertext
    auto check_divisor_upper_blocks = [&](cudaStream_t const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count) {
      auto trivial_blocks = divisor_ms_blocks;
      if (trivial_blocks->num_radix_blocks == 0) {
        set_zero_radix_ciphertext_slice_async<Torus>(
            streams[0], gpu_indexes[0], at_least_one_upper_block_is_non_zero, 0,
            1);
      } else {

        // We could call unchecked_scalar_ne
        // But we are in the special case where scalar == 0
        // So we can skip some stuff
        host_compare_blocks_with_zero<Torus>(
            streams, gpu_indexes, gpu_count, mem_ptr->tmp_1, trivial_blocks,
            mem_ptr->comparison_buffer, bsks, ksks, ms_noise_reduction_key,
            trivial_blocks->num_radix_blocks,
            mem_ptr->comparison_buffer->eq_buffer->is_non_zero_lut);

        is_at_least_one_comparisons_block_true<Torus>(
            streams, gpu_indexes, gpu_count,
            at_least_one_upper_block_is_non_zero, mem_ptr->tmp_1,
            mem_ptr->comparison_buffer, bsks, ksks, ms_noise_reduction_key,
            mem_ptr->tmp_1->num_radix_blocks);
      }
    };

    // Creates a cleaned version (noise wise) of the merged remainder
    // so that it can be safely used in bivariate PBSes
    // fills:
    //  `cleaned_merged_interesting_remainder` - radix ciphertext
    auto create_clean_version_of_merged_remainder =
        [&](cudaStream_t const *streams, uint32_t const *gpu_indexes,
            uint32_t gpu_count) {
          integer_radix_apply_univariate_lookup_table_kb<Torus>(
              streams, gpu_indexes, gpu_count,
              cleaned_merged_interesting_remainder,
              cleaned_merged_interesting_remainder, bsks, ksks,
              ms_noise_reduction_key, mem_ptr->message_extract_lut_1,
              cleaned_merged_interesting_remainder->num_radix_blocks);
        };

    // phase 2
    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }
    // new_remainder
    // subtraction_overflowed
    do_overflowing_sub(mem_ptr->sub_streams_1, gpu_indexes, gpu_count);
    // at_least_one_upper_block_is_non_zero
    check_divisor_upper_blocks(mem_ptr->sub_streams_2, gpu_indexes, gpu_count);
    // cleaned_merged_interesting_remainder
    create_clean_version_of_merged_remainder(mem_ptr->sub_streams_3,
                                             gpu_indexes, gpu_count);
    for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(mem_ptr->sub_streams_2[j], gpu_indexes[j]);
      cuda_synchronize_stream(mem_ptr->sub_streams_3[j], gpu_indexes[j]);
    }

    host_addition<Torus>(streams[0], gpu_indexes[0], overflow_sum,
                         subtraction_overflowed,
                         at_least_one_upper_block_is_non_zero, 1);

    auto message_modulus = radix_params.message_modulus;
    int factor = (i) ? message_modulus - 1 : message_modulus - 2;
    int factor_lut_id = (i) ? 1 : 0;
    for (size_t k = 0;
         k < cleaned_merged_interesting_remainder->num_radix_blocks; k++) {
      copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                               overflow_sum_radix, k, k + 1,
                                               overflow_sum, 0, 1);
    }

    auto conditionally_zero_out_merged_interesting_remainder =
        [&](cudaStream_t const *streams, uint32_t const *gpu_indexes,
            uint32_t gpu_count) {
          integer_radix_apply_bivariate_lookup_table_kb<Torus>(
              streams, gpu_indexes, gpu_count,
              cleaned_merged_interesting_remainder,
              cleaned_merged_interesting_remainder, overflow_sum_radix, bsks,
              ksks, ms_noise_reduction_key,
              mem_ptr->zero_out_if_overflow_did_not_happen[factor_lut_id],
              cleaned_merged_interesting_remainder->num_radix_blocks, factor);
        };

    auto conditionally_zero_out_merged_new_remainder =
        [&](cudaStream_t const *streams, uint32_t const *gpu_indexes,
            uint32_t gpu_count) {
          integer_radix_apply_bivariate_lookup_table_kb<Torus>(
              streams, gpu_indexes, gpu_count, new_remainder, new_remainder,
              overflow_sum_radix, bsks, ksks, ms_noise_reduction_key,
              mem_ptr->zero_out_if_overflow_happened[factor_lut_id],
              new_remainder->num_radix_blocks, factor);
        };

    auto set_quotient_bit = [&](cudaStream_t const *streams,
                                uint32_t const *gpu_indexes,
                                uint32_t gpu_count) {
      uint32_t block_of_bit = i / num_bits_in_message;
      integer_radix_apply_bivariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count, mem_ptr->did_not_overflow,
          subtraction_overflowed, at_least_one_upper_block_is_non_zero, bsks,
          ksks, ms_noise_reduction_key,
          mem_ptr->merge_overflow_flags_luts[pos_in_block], 1,
          mem_ptr->merge_overflow_flags_luts[pos_in_block]
              ->params.message_modulus);

      CudaRadixCiphertextFFI quotient_block;
      as_radix_ciphertext_slice<Torus>(&quotient_block, quotient, block_of_bit,
                                       block_of_bit + 1);
      host_addition<Torus>(streams[0], gpu_indexes[0], &quotient_block,
                           &quotient_block, mem_ptr->did_not_overflow, 1);
    };

    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }
    // cleaned_merged_interesting_remainder
    conditionally_zero_out_merged_interesting_remainder(mem_ptr->sub_streams_1,
                                                        gpu_indexes, gpu_count);
    // new_remainder
    conditionally_zero_out_merged_new_remainder(mem_ptr->sub_streams_2,
                                                gpu_indexes, gpu_count);
    // quotient
    set_quotient_bit(mem_ptr->sub_streams_3, gpu_indexes, gpu_count);
    for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(mem_ptr->sub_streams_2[j], gpu_indexes[j]);
      cuda_synchronize_stream(mem_ptr->sub_streams_3[j], gpu_indexes[j]);
    }

    if (first_trivial_block !=
        cleaned_merged_interesting_remainder->num_radix_blocks)
      PANIC("Cuda error: first_trivial_block should be equal to "
            "clean_merged_interesting_remainder num blocks")
    if (first_trivial_block != new_remainder->num_radix_blocks)
      PANIC("Cuda error: first_trivial_block should be equal to new_remainder "
            "num blocks")

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], remainder1, 0, first_trivial_block,
        cleaned_merged_interesting_remainder, 0, first_trivial_block);
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], remainder2, 0, first_trivial_block,
        new_remainder, 0, first_trivial_block);
  }

  if (remainder1->num_radix_blocks != remainder2->num_radix_blocks)
    PANIC("Cuda error: remainder1 and remainder2 should have the same number "
          "of blocks")

  // Clean the quotient and remainder
  // as even though they have no carries, they are not at nominal noise level
  host_addition<Torus>(streams[0], gpu_indexes[0], remainder, remainder1,
                       remainder2, remainder1->num_radix_blocks);

  for (uint j = 0; j < gpu_count; j++) {
    cuda_synchronize_stream(streams[j], gpu_indexes[j]);
  }
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      mem_ptr->sub_streams_1, gpu_indexes, gpu_count, remainder, remainder,
      bsks, ksks, ms_noise_reduction_key, mem_ptr->message_extract_lut_1,
      num_blocks);
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      mem_ptr->sub_streams_2, gpu_indexes, gpu_count, quotient, quotient, bsks,
      ksks, ms_noise_reduction_key, mem_ptr->message_extract_lut_2, num_blocks);
  for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
    cuda_synchronize_stream(mem_ptr->sub_streams_1[j], gpu_indexes[j]);
    cuda_synchronize_stream(mem_ptr->sub_streams_2[j], gpu_indexes[j]);
  }
}

template <typename Torus>
__host__ void host_integer_div_rem_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, CudaRadixCiphertextFFI const *numerator,
    CudaRadixCiphertextFFI const *divisor, bool is_signed, void *const *bsks,
    uint64_t *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    int_div_rem_memory<uint64_t> *int_mem_ptr) {
  if (remainder->num_radix_blocks != numerator->num_radix_blocks ||
      remainder->num_radix_blocks != divisor->num_radix_blocks ||
      remainder->num_radix_blocks != quotient->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be equal")
  if (remainder->lwe_dimension != numerator->lwe_dimension ||
      remainder->lwe_dimension != divisor->lwe_dimension ||
      remainder->lwe_dimension != quotient->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimension must be equal")

  auto num_blocks = quotient->num_radix_blocks;
  if (is_signed) {
    auto radix_params = int_mem_ptr->params;

    // temporary memory
    auto positive_numerator = int_mem_ptr->positive_numerator;
    auto positive_divisor = int_mem_ptr->positive_divisor;
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       positive_numerator, numerator);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       positive_divisor, divisor);

    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }

    host_integer_abs_kb<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count, positive_numerator,
        bsks, ksks, ms_noise_reduction_key, int_mem_ptr->abs_mem_1, true);
    host_integer_abs_kb<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count, positive_divisor,
        bsks, ksks, ms_noise_reduction_key, int_mem_ptr->abs_mem_2, true);
    for (uint j = 0; j < int_mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(int_mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(int_mem_ptr->sub_streams_2[j], gpu_indexes[j]);
    }

    host_unsigned_integer_div_rem_kb<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count, quotient, remainder,
        positive_numerator, positive_divisor, bsks, ksks,
        ms_noise_reduction_key, int_mem_ptr->unsigned_mem);

    CudaRadixCiphertextFFI numerator_sign;
    as_radix_ciphertext_slice<Torus>(&numerator_sign, numerator, num_blocks - 1,
                                     num_blocks);
    CudaRadixCiphertextFFI divisor_sign;
    as_radix_ciphertext_slice<Torus>(&divisor_sign, divisor, num_blocks - 1,
                                     num_blocks);
    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count,
        int_mem_ptr->sign_bits_are_different, &numerator_sign, &divisor_sign,
        bsks, ksks, ms_noise_reduction_key,
        int_mem_ptr->compare_signed_bits_lut, 1,
        int_mem_ptr->compare_signed_bits_lut->params.message_modulus);

    for (uint j = 0; j < int_mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(int_mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(int_mem_ptr->sub_streams_2[j], gpu_indexes[j]);
    }

    host_integer_radix_negation<Torus>(int_mem_ptr->sub_streams_1, gpu_indexes,
                                       gpu_count, int_mem_ptr->negated_quotient,
                                       quotient, radix_params.message_modulus,
                                       radix_params.carry_modulus, num_blocks);

    uint32_t requested_flag = outputFlag::FLAG_NONE;
    uint32_t uses_carry = 0;
    host_propagate_single_carry<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count,
        int_mem_ptr->negated_quotient, nullptr, nullptr, int_mem_ptr->scp_mem_1,
        bsks, ksks, ms_noise_reduction_key, requested_flag, uses_carry);

    host_integer_radix_negation<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count,
        int_mem_ptr->negated_remainder, remainder, radix_params.message_modulus,
        radix_params.carry_modulus, num_blocks);

    host_propagate_single_carry<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count,
        int_mem_ptr->negated_remainder, nullptr, nullptr,
        int_mem_ptr->scp_mem_2, bsks, ksks, ms_noise_reduction_key,
        requested_flag, uses_carry);

    host_integer_radix_cmux_kb<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count, quotient,
        int_mem_ptr->sign_bits_are_different, int_mem_ptr->negated_quotient,
        quotient, int_mem_ptr->cmux_quotient_mem, bsks, ksks,
        ms_noise_reduction_key);

    host_integer_radix_cmux_kb<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count, remainder,
        &numerator_sign, int_mem_ptr->negated_remainder, remainder,
        int_mem_ptr->cmux_remainder_mem, bsks, ksks, ms_noise_reduction_key);

    for (uint j = 0; j < int_mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(int_mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(int_mem_ptr->sub_streams_2[j], gpu_indexes[j]);
    }
  } else {
    host_unsigned_integer_div_rem_kb<Torus>(
        streams, gpu_indexes, gpu_count, quotient, remainder, numerator,
        divisor, bsks, ksks, ms_noise_reduction_key, int_mem_ptr->unsigned_mem);
  }
}

#endif // TFHE_RS_DIV_REM_CUH
