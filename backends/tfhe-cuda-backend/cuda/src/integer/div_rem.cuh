#ifndef TFHE_RS_DIV_REM_CUH
#define TFHE_RS_DIV_REM_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.h"
#include "integer/integer.cuh"
#include "integer/negation.cuh"
#include "integer/scalar_shifts.cuh"
#include "linear_algebra.h"
#include "programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <omp.h>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
__host__ void scratch_cuda_integer_div_rem_kb(
    cuda_stream_t *stream, int_div_rem_memory<Torus> **mem_ptr,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  cudaSetDevice(stream->gpu_index);
  *mem_ptr = new int_div_rem_memory<Torus>(stream, params, num_blocks,
                                           allocate_gpu_memory);
}

template <typename Torus, class params>
__host__ void host_integer_div_rem_kb(cuda_stream_t *stream, Torus *quotient,
                                      Torus *remainder, Torus *numerator,
                                      Torus *divisor, void *bsk, uint64_t *ksk,
                                      int_div_rem_memory<uint64_t> *mem_ptr,
                                      uint32_t num_blocks) {

  auto radix_params = mem_ptr->params;

  auto big_lwe_size = radix_params.big_lwe_dimension + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
  auto radix_size_bytes = big_lwe_size_bytes * num_blocks;

  uint32_t message_modulus = radix_params.message_modulus;
  uint32_t num_bits_in_message = 31 - __builtin_clz(message_modulus);
  uint32_t total_bits = num_bits_in_message * num_blocks;

  // TODO move in scratch
  Torus *remainder1 = (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *remainder2 = (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *numerator_block_stack =
      (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *interesting_remainder1 =
      (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *interesting_remainder2 =
      (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *interesting_divisor =
      (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *divisor_ms_blocks =
      (Torus *)cuda_malloc_async(radix_size_bytes, stream);

  Torus *merged_interesting_remainder =
      (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *cur_quotient = (Torus *)cuda_malloc_async(radix_size_bytes, stream);
  Torus *overflowed = (Torus *)cuda_malloc_async(big_lwe_size_bytes, stream);

  cuda_memcpy_async_gpu_to_gpu(numerator_block_stack, numerator,
                               radix_size_bytes, stream);

  cuda_memset_async(quotient, 0, radix_size_bytes, stream);
  cuda_memset_async(remainder1, 0, radix_size_bytes, stream);
  cuda_memset_async(remainder2, 0, radix_size_bytes, stream);

  // luts
  int_radix_lut<Torus> *merge_overflow_flags_luts =
      new int_radix_lut<Torus>(stream, radix_params, num_bits_in_message,
                               num_bits_in_message * num_blocks, true);
  int_radix_lut<Torus> *masking_lut =
      new int_radix_lut<Torus>(stream, radix_params, 1, num_blocks, true);

  uint32_t numerator_block_stack_size = num_blocks;
  uint32_t interesting_remainder1_size = 0;
  for (int i = 0; i < num_bits_in_message; i++) {
    auto lut_f_bit = [i](Torus x, Torus y) -> Torus {
      return (x == 0 && y == 0) << i;
    };
    auto cur_lut = merge_overflow_flags_luts->get_lut(i);
    generate_device_accumulator_bivariate<Torus>(
        stream, cur_lut, radix_params.glwe_dimension,
        radix_params.polynomial_size, radix_params.message_modulus,
        radix_params.carry_modulus, lut_f_bit);
  }

  // end of move in scratch

  for (int i = total_bits - 1; i >= 0; i--) {
    uint32_t msb_bit_set = total_bits - 1 - i;

    uint32_t last_non_trivial_block = msb_bit_set / num_bits_in_message;
    // Index to the first block of the remainder that is fully trivial 0
    // and all blocks after it are also trivial zeros
    // This number is in range 1..=num_bocks -1
    uint32_t first_trivial_block = last_non_trivial_block + 1;

    cuda_memcpy_async_gpu_to_gpu(interesting_remainder1, remainder1,
                                 big_lwe_size_bytes * last_non_trivial_block,
                                 stream);
    cuda_memcpy_async_gpu_to_gpu(interesting_remainder2, remainder2,
                                 big_lwe_size_bytes * last_non_trivial_block,
                                 stream);
    cuda_memcpy_async_gpu_to_gpu(interesting_divisor, divisor,
                                 big_lwe_size_bytes * last_non_trivial_block,
                                 stream);
    uint32_t ms_start_index =
        (msb_bit_set + 1) / num_bits_in_message * big_lwe_size;
    cuda_memcpy_async_gpu_to_gpu(
        divisor_ms_blocks, &divisor[ms_start_index],
        radix_size_bytes - ms_start_index * sizeof(Torus), stream);

    interesting_remainder1_size = last_non_trivial_block;
    // We split the divisor at a block position, when in reality the split
    // should be at a bit position meaning that potentially (depending on
    // msb_bit_set) the split versions share some bits they should not. So we do
    // one PBS on the last block of the interesting_divisor, and first block of
    // divisor_ms_blocks to trim out bits which should not be there

    // TODO following 3 apply_lookup_table can be called in one batch

    // trim_last_interesting_divisor_bits
    if (((msb_bit_set + 1) % num_bits_in_message)) {

      // The last block of the interesting part of the remainder
      // can contain bits which we should not account for
      // we have to zero them out.

      // Where the msb is set in the block
      uint32_t pos_in_block = msb_bit_set % num_bits_in_message;

      // e.g 2 bits in message:
      // if pos_in_block is 0, then we want to keep only first bit (right shift
      // mask by 1) if pos_in_block is 1, then we want to keep the two bits
      // (right shift mask by 0)
      uint32_t shift_amount = num_bits_in_message - (pos_in_block + 1);
      // Create mask of 1s on the message part, 0s in the carries
      uint32_t full_message_mask = message_modulus - 1;

      // Shift the mask so that we will only keep bits we should
      uint32_t shifted_mask = full_message_mask >> shift_amount;

      // TODO movie in scratch
      std::function<Torus(Torus)> lut_f_masking;
      lut_f_masking = [shifted_mask](Torus x) -> Torus {
        return x & shifted_mask;
      };
      generate_device_accumulator<Torus>(
          stream, masking_lut->lut, radix_params.glwe_dimension,
          radix_params.polynomial_size, radix_params.message_modulus,
          radix_params.carry_modulus, lut_f_masking);

      // end of move in scratch

      uint32_t last_block_index = big_lwe_size * (num_blocks - 1);

      integer_radix_apply_univariate_lookup_table_kb(
          stream, &interesting_divisor[last_block_index],
          &interesting_divisor[last_block_index], bsk, ksk, 1, masking_lut);
    }

    // trim_first_divisor_ms_bits
    if ((msb_bit_set + 1) / num_bits_in_message != (num_blocks - 1)) {
      // As above, we need to zero out some bits, but here it's in the
      // first block of most significant blocks of the divisor.
      // The block has the same value as the last block of interesting_divisor.
      // Here we will zero out the bits that the
      // trim_last_interesting_divisor_bits above wanted to keep.

      // Where the msb is set in the block
      uint32_t pos_in_block = msb_bit_set % num_bits_in_message;

      // e.g 2 bits in message:
      // if pos_in_block is 0, then we want to discard the first bit (left shift
      // mask by 1) if pos_in_block is 1, then we want to discard the two bits
      // (left shift mask by 2) let shift_amount = num_bits_in_message -
      // pos_in_block as u64;
      uint32_t shift_amount = pos_in_block + 1;
      uint32_t full_message_mask = message_modulus - 1;
      uint32_t shifted_mask = full_message_mask << shift_amount;
      // Keep the mask within the range of message bits, so that
      // the estimated degree of the output is < msg_modulus
      shifted_mask = shifted_mask & full_message_mask;

      // TODO movie in scratch
      std::function<Torus(Torus)> lut_f_masking;
      lut_f_masking = [shifted_mask](Torus x) -> Torus {
        return x & shifted_mask;
      };
      generate_device_accumulator<Torus>(
          stream, masking_lut->lut, radix_params.glwe_dimension,
          radix_params.polynomial_size, radix_params.message_modulus,
          radix_params.carry_modulus, lut_f_masking);

      // end of move in scratch

      integer_radix_apply_univariate_lookup_table_kb(stream, divisor_ms_blocks,
                                                     divisor_ms_blocks, bsk,
                                                     ksk, 1, masking_lut);
    }

    // left_shift_interesting_remainder1
    // This does
    //  R := R << 1; R(0) := N(i)
    //
    // We could to that by left shifting, R by one, then unchecked_add the
    // correct numerator bit.
    //
    // However, to keep the remainder clean (noise wise), what we do is that we
    // put the remainder block from which we need to extract the bit, as the LSB
    // of the Remainder, so that left shifting will pull the bit we need.

    if (numerator_block_stack_size) {
      uint32_t pos_in_block = msb_bit_set % num_bits_in_message;

      cuda_memcpy_async_gpu_to_gpu(
          &interesting_remainder1[big_lwe_size * interesting_remainder1_size],
          &numerator_block_stack[(numerator_block_stack_size - 1) *
                                 big_lwe_size],
          big_lwe_size_bytes, stream);
      numerator_block_stack_size--;
      interesting_remainder1_size++;
      host_integer_radix_logical_scalar_shift_kb_inplace(
          stream, interesting_remainder1, 1, mem_ptr->shift_mem, bsk, ksk,
          num_blocks);

      // Extract the block we prepended, and see if it should be dropped
      // or added back for processing
      radix_blocks_rotate_left<<<num_blocks, 256, 0, stream->stream>>>(
          interesting_remainder1, interesting_remainder1, 1, num_blocks,
          big_lwe_size);

      // This unwrap is unreachable, as we are removing the block we added
      // earlier
      if (pos_in_block != 0) {
        // We have not yet extracted all the bits from this numerator
        // so, we put it back on the front so that it gets taken next iteration
        cuda_memcpy_async_gpu_to_gpu(
            &numerator_block_stack[big_lwe_size * numerator_block_stack_size],
            &interesting_remainder1[(interesting_remainder1_size - 1) *
                                    big_lwe_size],
            big_lwe_size_bytes, stream);
        numerator_block_stack_size++;
      }
      interesting_remainder1_size--;
    }

    // left_shift_interesting_remainder2
    host_integer_radix_logical_scalar_shift_kb_inplace(
        stream, interesting_remainder2, 1, mem_ptr->shift_mem, bsk, ksk,
        num_blocks);

    cuda_memcpy_async_gpu_to_gpu(merged_interesting_remainder,
                                 interesting_remainder1, radix_size_bytes,
                                 stream);

    host_addition(stream, merged_interesting_remainder,
                  merged_interesting_remainder, interesting_remainder2,
                  radix_params.big_lwe_dimension, num_blocks);

    // TODO there is a way to parallelize following 3 calls
    // do_overflowing_sub
    //    host_integer_overflowing_sub_kb(stream,
    //                                    cur_quotient,
    //                                    overflowed,
    //                                    merged_interesting_remainder,
    //                                    interesting_divisor,
    //                                    bsk, ksk, mem_ptr->overflow_sub_mem,
    //                                    num_blocks);

    break;
  }

  cuda_memcpy_async_gpu_to_gpu(quotient, cur_quotient, radix_size_bytes,
                               stream);
}

#endif // TFHE_RS_DIV_REM_CUH
