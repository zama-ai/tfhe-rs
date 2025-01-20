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

int ceil_div(int a, int b) { return (a + b - 1) / b; }

// struct makes it easier to use list of ciphertexts and move data between them
// struct does not allocate or drop any memory,
// keeps track on number of ciphertexts inside list.
template <typename Torus> struct lwe_ciphertext_list {
  Torus *data;
  size_t max_blocks;
  size_t len;
  int_radix_params params;

  size_t big_lwe_size;
  size_t big_lwe_size_bytes;
  size_t big_lwe_dimension;

  lwe_ciphertext_list(Torus *src, int_radix_params params, size_t max_blocks)
      : data(src), params(params), max_blocks(max_blocks) {
    big_lwe_size = params.big_lwe_dimension + 1;
    big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
    big_lwe_dimension = params.big_lwe_dimension;
    len = max_blocks;
  }

  // copies ciphertexts from Torus*, starting from `starting_block` including
  // `finish_block`, does not change the value of self len
  void copy_from(Torus *src, size_t start_block, size_t finish_block,
                 cudaStream_t stream, uint32_t gpu_index) {
    size_t tmp_len = finish_block - start_block + 1;
    cuda_memcpy_async_gpu_to_gpu(data, &src[start_block * big_lwe_size],
                                 tmp_len * big_lwe_size_bytes, stream,
                                 gpu_index);
  }

  // copies ciphertexts from lwe_ciphertext_list, starting from `starting_block`
  // including `finish_block`, does not change the value of self len
  void copy_from(const lwe_ciphertext_list &src, size_t start_block,
                 size_t finish_block, cudaStream_t stream, uint32_t gpu_index) {
    copy_from(src.data, start_block, finish_block, stream, gpu_index);
  }

  // copies ciphertexts from Torus*, starting from `starting_block`
  // including `finish_block`, updating the value of self len
  void clone_from(Torus *src, size_t start_block, size_t finish_block,
                  cudaStream_t stream, uint32_t gpu_index) {
    len = finish_block - start_block + 1;

    cuda_memcpy_async_gpu_to_gpu(data, &src[start_block * big_lwe_size],
                                 len * big_lwe_size_bytes, stream, gpu_index);
  }

  // copies ciphertexts from ciphertexts_list, starting from `starting_block`
  // including `finish_block`, updating the value of self len
  void clone_from(const lwe_ciphertext_list &src, size_t start_block,
                  size_t finish_block, cudaStream_t stream,
                  uint32_t gpu_index) {
    clone_from(src.data, start_block, finish_block, stream, gpu_index);
  }

  // assign zero to blocks starting from `start_block` including `finish_block`
  void assign_zero(size_t start_block, size_t finish_block, cudaStream_t stream,
                   uint32_t gpu_index) {
    auto size = finish_block - start_block + 1;
    cuda_memset_async(&data[start_block * big_lwe_size], 0,
                      size * big_lwe_size_bytes, stream, gpu_index);
  }

  // return pointer to last block
  Torus *last_block() { return &data[(len - 1) * big_lwe_size]; }

  // return pointer to first_block
  Torus *first_block() { return data; }

  // return block with `index`
  Torus *get_block(size_t index) {
    assert(index < len);
    return &data[index * big_lwe_size];
  }

  bool is_empty() { return len == 0; }

  // does not dop actual memory from `data`, only reduces value of `len` by one
  void pop() {
    if (len > 0)
      len--;
    else
      assert(len > 0);
  }

  // insert ciphertext at index `ind`
  void insert(size_t ind, Torus *ciphertext_block, cudaStream_t stream,
              uint32_t gpu_index) {
    assert(ind <= len);
    assert(len < max_blocks);

    size_t insert_offset = ind * big_lwe_size;

    for (size_t i = len; i > ind; i--) {
      Torus *src = &data[(i - 1) * big_lwe_size];
      Torus *dst = &data[i * big_lwe_size];
      cuda_memcpy_async_gpu_to_gpu(dst, src, big_lwe_size_bytes, stream,
                                   gpu_index);
    }

    cuda_memcpy_async_gpu_to_gpu(&data[insert_offset], ciphertext_block,
                                 big_lwe_size_bytes, stream, gpu_index);
    len++;
  }

  // push ciphertext at the end of `data`
  void push(Torus *ciphertext_block, cudaStream_t stream, uint32_t gpu_index) {
    assert(len < max_blocks);

    size_t offset = len * big_lwe_size;
    cuda_memcpy_async_gpu_to_gpu(&data[offset], ciphertext_block,
                                 big_lwe_size_bytes, stream, gpu_index);
    len++;
  }

  // duplicate ciphertext into `number_of_blocks` ciphertexts
  void fill_with_same_ciphertext(Torus *ciphertext, size_t number_of_blocks,
                                 cudaStream_t stream, uint32_t gpu_index) {
    assert(number_of_blocks <= max_blocks);

    for (size_t i = 0; i < number_of_blocks; i++) {
      Torus *dest = &data[i * big_lwe_size];
      cuda_memcpy_async_gpu_to_gpu(dest, ciphertext, big_lwe_size_bytes, stream,
                                   gpu_index);
    }

    len = number_of_blocks;
  }

  // used for debugging, prints body of each ciphertext.
  void print_blocks_body(const char *name) {
    for (int i = 0; i < len; i++) {
      print_debug(name, &data[i * big_lwe_size + big_lwe_dimension], 1);
    }
  }
};

template <typename Torus>
__host__ void scratch_cuda_integer_div_rem_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, bool is_signed, int_div_rem_memory<Torus> **mem_ptr,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  *mem_ptr =
      new int_div_rem_memory<Torus>(streams, gpu_indexes, gpu_count, params,
                                    is_signed, num_blocks, allocate_gpu_memory);
}

template <typename Torus>
__host__ void host_unsigned_integer_div_rem_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *quotient, Torus *remainder,
    Torus const *numerator, Torus const *divisor, void *const *bsks,
    uint64_t *const *ksks, unsigned_int_div_rem_memory<uint64_t> *mem_ptr,
    uint32_t num_blocks) {

  auto radix_params = mem_ptr->params;

  auto big_lwe_dimension = radix_params.big_lwe_dimension;
  auto big_lwe_size = big_lwe_dimension + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  uint32_t message_modulus = radix_params.message_modulus;
  uint32_t carry_modulus = radix_params.carry_modulus;
  uint32_t num_bits_in_message = 31 - __builtin_clz(message_modulus);
  uint32_t total_bits = num_bits_in_message * num_blocks;

  // put temporary buffers in lwe_ciphertext_list for easy use
  lwe_ciphertext_list<Torus> remainder1(mem_ptr->remainder1, radix_params,
                                        num_blocks);
  lwe_ciphertext_list<Torus> remainder2(mem_ptr->remainder2, radix_params,
                                        num_blocks);
  lwe_ciphertext_list<Torus> numerator_block_stack(
      mem_ptr->numerator_block_stack, radix_params, num_blocks);
  lwe_ciphertext_list<Torus> numerator_block_1(mem_ptr->numerator_block_1,
                                               radix_params, 1);
  lwe_ciphertext_list<Torus> tmp_radix(mem_ptr->tmp_radix, radix_params,
                                       num_blocks + 1);
  lwe_ciphertext_list<Torus> interesting_remainder1(
      mem_ptr->interesting_remainder1, radix_params, num_blocks + 1);
  lwe_ciphertext_list<Torus> interesting_remainder2(
      mem_ptr->interesting_remainder2, radix_params, num_blocks);
  lwe_ciphertext_list<Torus> interesting_divisor(mem_ptr->interesting_divisor,
                                                 radix_params, num_blocks);
  lwe_ciphertext_list<Torus> divisor_ms_blocks(mem_ptr->divisor_ms_blocks,
                                               radix_params, num_blocks);
  lwe_ciphertext_list<Torus> new_remainder(mem_ptr->new_remainder, radix_params,
                                           num_blocks);
  lwe_ciphertext_list<Torus> subtraction_overflowed(
      mem_ptr->subtraction_overflowed, radix_params, 1);
  lwe_ciphertext_list<Torus> did_not_overflow(mem_ptr->did_not_overflow,
                                              radix_params, 1);
  lwe_ciphertext_list<Torus> overflow_sum(mem_ptr->overflow_sum, radix_params,
                                          1);
  lwe_ciphertext_list<Torus> overflow_sum_radix(mem_ptr->overflow_sum_radix,
                                                radix_params, num_blocks);
  lwe_ciphertext_list<Torus> tmp_1(mem_ptr->tmp_1, radix_params, num_blocks);
  lwe_ciphertext_list<Torus> at_least_one_upper_block_is_non_zero(
      mem_ptr->at_least_one_upper_block_is_non_zero, radix_params, 1);
  lwe_ciphertext_list<Torus> cleaned_merged_interesting_remainder(
      mem_ptr->cleaned_merged_interesting_remainder, radix_params, num_blocks);

  numerator_block_stack.clone_from((Torus *)numerator, 0, num_blocks - 1,
                                   streams[0], gpu_indexes[0]);
  remainder1.assign_zero(0, num_blocks - 1, streams[0], gpu_indexes[0]);
  remainder2.assign_zero(0, num_blocks - 1, streams[0], gpu_indexes[0]);

  cuda_memset_async(quotient, 0, big_lwe_size_bytes * num_blocks, streams[0],
                    gpu_indexes[0]);

  for (int i = total_bits - 1; i >= 0; i--) {
    uint32_t block_of_bit = i / num_bits_in_message;
    uint32_t pos_in_block = i % num_bits_in_message;
    uint32_t msb_bit_set = total_bits - 1 - i;
    uint32_t last_non_trivial_block = msb_bit_set / num_bits_in_message;

    // Index to the first block of the remainder that is fully trivial 0
    // and all blocks after it are also trivial zeros
    // This number is in range 1..=num_bocks -1
    uint32_t first_trivial_block = last_non_trivial_block + 1;

    interesting_remainder1.clone_from(remainder1, 0, last_non_trivial_block,
                                      streams[0], gpu_indexes[0]);
    interesting_remainder2.clone_from(remainder2, 0, last_non_trivial_block,
                                      streams[0], gpu_indexes[0]);
    interesting_divisor.clone_from((Torus *)divisor, 0, last_non_trivial_block,
                                   streams[0], gpu_indexes[0]);
    divisor_ms_blocks.clone_from((Torus *)divisor,
                                 (msb_bit_set + 1) / num_bits_in_message,
                                 num_blocks - 1, streams[0], gpu_indexes[0]);

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

      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count, interesting_divisor.last_block(),
          interesting_divisor.last_block(), bsks, ksks, 1,
          mem_ptr->masking_luts_1[shifted_mask]);
    }; // trim_last_interesting_divisor_bits

    auto trim_first_divisor_ms_bits = [&](cudaStream_t const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count) {
      if (divisor_ms_blocks.is_empty() ||
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
          streams, gpu_indexes, gpu_count, divisor_ms_blocks.first_block(),
          divisor_ms_blocks.first_block(), bsks, ksks, 1,
          mem_ptr->masking_luts_2[shifted_mask]);
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
      numerator_block_1.clone_from(
          numerator_block_stack, numerator_block_stack.len - 1,
          numerator_block_stack.len - 1, streams[0], gpu_indexes[0]);
      numerator_block_stack.pop();
      interesting_remainder1.insert(0, numerator_block_1.first_block(),
                                    streams[0], gpu_indexes[0]);

      host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
          streams, gpu_indexes, gpu_count, interesting_remainder1.data, 1,
          mem_ptr->shift_mem_1, bsks, ksks, interesting_remainder1.len);

      tmp_radix.clone_from(interesting_remainder1, 0,
                           interesting_remainder1.len - 1, streams[0],
                           gpu_indexes[0]);

      host_radix_blocks_rotate_left<Torus>(
          streams, gpu_indexes, gpu_count, interesting_remainder1.data,
          tmp_radix.data, 1, interesting_remainder1.len, big_lwe_size);

      numerator_block_1.clone_from(
          interesting_remainder1, interesting_remainder1.len - 1,
          interesting_remainder1.len - 1, streams[0], gpu_indexes[0]);

      interesting_remainder1.pop();

      if (pos_in_block != 0) {
        // We have not yet extracted all the bits from this numerator
        // so, we put it back on the front so that it gets taken next
        // iteration
        numerator_block_stack.push(numerator_block_1.first_block(), streams[0],
                                   gpu_indexes[0]);
      }
    }; // left_shift_interesting_remainder1

    auto left_shift_interesting_remainder2 = [&](cudaStream_t const *streams,
                                                 uint32_t const *gpu_indexes,
                                                 uint32_t gpu_count) {
      host_integer_radix_logical_scalar_shift_kb_inplace<Torus>(
          streams, gpu_indexes, gpu_count, interesting_remainder2.data, 1,
          mem_ptr->shift_mem_2, bsks, ksks, interesting_remainder2.len);
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
    auto &merged_interesting_remainder = interesting_remainder1;

    legacy_host_addition<Torus>(
        streams[0], gpu_indexes[0], merged_interesting_remainder.data,
        merged_interesting_remainder.data, interesting_remainder2.data,
        radix_params.big_lwe_dimension, merged_interesting_remainder.len);

    // after create_clean_version_of_merged_remainder
    // `merged_interesting_remainder` will be reused as
    // `cleaned_merged_interesting_remainder`
    cleaned_merged_interesting_remainder.clone_from(
        merged_interesting_remainder, 0, merged_interesting_remainder.len - 1,
        streams[0], gpu_indexes[0]);

    assert(merged_interesting_remainder.len == interesting_divisor.len);

    // `new_remainder` is not initialized yet, so need to set length
    new_remainder.len = merged_interesting_remainder.len;

    // fills:
    //  `new_remainder` - radix ciphertext
    //  `subtraction_overflowed` - single ciphertext
    auto do_overflowing_sub = [&](cudaStream_t const *streams,
                                  uint32_t const *gpu_indexes,
                                  uint32_t gpu_count) {
      uint32_t compute_borrow = 1;
      uint32_t uses_input_borrow = 0;
      auto first_indexes = mem_ptr->first_indexes_for_overflow_sub
                               [merged_interesting_remainder.len - 1];
      auto second_indexes = mem_ptr->second_indexes_for_overflow_sub
                                [merged_interesting_remainder.len - 1];
      auto scalar_indexes =
          mem_ptr
              ->scalars_for_overflow_sub[merged_interesting_remainder.len - 1];
      mem_ptr->overflow_sub_mem->update_lut_indexes(
          streams, gpu_indexes, first_indexes, second_indexes, scalar_indexes,
          merged_interesting_remainder.len);
      host_integer_overflowing_sub<uint64_t>(
          streams, gpu_indexes, gpu_count, new_remainder.data,
          (uint64_t *)merged_interesting_remainder.data,
          interesting_divisor.data, subtraction_overflowed.data,
          (const Torus *)nullptr, mem_ptr->overflow_sub_mem, bsks, ksks,
          merged_interesting_remainder.len, compute_borrow, uses_input_borrow);
    };

    // fills:
    //  `at_least_one_upper_block_is_non_zero` - single ciphertext
    auto check_divisor_upper_blocks = [&](cudaStream_t const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count) {
      auto &trivial_blocks = divisor_ms_blocks;
      if (trivial_blocks.is_empty()) {
        cuda_memset_async(at_least_one_upper_block_is_non_zero.first_block(), 0,
                          big_lwe_size_bytes, streams[0], gpu_indexes[0]);
      } else {

        // We could call unchecked_scalar_ne
        // But we are in the special case where scalar == 0
        // So we can skip some stuff
        host_compare_with_zero_equality<Torus>(
            streams, gpu_indexes, gpu_count, tmp_1.data, trivial_blocks.data,
            mem_ptr->comparison_buffer, bsks, ksks, trivial_blocks.len,
            mem_ptr->comparison_buffer->eq_buffer->is_non_zero_lut);

        tmp_1.len =
            ceil_div(trivial_blocks.len, message_modulus * carry_modulus - 1);

        is_at_least_one_comparisons_block_true<Torus>(
            streams, gpu_indexes, gpu_count,
            at_least_one_upper_block_is_non_zero.data, tmp_1.data,
            mem_ptr->comparison_buffer, bsks, ksks, tmp_1.len);
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
              cleaned_merged_interesting_remainder.data,
              cleaned_merged_interesting_remainder.data, bsks, ksks,
              cleaned_merged_interesting_remainder.len,
              mem_ptr->message_extract_lut_1);
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

    legacy_host_addition<Torus>(streams[0], gpu_indexes[0], overflow_sum.data,
                                subtraction_overflowed.data,
                                at_least_one_upper_block_is_non_zero.data,
                                radix_params.big_lwe_dimension, 1);

    int factor = (i) ? 3 : 2;
    int factor_lut_id = factor - 2;
    overflow_sum_radix.fill_with_same_ciphertext(
        overflow_sum.first_block(), cleaned_merged_interesting_remainder.len,
        streams[0], gpu_indexes[0]);

    auto conditionally_zero_out_merged_interesting_remainder =
        [&](cudaStream_t const *streams, uint32_t const *gpu_indexes,
            uint32_t gpu_count) {
          integer_radix_apply_bivariate_lookup_table_kb<Torus>(
              streams, gpu_indexes, gpu_count,
              cleaned_merged_interesting_remainder.data,
              cleaned_merged_interesting_remainder.data,
              overflow_sum_radix.data, bsks, ksks,
              cleaned_merged_interesting_remainder.len,
              mem_ptr->zero_out_if_overflow_did_not_happen[factor_lut_id],
              factor);
        };

    auto conditionally_zero_out_merged_new_remainder =
        [&](cudaStream_t const *streams, uint32_t const *gpu_indexes,
            uint32_t gpu_count) {
          integer_radix_apply_bivariate_lookup_table_kb<Torus>(
              streams, gpu_indexes, gpu_count, new_remainder.data,
              new_remainder.data, overflow_sum_radix.data, bsks, ksks,
              new_remainder.len,
              mem_ptr->zero_out_if_overflow_happened[factor_lut_id], factor);
        };

    auto set_quotient_bit = [&](cudaStream_t const *streams,
                                uint32_t const *gpu_indexes,
                                uint32_t gpu_count) {
      integer_radix_apply_bivariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count, did_not_overflow.data,
          subtraction_overflowed.data,
          at_least_one_upper_block_is_non_zero.data, bsks, ksks, 1,
          mem_ptr->merge_overflow_flags_luts[pos_in_block],
          mem_ptr->merge_overflow_flags_luts[pos_in_block]
              ->params.message_modulus);

      legacy_host_addition<Torus>(
          streams[0], gpu_indexes[0], &quotient[block_of_bit * big_lwe_size],
          &quotient[block_of_bit * big_lwe_size], did_not_overflow.data,
          radix_params.big_lwe_dimension, 1);
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

    assert(first_trivial_block - 1 == cleaned_merged_interesting_remainder.len);
    assert(first_trivial_block - 1 == new_remainder.len);

    remainder1.copy_from(cleaned_merged_interesting_remainder, 0,
                         first_trivial_block - 1, streams[0], gpu_indexes[0]);
    remainder2.copy_from(new_remainder, 0, first_trivial_block - 1, streams[0],
                         gpu_indexes[0]);
  }

  assert(remainder1.len == remainder2.len);

  // Clean the quotient and remainder
  // as even though they have no carries, they are not at nominal noise level
  legacy_host_addition<Torus>(streams[0], gpu_indexes[0], remainder,
                              remainder1.data, remainder2.data,
                              radix_params.big_lwe_dimension, remainder1.len);

  for (uint j = 0; j < gpu_count; j++) {
    cuda_synchronize_stream(streams[j], gpu_indexes[j]);
  }
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      mem_ptr->sub_streams_1, gpu_indexes, gpu_count, remainder, remainder,
      bsks, ksks, num_blocks, mem_ptr->message_extract_lut_1);
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      mem_ptr->sub_streams_2, gpu_indexes, gpu_count, quotient, quotient, bsks,
      ksks, num_blocks, mem_ptr->message_extract_lut_2);
  for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
    cuda_synchronize_stream(mem_ptr->sub_streams_1[j], gpu_indexes[j]);
    cuda_synchronize_stream(mem_ptr->sub_streams_2[j], gpu_indexes[j]);
  }
}

template <typename Torus>
__host__ void host_integer_div_rem_kb(cudaStream_t const *streams,
                                      uint32_t const *gpu_indexes,
                                      uint32_t gpu_count, Torus *quotient,
                                      Torus *remainder, Torus const *numerator,
                                      Torus const *divisor, bool is_signed,
                                      void *const *bsks, uint64_t *const *ksks,
                                      int_div_rem_memory<uint64_t> *int_mem_ptr,
                                      uint32_t num_blocks) {

  if (is_signed) {
    auto radix_params = int_mem_ptr->params;
    uint32_t big_lwe_size = radix_params.big_lwe_dimension + 1;

    // temporary memory
    lwe_ciphertext_list<Torus> positive_numerator(
        int_mem_ptr->positive_numerator, radix_params, num_blocks);
    lwe_ciphertext_list<Torus> positive_divisor(int_mem_ptr->positive_divisor,
                                                radix_params, num_blocks);

    positive_numerator.clone_from((Torus *)numerator, 0, num_blocks - 1,
                                  streams[0], gpu_indexes[0]);
    positive_divisor.clone_from((Torus *)divisor, 0, num_blocks - 1, streams[0],
                                gpu_indexes[0]);

    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }

    legacy_host_integer_abs_kb_async<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count,
        positive_numerator.data, bsks, ksks, int_mem_ptr->abs_mem_1, true,
        num_blocks);
    legacy_host_integer_abs_kb_async<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count,
        positive_divisor.data, bsks, ksks, int_mem_ptr->abs_mem_2, true,
        num_blocks);
    for (uint j = 0; j < int_mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(int_mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(int_mem_ptr->sub_streams_2[j], gpu_indexes[j]);
    }

    host_unsigned_integer_div_rem_kb<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count, quotient, remainder,
        positive_numerator.data, positive_divisor.data, bsks, ksks,
        int_mem_ptr->unsigned_mem, num_blocks);

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count,
        int_mem_ptr->sign_bits_are_different,
        &numerator[big_lwe_size * (num_blocks - 1)],
        &divisor[big_lwe_size * (num_blocks - 1)], bsks, ksks, 1,
        int_mem_ptr->compare_signed_bits_lut,
        int_mem_ptr->compare_signed_bits_lut->params.message_modulus);

    for (uint j = 0; j < int_mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(int_mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(int_mem_ptr->sub_streams_2[j], gpu_indexes[j]);
    }

    host_integer_radix_negation(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count,
        int_mem_ptr->negated_quotient, quotient, radix_params.big_lwe_dimension,
        num_blocks, radix_params.message_modulus, radix_params.carry_modulus);

    uint32_t requested_flag = outputFlag::FLAG_NONE;
    uint32_t uses_carry = 0;
    host_propagate_single_carry<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count,
        int_mem_ptr->negated_quotient, nullptr, nullptr, int_mem_ptr->scp_mem_1,
        bsks, ksks, num_blocks, requested_flag, uses_carry);

    host_integer_radix_negation(int_mem_ptr->sub_streams_2, gpu_indexes,
                                gpu_count, int_mem_ptr->negated_remainder,
                                remainder, radix_params.big_lwe_dimension,
                                num_blocks, radix_params.message_modulus,
                                radix_params.carry_modulus);

    host_propagate_single_carry<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count,
        int_mem_ptr->negated_remainder, nullptr, nullptr,
        int_mem_ptr->scp_mem_2, bsks, ksks, num_blocks, requested_flag,
        uses_carry);

    legacy_host_integer_radix_cmux_kb<Torus>(
        int_mem_ptr->sub_streams_1, gpu_indexes, gpu_count, quotient,
        int_mem_ptr->sign_bits_are_different, int_mem_ptr->negated_quotient,
        quotient, int_mem_ptr->cmux_quotient_mem, bsks, ksks, num_blocks);

    legacy_host_integer_radix_cmux_kb<Torus>(
        int_mem_ptr->sub_streams_2, gpu_indexes, gpu_count, remainder,
        &numerator[big_lwe_size * (num_blocks - 1)],
        int_mem_ptr->negated_remainder, remainder,
        int_mem_ptr->cmux_remainder_mem, bsks, ksks, num_blocks);

    for (uint j = 0; j < int_mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(int_mem_ptr->sub_streams_1[j], gpu_indexes[j]);
      cuda_synchronize_stream(int_mem_ptr->sub_streams_2[j], gpu_indexes[j]);
    }
  } else {
    host_unsigned_integer_div_rem_kb<Torus>(
        streams, gpu_indexes, gpu_count, quotient, remainder, numerator,
        divisor, bsks, ksks, int_mem_ptr->unsigned_mem, num_blocks);
  }
}

#endif // TFHE_RS_DIV_REM_CUH
