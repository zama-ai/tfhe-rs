#ifndef TFHE_RS_DIV_REM_CUH
#define TFHE_RS_DIV_REM_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer/abs.cuh"
#include "integer/cast.cuh"
#include "integer/comparison.cuh"
#include "integer/div_rem.h"
#include "integer/integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/scalar_shifts.cuh"
#include "integer/subtraction.cuh"
#include <fstream>

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_div_rem(
    CudaStreams streams, bool is_signed, int_div_rem_memory<Torus> **mem_ptr,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr =
      new int_div_rem_memory<Torus>(streams, params, is_signed, num_blocks,
                                    allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ void host_unsigned_integer_div_rem_block_by_block_2_2(
    CudaStreams streams, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, CudaRadixCiphertextFFI const *numerator,
    CudaRadixCiphertextFFI const *divisor, void *const *bsks,
    uint64_t *const *ksks, unsigned_int_div_rem_2_2_memory<uint64_t> *mem_ptr) {

  if (streams.count() < 4) {
    PANIC("GPU count should be greater than 4 when using div_rem_2_2");
  }
  if (mem_ptr->params.message_modulus != 4 ||
      mem_ptr->params.carry_modulus != 4) {
    PANIC("Only message_modulus == 4 && carry_modulus == 4 parameters are "
          "supported");
  }

  // alias
  auto radix_params = mem_ptr->params;
  auto num_blocks = quotient->num_radix_blocks;
  auto remainder_gpu_0 = remainder;
  auto remainder_gpu_1 = mem_ptr->remainder_gpu_1;
  auto remainder_gpu_2 = mem_ptr->remainder_gpu_2;
  auto remainder_gpu_3 = mem_ptr->remainder_gpu_3;
  auto divisor_gpu_0 = divisor;
  auto divisor_gpu_1 = mem_ptr->divisor_gpu_1;
  auto divisor_gpu_2 = mem_ptr->divisor_gpu_2;

  // gpu[0] -> gpu[0]
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     remainder_gpu_0, numerator);

  // gpu[0] -> gpu[1]
  copy_radix_ciphertext_async<Torus>(streams.stream(1), streams.gpu_index(1),
                                     remainder_gpu_1, numerator);
  // gpu[0] -> gpu[1]
  copy_radix_ciphertext_async<Torus>(streams.stream(1), streams.gpu_index(1),
                                     divisor_gpu_1, divisor);
  // gpu[0] -> gpu[2]
  copy_radix_ciphertext_async<Torus>(streams.stream(2), streams.gpu_index(2),
                                     remainder_gpu_2, numerator);
  // gpu[0] -> gpu[3]
  copy_radix_ciphertext_async<Torus>(streams.stream(3), streams.gpu_index(3),
                                     remainder_gpu_3, numerator);
  // gpu[0] -> gpu[2]
  copy_radix_ciphertext_async<Torus>(streams.stream(2), streams.gpu_index(2),
                                     divisor_gpu_2, divisor);

  // gpu[0]
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), quotient, 0, num_blocks);
  quotient->num_radix_blocks = 0;

  // Copy divisor_gpu_2 into d1 gpu[2] -> gpu[2]
  mem_ptr->d1->num_radix_blocks = divisor_gpu_2->num_radix_blocks;
  copy_radix_ciphertext_async<Torus>(streams.stream(2), streams.gpu_index(2),
                                     mem_ptr->d1, divisor_gpu_2);

  // Computes 2*d by extending and shifting on gpu[1]
  host_extend_radix_with_trivial_zero_blocks_msb<Torus>(
      mem_ptr->d2, divisor_gpu_1, streams.get_ith(1));
  host_logical_scalar_shift_inplace<Torus>(
      streams.get_ith(1), mem_ptr->d2, 1, mem_ptr->shift_mem, &bsks[1],
      &ksks[1], mem_ptr->d2->num_radix_blocks);

  // Computes 3*d = 4*d - d using block shift and subtraction on gpu[0]
  host_extend_radix_with_trivial_zero_blocks_msb<Torus>(
      mem_ptr->tmp_gpu_0, divisor_gpu_0, streams.get_ith(0));
  host_radix_blocks_rotate_right<Torus>(streams.get_ith(0), mem_ptr->d3,
                                        mem_ptr->tmp_gpu_0, 1,
                                        mem_ptr->tmp_gpu_0->num_radix_blocks);
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->d3, 0, 1);
  host_sub_and_propagate_single_carry(streams.get_ith(0), mem_ptr->d3,
                                      mem_ptr->tmp_gpu_0, nullptr, nullptr,
                                      mem_ptr->sub_and_propagate_mem, &bsks[0],
                                      &ksks[0], outputFlag::FLAG_NONE, 0);

  // +-----------------+-----------------+-----------------+-----------------+
  // |     GPU[0]      |     GPU[1]      |     GPU[2]      |     GPU[3]      |
  // +-----------------+-----------------+-----------------+-----------------+
  // | d3              | d2              | d1              | -               |
  // | low3            | low2            | low1            | -               |
  // | rem3            | rem2            | rem1            | rem0            |
  // | sub_result_1    | sub_result_2    | sub_result_3    | -               |
  // | s_1_overflowed  | s_2_overflowed  | s_3_overflowed  | -               |
  // | cmp_1           | cmp_2           | cmp_3           | -               |
  // | r3              | r2              | r1              | -               |
  // | o3              | o2              | o1              | -               |
  // | c3 = !o3        | c2 = !o2 + o3   | c1 = !o1 + o2   | c0 = o1         |
  // | z_o_not_1_lut_1 | z_o_not_2_lut_1 | z_o_not_2_lut_2 | z_o_not_1_lut_2 |
  // +-----------------+-----------------+-----------------+-----------------+
  for (int block_index = num_blocks - 1; block_index >= 0; block_index--) {

    uint32_t slice_len = num_blocks - block_index;

    auto init_low_rem_f =
        [&](CudaRadixCiphertextFFI *low, CudaRadixCiphertextFFI *xd,
            CudaRadixCiphertextFFI *rem, CudaRadixCiphertextFFI *cur_remainder,
            size_t gpu_index, bool init_low) {
          rem->num_radix_blocks = slice_len;
          if (init_low) {
            low->num_radix_blocks = slice_len;
            copy_radix_ciphertext_slice_async<Torus>(
                streams.stream(gpu_index), streams.gpu_index(gpu_index), low, 0,
                slice_len, xd, 0, slice_len);
          }
          copy_radix_ciphertext_slice_async<Torus>(
              streams.stream(gpu_index), streams.gpu_index(gpu_index), rem, 0,
              slice_len, cur_remainder, block_index, num_blocks);
        };

    init_low_rem_f(nullptr, nullptr, mem_ptr->rem0, remainder_gpu_3, 3, false);
    init_low_rem_f(mem_ptr->low1, mem_ptr->d1, mem_ptr->rem1, remainder_gpu_2,
                   2, true);
    init_low_rem_f(mem_ptr->low2, mem_ptr->d2, mem_ptr->rem2, remainder_gpu_1,
                   1, true);
    init_low_rem_f(mem_ptr->low3, mem_ptr->d3, mem_ptr->rem3, remainder_gpu_0,
                   0, true);

    auto sub_result_f = [&](CudaStreams streams, size_t gpu_index,
                            CudaRadixCiphertextFFI *sub_result,
                            CudaRadixCiphertextFFI *sub_overflowed,
                            int_borrow_prop_memory<Torus> *overflow_sub_mem,
                            CudaRadixCiphertextFFI *low,
                            CudaRadixCiphertextFFI *rem, Torus *first_indexes,
                            Torus *second_indexes, Torus *scalar_indexes) {
      uint32_t compute_overflow = 1;
      uint32_t uses_input_borrow = 0;
      sub_result->num_radix_blocks = low->num_radix_blocks;
      overflow_sub_mem->update_lut_indexes(
          streams.get_ith(gpu_index), first_indexes, second_indexes,
          scalar_indexes, rem->num_radix_blocks);
      host_integer_overflowing_sub<uint64_t>(
          streams.get_ith(gpu_index), sub_result, rem, low, sub_overflowed,
          (const CudaRadixCiphertextFFI *)nullptr, overflow_sub_mem,
          &bsks[gpu_index], &ksks[gpu_index], compute_overflow,
          uses_input_borrow);
    };

    auto cmp_f = [&](CudaStreams streams, size_t gpu_index,
                     CudaRadixCiphertextFFI *out_boolean_block,
                     CudaRadixCiphertextFFI *comparison_blocks,
                     CudaRadixCiphertextFFI *d,
                     int_comparison_buffer<Torus> *comparison_buffer) {
      CudaRadixCiphertextFFI d_msb;
      uint32_t slice_start = num_blocks - block_index;
      uint32_t slice_end = d->num_radix_blocks;
      as_radix_ciphertext_slice<Torus>(&d_msb, d, slice_start, slice_end);
      comparison_blocks->num_radix_blocks = d_msb.num_radix_blocks;
      if (d_msb.num_radix_blocks == 0) {
        cuda_memset_async((Torus *)out_boolean_block->ptr, 0,
                          safe_mul_sizeof<Torus>(
                              (size_t)(out_boolean_block->lwe_dimension + 1)),
                          streams.stream(gpu_index),
                          streams.gpu_index(gpu_index));
      } else {
        host_compare_blocks_with_zero<Torus>(
            streams.get_ith(gpu_index), comparison_blocks, &d_msb,
            comparison_buffer, &bsks[gpu_index], &ksks[gpu_index],
            d_msb.num_radix_blocks, comparison_buffer->is_zero_lut);
        are_all_comparisons_block_true(
            streams.get_ith(gpu_index), out_boolean_block, comparison_blocks,
            comparison_buffer, &bsks[gpu_index], &ksks[gpu_index],
            comparison_blocks->num_radix_blocks);

        host_negation<Torus>(
            streams.stream(gpu_index), streams.gpu_index(gpu_index),
            (Torus *)out_boolean_block->ptr, (Torus *)out_boolean_block->ptr,
            radix_params.big_lwe_dimension, 1);

        // we calculate encoding because this block works only for
        // message_modulus = 4 and carry_modulus = 4.
        const Torus encoded_scalar = 1ULL << (sizeof(Torus) * 8 - 5);
        host_addition_plaintext_scalar<Torus>(
            streams.stream(gpu_index), streams.gpu_index(gpu_index),
            (Torus *)out_boolean_block->ptr, (Torus *)out_boolean_block->ptr,
            encoded_scalar, radix_params.big_lwe_dimension, 1);
      }
    };

    for (uint j = 0; j < 3; j++) {
      cuda_synchronize_stream(streams.stream(j), streams.gpu_index(j));
    }

    size_t indexes_id = mem_ptr->rem3->num_radix_blocks - 1;
    sub_result_f(streams, 0, mem_ptr->sub_result_1, mem_ptr->sub_1_overflowed,
                 mem_ptr->overflow_sub_mem_1, mem_ptr->low3, mem_ptr->rem3,
                 mem_ptr->first_indexes_for_overflow_sub_gpu_0[indexes_id],
                 mem_ptr->second_indexes_for_overflow_sub_gpu_0[indexes_id],
                 mem_ptr->scalars_for_overflow_sub_gpu_0[indexes_id]);
    sub_result_f(streams, 1, mem_ptr->sub_result_2, mem_ptr->sub_2_overflowed,
                 mem_ptr->overflow_sub_mem_2, mem_ptr->low2, mem_ptr->rem2,
                 mem_ptr->first_indexes_for_overflow_sub_gpu_1[indexes_id],
                 mem_ptr->second_indexes_for_overflow_sub_gpu_1[indexes_id],
                 mem_ptr->scalars_for_overflow_sub_gpu_1[indexes_id]);
    sub_result_f(streams, 2, mem_ptr->sub_result_3, mem_ptr->sub_3_overflowed,
                 mem_ptr->overflow_sub_mem_3, mem_ptr->low1, mem_ptr->rem1,
                 mem_ptr->first_indexes_for_overflow_sub_gpu_2[indexes_id],
                 mem_ptr->second_indexes_for_overflow_sub_gpu_2[indexes_id],
                 mem_ptr->scalars_for_overflow_sub_gpu_2[indexes_id]);

    cmp_f(mem_ptr->sub_streams_1, 0, mem_ptr->cmp_1,
          mem_ptr->comparison_blocks_1, mem_ptr->d3,
          mem_ptr->comparison_buffer_1);
    cmp_f(mem_ptr->sub_streams_1, 1, mem_ptr->cmp_2,
          mem_ptr->comparison_blocks_2, mem_ptr->d2,
          mem_ptr->comparison_buffer_2);
    cmp_f(mem_ptr->sub_streams_1, 2, mem_ptr->cmp_3,
          mem_ptr->comparison_blocks_3, mem_ptr->d1,
          mem_ptr->comparison_buffer_3);

    for (uint j = 0; j < 3; j++) {
      cuda_synchronize_stream(streams.stream(j), streams.gpu_index(j));
      cuda_synchronize_stream(mem_ptr->sub_streams_1.stream(j),
                              mem_ptr->sub_streams_1.gpu_index(j));
    }

    auto r1 = mem_ptr->sub_result_3;
    auto r2 = mem_ptr->sub_result_2;
    auto r3 = mem_ptr->sub_result_1;
    auto o1 = mem_ptr->sub_3_overflowed;
    auto o2 = mem_ptr->sub_2_overflowed;
    auto o3 = mem_ptr->sub_1_overflowed;

    // used as a bitor
    host_bitop(streams.get_ith(0), o3, o3, mem_ptr->cmp_1, mem_ptr->bitor_mem_1,
               &bsks[0], &ksks[0]);
    // used as a bitor
    host_bitop(streams.get_ith(1), o2, o2, mem_ptr->cmp_2, mem_ptr->bitor_mem_2,
               &bsks[1], &ksks[1]);
    // used as a bitor
    host_bitop(streams.get_ith(2), o1, o1, mem_ptr->cmp_3, mem_ptr->bitor_mem_3,
               &bsks[2], &ksks[2]);

    // cmp_1, cmp_2, cmp_3 are not needed anymore, we can reuse them as c3,
    // c2, c1. c0 is allocated on gpu[3], we take it from mem_ptr.
    auto c3 = mem_ptr->cmp_1;
    auto c2 = mem_ptr->cmp_2;
    auto c1 = mem_ptr->cmp_3;
    auto c0 = mem_ptr->c0;

    // move all `o` so that each gpu has required `o` for calculating `c`
    auto o3_gpu_1 = mem_ptr->tmp_gpu_1;
    auto o2_gpu_2 = mem_ptr->tmp_gpu_2;
    auto o1_gpu_3 = mem_ptr->tmp_gpu_3;

    o3_gpu_1->num_radix_blocks = o3->num_radix_blocks;
    o2_gpu_2->num_radix_blocks = o2->num_radix_blocks;
    o1_gpu_3->num_radix_blocks = o1->num_radix_blocks;

    for (uint j = 0; j < 4; j++) {
      cuda_synchronize_stream(streams.stream(j), streams.gpu_index(j));
    }

    copy_radix_ciphertext_async<Torus>(streams.stream(1), streams.gpu_index(1),
                                       o3_gpu_1, o3);
    copy_radix_ciphertext_async<Torus>(streams.stream(2), streams.gpu_index(2),
                                       o2_gpu_2, o2);
    copy_radix_ciphertext_async<Torus>(streams.stream(3), streams.gpu_index(3),
                                       o1_gpu_3, o1);

    // c3 = !o3
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), c3, 0, 1, o3, 0, 1);
    host_negation<Torus>(streams.stream(0), streams.gpu_index(0),
                         (Torus *)c3->ptr, (Torus *)c3->ptr,
                         radix_params.big_lwe_dimension, 1);
    const Torus encoded_scalar = 1ULL << (sizeof(Torus) * 8 - 5);
    host_addition_plaintext_scalar<Torus>(
        streams.stream(0), streams.gpu_index(0), (Torus *)c3->ptr,
        (Torus *)c3->ptr, encoded_scalar, radix_params.big_lwe_dimension, 1);

    // c2 = !o2 + o3
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(1), streams.gpu_index(1), c2, 0, 1, o2, 0, 1);
    host_negation<Torus>(streams.stream(1), streams.gpu_index(1),
                         (Torus *)c2->ptr, (Torus *)c2->ptr,
                         radix_params.big_lwe_dimension, 1);
    host_addition_plaintext_scalar<Torus>(
        streams.stream(1), streams.gpu_index(1), (Torus *)c2->ptr,
        (Torus *)c2->ptr, encoded_scalar, radix_params.big_lwe_dimension, 1);
    host_addition<Torus>(streams.stream(1), streams.gpu_index(1), c2, c2,
                         o3_gpu_1, 1, 4, 4);

    // c1 = !o1 + o2
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(2), streams.gpu_index(2), c1, 0, 1, o1, 0, 1);
    host_negation<Torus>(streams.stream(2), streams.gpu_index(2),
                         (Torus *)c1->ptr, (Torus *)c1->ptr,
                         radix_params.big_lwe_dimension, 1);
    host_addition_plaintext_scalar<Torus>(
        streams.stream(2), streams.gpu_index(2), (Torus *)c1->ptr,
        (Torus *)c1->ptr, encoded_scalar, radix_params.big_lwe_dimension, 1);
    host_addition<Torus>(streams.stream(2), streams.gpu_index(2), c1, c1,
                         o2_gpu_2, 1, 4, 4);

    // c0 = o1 (direct copy)
    copy_radix_ciphertext_slice_async<Torus>(streams.stream(3),
                                             streams.gpu_index(3), mem_ptr->c0,
                                             0, 1, o1_gpu_3, 0, 1);

    auto conditional_update = [&](CudaStreams streams, size_t gpu_index,
                                  CudaRadixCiphertextFFI *cx,
                                  CudaRadixCiphertextFFI *rx,
                                  int_radix_lut<Torus> *lut, Torus factor) {
      auto rx_list = to_lwe_ciphertext_list(rx);
      host_cleartext_multiplication<Torus>(streams.stream(gpu_index),
                                           streams.gpu_index(gpu_index),
                                           (Torus *)rx->ptr, &rx_list, factor);
      host_add_the_same_block_to_all_blocks<Torus>(streams.stream(gpu_index),
                                                   streams.gpu_index(gpu_index),
                                                   rx, rx, cx, 4, 4);
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams.get_ith(gpu_index), rx, rx, &bsks[gpu_index],
          &ksks[gpu_index], lut, rx->num_radix_blocks);
    };

    for (uint j = 0; j < 4; j++) {
      cuda_synchronize_stream(streams.stream(j), streams.gpu_index(j));
      cuda_synchronize_stream(mem_ptr->sub_streams_1.stream(j),
                              mem_ptr->sub_streams_1.gpu_index(j));
    }

    conditional_update(streams, 0, c3, r3, mem_ptr->zero_out_if_not_1_lut_1, 2);
    conditional_update(streams, 1, c2, r2, mem_ptr->zero_out_if_not_2_lut_1, 3);
    conditional_update(streams, 2, c1, r1, mem_ptr->zero_out_if_not_2_lut_2, 3);
    conditional_update(streams, 3, c0, mem_ptr->rem0,
                       mem_ptr->zero_out_if_not_1_lut_2, 2);

    // calculate quotient bits GPU[2]
    integer_radix_apply_univariate_lookup_table<Torus>(
        mem_ptr->sub_streams_1.get_ith(2), mem_ptr->q1, c1, &bsks[2], &ksks[2],
        mem_ptr->quotient_lut_1, 1);
    // calculate quotient bits GPU[1]
    integer_radix_apply_univariate_lookup_table<Torus>(
        mem_ptr->sub_streams_1.get_ith(1), mem_ptr->q2, c2, &bsks[1], &ksks[1],
        mem_ptr->quotient_lut_2, 1);
    // calculate quotient bits GPU[0]
    integer_radix_apply_univariate_lookup_table<Torus>(
        mem_ptr->sub_streams_1.get_ith(0), mem_ptr->q3, c3, &bsks[0], &ksks[0],
        mem_ptr->quotient_lut_3, 1);

    for (uint j = 0; j < 4; j++) {
      cuda_synchronize_stream(streams.stream(j), streams.gpu_index(j));
      cuda_synchronize_stream(mem_ptr->sub_streams_1.stream(j),
                              mem_ptr->sub_streams_1.gpu_index(j));
    }

    // We need to accumulate rem, r1, r2, and r3, but each buffer currently
    // lives on a different GPU. To gather them on GPU[0], we’ll **reuse**
    // buffers already allocated on GPU[0]. At this point, the contents of rem3,
    // tmp_gpu_0, and low3 are no longer needed, so it’s safe to repurpose them.
    // Aliases for the GPU[0] destinations:
    auto r3_gpu_0 = r3;                 // reuse: destination for r3 on GPU[0]
    auto r2_gpu_0 = mem_ptr->tmp_gpu_0; // reuse: destination for r2 on GPU[0]
    auto r1_gpu_0 = mem_ptr->low3;      // reuse: destination for r1 on GPU[0]
    auto rem_gpu_0 = mem_ptr->rem3;     // reuse: destination for rem on GPU[0]

    r2_gpu_0->num_radix_blocks = r2->num_radix_blocks;
    // r3 is already on GPU 0, so no need to copy it.

    // Copy r2 from GPU[1] to GPU[0]
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       r2_gpu_0, r2);

    // Copy r1 from GPU[2] to GPU[0]
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       r1_gpu_0, r1);

    // Copy rem from GPU[3] to GPU[0]
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       rem_gpu_0, mem_ptr->rem0);

    // We do the same to accumulate quotient bits q1, q2 and q3. q3 is already
    // on GPU[0]. To copy q1 and q2 we will reuse buffers allocated on GPU[0]:
    // sub_1_overflowed and cmp_1.
    auto q3_gpu_0 = mem_ptr->q3; // q3 is already on GPU[0]
    auto q2_gpu_0 =
        mem_ptr->sub_1_overflowed;  // reuse: destination for q2 on GPU[0]
    auto q1_gpu_0 = mem_ptr->cmp_1; // reuse: destination for q1 on GPU[0]
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       q2_gpu_0, mem_ptr->q2);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       q1_gpu_0, mem_ptr->q1);

    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), rem_gpu_0,
                         rem_gpu_0, r3_gpu_0, rem_gpu_0->num_radix_blocks, 4,
                         4);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), rem_gpu_0,
                         rem_gpu_0, r2_gpu_0, rem_gpu_0->num_radix_blocks, 4,
                         4);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), rem_gpu_0,
                         rem_gpu_0, r1_gpu_0, rem_gpu_0->num_radix_blocks, 4,
                         4);

    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), q3_gpu_0,
                         q3_gpu_0, q2_gpu_0, 1, 4, 4);
    host_addition<Torus>(streams.stream(0), streams.gpu_index(0), q3_gpu_0,
                         q3_gpu_0, q1_gpu_0, 1, 4, 4);

    streams.synchronize();

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, rem_gpu_0, rem_gpu_0, bsks, ksks,
        mem_ptr->message_extract_lut_1, rem_gpu_0->num_radix_blocks);
    integer_radix_apply_univariate_lookup_table<Torus>(
        mem_ptr->sub_streams_1, q3_gpu_0, q3_gpu_0, bsks, ksks,
        mem_ptr->message_extract_lut_2, 1);
    streams.synchronize();
    mem_ptr->sub_streams_1.synchronize();

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), remainder_gpu_0, block_index,
        remainder_gpu_0->num_radix_blocks, rem_gpu_0, 0,
        rem_gpu_0->num_radix_blocks);
    insert_block_in_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), q3_gpu_0, quotient, 0);

    // Copy remainder_gpu_0 to all other GPUs
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       remainder_gpu_1, remainder_gpu_0);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       remainder_gpu_2, remainder_gpu_0);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       remainder_gpu_3, remainder_gpu_0);

    // non boolean blocks
    for (int block_id = 0; block_id < slice_len; block_id++) {
      mem_ptr->sub_result_1->degrees[block_id] =
          radix_params.message_modulus - 1;
      mem_ptr->rem0->degrees[block_id] = radix_params.message_modulus - 1;
    }

    // boolean blocks
    mem_ptr->cmp_3->degrees[0] = 0;
    mem_ptr->cmp_2->degrees[0] = 0;
    mem_ptr->cmp_1->degrees[0] = 0;
    mem_ptr->cmp_3->noise_levels[0] = 0;

    streams.synchronize();
  }
}

template <typename Torus>
__host__ void host_unsigned_integer_div_rem(
    CudaStreams streams, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, CudaRadixCiphertextFFI const *numerator,
    CudaRadixCiphertextFFI const *divisor, void *const *bsks,
    uint64_t *const *ksks, unsigned_int_div_rem_memory<uint64_t> *mem_ptr) {

  if (remainder->num_radix_blocks != numerator->num_radix_blocks ||
      remainder->num_radix_blocks != divisor->num_radix_blocks ||
      remainder->num_radix_blocks != quotient->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be equal")
  if (remainder->lwe_dimension != numerator->lwe_dimension ||
      remainder->lwe_dimension != divisor->lwe_dimension ||
      remainder->lwe_dimension != quotient->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimension must be equal")

  if (mem_ptr->params.message_modulus == 4 &&
      mem_ptr->params.carry_modulus == 4 && streams.count() >= 4) {
    host_unsigned_integer_div_rem_block_by_block_2_2<Torus>(
        streams, quotient, remainder, numerator, divisor, bsks, ksks,
        mem_ptr->div_rem_2_2_mem);
    return;
  }
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

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     numerator_block_stack, numerator);
  set_zero_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), quotient, 0, num_blocks);

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
        streams.stream(0), streams.gpu_index(0), interesting_remainder1, 0,
        first_trivial_block, remainder1, 0, first_trivial_block);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), interesting_remainder2, 0,
        first_trivial_block, remainder2, 0, first_trivial_block);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), interesting_divisor, 0,
        first_trivial_block, divisor, 0, first_trivial_block);
    if ((msb_bit_set + 1) / num_bits_in_message < num_blocks)
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), divisor_ms_blocks, 0,
          num_blocks - (msb_bit_set + 1) / num_bits_in_message, divisor,
          (msb_bit_set + 1) / num_bits_in_message, num_blocks);

    // We split the divisor at a block position, when in reality the split
    // should be at a bit position meaning that potentially (depending on
    // msb_bit_set) the split versions share some bits they should not. So we do
    // one PBS on the last block of the interesting_divisor, and first block of
    // divisor_ms_blocks to trim out bits which should not be there
    auto trim_last_interesting_divisor_bits = [&](CudaStreams streams) {
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
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, &last_interesting_divisor_block,
          &last_interesting_divisor_block, bsks, ksks,
          mem_ptr->masking_luts_1[shifted_mask], 1);
    }; // trim_last_interesting_divisor_bits

    auto trim_first_divisor_ms_bits = [&](CudaStreams streams) {
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

      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, divisor_ms_blocks, divisor_ms_blocks, bsks, ksks,
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
    auto left_shift_interesting_remainder1 = [&](CudaStreams streams) {
      pop_radix_ciphertext_block_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->numerator_block_1,
          numerator_block_stack);
      insert_block_in_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->numerator_block_1,
          interesting_remainder1, 0);

      host_logical_scalar_shift_inplace<Torus>(
          streams, interesting_remainder1, 1, mem_ptr->shift_mem_1, bsks, ksks,
          interesting_remainder1->num_radix_blocks);

      reset_radix_ciphertext_blocks(mem_ptr->tmp_radix,
                                    interesting_remainder1->num_radix_blocks);
      copy_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_radix,
          interesting_remainder1);

      host_radix_blocks_rotate_left<Torus>(
          streams, interesting_remainder1, mem_ptr->tmp_radix, 1,
          interesting_remainder1->num_radix_blocks);

      pop_radix_ciphertext_block_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->numerator_block_1,
          interesting_remainder1);

      if (pos_in_block != 0) {
        // We have not yet extracted all the bits from this numerator
        // so, we put it back on the front so that it gets taken next
        // iteration
        push_block_to_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), mem_ptr->numerator_block_1,
            numerator_block_stack);
      }
    }; // left_shift_interesting_remainder1

    auto left_shift_interesting_remainder2 = [&](CudaStreams streams) {
      host_logical_scalar_shift_inplace<Torus>(
          streams, interesting_remainder2, 1, mem_ptr->shift_mem_2, bsks, ksks,
          interesting_remainder2->num_radix_blocks);
    }; // left_shift_interesting_remainder2

    streams.synchronize();

    // interesting_divisor
    trim_last_interesting_divisor_bits(mem_ptr->sub_streams_1);
    // divisor_ms_blocks
    trim_first_divisor_ms_bits(mem_ptr->sub_streams_2);
    // interesting_remainder1
    // numerator_block_stack
    left_shift_interesting_remainder1(mem_ptr->sub_streams_3);
    // interesting_remainder2
    left_shift_interesting_remainder2(mem_ptr->sub_streams_4);

    mem_ptr->sub_streams_1.synchronize();
    mem_ptr->sub_streams_2.synchronize();
    mem_ptr->sub_streams_3.synchronize();
    mem_ptr->sub_streams_4.synchronize();

    // if interesting_remainder1 != 0 -> interesting_remainder2 == 0
    // if interesting_remainder1 == 0 -> interesting_remainder2 != 0
    // In practice interesting_remainder1 contains the numerator bit,
    // but in that position, interesting_remainder2 always has a 0
    auto merged_interesting_remainder = interesting_remainder1;

    host_addition<Torus>(
        streams.stream(0), streams.gpu_index(0), merged_interesting_remainder,
        merged_interesting_remainder, interesting_remainder2,
        merged_interesting_remainder->num_radix_blocks,
        radix_params.message_modulus, radix_params.carry_modulus);

    // after create_clean_version_of_merged_remainder
    // `merged_interesting_remainder` will be reused as
    // `cleaned_merged_interesting_remainder`
    reset_radix_ciphertext_blocks(
        cleaned_merged_interesting_remainder,
        merged_interesting_remainder->num_radix_blocks);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
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
    auto do_overflowing_sub = [&](CudaStreams streams) {
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
          streams, first_indexes, second_indexes, scalar_indexes,
          merged_interesting_remainder->num_radix_blocks);
      host_integer_overflowing_sub<uint64_t>(
          streams, new_remainder, merged_interesting_remainder,
          interesting_divisor, subtraction_overflowed,
          (const CudaRadixCiphertextFFI *)nullptr, mem_ptr->overflow_sub_mem,
          bsks, ksks, compute_borrow, uses_input_borrow);
    };

    // fills:
    //  `at_least_one_upper_block_is_non_zero` - single ciphertext
    auto check_divisor_upper_blocks = [&](CudaStreams streams) {
      auto trivial_blocks = divisor_ms_blocks;
      if (trivial_blocks->num_radix_blocks == 0) {
        set_zero_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0),
            at_least_one_upper_block_is_non_zero, 0, 1);
      } else {

        // We could call unchecked_scalar_ne
        // But we are in the special case where scalar == 0
        // So we can skip some stuff
        host_compare_blocks_with_zero<Torus>(
            streams, mem_ptr->tmp_1, trivial_blocks, mem_ptr->comparison_buffer,
            bsks, ksks, trivial_blocks->num_radix_blocks,
            mem_ptr->comparison_buffer->eq_buffer->is_non_zero_lut);

        is_at_least_one_comparisons_block_true<Torus>(
            streams, at_least_one_upper_block_is_non_zero, mem_ptr->tmp_1,
            mem_ptr->comparison_buffer, bsks, ksks,
            mem_ptr->tmp_1->num_radix_blocks);
      }
    };

    // Creates a cleaned version (noise wise) of the merged remainder
    // so that it can be safely used in bivariate PBSes
    // fills:
    //  `cleaned_merged_interesting_remainder` - radix ciphertext
    auto create_clean_version_of_merged_remainder = [&](CudaStreams streams) {
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, cleaned_merged_interesting_remainder,
          cleaned_merged_interesting_remainder, bsks, ksks,
          mem_ptr->message_extract_lut_1,
          cleaned_merged_interesting_remainder->num_radix_blocks);
    };

    // phase 2
    streams.synchronize();
    // new_remainder
    // subtraction_overflowed
    do_overflowing_sub(mem_ptr->sub_streams_1);
    // at_least_one_upper_block_is_non_zero
    check_divisor_upper_blocks(mem_ptr->sub_streams_2);
    // cleaned_merged_interesting_remainder
    create_clean_version_of_merged_remainder(mem_ptr->sub_streams_3);

    mem_ptr->sub_streams_1.synchronize();
    mem_ptr->sub_streams_2.synchronize();
    mem_ptr->sub_streams_3.synchronize();

    host_addition<Torus>(
        streams.stream(0), streams.gpu_index(0), overflow_sum,
        subtraction_overflowed, at_least_one_upper_block_is_non_zero, 1,
        radix_params.message_modulus, radix_params.carry_modulus);

    auto message_modulus = radix_params.message_modulus;
    int factor = (i) ? message_modulus - 1 : message_modulus - 2;
    int factor_lut_id = (i) ? 1 : 0;
    for (size_t k = 0;
         k < cleaned_merged_interesting_remainder->num_radix_blocks; k++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), overflow_sum_radix, k, k + 1,
          overflow_sum, 0, 1);
    }

    auto conditionally_zero_out_merged_interesting_remainder =
        [&](CudaStreams streams) {
          integer_radix_apply_bivariate_lookup_table<Torus>(
              streams, cleaned_merged_interesting_remainder,
              cleaned_merged_interesting_remainder, overflow_sum_radix, bsks,
              ksks, mem_ptr->zero_out_if_overflow_did_not_happen[factor_lut_id],
              cleaned_merged_interesting_remainder->num_radix_blocks, factor);
        };

    auto conditionally_zero_out_merged_new_remainder =
        [&](CudaStreams streams) {
          integer_radix_apply_bivariate_lookup_table<Torus>(
              streams, new_remainder, new_remainder, overflow_sum_radix, bsks,
              ksks, mem_ptr->zero_out_if_overflow_happened[factor_lut_id],
              new_remainder->num_radix_blocks, factor);
        };

    auto set_quotient_bit = [&](CudaStreams streams) {
      uint32_t block_of_bit = i / num_bits_in_message;
      integer_radix_apply_bivariate_lookup_table<Torus>(
          streams, mem_ptr->did_not_overflow, subtraction_overflowed,
          at_least_one_upper_block_is_non_zero, bsks, ksks,
          mem_ptr->merge_overflow_flags_luts[pos_in_block], 1,
          mem_ptr->merge_overflow_flags_luts[pos_in_block]
              ->params.message_modulus);

      CudaRadixCiphertextFFI quotient_block;
      as_radix_ciphertext_slice<Torus>(&quotient_block, quotient, block_of_bit,
                                       block_of_bit + 1);
      host_addition<Torus>(
          streams.stream(0), streams.gpu_index(0), &quotient_block,
          &quotient_block, mem_ptr->did_not_overflow, 1,
          radix_params.message_modulus, radix_params.carry_modulus);
    };

    streams.synchronize();

    // cleaned_merged_interesting_remainder
    conditionally_zero_out_merged_interesting_remainder(mem_ptr->sub_streams_1);
    // new_remainder
    conditionally_zero_out_merged_new_remainder(mem_ptr->sub_streams_2);
    // quotient
    set_quotient_bit(mem_ptr->sub_streams_3);

    mem_ptr->sub_streams_1.synchronize();
    mem_ptr->sub_streams_2.synchronize();
    mem_ptr->sub_streams_3.synchronize();

    if (first_trivial_block !=
        cleaned_merged_interesting_remainder->num_radix_blocks)
      PANIC("Cuda error: first_trivial_block should be equal to "
            "clean_merged_interesting_remainder num blocks")
    if (first_trivial_block != new_remainder->num_radix_blocks)
      PANIC("Cuda error: first_trivial_block should be equal to new_remainder "
            "num blocks")

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), remainder1, 0,
        first_trivial_block, cleaned_merged_interesting_remainder, 0,
        first_trivial_block);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), remainder2, 0,
        first_trivial_block, new_remainder, 0, first_trivial_block);
  }

  if (remainder1->num_radix_blocks != remainder2->num_radix_blocks)
    PANIC("Cuda error: remainder1 and remainder2 should have the same number "
          "of blocks")

  // Clean the quotient and remainder
  // as even though they have no carries, they are not at nominal noise level
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), remainder,
                       remainder1, remainder2, remainder1->num_radix_blocks,
                       radix_params.message_modulus,
                       radix_params.carry_modulus);

  streams.synchronize();

  integer_radix_apply_univariate_lookup_table<Torus>(
      mem_ptr->sub_streams_1, remainder, remainder, bsks, ksks,
      mem_ptr->message_extract_lut_1, num_blocks);
  integer_radix_apply_univariate_lookup_table<Torus>(
      mem_ptr->sub_streams_2, quotient, quotient, bsks, ksks,
      mem_ptr->message_extract_lut_2, num_blocks);

  mem_ptr->sub_streams_1.synchronize();
  mem_ptr->sub_streams_2.synchronize();
}

template <typename Torus>
__host__ void host_integer_div_rem(
    CudaStreams streams, CudaRadixCiphertextFFI *quotient,
    CudaRadixCiphertextFFI *remainder, CudaRadixCiphertextFFI const *numerator,
    CudaRadixCiphertextFFI const *divisor, bool is_signed, void *const *bsks,
    uint64_t *const *ksks, int_div_rem_memory<uint64_t> *int_mem_ptr) {
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
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       positive_numerator, numerator);
    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       positive_divisor, divisor);

    streams.synchronize();

    host_integer_abs<Torus>(int_mem_ptr->sub_streams_1, positive_numerator,
                            bsks, ksks, int_mem_ptr->abs_mem_1, true);
    host_integer_abs<Torus>(int_mem_ptr->sub_streams_2, positive_divisor, bsks,
                            ksks, int_mem_ptr->abs_mem_2, true);

    int_mem_ptr->sub_streams_1.synchronize();
    int_mem_ptr->sub_streams_2.synchronize();

    host_unsigned_integer_div_rem<Torus>(
        int_mem_ptr->sub_streams_1, quotient, remainder, positive_numerator,
        positive_divisor, bsks, ksks, int_mem_ptr->unsigned_mem);

    CudaRadixCiphertextFFI numerator_sign;
    as_radix_ciphertext_slice<Torus>(&numerator_sign, numerator, num_blocks - 1,
                                     num_blocks);
    CudaRadixCiphertextFFI divisor_sign;
    as_radix_ciphertext_slice<Torus>(&divisor_sign, divisor, num_blocks - 1,
                                     num_blocks);
    integer_radix_apply_bivariate_lookup_table<Torus>(
        int_mem_ptr->sub_streams_2, int_mem_ptr->sign_bits_are_different,
        &numerator_sign, &divisor_sign, bsks, ksks,
        int_mem_ptr->compare_signed_bits_lut, 1,
        int_mem_ptr->compare_signed_bits_lut->params.message_modulus);

    int_mem_ptr->sub_streams_1.synchronize();
    int_mem_ptr->sub_streams_2.synchronize();

    host_negation<Torus>(
        int_mem_ptr->sub_streams_1, int_mem_ptr->negated_quotient, quotient,
        radix_params.message_modulus, radix_params.carry_modulus, num_blocks);

    uint32_t requested_flag = outputFlag::FLAG_NONE;
    uint32_t uses_carry = 0;
    host_propagate_single_carry<Torus>(int_mem_ptr->sub_streams_1,
                                       int_mem_ptr->negated_quotient, nullptr,
                                       nullptr, int_mem_ptr->scp_mem_1, bsks,
                                       ksks, requested_flag, uses_carry);

    host_negation<Torus>(
        int_mem_ptr->sub_streams_2, int_mem_ptr->negated_remainder, remainder,
        radix_params.message_modulus, radix_params.carry_modulus, num_blocks);

    host_propagate_single_carry<Torus>(int_mem_ptr->sub_streams_2,
                                       int_mem_ptr->negated_remainder, nullptr,
                                       nullptr, int_mem_ptr->scp_mem_2, bsks,
                                       ksks, requested_flag, uses_carry);

    host_cmux<Torus>(int_mem_ptr->sub_streams_1, quotient,
                     int_mem_ptr->sign_bits_are_different,
                     int_mem_ptr->negated_quotient, quotient,
                     int_mem_ptr->cmux_quotient_mem, bsks, ksks);

    host_cmux<Torus>(int_mem_ptr->sub_streams_2, remainder, &numerator_sign,
                     int_mem_ptr->negated_remainder, remainder,
                     int_mem_ptr->cmux_remainder_mem, bsks, ksks);

    int_mem_ptr->sub_streams_1.synchronize();
    int_mem_ptr->sub_streams_2.synchronize();
  } else {
    host_unsigned_integer_div_rem<Torus>(streams, quotient, remainder,
                                         numerator, divisor, bsks, ksks,
                                         int_mem_ptr->unsigned_mem);
  }
}

#endif // TFHE_RS_DIV_REM_CUH
