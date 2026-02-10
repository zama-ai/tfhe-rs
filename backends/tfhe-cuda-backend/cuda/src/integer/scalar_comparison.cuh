#ifndef CUDA_INTEGER_SCALAR_COMPARISON_OPS_CUH
#define CUDA_INTEGER_SCALAR_COMPARISON_OPS_CUH

#include "integer/comparison.cuh"
template <typename Torus>
Torus is_x_less_than_y_given_input_borrow(Torus last_x_block,
                                          Torus last_y_block, Torus borrow,
                                          uint32_t message_modulus) {
  Torus last_bit_pos = log2_int(message_modulus) - 1;
  Torus mask = (1 << last_bit_pos) - 1;
  Torus x_without_last_bit = last_x_block & mask;
  Torus y_without_last_bit = last_y_block & mask;

  bool input_borrow_to_last_bit =
      x_without_last_bit < (y_without_last_bit + borrow);

  Torus result = last_x_block - (last_y_block + borrow);

  Torus output_sign_bit = (result >> last_bit_pos) & 1;
  bool output_borrow = last_x_block < (last_y_block + borrow);

  Torus overflow_flag = (Torus)(input_borrow_to_last_bit ^ output_borrow);

  return output_sign_bit ^ overflow_flag;
}

template <typename Torus, typename KSTorus>
__host__ void scalar_compare_radix_blocks(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI *lwe_array_in, Torus *scalar_blocks,
    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks) {

  if (num_radix_blocks == 0)
    return;
  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")
  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")

  auto params = mem_ptr->params;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  // When rhs > lhs, the subtraction will overflow, and the bit of padding will
  // be set to 1
  // meaning that the output of the pbs will be the negative (modulo message
  // space)
  //
  // Example:
  // lhs: 1, rhs: 3, message modulus: 4, carry modulus 4
  // lhs - rhs = -2 % (4 * 4) = 14 = 1|1110 (padding_bit|b4b3b2b1)
  // Since there was an overflow the bit of padding is 1 and not 0.
  // When applying the LUT for an input value of 14 we would expect 1,
  // but since the bit of padding is 1, we will get -1 modulus our message
  // space, so (-1) % (4 * 4) = 15 = 1|1111 We then add one and get 0 = 0|0000

  auto subtracted_blocks = mem_ptr->tmp_block_comparisons;
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     subtracted_blocks, lwe_array_in);
  // Subtract
  // Here we need the true lwe sub, not the one that comes from shortint.
  host_scalar_subtraction_inplace<Torus>(
      streams, (Torus *)subtracted_blocks->ptr, scalar_blocks,
      big_lwe_dimension, num_radix_blocks, message_modulus, carry_modulus);

  // Apply LUT to compare to 0
  auto sign_lut = mem_ptr->eq_buffer->is_non_zero_lut;
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, lwe_array_out, subtracted_blocks, bsks, ksks, sign_lut,
      num_radix_blocks);

  // FIXME: without this sync signed scalar eq tests fail, I don't understand
  // the reason
  cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  // Add one
  // Here Lhs can have the following values: (-1) % (message modulus * carry
  // modulus), 0, 1 So the output values after the addition will be: 0, 1, 2
  host_add_scalar_one_inplace<Torus>(streams, lwe_array_out, message_modulus,
                                     carry_modulus);
}

template <typename Torus, typename KSTorus>
__host__ void integer_radix_unsigned_scalar_difference_check(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, Torus const *scalar_blocks,
    Torus const *h_scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> sign_handler_f, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks,
    uint32_t num_scalar_blocks) {
  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")
  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")

  auto params = mem_ptr->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  auto diff_buffer = mem_ptr->diff_buffer;

  // Reducing the signs is the bottleneck of the comparison algorithms,
  // however if the scalar case there is an improvement:
  //
  // The idea is to reduce the number of signs block we have to
  // reduce. We can do that by splitting the comparison problem in two parts.
  //
  // - One part where we compute the signs block between the scalar with just
  // enough blocks
  //   from the ciphertext that can represent the scalar value
  //
  // - The other part is to compare the ciphertext blocks not considered for the
  // sign
  //   computation with zero, and create a single sign block from that.
  //
  // The smaller the scalar value is compared to the ciphertext num bits
  // encrypted, the more the comparisons with zeros we have to do, and the less
  // signs block we will have to reduce.
  //
  // This will create a speedup as comparing a bunch of blocks with 0
  // is faster
  if (num_scalar_blocks == 0) {
    // We only have to compare blocks with zero
    // means scalar is zero
    host_compare_blocks_with_zero<Torus>(
        streams, mem_ptr->tmp_lwe_array_out, lwe_array_in, mem_ptr, bsks, ksks,
        num_radix_blocks, mem_ptr->is_zero_lut);
    are_all_comparisons_block_true<Torus>(
        streams, mem_ptr->tmp_lwe_array_out, mem_ptr->tmp_lwe_array_out,
        mem_ptr, bsks, ksks, mem_ptr->tmp_lwe_array_out->num_radix_blocks);

    auto scalar_last_leaf_lut_f = [sign_handler_f](Torus x) -> Torus {
      x = (x == 1 ? IS_EQUAL : IS_SUPERIOR);

      return sign_handler_f(x);
    };

    auto lut = mem_ptr->diff_buffer->tree_buffer->tree_last_leaf_scalar_lut;
    auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
    lut->generate_and_broadcast_lut(
        active_streams, {0}, {scalar_last_leaf_lut_f}, LUT_0_FOR_ALL_BLOCKS,
        true, {&mem_ptr->diff_buffer->tree_buffer->h_preallocated_lut});

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, lwe_array_out, mem_ptr->tmp_lwe_array_out, bsks, ksks, lut, 1);

  } else if (num_scalar_blocks < num_radix_blocks) {
    // We have to handle both part of the work described above

    uint32_t num_lsb_radix_blocks = num_scalar_blocks;
    uint32_t num_msb_radix_blocks = num_radix_blocks - num_lsb_radix_blocks;

    CudaRadixCiphertextFFI msb;
    as_radix_ciphertext_slice<Torus>(&msb, lwe_array_in, num_lsb_radix_blocks,
                                     num_radix_blocks);

    auto lwe_array_lsb_out = mem_ptr->tmp_lwe_array_out;
    CudaRadixCiphertextFFI lwe_array_msb_out;
    // host_compare_with_zero equality is kind of flawed because it returns a
    // single LWE block but requires the output array to have more than 1 block
    // to compute intermediate values, hence why we have to take more than 1 LWE
    // here
    as_radix_ciphertext_slice<Torus>(
        &lwe_array_msb_out, mem_ptr->tmp_lwe_array_out, 1,
        mem_ptr->tmp_lwe_array_out->num_radix_blocks);

    auto lsb_streams = mem_ptr->lsb_streams;
    auto msb_streams = mem_ptr->msb_streams;

    streams.synchronize();

    //////////////
    // lsb
    auto lhs = diff_buffer->tmp_packed;
    CudaRadixCiphertextFFI rhs;
    as_radix_ciphertext_slice<Torus>(&rhs, lhs, num_radix_blocks / 2,
                                     lhs->num_radix_blocks);

    pack_blocks<Torus>(lsb_streams.stream(0), streams.gpu_index(0), lhs,
                       lwe_array_in, num_lsb_radix_blocks, message_modulus);
    scalar_pack_blocks<Torus>(lsb_streams.stream(0), streams.gpu_index(0), &rhs,
                              scalar_blocks, num_scalar_blocks,
                              message_modulus);

    // From this point we have half number of blocks
    num_lsb_radix_blocks /= 2;
    num_lsb_radix_blocks += (num_scalar_blocks % 2);

    // comparisons will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs

    auto comparisons = mem_ptr->tmp_block_comparisons;
    scalar_compare_radix_blocks<Torus>(
        lsb_streams, comparisons, diff_buffer->tmp_packed, (Torus *)rhs.ptr,
        mem_ptr, bsks, ksks, num_lsb_radix_blocks);

    // Reduces a vec containing radix blocks that encrypts a sign
    // (inferior, equal, superior) to one single radix block containing the
    // final sign
    tree_sign_reduction<Torus>(lsb_streams, lwe_array_lsb_out, comparisons,
                               mem_ptr->diff_buffer->tree_buffer,
                               mem_ptr->identity_lut_f, bsks, ksks,
                               num_lsb_radix_blocks);
    //////////////
    // msb
    host_compare_blocks_with_zero<Torus>(
        msb_streams, &lwe_array_msb_out, &msb, mem_ptr, bsks, ksks,
        num_msb_radix_blocks, mem_ptr->is_zero_lut);
    are_all_comparisons_block_true<Torus>(
        msb_streams, &lwe_array_msb_out, &lwe_array_msb_out, mem_ptr, bsks,
        ksks, lwe_array_msb_out.num_radix_blocks);
    lsb_streams.synchronize();
    msb_streams.synchronize();

    //////////////
    // Reduce the two blocks into one final

    auto scalar_bivariate_last_leaf_lut_f =
        [sign_handler_f](Torus lsb, Torus msb) -> Torus {
      if (msb == 1)
        return sign_handler_f(lsb);
      else
        return sign_handler_f(IS_SUPERIOR);
    };

    auto lut = diff_buffer->tree_buffer->tree_last_leaf_scalar_lut;
    auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
    lut->generate_and_broadcast_bivariate_lut(
        active_streams, {0}, {scalar_bivariate_last_leaf_lut_f},
        LUT_0_FOR_ALL_BLOCKS,
        {&mem_ptr->diff_buffer->tree_buffer->h_preallocated_lut});

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, lwe_array_out, lwe_array_lsb_out, &lwe_array_msb_out, bsks,
        ksks, lut, 1, lut->params.message_modulus);

  } else {
    if (num_radix_blocks == 1) {
      std::pair<bool, bool> invert_flags = get_invert_flags(mem_ptr->op);
      Torus scalar = h_scalar_blocks[0];
      auto one_block_lut_f = [invert_flags, scalar](Torus x) -> Torus {
        Torus x_0;
        Torus x_1;
        if (invert_flags.first) {
          x_0 = scalar;
          x_1 = x;
        } else {
          x_0 = x;
          x_1 = scalar;
        }
        auto overflowed = x_0 < x_1;
        return (Torus)(invert_flags.second ^ overflowed);
      };
      uint64_t size = 0;
      int_radix_lut<Torus> *one_block_lut =
          new int_radix_lut<Torus>(streams, params, 1, 1, true, size);

      auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
      one_block_lut->generate_and_broadcast_lut(
          active_streams, {0}, {one_block_lut_f}, LUT_0_FOR_ALL_BLOCKS, true,
          {&mem_ptr->h_preallocated_lut});

      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, lwe_array_out, lwe_array_in, bsks, ksks, one_block_lut, 1);
      one_block_lut->release(streams);
      delete one_block_lut;
    } else {
      // We only have to do the regular comparison
      // And not the part where we compare most significant blocks with zeros
      // num_radix_blocks == num_scalar_blocks
      uint32_t num_lsb_radix_blocks = num_radix_blocks;

      auto lhs = diff_buffer->tmp_packed;
      CudaRadixCiphertextFFI rhs;
      as_radix_ciphertext_slice<Torus>(&rhs, lhs, num_radix_blocks / 2,
                                       lhs->num_radix_blocks);

      pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), lhs,
                         lwe_array_in, num_lsb_radix_blocks, message_modulus);
      scalar_pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), &rhs,
                                scalar_blocks, num_scalar_blocks,
                                message_modulus);

      // From this point we have half number of blocks
      num_lsb_radix_blocks /= 2;

      // comparisons will be assigned
      // - 0 if lhs < rhs
      // - 1 if lhs == rhs
      // - 2 if lhs > rhs
      auto comparisons = mem_ptr->tmp_lwe_array_out;
      scalar_compare_radix_blocks<Torus>(
          streams, comparisons, diff_buffer->tmp_packed, (Torus *)rhs.ptr,
          mem_ptr, bsks, ksks, num_lsb_radix_blocks);

      // Reduces a vec containing radix blocks that encrypts a sign
      // (inferior, equal, superior) to one single radix block containing the
      // final sign
      tree_sign_reduction<Torus>(streams, lwe_array_out, comparisons,
                                 mem_ptr->diff_buffer->tree_buffer,
                                 sign_handler_f, bsks, ksks,
                                 num_lsb_radix_blocks);
    }
  }
}

template <typename Torus, typename KSTorus>
__host__ void integer_radix_signed_scalar_difference_check(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, Torus const *scalar_blocks,
    Torus const *h_scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> sign_handler_f, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks,
    uint32_t num_scalar_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")
  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")
  auto params = mem_ptr->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  auto diff_buffer = mem_ptr->diff_buffer;

  // Reducing the signs is the bottleneck of the comparison algorithms,
  // however if the scalar case there is an improvement:
  //
  // The idea is to reduce the number of signs block we have to
  // reduce. We can do that by splitting the comparison problem in two parts.
  //
  // - One part where we compute the signs block between the scalar with just
  // enough blocks
  //   from the ciphertext that can represent the scalar value
  //
  // - The other part is to compare the ciphertext blocks not considered for the
  // sign
  //   computation with zero, and create a single sign block from that.
  //
  // The smaller the scalar value is compared to the ciphertext num bits
  // encrypted, the more the comparisons with zeros we have to do, and the less
  // signs block we will have to reduce.
  //
  // This will create a speedup as comparing a bunch of blocks with 0
  // is faster
  if (num_scalar_blocks == 0) {
    // We only have to compare blocks with zero
    // means scalar is zero
    auto are_all_msb_zeros = mem_ptr->tmp_lwe_array_out;
    host_compare_blocks_with_zero<Torus>(
        streams, are_all_msb_zeros, lwe_array_in, mem_ptr, bsks, ksks,
        num_radix_blocks, mem_ptr->is_zero_lut);
    are_all_comparisons_block_true<Torus>(
        streams, are_all_msb_zeros, are_all_msb_zeros, mem_ptr, bsks, ksks,
        are_all_msb_zeros->num_radix_blocks);
    CudaRadixCiphertextFFI sign_block;
    as_radix_ciphertext_slice<Torus>(&sign_block, lwe_array_in,
                                     num_radix_blocks - 1, num_radix_blocks);

    auto sign_bit_pos = (int)log2_int(message_modulus) - 1;

    auto scalar_last_leaf_with_respect_to_zero_lut_f =
        [sign_handler_f, sign_bit_pos,
         message_modulus](Torus sign_block) -> Torus {
      sign_block %= message_modulus;
      int sign_bit_is_set = (sign_block >> sign_bit_pos) == 1;
      CMP_ORDERING sign_block_ordering;
      if (sign_bit_is_set) {
        sign_block_ordering = CMP_ORDERING::IS_INFERIOR;
      } else if (sign_block != 0) {
        sign_block_ordering = CMP_ORDERING::IS_SUPERIOR;
      } else {
        sign_block_ordering = CMP_ORDERING::IS_EQUAL;
      }

      return sign_block_ordering;
    };

    auto block_selector_f = mem_ptr->diff_buffer->tree_buffer->block_selector_f;
    auto scalar_bivariate_last_leaf_lut_f =
        [scalar_last_leaf_with_respect_to_zero_lut_f, sign_handler_f,
         block_selector_f](Torus are_all_zeros, Torus sign_block) -> Torus {
      // "re-code" are_all_zeros as an ordering value
      if (are_all_zeros == 1) {
        are_all_zeros = CMP_ORDERING::IS_EQUAL;
      } else {
        are_all_zeros = CMP_ORDERING::IS_SUPERIOR;
      }

      return sign_handler_f(block_selector_f(
          scalar_last_leaf_with_respect_to_zero_lut_f(sign_block),
          are_all_zeros));
    };

    auto lut = mem_ptr->diff_buffer->tree_buffer->tree_last_leaf_scalar_lut;

    auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
    lut->generate_and_broadcast_bivariate_lut(
        active_streams, {0}, {scalar_bivariate_last_leaf_lut_f},
        LUT_0_FOR_ALL_BLOCKS,
        {&mem_ptr->diff_buffer->tree_buffer->h_preallocated_lut});

    integer_radix_apply_bivariate_lookup_table<Torus>(
        streams, lwe_array_out, are_all_msb_zeros, &sign_block, bsks, ksks, lut,
        1, lut->params.message_modulus);

  } else if (num_scalar_blocks < num_radix_blocks) {
    // We have to handle both part of the work described above
    // And the sign bit is located in the most_significant_blocks

    uint32_t num_lsb_radix_blocks = num_scalar_blocks;
    uint32_t num_msb_radix_blocks = num_radix_blocks - num_lsb_radix_blocks;
    CudaRadixCiphertextFFI msb;
    as_radix_ciphertext_slice<Torus>(&msb, lwe_array_in, num_lsb_radix_blocks,
                                     num_radix_blocks);

    auto lwe_array_lsb_out = mem_ptr->tmp_lwe_array_out;
    CudaRadixCiphertextFFI lwe_array_msb_out;
    as_radix_ciphertext_slice<Torus>(&lwe_array_msb_out, lwe_array_lsb_out, 1,
                                     lwe_array_lsb_out->num_radix_blocks);

    auto lsb_streams = mem_ptr->lsb_streams;
    auto msb_streams = mem_ptr->msb_streams;
    streams.synchronize();

    //////////////
    // lsb
    auto lhs = diff_buffer->tmp_packed;
    CudaRadixCiphertextFFI rhs;
    as_radix_ciphertext_slice<Torus>(&rhs, lhs, num_radix_blocks / 2,
                                     lhs->num_radix_blocks);

    pack_blocks<Torus>(lsb_streams.stream(0), streams.gpu_index(0), lhs,
                       lwe_array_in, num_lsb_radix_blocks, message_modulus);
    scalar_pack_blocks<Torus>(lsb_streams.stream(0), streams.gpu_index(0), &rhs,
                              scalar_blocks, num_scalar_blocks,
                              message_modulus);

    // From this point we have half number of blocks
    num_lsb_radix_blocks /= 2;
    num_lsb_radix_blocks += (num_scalar_blocks % 2);

    // comparisons will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs

    auto comparisons = mem_ptr->tmp_block_comparisons;
    scalar_compare_radix_blocks<Torus>(
        lsb_streams, comparisons, diff_buffer->tmp_packed, (Torus *)rhs.ptr,
        mem_ptr, bsks, ksks, num_lsb_radix_blocks);

    // Reduces a vec containing radix blocks that encrypts a sign
    // (inferior, equal, superior) to one single radix block containing the
    // final sign
    tree_sign_reduction<Torus>(lsb_streams, lwe_array_lsb_out, comparisons,
                               mem_ptr->diff_buffer->tree_buffer,
                               mem_ptr->identity_lut_f, bsks, ksks,
                               num_lsb_radix_blocks);
    //////////////
    // msb
    // We remove the last block (which is the sign)
    auto are_all_msb_zeros = lwe_array_msb_out;
    host_compare_blocks_with_zero<Torus>(
        msb_streams, &are_all_msb_zeros, &msb, mem_ptr, bsks, ksks,
        num_msb_radix_blocks, mem_ptr->is_zero_lut);
    are_all_comparisons_block_true<Torus>(
        msb_streams, &are_all_msb_zeros, &are_all_msb_zeros, mem_ptr, bsks,
        ksks, are_all_msb_zeros.num_radix_blocks);

    auto sign_bit_pos = (int)log2(message_modulus) - 1;

    auto lut_f = [mem_ptr, sign_bit_pos](Torus sign_block,
                                         Torus msb_are_zeros) {
      bool sign_bit_is_set = (sign_block >> sign_bit_pos) == 1;
      CMP_ORDERING sign_block_ordering;
      if (sign_bit_is_set) {
        sign_block_ordering = CMP_ORDERING::IS_INFERIOR;
      } else if (sign_block != 0) {
        sign_block_ordering = CMP_ORDERING::IS_SUPERIOR;
      } else {
        sign_block_ordering = CMP_ORDERING::IS_EQUAL;
      }

      CMP_ORDERING msb_ordering;
      if (msb_are_zeros == 1)
        msb_ordering = CMP_ORDERING::IS_EQUAL;
      else
        msb_ordering = CMP_ORDERING::IS_SUPERIOR;

      return mem_ptr->diff_buffer->tree_buffer->block_selector_f(
          sign_block_ordering, msb_ordering);
    };

    auto signed_msb_lut = mem_ptr->signed_msb_lut;
    auto msb_active_streams = msb_streams.active_gpu_subset(1, params.pbs_type);
    signed_msb_lut->generate_and_broadcast_bivariate_lut(
        msb_active_streams, {0}, {lut_f}, LUT_0_FOR_ALL_BLOCKS,
        {&mem_ptr->h_preallocated_lut});

    CudaRadixCiphertextFFI sign_block;
    as_radix_ciphertext_slice<Torus>(
        &sign_block, &msb, num_msb_radix_blocks - 1, num_msb_radix_blocks);
    integer_radix_apply_bivariate_lookup_table<Torus>(
        msb_streams, &lwe_array_msb_out, &sign_block, &are_all_msb_zeros, bsks,
        ksks, signed_msb_lut, 1, signed_msb_lut->params.message_modulus);
    lsb_streams.synchronize();
    msb_streams.synchronize();

    //////////////
    // Reduce the two blocks into one final
    reduce_signs<Torus>(streams, lwe_array_out, lwe_array_lsb_out, mem_ptr,
                        sign_handler_f, bsks, ksks, 2);

  } else {
    if (num_radix_blocks == 1) {
      std::pair<bool, bool> invert_flags = get_invert_flags(mem_ptr->op);
      Torus scalar = h_scalar_blocks[0];
      auto one_block_lut_f = [invert_flags, scalar,
                              message_modulus](Torus x) -> Torus {
        Torus x_0;
        Torus x_1;
        if (invert_flags.first) {
          x_0 = scalar;
          x_1 = x;
        } else {
          x_0 = x;
          x_1 = scalar;
        }
        return (Torus)(invert_flags.second) ^
               is_x_less_than_y_given_input_borrow<Torus>(x_0, x_1, 0,
                                                          message_modulus);
      };
      uint64_t size = 0;
      int_radix_lut<Torus> *one_block_lut =
          new int_radix_lut<Torus>(streams, params, 1, 1, true, size);

      auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
      one_block_lut->generate_and_broadcast_lut(
          active_streams, {0}, {one_block_lut_f}, LUT_0_FOR_ALL_BLOCKS, true,
          {&mem_ptr->h_preallocated_lut});

      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, lwe_array_out, lwe_array_in, bsks, ksks, one_block_lut, 1);
      one_block_lut->release(streams);
      delete one_block_lut;
    } else {
      // We only have to do the regular comparison
      // And not the part where we compare most significant blocks with zeros
      // total_num_radix_blocks == total_num_scalar_blocks
      uint32_t num_lsb_radix_blocks = num_radix_blocks;

      streams.synchronize();
      auto lsb_streams = mem_ptr->lsb_streams;
      auto msb_streams = mem_ptr->msb_streams;

      auto lwe_array_ct_out = mem_ptr->tmp_lwe_array_out;
      CudaRadixCiphertextFFI lwe_array_sign_out;
      as_radix_ciphertext_slice<Torus>(&lwe_array_sign_out, lwe_array_ct_out,
                                       num_lsb_radix_blocks / 2,
                                       lwe_array_ct_out->num_radix_blocks);
      auto lhs = diff_buffer->tmp_packed;
      CudaRadixCiphertextFFI rhs;
      as_radix_ciphertext_slice<Torus>(&rhs, lhs, num_radix_blocks / 2,
                                       lhs->num_radix_blocks);

      pack_blocks<Torus>(lsb_streams.stream(0), streams.gpu_index(0), lhs,
                         lwe_array_in, num_lsb_radix_blocks - 1,
                         message_modulus);
      scalar_pack_blocks<Torus>(lsb_streams.stream(0), streams.gpu_index(0),
                                &rhs, scalar_blocks, num_lsb_radix_blocks - 1,
                                message_modulus);

      // From this point we have half number of blocks
      num_lsb_radix_blocks /= 2;

      // comparisons will be assigned
      // - 0 if lhs < rhs
      // - 1 if lhs == rhs
      // - 2 if lhs > rhs
      scalar_compare_radix_blocks<Torus>(
          lsb_streams, lwe_array_ct_out, diff_buffer->tmp_packed,
          (Torus *)rhs.ptr, mem_ptr, bsks, ksks, num_lsb_radix_blocks);
      CudaRadixCiphertextFFI encrypted_sign_block;
      as_radix_ciphertext_slice<Torus>(&encrypted_sign_block, lwe_array_in,
                                       num_radix_blocks - 1, num_radix_blocks);
      Torus const *scalar_sign_block = scalar_blocks + (num_scalar_blocks - 1);
      Torus const *h_scalar_sign_block =
          h_scalar_blocks + (num_scalar_blocks - 1);

      auto trivial_sign_block = mem_ptr->tmp_trivial_sign_block;
      set_trivial_radix_ciphertext_async<Torus>(
          msb_streams.stream(0), streams.gpu_index(0), trivial_sign_block,
          scalar_sign_block, h_scalar_sign_block, 1, message_modulus,
          carry_modulus);

      integer_radix_apply_bivariate_lookup_table<Torus>(
          msb_streams, &lwe_array_sign_out, &encrypted_sign_block,
          trivial_sign_block, bsks, ksks, mem_ptr->signed_lut, 1,
          mem_ptr->signed_lut->params.message_modulus);
      lsb_streams.synchronize();
      msb_streams.synchronize();

      // Reduces a vec containing radix blocks that encrypts a sign
      // (inferior, equal, superior) to one single radix block containing the
      // final sign
      reduce_signs<Torus>(streams, lwe_array_out, lwe_array_ct_out, mem_ptr,
                          sign_handler_f, bsks, ksks, num_lsb_radix_blocks + 1);
    }
  }
}

template <typename Torus, typename KSTorus>
__host__ void host_scalar_difference_check(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, Torus const *scalar_blocks,
    Torus const *h_scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> sign_handler_f, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks,
    uint32_t num_scalar_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")
  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")

  if (mem_ptr->is_signed) {
    // is signed and scalar is positive
    integer_radix_signed_scalar_difference_check<Torus>(
        streams, lwe_array_out, lwe_array_in, scalar_blocks, h_scalar_blocks,
        mem_ptr, sign_handler_f, bsks, ksks, num_radix_blocks,
        num_scalar_blocks);
  } else {
    integer_radix_unsigned_scalar_difference_check<Torus>(
        streams, lwe_array_out, lwe_array_in, scalar_blocks, h_scalar_blocks,
        mem_ptr, sign_handler_f, bsks, ksks, num_radix_blocks,
        num_scalar_blocks);
  }
}

template <typename Torus, typename KSTorus>
__host__ void
host_scalar_maxmin(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
                   CudaRadixCiphertextFFI const *lwe_array_in,
                   Torus const *scalar_blocks, Torus const *h_scalar_blocks,
                   int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
                   KSTorus *const *ksks, uint32_t num_radix_blocks,
                   uint32_t num_scalar_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions must be the same")
  if (lwe_array_out->num_radix_blocks < num_radix_blocks ||
      lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks should not be lower "
          "than the number of blocks to operate on")

  auto params = mem_ptr->params;

  // Calculates the difference sign between the ciphertext and the scalar
  // - 0 if lhs < rhs
  // - 1 if lhs == rhs
  // - 2 if lhs > rhs
  auto sign = mem_ptr->tmp_lwe_array_out;
  host_scalar_difference_check<Torus>(
      streams, sign, lwe_array_in, scalar_blocks, h_scalar_blocks, mem_ptr,
      mem_ptr->identity_lut_f, bsks, ksks, num_radix_blocks, num_scalar_blocks);

  // There is no optimized CMUX for scalars, so we convert to a trivial
  // ciphertext
  auto lwe_array_left = lwe_array_in;
  auto lwe_array_right = mem_ptr->tmp_block_comparisons;

  set_trivial_radix_ciphertext_async<Torus>(
      streams.stream(0), streams.gpu_index(0), lwe_array_right, scalar_blocks,
      h_scalar_blocks, num_scalar_blocks, params.message_modulus,
      params.carry_modulus);

  // Selector
  // CMUX for Max or Min
  host_cmux<Torus>(streams, lwe_array_out, mem_ptr->tmp_lwe_array_out,
                   lwe_array_left, lwe_array_right, mem_ptr->cmux_buffer, bsks,
                   ksks);
}

template <typename Torus, typename KSTorus>
__host__ void host_scalar_equality_check(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, Torus const *scalar_blocks,
    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks,
    uint32_t num_scalar_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions must be the same")
  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")

  auto params = mem_ptr->params;
  auto message_modulus = params.message_modulus;

  auto eq_buffer = mem_ptr->eq_buffer;

  auto scalar_comparison_luts = eq_buffer->scalar_comparison_luts;

  uint32_t num_halved_scalar_blocks =
      (num_scalar_blocks / 2) + (num_scalar_blocks % 2);

  uint32_t num_lsb_radix_blocks =
      std::min(num_radix_blocks, 2 * num_halved_scalar_blocks);
  uint32_t num_msb_radix_blocks = num_radix_blocks - num_lsb_radix_blocks;
  uint32_t num_halved_lsb_radix_blocks =
      (num_lsb_radix_blocks / 2) + (num_lsb_radix_blocks % 2);

  CudaRadixCiphertextFFI msb_in;
  if (num_msb_radix_blocks != 0)
    as_radix_ciphertext_slice<Torus>(&msb_in, lwe_array_in,
                                     num_lsb_radix_blocks,
                                     lwe_array_in->num_radix_blocks);

  CudaRadixCiphertextFFI msb_out;
  as_radix_ciphertext_slice<Torus>(&msb_out, mem_ptr->tmp_lwe_array_out,
                                   num_halved_lsb_radix_blocks,
                                   lwe_array_in->num_radix_blocks);

  streams.synchronize();

  auto lsb_streams = mem_ptr->lsb_streams;
  auto msb_streams = mem_ptr->msb_streams;

  if (num_halved_scalar_blocks > 0) {
    auto packed_blocks = mem_ptr->tmp_packed_input;
    CudaRadixCiphertextFFI packed_scalar;
    as_radix_ciphertext_slice<Torus>(&packed_scalar, packed_blocks,
                                     num_halved_lsb_radix_blocks,
                                     packed_blocks->num_radix_blocks);
    auto active_lsb_streams = lsb_streams.active_gpu_subset(
        num_halved_scalar_blocks, params.pbs_type);
    if (num_lsb_radix_blocks > 1) {
      pack_blocks<Torus>(lsb_streams.stream(0), lsb_streams.gpu_index(0),
                         packed_blocks, lwe_array_in, num_lsb_radix_blocks,
                         message_modulus);
      scalar_pack_blocks(lsb_streams.stream(0), streams.gpu_index(0),
                         &packed_scalar, scalar_blocks, num_scalar_blocks,
                         message_modulus);
      scalar_comparison_luts->set_lut_indexes_and_broadcast_from_gpu(
          active_lsb_streams, (Torus const *)packed_scalar.ptr,
          num_halved_scalar_blocks);
    } else if (num_lsb_radix_blocks == 1) {
      copy_radix_ciphertext_slice_async<Torus>(
          lsb_streams.stream(0), lsb_streams.gpu_index(0), packed_blocks, 0, 1,
          lwe_array_in, 0, 1);
      scalar_comparison_luts->set_lut_indexes_and_broadcast_from_gpu(
          active_lsb_streams, scalar_blocks, num_halved_scalar_blocks);
    }

    integer_radix_apply_univariate_lookup_table<Torus>(
        lsb_streams, mem_ptr->tmp_lwe_array_out, mem_ptr->tmp_packed_input,
        bsks, ksks, scalar_comparison_luts, num_halved_lsb_radix_blocks);
  }
  //////////////
  // msb_in
  if (num_msb_radix_blocks > 0) {
    int_radix_lut<Torus> *msb_lut;
    switch (mem_ptr->op) {
    case COMPARISON_TYPE::EQ:
      msb_lut = mem_ptr->is_zero_lut;
      break;
    case COMPARISON_TYPE::NE:
      msb_lut = mem_ptr->eq_buffer->is_non_zero_lut;
      break;
    default:
      PANIC("Cuda error: integer operation not supported")
    }

    host_compare_blocks_with_zero<Torus>(msb_streams, &msb_out, &msb_in,
                                         mem_ptr, bsks, ksks,
                                         num_msb_radix_blocks, msb_lut);
    are_all_comparisons_block_true<Torus>(msb_streams, &msb_out, &msb_out,
                                          mem_ptr, bsks, ksks,
                                          msb_out.num_radix_blocks);
  }

  lsb_streams.synchronize();
  msb_streams.synchronize();

  switch (mem_ptr->op) {
  case COMPARISON_TYPE::EQ:
    are_all_comparisons_block_true<Torus>(
        streams, lwe_array_out, mem_ptr->tmp_lwe_array_out, mem_ptr, bsks, ksks,
        num_halved_scalar_blocks + (num_msb_radix_blocks > 0));
    break;
  case COMPARISON_TYPE::NE:
    is_at_least_one_comparisons_block_true<Torus>(
        streams, lwe_array_out, mem_ptr->tmp_lwe_array_out, mem_ptr, bsks, ksks,
        num_halved_scalar_blocks + (num_msb_radix_blocks > 0));
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
}
#endif
