#ifndef CUDA_INTEGER_SCALAR_COMPARISON_OPS_CUH
#define CUDA_INTEGER_SCALAR_COMPARISON_OPS_CUH

#include "integer/comparison.cuh"

template <typename Torus>
__host__ void scalar_compare_radix_blocks_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus *lwe_array_in,
    Torus *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks) {

  if (num_radix_blocks == 0)
    return;
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
  cuda_memcpy_async_gpu_to_gpu(subtracted_blocks, lwe_array_in,
                               num_radix_blocks * (big_lwe_dimension + 1) *
                                   sizeof(Torus),
                               streams[0], gpu_indexes[0]);
  // Subtract
  // Here we need the true lwe sub, not the one that comes from shortint.
  host_integer_radix_scalar_subtraction_inplace<Torus>(
      streams, gpu_indexes, gpu_count, subtracted_blocks, scalar_blocks,
      big_lwe_dimension, num_radix_blocks, message_modulus, carry_modulus);

  // Apply LUT to compare to 0
  auto sign_lut = mem_ptr->eq_buffer->is_non_zero_lut;
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, subtracted_blocks, bsks,
      ksks, num_radix_blocks, sign_lut);

  // Add one
  // Here Lhs can have the following values: (-1) % (message modulus * carry
  // modulus), 0, 1 So the output values after the addition will be: 0, 1, 2
  host_integer_radix_add_scalar_one_inplace<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, big_lwe_dimension,
      num_radix_blocks, message_modulus, carry_modulus);
}

template <typename Torus>
__host__ void integer_radix_unsigned_scalar_difference_check_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_in,
    Torus const *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> sign_handler_f, void *const *bsks,
    Torus *const *ksks, uint32_t total_num_radix_blocks,
    uint32_t total_num_scalar_blocks) {

  auto params = mem_ptr->params;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  auto diff_buffer = mem_ptr->diff_buffer;

  size_t big_lwe_size = big_lwe_dimension + 1;

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
  if (total_num_scalar_blocks == 0) {
    // We only have to compare blocks with zero
    // means scalar is zero
    host_compare_with_zero_equality<Torus>(
        streams, gpu_indexes, gpu_count, mem_ptr->tmp_lwe_array_out,
        lwe_array_in, mem_ptr, bsks, ksks, total_num_radix_blocks,
        mem_ptr->is_zero_lut);

    auto scalar_last_leaf_lut_f = [sign_handler_f](Torus x) -> Torus {
      x = (x == 1 ? IS_EQUAL : IS_SUPERIOR);

      return sign_handler_f(x);
    };

    auto lut = mem_ptr->diff_buffer->tree_buffer->tree_last_leaf_scalar_lut;
    generate_device_accumulator<Torus>(streams[0], gpu_indexes[0],
                                       lut->get_lut(0, 0), glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, scalar_last_leaf_lut_f);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out,
        mem_ptr->tmp_lwe_array_out, bsks, ksks, 1, lut);

  } else if (total_num_scalar_blocks < total_num_radix_blocks) {
    // We have to handle both part of the work described above

    uint32_t num_lsb_radix_blocks = total_num_scalar_blocks;
    uint32_t num_msb_radix_blocks =
        total_num_radix_blocks - num_lsb_radix_blocks;

    auto msb = lwe_array_in + num_lsb_radix_blocks * big_lwe_size;

    auto lwe_array_lsb_out = mem_ptr->tmp_lwe_array_out;
    auto lwe_array_msb_out = lwe_array_lsb_out + big_lwe_size;

    auto lsb_streams = mem_ptr->lsb_streams;
    auto msb_streams = mem_ptr->msb_streams;

    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }

    //////////////
    // lsb
    Torus *lhs = diff_buffer->tmp_packed;
    Torus *rhs =
        diff_buffer->tmp_packed + total_num_radix_blocks / 2 * big_lwe_size;

    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], lhs, lwe_array_in,
                       big_lwe_dimension, num_lsb_radix_blocks,
                       message_modulus);
    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], rhs, scalar_blocks, 0,
                       total_num_scalar_blocks, message_modulus);

    // From this point we have half number of blocks
    num_lsb_radix_blocks /= 2;
    num_lsb_radix_blocks += (total_num_scalar_blocks % 2);

    // comparisons will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs

    auto comparisons = mem_ptr->tmp_block_comparisons;
    scalar_compare_radix_blocks_kb<Torus>(lsb_streams, gpu_indexes, gpu_count,
                                          comparisons, lhs, rhs, mem_ptr, bsks,
                                          ksks, num_lsb_radix_blocks);

    // Reduces a vec containing radix blocks that encrypts a sign
    // (inferior, equal, superior) to one single radix block containing the
    // final sign
    tree_sign_reduction<Torus>(
        lsb_streams, gpu_indexes, gpu_count, lwe_array_lsb_out, comparisons,
        mem_ptr->diff_buffer->tree_buffer, mem_ptr->identity_lut_f, bsks, ksks,
        num_lsb_radix_blocks);
    //////////////
    // msb
    host_compare_with_zero_equality<Torus>(
        msb_streams, gpu_indexes, gpu_count, lwe_array_msb_out, msb, mem_ptr,
        bsks, ksks, num_msb_radix_blocks, mem_ptr->is_zero_lut);
    for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(lsb_streams[j], gpu_indexes[j]);
      cuda_synchronize_stream(msb_streams[j], gpu_indexes[j]);
    }

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
    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], lut->get_lut(0, 0), glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        scalar_bivariate_last_leaf_lut_f);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_lsb_out,
        lwe_array_msb_out, bsks, ksks, 1, lut, lut->params.message_modulus);

  } else {
    // We only have to do the regular comparison
    // And not the part where we compare most significant blocks with zeros
    // total_num_radix_blocks == total_num_scalar_blocks
    uint32_t num_lsb_radix_blocks = total_num_radix_blocks;
    uint32_t num_scalar_blocks = total_num_scalar_blocks;

    Torus *lhs = diff_buffer->tmp_packed;
    Torus *rhs =
        diff_buffer->tmp_packed + total_num_radix_blocks / 2 * big_lwe_size;

    pack_blocks<Torus>(streams[0], gpu_indexes[0], lhs, lwe_array_in,
                       big_lwe_dimension, num_lsb_radix_blocks,
                       message_modulus);
    pack_blocks<Torus>(streams[0], gpu_indexes[0], rhs, scalar_blocks, 0,
                       num_scalar_blocks, message_modulus);

    // From this point we have half number of blocks
    num_lsb_radix_blocks /= 2;
    num_scalar_blocks /= 2;

    // comparisons will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs
    auto comparisons = mem_ptr->tmp_lwe_array_out;
    scalar_compare_radix_blocks_kb<Torus>(streams, gpu_indexes, gpu_count,
                                          comparisons, lhs, rhs, mem_ptr, bsks,
                                          ksks, num_lsb_radix_blocks);

    // Reduces a vec containing radix blocks that encrypts a sign
    // (inferior, equal, superior) to one single radix block containing the
    // final sign
    tree_sign_reduction<Torus>(streams, gpu_indexes, gpu_count, lwe_array_out,
                               comparisons, mem_ptr->diff_buffer->tree_buffer,
                               sign_handler_f, bsks, ksks,
                               num_lsb_radix_blocks);
  }
}

template <typename Torus>
__host__ void integer_radix_signed_scalar_difference_check_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_in,
    Torus const *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> sign_handler_f, void *const *bsks,
    Torus *const *ksks, uint32_t total_num_radix_blocks,
    uint32_t total_num_scalar_blocks) {

  auto params = mem_ptr->params;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  auto diff_buffer = mem_ptr->diff_buffer;

  size_t big_lwe_size = big_lwe_dimension + 1;

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
  if (total_num_scalar_blocks == 0) {
    // We only have to compare blocks with zero
    // means scalar is zero
    Torus *are_all_msb_zeros = mem_ptr->tmp_lwe_array_out;
    host_compare_with_zero_equality<Torus>(
        streams, gpu_indexes, gpu_count, are_all_msb_zeros, lwe_array_in,
        mem_ptr, bsks, ksks, total_num_radix_blocks, mem_ptr->is_zero_lut);
    Torus const *sign_block =
        lwe_array_in + (total_num_radix_blocks - 1) * big_lwe_size;

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
      };

      return sign_handler_f(block_selector_f(
          scalar_last_leaf_with_respect_to_zero_lut_f(sign_block),
          are_all_zeros));
    };

    auto lut = mem_ptr->diff_buffer->tree_buffer->tree_last_leaf_scalar_lut;
    generate_device_accumulator_bivariate<Torus>(
        streams[0], gpu_indexes[0], lut->get_lut(0, 0), glwe_dimension,
        polynomial_size, message_modulus, carry_modulus,
        scalar_bivariate_last_leaf_lut_f);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, are_all_msb_zeros,
        sign_block, bsks, ksks, 1, lut, lut->params.message_modulus);

  } else if (total_num_scalar_blocks < total_num_radix_blocks) {
    // We have to handle both part of the work described above
    // And the sign bit is located in the most_significant_blocks

    uint32_t num_lsb_radix_blocks = total_num_scalar_blocks;
    uint32_t num_msb_radix_blocks =
        total_num_radix_blocks - num_lsb_radix_blocks;
    auto msb = lwe_array_in + num_lsb_radix_blocks * big_lwe_size;

    auto lwe_array_lsb_out = mem_ptr->tmp_lwe_array_out;
    auto lwe_array_msb_out = lwe_array_lsb_out + big_lwe_size;

    auto lsb_streams = mem_ptr->lsb_streams;
    auto msb_streams = mem_ptr->msb_streams;
    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }

    //////////////
    // lsb
    Torus *lhs = diff_buffer->tmp_packed;
    Torus *rhs =
        diff_buffer->tmp_packed + total_num_radix_blocks / 2 * big_lwe_size;

    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], lhs, lwe_array_in,
                       big_lwe_dimension, num_lsb_radix_blocks,
                       message_modulus);
    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], rhs, scalar_blocks, 0,
                       total_num_scalar_blocks, message_modulus);

    // From this point we have half number of blocks
    num_lsb_radix_blocks /= 2;
    num_lsb_radix_blocks += (total_num_scalar_blocks % 2);

    // comparisons will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs

    auto comparisons = mem_ptr->tmp_block_comparisons;
    scalar_compare_radix_blocks_kb<Torus>(lsb_streams, gpu_indexes, gpu_count,
                                          comparisons, lhs, rhs, mem_ptr, bsks,
                                          ksks, num_lsb_radix_blocks);

    // Reduces a vec containing radix blocks that encrypts a sign
    // (inferior, equal, superior) to one single radix block containing the
    // final sign
    tree_sign_reduction<Torus>(
        lsb_streams, gpu_indexes, gpu_count, lwe_array_lsb_out, comparisons,
        mem_ptr->diff_buffer->tree_buffer, mem_ptr->identity_lut_f, bsks, ksks,
        num_lsb_radix_blocks);
    //////////////
    // msb
    // We remove the last block (which is the sign)
    Torus *are_all_msb_zeros = lwe_array_msb_out;
    host_compare_with_zero_equality<Torus>(
        msb_streams, gpu_indexes, gpu_count, are_all_msb_zeros, msb, mem_ptr,
        bsks, ksks, num_msb_radix_blocks, mem_ptr->is_zero_lut);

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
    generate_device_accumulator_bivariate<Torus>(
        msb_streams[0], gpu_indexes[0], signed_msb_lut->get_lut(0, 0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, lut_f);
    signed_msb_lut->broadcast_lut(streams, gpu_indexes, 0);

    Torus const *sign_block = msb + (num_msb_radix_blocks - 1) * big_lwe_size;
    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        msb_streams, gpu_indexes, gpu_count, lwe_array_msb_out, sign_block,
        are_all_msb_zeros, bsks, ksks, 1, signed_msb_lut,
        signed_msb_lut->params.message_modulus);
    for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(lsb_streams[j], gpu_indexes[j]);
      cuda_synchronize_stream(msb_streams[j], gpu_indexes[j]);
    }

    //////////////
    // Reduce the two blocks into one final
    reduce_signs<Torus>(streams, gpu_indexes, gpu_count, lwe_array_out,
                        lwe_array_lsb_out, mem_ptr, sign_handler_f, bsks, ksks,
                        2);

  } else {
    // We only have to do the regular comparison
    // And not the part where we compare most significant blocks with zeros
    // total_num_radix_blocks == total_num_scalar_blocks
    uint32_t num_lsb_radix_blocks = total_num_radix_blocks;

    for (uint j = 0; j < gpu_count; j++) {
      cuda_synchronize_stream(streams[j], gpu_indexes[j]);
    }
    auto lsb_streams = mem_ptr->lsb_streams;
    auto msb_streams = mem_ptr->msb_streams;

    auto lwe_array_ct_out = mem_ptr->tmp_lwe_array_out;
    auto lwe_array_sign_out =
        lwe_array_ct_out + (num_lsb_radix_blocks / 2) * big_lwe_size;
    Torus *lhs = diff_buffer->tmp_packed;
    Torus *rhs =
        diff_buffer->tmp_packed + total_num_radix_blocks / 2 * big_lwe_size;

    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], lhs, lwe_array_in,
                       big_lwe_dimension, num_lsb_radix_blocks - 1,
                       message_modulus);
    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], rhs, scalar_blocks, 0,
                       num_lsb_radix_blocks - 1, message_modulus);

    // From this point we have half number of blocks
    num_lsb_radix_blocks /= 2;

    // comparisons will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs
    scalar_compare_radix_blocks_kb<Torus>(lsb_streams, gpu_indexes, gpu_count,
                                          lwe_array_ct_out, lhs, rhs, mem_ptr,
                                          bsks, ksks, num_lsb_radix_blocks);
    Torus const *encrypted_sign_block =
        lwe_array_in + (total_num_radix_blocks - 1) * big_lwe_size;
    Torus const *scalar_sign_block =
        scalar_blocks + (total_num_scalar_blocks - 1);

    auto trivial_sign_block = mem_ptr->tmp_trivial_sign_block;
    create_trivial_radix<Torus>(
        msb_streams[0], gpu_indexes[0], trivial_sign_block, scalar_sign_block,
        big_lwe_dimension, 1, 1, message_modulus, carry_modulus);

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        msb_streams, gpu_indexes, gpu_count, lwe_array_sign_out,
        encrypted_sign_block, trivial_sign_block, bsks, ksks, 1,
        mem_ptr->signed_lut, mem_ptr->signed_lut->params.message_modulus);
    for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
      cuda_synchronize_stream(lsb_streams[j], gpu_indexes[j]);
      cuda_synchronize_stream(msb_streams[j], gpu_indexes[j]);
    }

    // Reduces a vec containing radix blocks that encrypts a sign
    // (inferior, equal, superior) to one single radix block containing the
    // final sign
    reduce_signs<Torus>(streams, gpu_indexes, gpu_count, lwe_array_out,
                        lwe_array_ct_out, mem_ptr, sign_handler_f, bsks, ksks,
                        num_lsb_radix_blocks + 1);
  }
}

template <typename Torus>
__host__ void integer_radix_signed_scalar_maxmin_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus *lwe_array_in,
    Torus *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks, uint32_t total_num_radix_blocks,
    uint32_t total_num_scalar_blocks) {

  auto params = mem_ptr->params;
  // Calculates the difference sign between the ciphertext and the scalar
  // - 0 if lhs < rhs
  // - 1 if lhs == rhs
  // - 2 if lhs > rhs
  auto sign = mem_ptr->tmp_lwe_array_out;
  integer_radix_signed_scalar_difference_check_kb<Torus>(
      streams, gpu_indexes, gpu_count, sign, lwe_array_in, scalar_blocks,
      mem_ptr, mem_ptr->identity_lut_f, bsks, ksks, total_num_radix_blocks,
      total_num_scalar_blocks);

  // There is no optimized CMUX for scalars, so we convert to a trivial
  // ciphertext
  auto lwe_array_left = lwe_array_in;
  auto lwe_array_right = mem_ptr->tmp_block_comparisons;

  create_trivial_radix<Torus>(streams[0], gpu_indexes[0], lwe_array_right,
                              scalar_blocks, params.big_lwe_dimension,
                              total_num_radix_blocks, total_num_scalar_blocks,
                              params.message_modulus, params.carry_modulus);

  // Selector
  // CMUX for Max or Min
  legacy_host_integer_radix_cmux_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, sign, lwe_array_left,
      lwe_array_right, mem_ptr->cmux_buffer, bsks, ksks,
      total_num_radix_blocks);
}

template <typename Torus>
__host__ void host_integer_radix_scalar_difference_check_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_in,
    Torus const *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> sign_handler_f, void *const *bsks,
    Torus *const *ksks, uint32_t total_num_radix_blocks,
    uint32_t total_num_scalar_blocks) {

  if (mem_ptr->is_signed) {
    // is signed and scalar is positive
    integer_radix_signed_scalar_difference_check_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_in,
        scalar_blocks, mem_ptr, sign_handler_f, bsks, ksks,
        total_num_radix_blocks, total_num_scalar_blocks);
  } else {
    integer_radix_unsigned_scalar_difference_check_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_in,
        scalar_blocks, mem_ptr, sign_handler_f, bsks, ksks,
        total_num_radix_blocks, total_num_scalar_blocks);
  }
}

template <typename Torus>
__host__ void host_integer_radix_signed_scalar_maxmin_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus *lwe_array_in,
    Torus *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks, uint32_t total_num_radix_blocks,
    uint32_t total_num_scalar_blocks) {

  if (mem_ptr->is_signed) {
    // is signed and scalar is positive
    integer_radix_signed_scalar_maxmin_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_in,
        scalar_blocks, mem_ptr, bsks, ksks, total_num_radix_blocks,
        total_num_scalar_blocks);
  } else {
    PANIC("Cuda error: only signed scalar maxmin can be called in signed "
          "scalar comparison")
  }
}

template <typename Torus>
__host__ void host_integer_radix_scalar_maxmin_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_in,
    Torus const *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks, uint32_t total_num_radix_blocks,
    uint32_t total_num_scalar_blocks) {

  auto params = mem_ptr->params;

  // Calculates the difference sign between the ciphertext and the scalar
  // - 0 if lhs < rhs
  // - 1 if lhs == rhs
  // - 2 if lhs > rhs
  auto sign = mem_ptr->tmp_lwe_array_out;
  host_integer_radix_scalar_difference_check_kb<Torus>(
      streams, gpu_indexes, gpu_count, sign, lwe_array_in, scalar_blocks,
      mem_ptr, mem_ptr->identity_lut_f, bsks, ksks, total_num_radix_blocks,
      total_num_scalar_blocks);

  // There is no optimized CMUX for scalars, so we convert to a trivial
  // ciphertext
  auto lwe_array_left = lwe_array_in;
  auto lwe_array_right = mem_ptr->tmp_block_comparisons;

  create_trivial_radix<Torus>(streams[0], gpu_indexes[0], lwe_array_right,
                              scalar_blocks, params.big_lwe_dimension,
                              total_num_radix_blocks, total_num_scalar_blocks,
                              params.message_modulus, params.carry_modulus);

  // Selector
  // CMUX for Max or Min
  legacy_host_integer_radix_cmux_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out,
      mem_ptr->tmp_lwe_array_out, lwe_array_left, lwe_array_right,
      mem_ptr->cmux_buffer, bsks, ksks, total_num_radix_blocks);
}

template <typename Torus>
__host__ void host_integer_radix_scalar_equality_check_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_in,
    Torus const *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks,
    uint32_t num_scalar_blocks) {

  auto params = mem_ptr->params;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto message_modulus = params.message_modulus;

  auto eq_buffer = mem_ptr->eq_buffer;

  size_t big_lwe_size = big_lwe_dimension + 1;

  auto scalar_comparison_luts = eq_buffer->scalar_comparison_luts;

  uint32_t num_halved_scalar_blocks =
      (num_scalar_blocks / 2) + (num_scalar_blocks % 2);

  uint32_t num_lsb_radix_blocks =
      std::min(num_radix_blocks, 2 * num_halved_scalar_blocks);
  uint32_t num_msb_radix_blocks = num_radix_blocks - num_lsb_radix_blocks;
  uint32_t num_halved_lsb_radix_blocks =
      (num_lsb_radix_blocks / 2) + (num_lsb_radix_blocks % 2);

  auto lsb = lwe_array_in;
  auto msb = lwe_array_in + big_lwe_size * num_lsb_radix_blocks;

  auto lwe_array_lsb_out = mem_ptr->tmp_lwe_array_out;
  auto lwe_array_msb_out =
      lwe_array_lsb_out + big_lwe_size * num_halved_lsb_radix_blocks;

  for (uint j = 0; j < gpu_count; j++) {
    cuda_synchronize_stream(streams[j], gpu_indexes[j]);
  }

  auto lsb_streams = mem_ptr->lsb_streams;
  auto msb_streams = mem_ptr->msb_streams;

  if (num_halved_scalar_blocks > 0) {
    auto packed_blocks = mem_ptr->tmp_packed_input;
    auto packed_scalar =
        packed_blocks + big_lwe_size * num_halved_lsb_radix_blocks;

    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], packed_blocks, lsb,
                       big_lwe_dimension, num_lsb_radix_blocks,
                       message_modulus);
    pack_blocks<Torus>(lsb_streams[0], gpu_indexes[0], packed_scalar,
                       scalar_blocks, 0, num_scalar_blocks, message_modulus);

    cuda_memcpy_async_gpu_to_gpu(scalar_comparison_luts->get_lut_indexes(0, 0),
                                 packed_scalar,
                                 num_halved_scalar_blocks * sizeof(Torus),
                                 lsb_streams[0], gpu_indexes[0]);
    scalar_comparison_luts->broadcast_lut(lsb_streams, gpu_indexes, 0);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        lsb_streams, gpu_indexes, gpu_count, lwe_array_lsb_out, packed_blocks,
        bsks, ksks, num_halved_lsb_radix_blocks, scalar_comparison_luts);
  }
  //////////////
  // msb
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

    host_compare_with_zero_equality<Torus>(
        msb_streams, gpu_indexes, gpu_count, lwe_array_msb_out, msb, mem_ptr,
        bsks, ksks, num_msb_radix_blocks, msb_lut);
  }

  for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
    cuda_synchronize_stream(lsb_streams[j], gpu_indexes[j]);
    cuda_synchronize_stream(msb_streams[j], gpu_indexes[j]);
  }

  switch (mem_ptr->op) {
  case COMPARISON_TYPE::EQ:
    are_all_comparisons_block_true<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_lsb_out,
        mem_ptr, bsks, ksks,
        num_halved_scalar_blocks + (num_msb_radix_blocks > 0));
    break;
  case COMPARISON_TYPE::NE:
    is_at_least_one_comparisons_block_true<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_lsb_out,
        mem_ptr, bsks, ksks,
        num_halved_scalar_blocks + (num_msb_radix_blocks > 0));
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
}
#endif
