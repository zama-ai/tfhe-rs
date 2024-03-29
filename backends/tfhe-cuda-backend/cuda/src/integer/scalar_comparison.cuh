#ifndef CUDA_INTEGER_SCALAR_COMPARISON_OPS_CUH
#define CUDA_INTEGER_SCALAR_COMPARISON_OPS_CUH

#include "integer/comparison.cuh"
#include <omp.h>

template <typename Torus>
__host__ void host_integer_radix_scalar_difference_check_kb(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_array_in,
    Torus *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> sign_handler_f, void *bsk, Torus *ksk,
    uint32_t total_num_radix_blocks, uint32_t total_num_scalar_blocks) {

  cudaSetDevice(stream->gpu_index);
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
    host_compare_with_zero_equality(
        stream, mem_ptr->tmp_lwe_array_out, lwe_array_in, mem_ptr, bsk, ksk,
        total_num_radix_blocks, mem_ptr->is_zero_lut);

    auto scalar_last_leaf_lut_f = [sign_handler_f](Torus x) -> Torus {
      x = (x == 1 ? IS_EQUAL : IS_SUPERIOR);

      return sign_handler_f(x);
    };

    auto lut = mem_ptr->diff_buffer->tree_buffer->tree_last_leaf_scalar_lut;
    generate_device_accumulator<Torus>(stream, lut->lut, glwe_dimension,
                                       polynomial_size, message_modulus,
                                       carry_modulus, scalar_last_leaf_lut_f);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        stream, lwe_array_out, mem_ptr->tmp_lwe_array_out, bsk, ksk, 1, lut);

  } else if (total_num_scalar_blocks < total_num_radix_blocks) {
    // We have to handle both part of the work described above

    uint32_t num_lsb_radix_blocks = total_num_scalar_blocks;
    uint32_t num_msb_radix_blocks =
        total_num_radix_blocks - num_lsb_radix_blocks;

    auto msb = lwe_array_in + num_lsb_radix_blocks * big_lwe_size;

    auto lwe_array_lsb_out = mem_ptr->tmp_lwe_array_out;
    auto lwe_array_msb_out = lwe_array_lsb_out + big_lwe_size;

    cuda_synchronize_stream(stream);
    auto lsb_stream = mem_ptr->lsb_stream;
    auto msb_stream = mem_ptr->msb_stream;

#pragma omp parallel sections
    {
      // Both sections may be executed in parallel
#pragma omp section
      {
        //////////////
        // lsb
        Torus *lhs = diff_buffer->tmp_packed_left;
        Torus *rhs = diff_buffer->tmp_packed_right;

        pack_blocks(lsb_stream, lhs, lwe_array_in, big_lwe_dimension,
                    num_lsb_radix_blocks, message_modulus);
        pack_blocks(lsb_stream, rhs, scalar_blocks, 0, total_num_scalar_blocks,
                    message_modulus);

        // From this point we have half number of blocks
        num_lsb_radix_blocks /= 2;
        num_lsb_radix_blocks += (total_num_scalar_blocks % 2);

        // comparisons will be assigned
        // - 0 if lhs < rhs
        // - 1 if lhs == rhs
        // - 2 if lhs > rhs

        auto comparisons = mem_ptr->tmp_block_comparisons;
        scalar_compare_radix_blocks_kb(lsb_stream, comparisons, lhs, rhs,
                                       mem_ptr, bsk, ksk, num_lsb_radix_blocks);

        // Reduces a vec containing radix blocks that encrypts a sign
        // (inferior, equal, superior) to one single radix block containing the
        // final sign
        tree_sign_reduction(lsb_stream, lwe_array_lsb_out, comparisons,
                            mem_ptr->diff_buffer->tree_buffer,
                            mem_ptr->identity_lut_f, bsk, ksk,
                            num_lsb_radix_blocks);
      }
#pragma omp section
      {
        //////////////
        // msb
        host_compare_with_zero_equality(msb_stream, lwe_array_msb_out, msb,
                                        mem_ptr, bsk, ksk, num_msb_radix_blocks,
                                        mem_ptr->is_zero_lut);
      }
    }
    cuda_synchronize_stream(lsb_stream);
    cuda_synchronize_stream(msb_stream);

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
        stream, lut->lut, glwe_dimension, polynomial_size, message_modulus,
        carry_modulus, scalar_bivariate_last_leaf_lut_f);

    integer_radix_apply_bivariate_lookup_table_kb(
        stream, lwe_array_out, lwe_array_lsb_out, lwe_array_msb_out, bsk, ksk,
        1, lut);

  } else {
    // We only have to do the regular comparison
    // And not the part where we compare most significant blocks with zeros
    // total_num_radix_blocks == total_num_scalar_blocks
    uint32_t num_lsb_radix_blocks = total_num_radix_blocks;
    uint32_t num_scalar_blocks = total_num_scalar_blocks;

    Torus *lhs = diff_buffer->tmp_packed_left;
    Torus *rhs = diff_buffer->tmp_packed_right;

    pack_blocks(stream, lhs, lwe_array_in, big_lwe_dimension,
                num_lsb_radix_blocks, message_modulus);
    pack_blocks(stream, rhs, scalar_blocks, 0, num_scalar_blocks,
                message_modulus);

    // From this point we have half number of blocks
    num_lsb_radix_blocks /= 2;
    num_scalar_blocks /= 2;

    // comparisons will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs
    auto comparisons = mem_ptr->tmp_lwe_array_out;
    scalar_compare_radix_blocks_kb(stream, comparisons, lhs, rhs, mem_ptr, bsk,
                                   ksk, num_lsb_radix_blocks);

    // Reduces a vec containing radix blocks that encrypts a sign
    // (inferior, equal, superior) to one single radix block containing the
    // final sign
    tree_sign_reduction(stream, lwe_array_out, comparisons,
                        mem_ptr->diff_buffer->tree_buffer, sign_handler_f, bsk,
                        ksk, num_lsb_radix_blocks);
  }
}

template <typename Torus>
__host__ void
scalar_compare_radix_blocks_kb(cuda_stream_t *stream, Torus *lwe_array_out,
                               Torus *lwe_array_in, Torus *scalar_blocks,
                               int_comparison_buffer<Torus> *mem_ptr, void *bsk,
                               Torus *ksk, uint32_t num_radix_blocks) {

  cudaSetDevice(stream->gpu_index);
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
  cuda_memcpy_async_gpu_to_gpu(
      subtracted_blocks, lwe_array_in,
      num_radix_blocks * (big_lwe_dimension + 1) * sizeof(Torus), stream);
  // Subtract
  // Here we need the true lwe sub, not the one that comes from shortint.
  host_integer_radix_scalar_subtraction_inplace(
      stream, subtracted_blocks, scalar_blocks, big_lwe_dimension,
      num_radix_blocks, message_modulus, carry_modulus);

  // Apply LUT to compare to 0
  auto sign_lut = mem_ptr->eq_buffer->is_non_zero_lut;
  integer_radix_apply_univariate_lookup_table_kb(stream, lwe_array_out,
                                                 subtracted_blocks, bsk, ksk,
                                                 num_radix_blocks, sign_lut);

  // Add one
  // Here Lhs can have the following values: (-1) % (message modulus * carry
  // modulus), 0, 1 So the output values after the addition will be: 0, 1, 2
  host_integer_radix_add_scalar_one_inplace(stream, lwe_array_out,
                                            big_lwe_dimension, num_radix_blocks,
                                            message_modulus, carry_modulus);
}

template <typename Torus>
__host__ void host_integer_radix_scalar_maxmin_kb(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_array_in,
    Torus *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr, void *bsk,
    Torus *ksk, uint32_t total_num_radix_blocks,
    uint32_t total_num_scalar_blocks) {

  cudaSetDevice(stream->gpu_index);
  auto params = mem_ptr->params;

  // Calculates the difference sign between the ciphertext and the scalar
  // - 0 if lhs < rhs
  // - 1 if lhs == rhs
  // - 2 if lhs > rhs
  auto sign = mem_ptr->tmp_lwe_array_out;
  host_integer_radix_scalar_difference_check_kb(
      stream, sign, lwe_array_in, scalar_blocks, mem_ptr,
      mem_ptr->identity_lut_f, bsk, ksk, total_num_radix_blocks,
      total_num_scalar_blocks);

  // There is no optimized CMUX for scalars, so we convert to a trivial
  // ciphertext
  auto lwe_array_left = lwe_array_in;
  auto lwe_array_right = mem_ptr->tmp_block_comparisons;

  create_trivial_radix(stream, lwe_array_right, scalar_blocks,
                       params.big_lwe_dimension, total_num_radix_blocks,
                       total_num_scalar_blocks, params.message_modulus,
                       params.carry_modulus);

  // Selector
  // CMUX for Max or Min
  host_integer_radix_cmux_kb(
      stream, lwe_array_out, mem_ptr->tmp_lwe_array_out, lwe_array_left,
      lwe_array_right, mem_ptr->cmux_buffer, bsk, ksk, total_num_radix_blocks);
}

template <typename Torus>
__host__ void host_integer_radix_scalar_equality_check_kb(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_array_in,
    Torus *scalar_blocks, int_comparison_buffer<Torus> *mem_ptr, void *bsk,
    Torus *ksk, uint32_t num_radix_blocks, uint32_t num_scalar_blocks) {

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

  cuda_synchronize_stream(stream);

  auto lsb_stream = mem_ptr->lsb_stream;
  auto msb_stream = mem_ptr->msb_stream;

#pragma omp parallel sections
  {
    // Both sections may be executed in parallel
#pragma omp section
    {
      if (num_halved_scalar_blocks > 0) {
        auto packed_blocks = mem_ptr->tmp_packed_input;
        auto packed_scalar =
            packed_blocks + big_lwe_size * num_halved_lsb_radix_blocks;

        pack_blocks(lsb_stream, packed_blocks, lsb, big_lwe_dimension,
                    num_lsb_radix_blocks, message_modulus);
        pack_blocks(lsb_stream, packed_scalar, scalar_blocks, 0,
                    num_scalar_blocks, message_modulus);

        cuda_memcpy_async_gpu_to_gpu(
            scalar_comparison_luts->lut_indexes, packed_scalar,
            num_halved_scalar_blocks * sizeof(Torus), lsb_stream);

        integer_radix_apply_univariate_lookup_table_kb(
            lsb_stream, lwe_array_lsb_out, packed_blocks, bsk, ksk,
            num_halved_lsb_radix_blocks, scalar_comparison_luts);
      }
    }
#pragma omp section
    {
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

        host_compare_with_zero_equality(msb_stream, lwe_array_msb_out, msb,
                                        mem_ptr, bsk, ksk, num_msb_radix_blocks,
                                        msb_lut);
      }
    }
  }

  cuda_synchronize_stream(lsb_stream);
  cuda_synchronize_stream(msb_stream);

  switch (mem_ptr->op) {
  case COMPARISON_TYPE::EQ:
    are_all_comparisons_block_true(
        stream, lwe_array_out, lwe_array_lsb_out, mem_ptr, bsk, ksk,
        num_halved_scalar_blocks + (num_msb_radix_blocks > 0));
    break;
  case COMPARISON_TYPE::NE:
    is_at_least_one_comparisons_block_true(
        stream, lwe_array_out, lwe_array_lsb_out, mem_ptr, bsk, ksk,
        num_halved_scalar_blocks + (num_msb_radix_blocks > 0));
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
}
#endif
