#ifndef CUDA_INTEGER_COMPARISON_OPS_CUH
#define CUDA_INTEGER_COMPARISON_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/cmux.cuh"
#include "integer/comparison.h"
#include "integer/integer_utilities.h"
#include "integer/negation.cuh"
#include "integer/scalar_addition.cuh"
#include "integer/subtraction.cuh"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "utils/helper.cuh"

// lwe_dimension + 1 threads
// todo: This kernel MUST be refactored to a binary reduction
template <typename Torus>
__global__ void
device_accumulate_all_blocks(Torus *output, Torus const *input_block,
                             uint32_t lwe_dimension, uint32_t num_blocks) {
  int idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < lwe_dimension + 1) {
    auto block = &input_block[idx];

    Torus sum = block[0];
    for (int i = 1; i < num_blocks; i++) {
      sum += block[i * (lwe_dimension + 1)];
    }

    output[idx] = sum;
  }
}

template <typename Torus>
__host__ void accumulate_all_blocks(cudaStream_t stream, uint32_t gpu_index,
                                    Torus *output, Torus const *input,
                                    uint32_t lwe_dimension,
                                    uint32_t num_radix_blocks) {

  cuda_set_device(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = (lwe_dimension + 1);
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  // Add all blocks and store in sum
  device_accumulate_all_blocks<Torus><<<num_blocks, num_threads, 0, stream>>>(
      output, input, lwe_dimension, num_radix_blocks);
  check_cuda_error(cudaGetLastError());
}

/* This takes an array of lwe ciphertexts, where each is an encryption of
 * either 0 or 1.
 *
 * It writes in lwe_array_out a single lwe ciphertext encrypting 1 if all input
 * blocks are 1 otherwise the block encrypts 0
 *
 */
template <typename Torus, typename KSTorus>
__host__ void are_all_comparisons_block_true(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in,
    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions must be the same")
  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")

  auto params = mem_ptr->params;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  if (num_radix_blocks == 0) {
    set_single_scalar_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array_out, 1,
        message_modulus, carry_modulus);
    return;
  }

  auto are_all_block_true_buffer =
      mem_ptr->eq_buffer->are_all_block_true_buffer;
  auto tmp_out = are_all_block_true_buffer->tmp_out;

  uint32_t total_modulus = message_modulus * carry_modulus;
  uint32_t max_value = (total_modulus - 1) / (message_modulus - 1);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), tmp_out, 0, num_radix_blocks,
      lwe_array_in, 0, num_radix_blocks);

  uint32_t remaining_blocks = num_radix_blocks;

  while (remaining_blocks > 0) {
    // Split in max_value chunks
    int num_chunks = CEIL_DIV(remaining_blocks, max_value);

    // Since all blocks encrypt either 0 or 1, we can sum max_value of them
    // as in the worst case we will be adding `max_value` ones
    auto input_blocks = (Torus *)tmp_out->ptr;
    auto accumulator_ptr =
        (Torus *)are_all_block_true_buffer->tmp_block_accumulated->ptr;
    auto is_max_value_lut = are_all_block_true_buffer->is_max_value;
    uint32_t chunk_lengths[num_chunks];
    auto begin_remaining_blocks = remaining_blocks;
    for (int i = 0; i < num_chunks; i++) {
      uint32_t chunk_length =
          std::min(max_value, begin_remaining_blocks - i * max_value);
      chunk_lengths[i] = chunk_length;
      accumulate_all_blocks<Torus>(streams.stream(0), streams.gpu_index(0),
                                   accumulator_ptr, input_blocks,
                                   big_lwe_dimension, chunk_length);

      accumulator_ptr += (big_lwe_dimension + 1);
      remaining_blocks -= (chunk_length - 1);
      input_blocks += (big_lwe_dimension + 1) * chunk_length;
    }
    auto accumulator = are_all_block_true_buffer->tmp_block_accumulated;

    // Selects a LUT
    int_radix_lut<Torus> *lut;
    if (are_all_block_true_buffer->op == COMPARISON_TYPE::NE) {
      // is_non_zero_lut_buffer LUT
      lut = mem_ptr->eq_buffer->is_non_zero_lut;
    } else {
      // Pad the last chunk's accumulator block up to max_value by adding
      // trivial plaintext 1s, so that all chunks can use the same
      // is_max_value LUT uniformly.
      uint32_t last_chunk_length = chunk_lengths[num_chunks - 1];
      if (last_chunk_length != max_value) {
        uint32_t pad = max_value - last_chunk_length;
        GPU_ASSERT(pad < max_value,
                   "pad (%u) must be strictly less than max_value (%u)", pad,
                   max_value);
        Torus delta = (Torus(1) << (sizeof(Torus) * 8 - 1)) /
                      (message_modulus * carry_modulus);
        Torus *last_block_ptr = (Torus *)accumulator->ptr +
                                (num_chunks - 1) * (big_lwe_dimension + 1);
        device_add_scalar_one_inplace<<<1, 1, 0, streams.stream(0)>>>(
            last_block_ptr, 1, big_lwe_dimension, pad * delta);
        check_cuda_error(cudaGetLastError());
      }
      lut = is_max_value_lut;
    }

    // Applies the LUT
    if (remaining_blocks == 1) {
      // In the last iteration we copy the output to the final address
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, lwe_array_out, accumulator, bsks, ksks, lut, 1);
      reset_radix_ciphertext_blocks(lwe_array_out, 1);
      return;
    } else {
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, tmp_out, accumulator, bsks, ksks, lut, num_chunks);
    }
  }
}

/* This takes an array of lwe ciphertexts, where each is an encryption of
 * either 0 or 1.
 *
 * It writes in lwe_array_out a single lwe ciphertext encrypting 1 if at least
 * one input ciphertext encrypts 1 otherwise encrypts 0
 */
template <typename Torus, typename KSTorus>
__host__ void is_at_least_one_comparisons_block_true(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in,
    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")

  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")
  auto params = mem_ptr->params;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  auto buffer = mem_ptr->eq_buffer->are_all_block_true_buffer;

  uint32_t total_modulus = message_modulus * carry_modulus;
  uint32_t max_value = (total_modulus - 1) / (message_modulus - 1);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->tmp_lwe_array_out, 0,
      num_radix_blocks, lwe_array_in, 0, num_radix_blocks);

  uint32_t remaining_blocks = num_radix_blocks;
  while (remaining_blocks > 0) {
    // Split in max_value chunks
    int num_chunks = CEIL_DIV(remaining_blocks, max_value);

    // Since all blocks encrypt either 0 or 1, we can sum max_value of them
    // as in the worst case we will be adding `max_value` ones
    auto input_blocks = (Torus *)mem_ptr->tmp_lwe_array_out->ptr;
    auto accumulator = (Torus *)buffer->tmp_block_accumulated->ptr;
    uint32_t chunk_lengths[num_chunks];
    auto begin_remaining_blocks = remaining_blocks;
    for (int i = 0; i < num_chunks; i++) {
      uint32_t chunk_length =
          std::min(max_value, begin_remaining_blocks - i * max_value);
      chunk_lengths[i] = chunk_length;
      accumulate_all_blocks<Torus>(streams.stream(0), streams.gpu_index(0),
                                   accumulator, input_blocks, big_lwe_dimension,
                                   chunk_length);

      accumulator += (big_lwe_dimension + 1);
      remaining_blocks -= (chunk_length - 1);
      input_blocks += (big_lwe_dimension + 1) * chunk_length;
    }

    // Selects a LUT
    int_radix_lut<Torus> *lut = mem_ptr->eq_buffer->is_non_zero_lut;

    // Applies the LUT
    if (remaining_blocks == 1) {
      // In the last iteration we copy the output to the final address
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, lwe_array_out, buffer->tmp_block_accumulated, bsks, ksks,
          lut, 1);
      return;
    } else {
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, mem_ptr->tmp_lwe_array_out, buffer->tmp_block_accumulated,
          bsks, ksks, lut, num_chunks);
    }
  }
}

template <typename Torus, typename KSTorus>
__host__ void host_compare_blocks_with_zero(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in,
    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, int32_t num_radix_blocks,
    int_radix_lut<Torus> *zero_comparison) {

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

  // The idea is that we will sum chunks of blocks until carries are full
  // then we compare the sum with 0.
  //
  // If all blocks were 0, the sum will be zero
  // If at least one bock was not zero, the sum won't be zero
  uint32_t total_modulus = message_modulus * carry_modulus;
  uint32_t message_max = message_modulus - 1;

  uint32_t num_elements_to_fill_carry = (total_modulus - 1) / message_max;

  size_t big_lwe_size = big_lwe_dimension + 1;
  int num_sum_blocks = 0;
  // Accumulator
  auto sum = lwe_array_out;

  if (num_radix_blocks == 1) {
    // Just copy
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), sum, 0, 1, lwe_array_in, 0, 1);
    num_sum_blocks = 1;
  } else {
    uint32_t remainder_blocks = num_radix_blocks;
    auto sum_i = (Torus *)sum->ptr;
    auto chunk = (Torus *)lwe_array_in->ptr;
    while (remainder_blocks > 1) {
      uint32_t chunk_size =
          std::min(remainder_blocks, num_elements_to_fill_carry);

      accumulate_all_blocks<Torus>(streams.stream(0), streams.gpu_index(0),
                                   sum_i, chunk, big_lwe_dimension, chunk_size);

      num_sum_blocks++;
      remainder_blocks -= (chunk_size - 1);

      // Update operands
      chunk += (chunk_size - 1) * big_lwe_size;
      sum_i += big_lwe_size;
    }
  }

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, lwe_array_out, sum, bsks, ksks, zero_comparison, num_sum_blocks);

  reset_radix_ciphertext_blocks(lwe_array_out, num_sum_blocks);
}

template <typename Torus, typename KSTorus>
__host__ void
host_equality_check(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
                    CudaRadixCiphertextFFI const *lwe_array_1,
                    CudaRadixCiphertextFFI const *lwe_array_2,
                    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
                    KSTorus *const *ksks, uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_1->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_2->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")
  auto eq_buffer = mem_ptr->eq_buffer;

  // Applies the LUT for the comparison operation
  auto comparisons = mem_ptr->tmp_block_comparisons;
  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, comparisons, lwe_array_1, lwe_array_2, bsks, ksks,
      eq_buffer->operator_lut, num_radix_blocks,
      eq_buffer->operator_lut->params.message_modulus);

  // This takes a Vec of blocks, where each block is either 0 or 1.
  //
  // It returns a block encrypting 1 if all input blocks are 1
  // otherwise the block encrypts 0
  are_all_comparisons_block_true<Torus>(streams, lwe_array_out, comparisons,
                                        mem_ptr, bsks, ksks, num_radix_blocks);
}

template <typename Torus, typename KSTorus>
__host__ void
compare_radix_blocks(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
                     CudaRadixCiphertextFFI const *lwe_array_left,
                     CudaRadixCiphertextFFI const *lwe_array_right,
                     int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
                     KSTorus *const *ksks, uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_left->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_right->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")
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

  // Subtract
  host_subtraction<Torus>(
      streams.stream(0), streams.gpu_index(0), (Torus *)lwe_array_out->ptr,
      (Torus *)lwe_array_left->ptr, (Torus *)lwe_array_right->ptr,
      big_lwe_dimension, num_radix_blocks);

  // Apply LUT to compare to 0
  auto is_non_zero_lut = mem_ptr->eq_buffer->is_non_zero_lut;
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, lwe_array_out, lwe_array_out, bsks, ksks, is_non_zero_lut,
      num_radix_blocks);

  // Add one
  // Here Lhs can have the following values: (-1) % (message modulus * carry
  // modulus), 0, 1 So the output values after the addition will be: 0, 1, 2
  host_add_scalar_one_inplace<Torus>(streams, lwe_array_out, message_modulus,
                                     carry_modulus);
}

// Reduces a vec containing shortint blocks that encrypts a sign
// (inferior, equal, superior) to one single shortint block containing the
// final sign
template <typename Torus, typename KSTorus>
__host__ void
tree_sign_reduction(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
                    CudaRadixCiphertextFFI *lwe_block_comparisons,
                    int_tree_sign_reduction_buffer<Torus> *tree_buffer,
                    std::function<Torus(Torus)> sign_handler_f,
                    void *const *bsks, KSTorus *const *ksks,
                    uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_block_comparisons->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")
  if (lwe_block_comparisons->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: block comparisons num radix blocks should not be lower "
          "than the number of blocks to operate on")

  auto params = tree_buffer->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  // Tree reduction
  // Reduces a vec containing shortint blocks that encrypts a sign
  // (inferior, equal, superior) to one single shortint block containing the
  // final sign
  auto x = tree_buffer->tmp_x;
  auto y = tree_buffer->tmp_y;
  if (x != lwe_block_comparisons)
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), x, 0, num_radix_blocks,
        lwe_block_comparisons, 0, num_radix_blocks);

  uint32_t partial_block_count = num_radix_blocks;

  auto inner_tree_leaf = tree_buffer->tree_inner_leaf_lut;
  while (partial_block_count > 2) {
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), y, x,
                       partial_block_count, message_modulus);

    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, x, y, bsks, ksks, inner_tree_leaf, partial_block_count >> 1);

    if ((partial_block_count % 2) != 0) {
      partial_block_count >>= 1;
      partial_block_count++;

      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), x, partial_block_count - 1,
          partial_block_count, y, partial_block_count - 1, partial_block_count);
    } else {
      partial_block_count >>= 1;
    }
  }

  auto last_lut = tree_buffer->tree_last_leaf_lut;
  auto block_selector_f = tree_buffer->block_selector_f;
  std::function<Torus(Torus)> f;
  auto num_bits_in_message = log2_int(params.message_modulus);
  if (partial_block_count == 2) {
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), y, x,
                       partial_block_count, message_modulus);

    f = [block_selector_f, sign_handler_f, num_bits_in_message,
         message_modulus](Torus x) -> Torus {
      Torus msb = (x >> num_bits_in_message) & (message_modulus - 1);
      Torus lsb = x & (message_modulus - 1);

      Torus final_sign = block_selector_f(msb, lsb);
      return sign_handler_f(final_sign);
    };
  } else {
    // partial_block_count == 1
    y = x;
    f = sign_handler_f;
  }

  auto active_streams = streams.active_gpu_subset(1, params.pbs_type);
  last_lut->generate_and_broadcast_lut(active_streams, {0}, {f},
                                       LUT_0_FOR_ALL_BLOCKS, true,
                                       {tree_buffer->preallocated_h_lut});

  // Last leaf
  integer_radix_apply_univariate_lookup_table<Torus>(streams, lwe_array_out, y,
                                                     bsks, ksks, last_lut, 1);
}

template <typename Torus, typename KSTorus>
__host__ void host_difference_check(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_left,
    CudaRadixCiphertextFFI const *lwe_array_right,
    int_comparison_buffer<Torus> *mem_ptr,
    std::function<Torus(Torus)> reduction_lut_f, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_left->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_right->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")

  auto diff_buffer = mem_ptr->diff_buffer;

  auto params = mem_ptr->params;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  uint32_t packed_num_radix_blocks = num_radix_blocks;
  CudaRadixCiphertextFFI lhs;
  as_radix_ciphertext_slice<Torus>(&lhs, diff_buffer->tmp_packed, 0,
                                   num_radix_blocks / 2);
  CudaRadixCiphertextFFI rhs;
  as_radix_ciphertext_slice<Torus>(&rhs, diff_buffer->tmp_packed,
                                   num_radix_blocks / 2, num_radix_blocks);
  if (carry_modulus >= message_modulus) {
    // Packing is possible
    // Pack inputs
    // In case the ciphertext is signed, the sign block and the one before it
    // are handled separately
    if (mem_ptr->is_signed) {
      packed_num_radix_blocks -= 2;
    }
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), &lhs,
                       lwe_array_left, packed_num_radix_blocks,
                       message_modulus);
    pack_blocks<Torus>(streams.stream(0), streams.gpu_index(0), &rhs,
                       lwe_array_right, packed_num_radix_blocks,
                       message_modulus);
    // From this point we have half number of blocks
    packed_num_radix_blocks /= 2;

    // Clean noise
    auto identity_lut = mem_ptr->identity_lut;
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, diff_buffer->tmp_packed, diff_buffer->tmp_packed, bsks, ksks,
        identity_lut, 2 * packed_num_radix_blocks);
  } else {
    as_radix_ciphertext_slice<Torus>(&lhs, lwe_array_left, 0,
                                     lwe_array_left->num_radix_blocks);
    as_radix_ciphertext_slice<Torus>(&rhs, lwe_array_right, 0,
                                     lwe_array_right->num_radix_blocks);
  }

  // comparisons will be assigned
  // - 0 if lhs < rhs
  // - 1 if lhs == rhs
  // - 2 if lhs > rhs
  auto comparisons = mem_ptr->tmp_block_comparisons;
  auto num_comparisons = 0;
  if (!mem_ptr->is_signed) {
    // Compare packed blocks, or simply the total number of radix blocks in the
    // inputs
    compare_radix_blocks<Torus>(streams, comparisons, &lhs, &rhs, mem_ptr, bsks,
                                ksks, packed_num_radix_blocks);
    num_comparisons = packed_num_radix_blocks;
  } else {
    // Packing is possible
    if (carry_modulus >= message_modulus) {
      // Compare (num_radix_blocks - 2) / 2 packed blocks
      compare_radix_blocks<Torus>(streams, comparisons, &lhs, &rhs, mem_ptr,
                                  bsks, ksks, packed_num_radix_blocks);

      // Compare the last block before the sign block separately
      auto identity_lut = mem_ptr->identity_lut;
      CudaRadixCiphertextFFI last_left_block_before_sign_block;
      as_radix_ciphertext_slice<Torus>(
          &last_left_block_before_sign_block, diff_buffer->tmp_packed,
          packed_num_radix_blocks, packed_num_radix_blocks + 1);
      CudaRadixCiphertextFFI shifted_lwe_array_left;
      as_radix_ciphertext_slice<Torus>(&shifted_lwe_array_left, lwe_array_left,
                                       num_radix_blocks - 2,
                                       num_radix_blocks - 1);
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, &last_left_block_before_sign_block, &shifted_lwe_array_left,
          bsks, ksks, identity_lut, 1);

      CudaRadixCiphertextFFI last_right_block_before_sign_block;
      as_radix_ciphertext_slice<Torus>(
          &last_right_block_before_sign_block, diff_buffer->tmp_packed,
          num_radix_blocks / 2 + packed_num_radix_blocks,
          num_radix_blocks / 2 + packed_num_radix_blocks + 1);
      CudaRadixCiphertextFFI shifted_lwe_array_right;
      as_radix_ciphertext_slice<Torus>(&shifted_lwe_array_right,
                                       lwe_array_right, num_radix_blocks - 2,
                                       num_radix_blocks - 1);
      integer_radix_apply_univariate_lookup_table<Torus>(
          streams, &last_right_block_before_sign_block,
          &shifted_lwe_array_right, bsks, ksks, identity_lut, 1);

      CudaRadixCiphertextFFI shifted_comparisons;
      as_radix_ciphertext_slice<Torus>(&shifted_comparisons, comparisons,
                                       packed_num_radix_blocks,
                                       packed_num_radix_blocks + 1);
      compare_radix_blocks<Torus>(
          streams, &shifted_comparisons, &last_left_block_before_sign_block,
          &last_right_block_before_sign_block, mem_ptr, bsks, ksks, 1);

      // Compare the sign block separately
      as_radix_ciphertext_slice<Torus>(&shifted_comparisons, comparisons,
                                       packed_num_radix_blocks + 1,
                                       packed_num_radix_blocks + 2);
      CudaRadixCiphertextFFI last_left_block;
      as_radix_ciphertext_slice<Torus>(&last_left_block, lwe_array_left,
                                       num_radix_blocks - 1, num_radix_blocks);
      CudaRadixCiphertextFFI last_right_block;
      as_radix_ciphertext_slice<Torus>(&last_right_block, lwe_array_right,
                                       num_radix_blocks - 1, num_radix_blocks);
      integer_radix_apply_bivariate_lookup_table<Torus>(
          streams, &shifted_comparisons, &last_left_block, &last_right_block,
          bsks, ksks, mem_ptr->signed_lut, 1,
          mem_ptr->signed_lut->params.message_modulus);
      num_comparisons = packed_num_radix_blocks + 2;

    } else {
      compare_radix_blocks<Torus>(streams, comparisons, lwe_array_left,
                                  lwe_array_right, mem_ptr, bsks, ksks,
                                  num_radix_blocks - 1);
      // Compare the sign block separately
      CudaRadixCiphertextFFI shifted_comparisons;
      as_radix_ciphertext_slice<Torus>(&shifted_comparisons, comparisons,
                                       num_radix_blocks - 1, num_radix_blocks);
      CudaRadixCiphertextFFI last_left_block;
      as_radix_ciphertext_slice<Torus>(&last_left_block, lwe_array_left,
                                       num_radix_blocks - 1, num_radix_blocks);
      CudaRadixCiphertextFFI last_right_block;
      as_radix_ciphertext_slice<Torus>(&last_right_block, lwe_array_right,
                                       num_radix_blocks - 1, num_radix_blocks);
      integer_radix_apply_bivariate_lookup_table<Torus>(
          streams, &shifted_comparisons, &last_left_block, &last_right_block,
          bsks, ksks, mem_ptr->signed_lut, 1,
          mem_ptr->signed_lut->params.message_modulus);
      num_comparisons = num_radix_blocks;
    }
  }

  // Reduces a vec containing radix blocks that encrypts a sign
  // (inferior, equal, superior) to one single radix block containing the
  // final sign
  tree_sign_reduction<Torus>(streams, lwe_array_out, comparisons,
                             mem_ptr->diff_buffer->tree_buffer, reduction_lut_f,
                             bsks, ksks, num_comparisons);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_comparison_check(
    CudaStreams streams, int_comparison_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, COMPARISON_TYPE op,
    bool is_signed, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_comparison_buffer<Torus>(
      streams, op, params, num_radix_blocks, is_signed, allocate_gpu_memory,
      size_tracker);
  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void
host_maxmin(CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
            CudaRadixCiphertextFFI const *lwe_array_left,
            CudaRadixCiphertextFFI const *lwe_array_right,
            int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
            KSTorus *const *ksks, uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_left->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_right->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions must be the same")
  if (lwe_array_out->num_radix_blocks < num_radix_blocks ||
      lwe_array_left->num_radix_blocks < num_radix_blocks ||
      lwe_array_right->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks should not be lower "
          "than the number of blocks to operate on")

  // Compute the sign
  host_difference_check<Torus>(
      streams, mem_ptr->tmp_lwe_array_out, lwe_array_left, lwe_array_right,
      mem_ptr, mem_ptr->identity_lut_f, bsks, ksks, num_radix_blocks);

  // Selector
  host_cmux<Torus>(streams, lwe_array_out, mem_ptr->tmp_lwe_array_out,
                   lwe_array_left, lwe_array_right, mem_ptr->cmux_buffer, bsks,
                   ksks);
}

template <typename Torus, typename KSTorus>
__host__ void host_integer_are_all_comparisons_block_true(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in,
    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks) {

  // It returns a block encrypting 1 if all input blocks are 1
  // otherwise the block encrypts 0
  are_all_comparisons_block_true<Torus>(streams, lwe_array_out, lwe_array_in,
                                        mem_ptr, bsks, ksks, num_radix_blocks);
}

template <typename Torus, typename KSTorus>
__host__ void host_integer_is_at_least_one_comparisons_block_true(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in,
    int_comparison_buffer<Torus> *mem_ptr, void *const *bsks,
    KSTorus *const *ksks, uint32_t num_radix_blocks) {

  // It returns a block encrypting 1 if all input blocks are 1
  // otherwise the block encrypts 0
  is_at_least_one_comparisons_block_true<Torus>(streams, lwe_array_out,
                                                lwe_array_in, mem_ptr, bsks,
                                                ksks, num_radix_blocks);
}
#endif
