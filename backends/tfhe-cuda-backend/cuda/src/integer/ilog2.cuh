#ifndef ILOG2_CUH
#define ILOG2_CUH

#include "integer.cuh"
#include "integer/ilog2.h"
#include "integer/integer_utilities.h"
#include "multiplication.cuh"

template <typename Torus>
__host__ void host_integer_prepare_count_of_consecutive_bits(
    CudaStreams streams, CudaRadixCiphertextFFI *ciphertext,
    int_prepare_count_of_consecutive_bits_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  auto tmp = mem_ptr->tmp_ct;

  host_apply_univariate_lut<Torus>(streams, tmp, ciphertext,
                                   mem_ptr->univ_lut_mem, ksks, bsks);

  if (mem_ptr->direction == Leading) {
    host_radix_blocks_reverse_inplace<Torus>(streams, tmp);
  }

  host_compute_prefix_sum_hillis_steele<uint64_t>(
      streams, ciphertext, tmp, mem_ptr->biv_lut_mem, bsks, ksks,
      ciphertext->num_radix_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_integer_count_of_consecutive_bits(
    CudaStreams streams, const int_radix_params params,
    int_count_of_consecutive_bits_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, uint32_t counter_num_blocks, Direction direction,
    BitValue bit_value, const bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_count_of_consecutive_bits_buffer<Torus>(
      streams, params, num_radix_blocks, counter_num_blocks, direction,
      bit_value, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_count_of_consecutive_bits(
    CudaStreams streams, CudaRadixCiphertextFFI *output_ct,
    CudaRadixCiphertextFFI const *input_ct,
    int_count_of_consecutive_bits_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks) {

  auto params = mem_ptr->params;
  auto ct_prepared = mem_ptr->ct_prepared;
  auto counter_num_blocks = mem_ptr->counter_num_blocks;

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     ct_prepared, input_ct);

  // Prepare count of consecutive bits
  //
  host_integer_prepare_count_of_consecutive_bits(
      streams, ct_prepared, mem_ptr->prepare_mem, bsks, ksks);

  // Perform addition and propagation of prepared cts
  //
  auto cts = mem_ptr->cts;

  for (uint32_t i = 0; i < ct_prepared->num_radix_blocks; ++i) {
    uint32_t output_start_index = i * counter_num_blocks;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), cts, output_start_index,
        output_start_index + 1, ct_prepared, i, i + 1);
  }

  host_integer_partial_sum_ciphertexts_vec<Torus>(
      streams, output_ct, cts, bsks, ksks, mem_ptr->sum_mem, counter_num_blocks,
      ct_prepared->num_radix_blocks);

  host_propagate_single_carry<Torus>(streams, output_ct, nullptr, nullptr,
                                     mem_ptr->propagate_mem, bsks, ksks, 0, 0);
}

template <typename Torus>
__host__ uint64_t scratch_integer_ilog2(CudaStreams streams,
                                        const int_radix_params params,
                                        int_ilog2_buffer<Torus> **mem_ptr,
                                        uint32_t input_num_blocks,
                                        uint32_t counter_num_blocks,
                                        uint32_t num_bits_in_ciphertext,
                                        const bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_ilog2_buffer<Torus>(
      streams, params, input_num_blocks, counter_num_blocks,
      num_bits_in_ciphertext, allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void
host_integer_ilog2(CudaStreams streams, CudaRadixCiphertextFFI *output_ct,
                   CudaRadixCiphertextFFI const *input_ct,
                   CudaRadixCiphertextFFI const *trivial_ct_neg_n,
                   CudaRadixCiphertextFFI const *trivial_ct_2,
                   CudaRadixCiphertextFFI const *trivial_ct_m_minus_1_block,
                   int_ilog2_buffer<Torus> *mem_ptr, void *const *bsks,
                   Torus *const *ksks) {

  // Prepare the input ciphertext by computing the number of consecutive
  // leading zeros for each of its blocks.
  //
  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     mem_ptr->ct_in_buffer, input_ct);
  host_integer_prepare_count_of_consecutive_bits<Torus>(
      streams, mem_ptr->ct_in_buffer, mem_ptr->prepare_mem, bsks, ksks);

  // Build the input for the sum by taking each block's leading zero count
  // and placing it into a separate, zero-padded ct slot.
  //
  for (uint32_t i = 0; i < mem_ptr->input_num_blocks; ++i) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->sum_input_cts,
        i * mem_ptr->counter_num_blocks, (i * mem_ptr->counter_num_blocks) + 1,
        mem_ptr->ct_in_buffer, i, i + 1);
  }

  // Add the trivial ct encrypting -(num_bits_in_ciphertext-1) as the last
  // element to sum.
  //
  if (trivial_ct_neg_n->num_radix_blocks != mem_ptr->counter_num_blocks) {
    PANIC(
        "num blocks of trivial_ct_neg_n should be equal to counter_num_blocks");
  }
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->sum_input_cts,
      mem_ptr->input_num_blocks * mem_ptr->counter_num_blocks,
      (mem_ptr->input_num_blocks + 1) * mem_ptr->counter_num_blocks,
      trivial_ct_neg_n, 0, trivial_ct_neg_n->num_radix_blocks);

  // Perform a partial sum of all the elements without carry propagation.
  //
  host_integer_partial_sum_ciphertexts_vec<Torus>(
      streams, mem_ptr->sum_output_not_propagated, mem_ptr->sum_input_cts, bsks,
      ksks, mem_ptr->sum_mem, mem_ptr->counter_num_blocks,
      mem_ptr->input_num_blocks + 1);

  // Apply luts to the partial sum.
  //
  host_apply_univariate_lut<Torus>(streams, mem_ptr->message_blocks_not,
                                   mem_ptr->sum_output_not_propagated,
                                   mem_ptr->lut_message_not, ksks, bsks);
  host_apply_univariate_lut<Torus>(streams, mem_ptr->carry_blocks_not,
                                   mem_ptr->sum_output_not_propagated,
                                   mem_ptr->lut_carry_not, ksks, bsks);

  // Left-shift the bitwise-negated carry blocks by one position.
  //
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->rotated_carry_blocks, 1,
      mem_ptr->counter_num_blocks, mem_ptr->carry_blocks_not, 0,
      mem_ptr->counter_num_blocks - 1);

  // Insert a block of (mod - 1) at the least significant position.
  //
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->rotated_carry_blocks, 0,
      1, trivial_ct_m_minus_1_block, 0, 1);

  // Update the degree metadata for the rotated carry blocks.
  //
  for (uint32_t i = 0; i < mem_ptr->counter_num_blocks; ++i) {
    mem_ptr->rotated_carry_blocks->degrees[i] =
        mem_ptr->params.message_modulus - 1;
  }

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->sum_input_cts, 0,
      mem_ptr->counter_num_blocks, mem_ptr->message_blocks_not, 0,
      mem_ptr->counter_num_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->sum_input_cts,
      mem_ptr->counter_num_blocks, 2 * mem_ptr->counter_num_blocks,
      mem_ptr->rotated_carry_blocks, 0, mem_ptr->counter_num_blocks);

  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), mem_ptr->sum_input_cts,
      2 * mem_ptr->counter_num_blocks, 3 * mem_ptr->counter_num_blocks,
      trivial_ct_2, 0, mem_ptr->counter_num_blocks);

  host_integer_partial_sum_ciphertexts_vec<Torus>(
      streams, output_ct, mem_ptr->sum_input_cts, bsks, ksks, mem_ptr->sum_mem,
      mem_ptr->counter_num_blocks, 3);

  host_full_propagate_inplace<Torus>(streams, output_ct,
                                     mem_ptr->final_propagate_mem, ksks, bsks,
                                     mem_ptr->counter_num_blocks);
}

#endif
