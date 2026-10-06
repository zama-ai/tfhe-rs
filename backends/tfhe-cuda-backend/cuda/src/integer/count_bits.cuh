#ifndef COUNT_BITS_CUH
#define COUNT_BITS_CUH

#include "integer.cuh"
#include "integer/count_bits.h"
#include "integer/integer_utilities.h"
#include "multiplication.cuh"

template <typename Torus>
__host__ uint64_t scratch_integer_count_bits(
    CudaStreams streams, const int_radix_params params,
    int_count_bits_buffer<Torus> **mem_ptr, uint32_t num_radix_blocks,
    uint32_t counter_num_blocks, BitValue bit_value,
    const bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_count_bits_buffer<Torus>(
      streams, params, num_radix_blocks, counter_num_blocks, bit_value,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

/**
 * @brief First PBS layer, fills mem_ptr->counts with the bit count of each
 * packed pair and of each single block of input_ct.
 *
 * Regular and duo blocks are packed by pairs so that one PBS counts two
 * blocks, single blocks go as they are.
 *
 * @param input_ct Ciphertext to count, with clean carries
 */
template <typename Torus, typename KSTorus>
__host__ void
host_integer_count_bits_counts(CudaStreams streams,
                               CudaRadixCiphertextFFI const *input_ct,
                               int_count_bits_buffer<Torus> *mem_ptr,
                               void *const *bsks, KSTorus *const *ksks) {

  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  auto message_modulus = mem_ptr->params.message_modulus;
  auto carry_modulus = mem_ptr->params.carry_modulus;
  auto lut_inputs = mem_ptr->lut_inputs;
  const uint32_t num_regular_blocks = 6 * mem_ptr->num_chunks;
  const uint32_t num_duo_counts = mem_ptr->num_duo_counts;
  const uint32_t first_duo_count = mem_ptr->first_duo_count;
  const uint32_t first_single_count = mem_ptr->first_single_count;

  if (num_regular_blocks > 0) {
    CudaRadixCiphertextFFI regular_blocks;
    as_radix_ciphertext_slice<Torus>(&regular_blocks, input_ct, 0,
                                     num_regular_blocks);
    CudaRadixCiphertextFFI packed_regular_blocks;
    as_radix_ciphertext_slice<Torus>(&packed_regular_blocks, lut_inputs, 0,
                                     first_duo_count);
    pack_blocks<Torus>(stream, gpu_index, &packed_regular_blocks,
                       &regular_blocks, num_regular_blocks, message_modulus,
                       message_modulus, carry_modulus);
  }

  if (num_duo_counts > 0) {
    copy_radix_ciphertext_blocks_from_indexes_async<Torus>(
        stream, gpu_index, mem_ptr->duo_blocks, input_ct,
        mem_ptr->d_duo_block_indexes, mem_ptr->h_duo_block_indexes.data(),
        2 * num_duo_counts);
    CudaRadixCiphertextFFI packed_duo_blocks;
    as_radix_ciphertext_slice<Torus>(&packed_duo_blocks, lut_inputs,
                                     first_duo_count, first_single_count);
    pack_blocks<Torus>(stream, gpu_index, &packed_duo_blocks,
                       mem_ptr->duo_blocks, 2 * num_duo_counts, message_modulus,
                       message_modulus, carry_modulus);
  }

  if (mem_ptr->num_single_blocks > 0) {
    const uint32_t first_single_block =
        num_regular_blocks + mem_ptr->num_duo_blocks;
    copy_radix_ciphertext_slice_async<Torus>(
        stream, gpu_index, lut_inputs, first_single_count,
        first_single_count + mem_ptr->num_single_blocks, input_ct,
        first_single_block, input_ct->num_radix_blocks);
  }

  host_apply_univariate_lut<Torus>(streams, mem_ptr->counts, lut_inputs,
                                   mem_ptr->count_lut, ksks, bsks);
}

/**
 * @brief Adds the counts of each chunk, then splits the chunks into their
 * message and carry with the second PBS layer, the extra cost of this path.
 *
 * The additions need no PBS, degree <= 15 and noise level <= 4 fit the 2_2
 * limits.
 */
template <typename Torus, typename KSTorus>
__host__ void
host_integer_count_bits_chunks(CudaStreams streams,
                               int_count_bits_buffer<Torus> *mem_ptr,
                               void *const *bsks, KSTorus *const *ksks) {

  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  auto message_modulus = mem_ptr->params.message_modulus;
  auto carry_modulus = mem_ptr->params.carry_modulus;
  auto chunks = mem_ptr->chunks;
  const uint32_t num_chunks = mem_ptr->num_chunks;
  const uint32_t num_completed_chunks = mem_ptr->num_completed_chunks;

  CudaRadixCiphertextFFI regular_counts[3];
  for (uint32_t i = 0; i < 3; ++i) {
    as_radix_ciphertext_slice<Torus>(&regular_counts[i], mem_ptr->counts,
                                     i * num_chunks, (i + 1) * num_chunks);
  }
  host_addition<Torus>(stream, gpu_index, chunks, &regular_counts[0],
                       &regular_counts[1], num_chunks, message_modulus,
                       carry_modulus);
  host_addition<Torus>(stream, gpu_index, chunks, chunks, &regular_counts[2],
                       num_chunks, message_modulus, carry_modulus);

  if (num_completed_chunks > 0) {
    CudaRadixCiphertextFFI completer_counts;
    as_radix_ciphertext_slice<Torus>(
        &completer_counts, mem_ptr->counts, mem_ptr->first_duo_count,
        mem_ptr->first_duo_count + num_completed_chunks);
    host_addition<Torus>(stream, gpu_index, chunks, chunks, &completer_counts,
                         num_completed_chunks, message_modulus, carry_modulus);
  }

  for (uint32_t i = 0; i < num_chunks; ++i) {
    GPU_ASSERT(chunks->degrees[i] < message_modulus * carry_modulus,
               "Cuda error: chunk %u has degree %llu, it does not fit in a "
               "block",
               i, (unsigned long long)chunks->degrees[i]);
  }

  host_apply_univariate_lut<Torus>(streams, mem_ptr->chunks_message_carry,
                                   chunks, mem_ptr->extract_lut, ksks, bsks);
}

/**
 * @brief Fills mem_ptr->sum_input_cts, a chunk fills the two low blocks of
 * its term, a leftover completer fills one.
 */
template <typename Torus>
__host__ void
host_integer_count_bits_terms(CudaStreams streams,
                              int_count_bits_buffer<Torus> *mem_ptr) {

  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  auto sum_input_cts = mem_ptr->sum_input_cts;
  const uint32_t num_chunks = mem_ptr->num_chunks;
  const uint32_t num_leftover_completers = mem_ptr->num_terms - num_chunks;

  copy_radix_ciphertext_blocks_to_indexes_async<Torus>(
      stream, gpu_index, sum_input_cts, mem_ptr->chunks_message_carry,
      mem_ptr->d_term_block_indexes, mem_ptr->h_term_block_indexes.data(),
      2 * num_chunks);

  if (num_leftover_completers > 0) {
    const uint32_t first_leftover_completer =
        mem_ptr->first_duo_count + mem_ptr->num_completed_chunks;
    CudaRadixCiphertextFFI leftover_completer_counts;
    as_radix_ciphertext_slice<Torus>(
        &leftover_completer_counts, mem_ptr->counts, first_leftover_completer,
        first_leftover_completer + num_leftover_completers);
    copy_radix_ciphertext_blocks_to_indexes_async<Torus>(
        stream, gpu_index, sum_input_cts, &leftover_completer_counts,
        mem_ptr->d_term_block_indexes + 2 * num_chunks,
        mem_ptr->h_term_block_indexes.data() + 2 * num_chunks,
        num_leftover_completers);
  }
}

/**
 * @brief Sums the terms into the counter_num_blocks low blocks of output_ct
 * and cleans them with one carry propagation, the blocks above are zeros as
 * in the 32 bits result of the CPU.
 *
 * The partial sum reduces degrees so that one carry propagation suffices.
 *
 * @param output_ct At least counter_num_blocks blocks, clean on return
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_count_bits_sum(CudaStreams streams,
                                          CudaRadixCiphertextFFI *output_ct,
                                          int_count_bits_buffer<Torus> *mem_ptr,
                                          void *const *bsks,
                                          KSTorus *const *ksks) {

  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  const uint32_t counter_num_blocks = mem_ptr->counter_num_blocks;

  CudaRadixCiphertextFFI counter;
  as_radix_ciphertext_slice<Torus>(&counter, output_ct, 0, counter_num_blocks);
  if (output_ct->num_radix_blocks > counter_num_blocks) {
    set_zero_radix_ciphertext_slice_async<Torus>(stream, gpu_index, output_ct,
                                                 counter_num_blocks,
                                                 output_ct->num_radix_blocks);
  }

  host_integer_partial_sum_ciphertexts_vec<Torus>(
      streams, &counter, mem_ptr->sum_input_cts, bsks, ksks, mem_ptr->sum_mem,
      counter_num_blocks, mem_ptr->num_terms);

  host_propagate_single_carry<Torus>(streams, &counter, nullptr, nullptr,
                                     mem_ptr->propagate_mem, bsks, ksks, 0, 0);
}

/**
 * @brief Counts the ones or the zeros of input_ct, depending on the bit value
 * mem_ptr was built for, see int_count_bits_buffer.
 *
 * @param output_ct At least counter_num_blocks blocks, clean on return
 * @param input_ct  Ciphertext to count, with clean carries
 */
template <typename Torus, typename KSTorus>
__host__ void host_integer_count_bits(CudaStreams streams,
                                      CudaRadixCiphertextFFI *output_ct,
                                      CudaRadixCiphertextFFI const *input_ct,
                                      int_count_bits_buffer<Torus> *mem_ptr,
                                      void *const *bsks, KSTorus *const *ksks) {

  // The block split and the buffers were sized at scratch time
  GPU_ASSERT(input_ct->num_radix_blocks == mem_ptr->num_radix_blocks,
             "Cuda error: input num radix blocks (%u) must be equal to the "
             "num blocks given to the scratch call (%u)",
             input_ct->num_radix_blocks, mem_ptr->num_radix_blocks);
  GPU_ASSERT(output_ct->num_radix_blocks >= mem_ptr->counter_num_blocks,
             "Cuda error: output num radix blocks (%u) must be at least "
             "the counter num blocks given to the scratch call (%u)",
             output_ct->num_radix_blocks, mem_ptr->counter_num_blocks);
  GPU_ASSERT(output_ct->lwe_dimension == input_ct->lwe_dimension,
             "Cuda error: input and output lwe dimension must be equal");
  // A carry would spill into the other block of a packed pair
  for (uint32_t i = 0; i < input_ct->num_radix_blocks; ++i) {
    GPU_ASSERT(input_ct->degrees[i] < mem_ptr->params.message_modulus,
               "Cuda error: input block %u has degree %llu, its carries "
               "should be clean",
               i, (unsigned long long)input_ct->degrees[i]);
  }

  host_integer_count_bits_counts<Torus>(streams, input_ct, mem_ptr, bsks, ksks);
  if (mem_ptr->num_chunks > 0) {
    host_integer_count_bits_chunks<Torus>(streams, mem_ptr, bsks, ksks);
  }
  host_integer_count_bits_terms<Torus>(streams, mem_ptr);
  host_integer_count_bits_sum<Torus>(streams, output_ct, mem_ptr, bsks, ksks);
}

#endif
