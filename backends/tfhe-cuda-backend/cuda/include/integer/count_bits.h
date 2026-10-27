#pragma once
#include "integer_utilities.h"

/**
 * @brief Backs count_ones and count_zeros, following the CPU count_bits_2_2.
 * Only 2_2 parameters are accepted, the bit value to count is fixed at
 * construction.
 *
 * Instead of one sum term per block, the counts of 6 blocks and of a completer
 * c are added without PBS into a chunk filled up to degree 15. The final sum
 * then gets about 6 times fewer terms, for one extra PBS layer splitting each
 * chunk into its message and carry.
 *
 *     regular blocks   (b0 b1)  (b2 b3)  (b4 b5)     c
 *     count LUTs         0..4     0..4     0..4     0..3
 *                          \        |        /       /
 *     no PBS                +-------+-------+-------+
 *                                   |
 *                  chunk, degree <= 15, noise level 4
 *                               /         \
 *     extract LUTs          message      carry
 *                               \         /
 *                          one term of the sum
 *
 * c is a completer count. A duo [d0 d1 d2] is packed as (d0 d1) and (d1 d2),
 * giving two counts in 0..3 that complete two chunks. A single block gives a
 * count in 0..2. Completers left without a chunk are summed as they are.
 *
 * Zeros are counted directly by the LUTs, so count_zeros costs the same as
 * count_ones, unlike the generic CPU path that derives it from the number of
 * ones.
 */
template <typename Torus> struct int_count_bits_buffer {
  /// @brief A 2_2 block holds up to 15, 3 pair counts in 0..4 reach 12 and
  /// leave exactly the room of a completer in 0..3. A 4th pair would overflow.
  static constexpr uint32_t PAIRS_PER_CHUNK = 3;
  /// A pair packs 2 blocks as the 4 bits of one PBS input.
  static constexpr uint32_t BLOCKS_PER_CHUNK = 2 * PAIRS_PER_CHUNK;

  int_radix_params params;
  bool allocate_gpu_memory;
  /// Blocks of the input, the split and the buffers below are sized for them.
  uint32_t num_radix_blocks;
  /// @brief Low blocks of the output the sum runs on, just enough to hold the
  /// number of input bits, the largest count.
  uint32_t counter_num_blocks;

  // Split of the input, regular blocks come first, then duos, then singles
  //
  /// Groups of 6 regular blocks, each one ends up as a (message, carry) term.
  uint32_t num_chunks;
  /// Multiple of 3, each group of 3 blocks tops up 2 chunks.
  uint32_t num_duo_blocks;
  /// Blocks counted alone, they top up chunks too while some remain.
  uint32_t num_single_blocks;
  /// Chunks that got a completer, the others stay at degree 12.
  uint32_t num_completed_chunks;
  /// Chunks plus the completers that found no chunk, handed to the sum.
  uint32_t num_terms;

  // Layout of the counts, the index of a count picks its LUT
  //
  /// Two per duo, the pairs (d0 d1) and (d1 d2).
  uint32_t num_duo_counts;
  /// Start of the duo counts, after the 3 packed pairs of each chunk.
  uint32_t first_duo_count;
  /// Start of the single block counts, the ones that take LUT 3.
  uint32_t first_single_count;
  /// Packed pairs of each chunk, then duo pairs, then single blocks.
  uint32_t num_lut_inputs;

  // Count stage
  //
  /// Four LUTs picked per block, so that all the counts take one PBS call.
  int_radix_lut<Torus> *count_lut = nullptr;
  /// Input block of each duo block, b0 b0+1 b0+1 b0+2 per duo.
  std::vector<Torus> h_duo_block_indexes;
  /// GPU copy of h_duo_block_indexes, read by the copy kernel.
  Torus *d_duo_block_indexes = nullptr;
  /// Duo blocks laid out as [d0 d1 d1 d2], pack_blocks then gives both pairs.
  CudaRadixCiphertextFFI duo_blocks;
  /// Packed regular blocks, then packed duo pairs, then single blocks.
  CudaRadixCiphertextFFI lut_inputs;
  /// Bit counts, in the same order as lut_inputs.
  CudaRadixCiphertextFFI counts;

  // Chunk stage, unused without chunk
  //
  /// Message and carry LUTs, both read each chunk.
  int_radix_lut<Torus> *extract_lut = nullptr;
  /// Chunk of each extract LUT input, the same chunk for message and carry.
  std::vector<Torus> h_extract_indexes_in;
  /// Block of each extract LUT output, the messages then the carries.
  std::vector<Torus> h_extract_indexes_out;
  /// Chunk sums, input of both extract LUTs.
  CudaRadixCiphertextFFI chunks;
  /// Messages of all the chunks, then their carries.
  CudaRadixCiphertextFFI chunks_message_carry;

  // Sum stage
  //
  /// Term block of each chunk message, chunk carry, then leftover completer.
  std::vector<Torus> h_term_block_indexes;
  /// GPU copy of h_term_block_indexes, read by the copy kernel.
  Torus *d_term_block_indexes = nullptr;
  /// num_terms zero padded radix ciphertexts of counter_num_blocks blocks.
  CudaRadixCiphertextFFI sum_input_cts;
  /// Partial sum reducing degrees for one propagation.
  int_sum_ciphertexts_vec_memory<Torus> *sum_mem = nullptr;
  /// Single carry propagation that cleans the summed counter.
  int_sc_prop_memory<Torus> *propagate_mem = nullptr;

  int_count_bits_buffer(CudaStreams streams, const int_radix_params params,
                        uint32_t num_radix_blocks, uint32_t counter_num_blocks,
                        BitValue bit_value, const bool allocate_gpu_memory,
                        uint64_t &size_tracker) {
    GPU_ASSERT(params.message_modulus == 4 && params.carry_modulus == 4,
               "Cuda error: count_ones and count_zeros only support 2_2 "
               "parameters");
    GPU_ASSERT(num_radix_blocks > 0,
               "Cuda error: the input should have at least 1 block");
    // The count can reach the number of input bits, 2 per block, so the
    // counter needs the bits of that value, 7 bits and 4 blocks for a u64.
    // The caller sizes it just for that since the sum runs on it.
    const uint64_t max_count = 2ull * num_radix_blocks;
    const uint32_t max_count_num_bits = log2_int(max_count) + 1;
    GPU_ASSERT(2 * counter_num_blocks >= max_count_num_bits,
               "Cuda error: a counter of %u blocks cannot hold a count up to "
               "%llu, which takes %u bits",
               counter_num_blocks, (unsigned long long)max_count,
               max_count_num_bits);

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_radix_blocks = num_radix_blocks;
    this->counter_num_blocks = counter_num_blocks;

    split_blocks();
    GPU_ASSERT(num_chunks == 0 || counter_num_blocks >= 2,
               "Cuda error: the counter should have at least 2 blocks to hold "
               "the message and carry of a chunk");

    init_count_stage(streams, bit_value, size_tracker);
    if (num_chunks > 0) {
      init_chunk_stage(streams, size_tracker);
    }
    init_sum_stage(streams, size_tracker);
  }

  /// Same split as the CPU count_bits_2_2, both backends build the same terms.
  void split_blocks() {
    // A chunk to complete has all its blocks, it only waits for a completer
    // on top of its degree 12
    uint32_t num_chunks_to_complete = num_radix_blocks / BLOCKS_PER_CHUNK;
    uint32_t num_non_chunked = num_radix_blocks % BLOCKS_PER_CHUNK;
    num_completed_chunks = 0;
    num_duo_blocks = 0;

    // A duo counts 3 leftover blocks with 2 PBS and tops up 2 chunks
    if (num_chunks_to_complete >= 2 && num_non_chunked >= 3) {
      num_non_chunked -= 3;
      num_chunks_to_complete -= 2;
      num_completed_chunks += 2;
      num_duo_blocks += 3;
    }

    // The other leftover blocks top up one chunk each
    const uint32_t num_single_completers =
        std::min(num_non_chunked, num_chunks_to_complete);
    num_chunks_to_complete -= num_single_completers;
    num_completed_chunks += num_single_completers;
    num_non_chunked -= num_single_completers;

    // Giving up one chunk as 2 duos tops up 4 others, so fewer terms overall
    while (num_chunks_to_complete >= 5) {
      num_chunks_to_complete -= 5;
      num_completed_chunks += 4;
      num_duo_blocks += BLOCKS_PER_CHUNK;
    }

    num_single_blocks = num_non_chunked + num_single_completers;
    num_chunks = num_completed_chunks + num_chunks_to_complete;
    const uint32_t num_split_blocks =
        BLOCKS_PER_CHUNK * num_chunks + num_duo_blocks + num_single_blocks;
    GPU_ASSERT(num_split_blocks == num_radix_blocks,
               "Cuda error: invalid split of the blocks to count");

    num_duo_counts = 2 * (num_duo_blocks / 3);
    first_duo_count = PAIRS_PER_CHUNK * num_chunks;
    first_single_count = first_duo_count + num_duo_counts;
    const uint32_t num_completers = num_duo_counts + num_single_blocks;
    num_terms = num_chunks + num_completers - num_completed_chunks;
    num_lut_inputs = PAIRS_PER_CHUNK * num_chunks + num_completers;
  }

  /**
   * @brief Count LUTs and the buffers of the first PBS layer.
   *
   * @param bit_value Bit counted by the LUTs, zeros cost no more than ones
   */
  void init_count_stage(CudaStreams streams, BitValue bit_value,
                        uint64_t &size_tracker) {
    // The duo pairs overlap on d1, its low bit is counted with d0 and its high
    // bit with d2
    auto count_bits = [bit_value](Torus x, uint32_t first_bit,
                                  uint32_t end_bit) -> Torus {
      Torus count = 0;
      for (uint32_t i = first_bit; i < end_bit; ++i) {
        if (((x >> i) & 1) == (Torus)bit_value) {
          count++;
        }
      }
      return count;
    };
    std::function<Torus(Torus)> count_packed_block =
        [count_bits](Torus x) -> Torus { return count_bits(x, 0, 4); };
    std::function<Torus(Torus)> count_duo_first_block =
        [count_bits](Torus x) -> Torus { return count_bits(x, 0, 3); };
    std::function<Torus(Torus)> count_duo_second_block =
        [count_bits](Torus x) -> Torus { return count_bits(x, 1, 4); };
    std::function<Torus(Torus)> count_single_block =
        [count_bits](Torus x) -> Torus { return count_bits(x, 0, 2); };

    const uint32_t first_duo_count = this->first_duo_count;
    const uint32_t first_single_count = this->first_single_count;
    auto count_index_generator = [first_duo_count,
                                  first_single_count](Torus *h_lut_indexes,
                                                      uint32_t num_indexes) {
      for (uint32_t i = 0; i < num_indexes; ++i) {
        if (i < first_duo_count) {
          h_lut_indexes[i] = 0;
        } else if (i < first_single_count) {
          h_lut_indexes[i] = 1 + (i - first_duo_count) % 2;
        } else {
          h_lut_indexes[i] = 3;
        }
      }
    };

    count_lut = new int_radix_lut<Torus>(streams, params, 4, num_lut_inputs,
                                         allocate_gpu_memory, size_tracker);
    count_lut->generate_and_broadcast_lut(
        streams.active_gpu_subset(num_lut_inputs, params.pbs_type()),
        {0, 1, 2, 3},
        {count_packed_block, count_duo_first_block, count_duo_second_block,
         count_single_block},
        count_index_generator);

    if (num_duo_blocks > 0) {
      for (uint32_t i = 0; i < num_duo_blocks / 3; ++i) {
        const Torus b0 = BLOCKS_PER_CHUNK * num_chunks + 3 * i;
        h_duo_block_indexes.insert(h_duo_block_indexes.end(),
                                   {b0, b0 + 1, b0 + 1, b0 + 2});
      }
      const uint64_t duo_indexes_size =
          safe_mul_sizeof<Torus>(h_duo_block_indexes.size());
      d_duo_block_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
          duo_indexes_size, streams.stream(0), streams.gpu_index(0),
          size_tracker, allocate_gpu_memory);
      cuda_memcpy_with_size_tracking_async_to_gpu(
          d_duo_block_indexes, h_duo_block_indexes.data(), duo_indexes_size,
          streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);

      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), &duo_blocks,
          2 * num_duo_counts, params.big_lwe_dimension, size_tracker,
          allocate_gpu_memory);
    }

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &lut_inputs, num_lut_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &counts, num_lut_inputs,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
  }

  /// Extract LUTs and the chunk buffers of the second PBS layer.
  void init_chunk_stage(CudaStreams streams, uint64_t &size_tracker) {
    std::function<Torus(Torus)> extract_message = [](Torus x) -> Torus {
      return x % 4;
    };
    std::function<Torus(Torus)> extract_carry = [](Torus x) -> Torus {
      return x / 4;
    };
    const uint32_t num_chunks = this->num_chunks;
    auto extract_index_generator = [num_chunks](Torus *h_lut_indexes,
                                                uint32_t num_indexes) {
      for (uint32_t i = 0; i < num_indexes; ++i) {
        h_lut_indexes[i] = (i < num_chunks) ? 0 : 1;
      }
    };

    extract_lut = new int_radix_lut<Torus>(streams, params, 2, 2 * num_chunks,
                                           allocate_gpu_memory, size_tracker);
    auto active_streams =
        streams.active_gpu_subset(2 * num_chunks, params.pbs_type());
    extract_lut->generate_and_broadcast_lut(active_streams, {0, 1},
                                            {extract_message, extract_carry},
                                            extract_index_generator);

    // Reading each chunk twice saves a copy of the chunks
    for (uint32_t i = 0; i < 2 * num_chunks; ++i) {
      h_extract_indexes_in.push_back(i % num_chunks);
      h_extract_indexes_out.push_back(i);
    }
    extract_lut->set_lwe_indexes(streams.stream(0), streams.gpu_index(0),
                                 h_extract_indexes_in.data(),
                                 h_extract_indexes_out.data());
    extract_lut->allocate_lwe_vector_for_non_trivial_indexes(
        active_streams, 2 * num_chunks, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &chunks, num_chunks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &chunks_message_carry,
        2 * num_chunks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  /// Term layout, partial sum and carry propagation of the final count.
  void init_sum_stage(CudaStreams streams, uint64_t &size_tracker) {
    for (uint32_t i = 0; i < num_chunks; ++i) {
      h_term_block_indexes.push_back(i * counter_num_blocks);
    }
    for (uint32_t i = 0; i < num_chunks; ++i) {
      h_term_block_indexes.push_back(i * counter_num_blocks + 1);
    }
    for (uint32_t i = num_chunks; i < num_terms; ++i) {
      h_term_block_indexes.push_back(i * counter_num_blocks);
    }
    const uint64_t term_indexes_size =
        safe_mul_sizeof<Torus>(h_term_block_indexes.size());
    d_term_block_indexes = (Torus *)cuda_malloc_with_size_tracking_async(
        term_indexes_size, streams.stream(0), streams.gpu_index(0),
        size_tracker, allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_term_block_indexes, h_term_block_indexes.data(), term_indexes_size,
        streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);

    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &sum_input_cts,
        num_terms * counter_num_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    sum_mem = new int_sum_ciphertexts_vec_memory<Torus>(
        streams, params, counter_num_blocks, num_terms, true,
        allocate_gpu_memory, size_tracker);

    propagate_mem = new int_sc_prop_memory<Torus>(
        streams, params, counter_num_blocks, FLAG_NONE, allocate_gpu_memory,
        size_tracker);
  }

  void release(CudaStreams streams) {
    count_lut->release(streams);
    delete count_lut;
    count_lut = nullptr;

    if (extract_lut != nullptr) {
      extract_lut->release(streams);
      delete extract_lut;
      extract_lut = nullptr;
    }

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &lut_inputs, allocate_gpu_memory);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &counts, allocate_gpu_memory);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   &sum_input_cts, allocate_gpu_memory);
    if (num_duo_blocks > 0) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &duo_blocks, allocate_gpu_memory);
    }
    if (num_chunks > 0) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &chunks, allocate_gpu_memory);
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     &chunks_message_carry,
                                     allocate_gpu_memory);
    }

    for (auto d_indexes : {&d_duo_block_indexes, &d_term_block_indexes}) {
      if (*d_indexes != nullptr) {
        cuda_drop_with_size_tracking_async(*d_indexes, streams.stream(0),
                                           streams.gpu_index(0),
                                           allocate_gpu_memory);
        *d_indexes = nullptr;
      }
    }

    sum_mem->release(streams);
    delete sum_mem;
    sum_mem = nullptr;

    propagate_mem->release(streams);
    delete propagate_mem;
    propagate_mem = nullptr;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
