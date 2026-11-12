#pragma once
#include "integer_utilities.h"
#include <map>

/// @brief Scratch of the keystream application, the XOR of transciphering.
///
///     keystream blocks   k0  k1  k2
///                          \  |  /     sum of 2^dst_bit_pos * k over the
///                           \ | /      contributions (device_pack_keystream)
///     packed_keystream       p_b
///                             |        one PBS, LUT of b: extract the
///                             v        keystream bits and xor the input bits
///     output block           o_b
///
/// The input bits are clear, so they live in the LUTs, which use the CPU
/// functions extract_xor and packed_xor. Blocks with the same function share a
/// LUT, and 2 bit blocks only have a few distinct functions.
template <typename Torus> struct int_apply_keystream_buffer {
  /// Read by the debug noise check of host_apply_keystream
  int_radix_params params;
  /// False when the scratch only measures its size, release reads it
  bool allocate_gpu_memory;
  /// Size of the output, one PBS per block
  uint32_t num_output_blocks;

  /// @brief Contributions given to the scratch, sorted by output block. The
  /// host copy gives the degrees and noise levels of the packed blocks.
  std::vector<CudaKeystreamContributionFFI> h_contributions;
  /// @brief Contributions of output block b: from h_block_offsets[b] to
  /// h_block_offsets[b + 1] excluded
  std::vector<uint32_t> h_block_offsets;
  /// GPU copy of h_contributions, read by device_pack_keystream
  CudaKeystreamContributionFFI *d_contributions;
  /// GPU copy of h_block_offsets, read by device_pack_keystream
  uint32_t *d_block_offsets;

  /// PBS input, one linear combination of keystream blocks per output block
  CudaRadixCiphertextFFI *packed_keystream;
  /// One LUT per distinct block function
  int_radix_lut<Torus> *luts;

  /// @brief Checks the order of the contributions, then builds one LUT per
  /// distinct block function.
  ///
  /// @param contributions     Copied, the caller can free them on return
  /// @param num_contributions Length of contributions
  /// @param num_output_blocks Each one needs at least one contribution
  int_apply_keystream_buffer(CudaStreams streams, int_radix_params params,
                             CudaKeystreamContributionFFI const *contributions,
                             uint32_t num_contributions,
                             uint32_t num_output_blocks,
                             bool allocate_gpu_memory, uint64_t &size_tracker)
      : params(params), allocate_gpu_memory(allocate_gpu_memory),
        num_output_blocks(num_output_blocks),
        h_contributions(contributions, contributions + num_contributions) {
    PANIC_IF_FALSE(num_output_blocks > 0,
                   "Cuda error (apply keystream): no output block");

    // Unsorted contributions or a block without any are a bug of the Rust
    // caller, which builds them from the CPU plan
    for (uint32_t c = 0; c < num_contributions; c++) {
      uint32_t block = h_contributions[c].output_block_index;
      if (block == h_block_offsets.size())
        h_block_offsets.push_back(c);
      else
        PANIC_IF_FALSE(block + 1 == h_block_offsets.size(),
                       "Cuda error (apply keystream): the contributions must "
                       "be sorted by output block, with at least one per "
                       "output block");
    }
    PANIC_IF_FALSE(h_block_offsets.size() == num_output_blocks,
                   "Cuda error (apply keystream): each output block must have "
                   "at least one contribution");
    h_block_offsets.push_back(num_contributions);

    // LUTs are keyed on their values, to share them between blocks
    const uint32_t lut_domain_size =
        params.message_modulus * params.carry_modulus;
    std::map<std::vector<Torus>, uint32_t> lut_id_of_values;
    std::vector<std::function<Torus(Torus)>> lut_funcs;
    std::vector<uint32_t> lut_ids;
    std::vector<uint32_t> h_lut_indexes;
    for (uint32_t b = 0; b < num_output_blocks; b++) {
      CudaKeystreamContributionFFI const *block_contribs =
          h_contributions.data() + h_block_offsets[b];
      uint32_t num_block_contribs = h_block_offsets[b + 1] - h_block_offsets[b];

      std::vector<Torus> values(lut_domain_size);
      for (uint32_t x = 0; x < lut_domain_size; x++)
        values[x] = block_function(block_contribs, num_block_contribs, x);

      auto [it, inserted] =
          lut_id_of_values.try_emplace(values, (uint32_t)lut_funcs.size());
      if (inserted) {
        lut_ids.push_back(it->second);
        lut_funcs.push_back([values](Torus x) -> Torus { return values[x]; });
      }
      h_lut_indexes.push_back(it->second);
    }

    luts = new int_radix_lut<Torus>(streams, params, (uint32_t)lut_funcs.size(),
                                    num_output_blocks, allocate_gpu_memory,
                                    size_tracker);
    auto active_streams =
        streams.active_gpu_subset(num_output_blocks, params.pbs_type());
    luts->generate_and_broadcast_lut(
        active_streams, lut_ids, lut_funcs,
        [&h_lut_indexes](Torus *lut_indexes, uint32_t count) {
          for (uint32_t i = 0; i < count; i++)
            lut_indexes[i] = h_lut_indexes[i];
        });

    d_contributions =
        (CudaKeystreamContributionFFI *)cuda_malloc_with_size_tracking_async(
            safe_mul_sizeof<CudaKeystreamContributionFFI>(num_contributions),
            streams.stream(0), streams.gpu_index(0), size_tracker,
            allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_contributions, h_contributions.data(),
        safe_mul_sizeof<CudaKeystreamContributionFFI>(num_contributions),
        streams.stream(0), streams.gpu_index(0), allocate_gpu_memory);
    d_block_offsets = (uint32_t *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<uint32_t>(h_block_offsets.size()), streams.stream(0),
        streams.gpu_index(0), size_tracker, allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_block_offsets, h_block_offsets.data(),
        safe_mul_sizeof<uint32_t>(h_block_offsets.size()), streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);

    packed_keystream = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), packed_keystream,
        num_output_blocks, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  /// @brief LUT function of an output block. Example of a lone contribution,
  /// src_bit_pos = 1 and len = 2:
  ///
  ///     x              b3 b2 b1 b0
  ///                       \___/
  ///                         |  xor input_bits
  ///                         v
  ///     result            o1 o0
  ///
  /// @param contribs     Contributions of the output block
  /// @param num_contribs 1 for extract_xor, more for packed_xor
  /// @param x            Packed keystream value of the output block
  static Torus block_function(CudaKeystreamContributionFFI const *contribs,
                              uint32_t num_contribs, Torus x) {
    if (num_contribs == 1) {
      // extract_xor: a lone contribution is the first of its block, so
      // dst_bit_pos == 0 and x is the keystream block itself
      auto const &c = contribs[0];
      Torus xored_input = (x >> c.src_bit_pos) ^ c.input_bits;
      return (xored_input & (((Torus)1 << c.len) - 1)) << c.dst_bit_pos;
    }
    // packed_xor: whole keystream blocks, already packed at their dst_bit_pos
    Torus input = 0;
    uint32_t width = 0;
    for (uint32_t i = 0; i < num_contribs; i++) {
      input |= (Torus)contribs[i].input_bits << contribs[i].dst_bit_pos;
      width += contribs[i].len;
    }
    return (x ^ input) & (((Torus)1 << width) - 1);
  }

  void release(CudaStreams streams) {
    luts->release(streams);
    delete luts;
    luts = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   packed_keystream, allocate_gpu_memory);
    delete packed_keystream;
    packed_keystream = nullptr;

    cuda_drop_with_size_tracking_async(d_contributions, streams.stream(0),
                                       streams.gpu_index(0),
                                       allocate_gpu_memory);
    cuda_drop_with_size_tracking_async(d_block_offsets, streams.stream(0),
                                       streams.gpu_index(0),
                                       allocate_gpu_memory);
    // The async copies to the GPU read the host vectors, freed with this buffer
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
