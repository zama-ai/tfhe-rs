#pragma once
#include "integer_utilities.h"
#include <map>

/// @brief Scratch of the keystream application: output = keystream XOR input.
///
///     entity          status      held by
///     ------------------------------------------------------------------
///     message         clear       client, never sent
///     keystream       encrypted   server, the client has it in clear
///     input           clear       client, message XOR keystream
///     contributions   clear       server, from the input and the layouts
///     output          encrypted   server, the message
///
///                              one contribution   two contributions
///                              OTP OPRF           Kreyvium
///                              2 bits per block   1 bit per block
///
///     keystream blocks             k0 = 2          k0 = 1   k1 = 1
///                                    |                 \     /
///     1. sum of 2^dst_bit_pos * k   copy             k0 + 2 * k1
///        (device_pack_keystream)     |                    |
///     packed_keystream             p = 2                p = 3
///     clear input                  i = 3                i = 1
///                                    |                    |
///     2. one PBS, p XOR i          2 ^ 3                3 ^ 1
///        (block_function)            |                    |
///     output block                 o = 1                o = 2
///
/// CudaKeystreamContributionFFI defines a contribution and gives two examples.
/// Each column builds the block o0 of one of them.
///
/// Rust refuses this layout, it never reaches the backend:
///
///     keystream blocks   [  k0  ][  k1  ]
///     keystream bits     [b0][b1][b2][b3]
///     output blocks      [o0][  o1  ][o2]
///
/// o1 needs the high bit of k0 and the low bit of k1. The sum k0 + 2 * k1
/// would bring the two other bits along.
template <typename Torus> struct int_apply_keystream_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// One PBS each
  uint32_t num_output_blocks;

  /// Sorted by output block
  std::vector<CudaKeystreamContributionFFI> h_contributions;
  /// @brief Output block b owns the contributions from h_block_offsets[b] to
  /// h_block_offsets[b + 1] excluded
  std::vector<uint32_t> h_block_offsets;
  /// GPU copy of h_contributions
  CudaKeystreamContributionFFI *d_contributions;
  /// GPU copy of h_block_offsets
  uint32_t *d_block_offsets;

  /// p in the schema
  CudaRadixCiphertextFFI *packed_keystream;
  /// One LUT per distinct block function
  int_radix_lut<Torus> *luts;

  /// @brief Builds the LUTs of step 2. Blocks with the same block function
  /// share one LUT: the 32 blocks of the Kreyvium example need at most 4, one
  /// per value of their 2 input bits.
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

    const uint32_t message_bits = log2_int(params.message_modulus);
    for (uint32_t c = 0; c < num_contributions; c++) {
      auto const &contrib = h_contributions[c];
      // The bits land inside the message space of the output block. This also
      // bounds every shift by dst_bit_pos and len, here and in the kernel
      PANIC_IF_FALSE(contrib.len > 0 &&
                         contrib.dst_bit_pos + contrib.len <= message_bits,
                     "Cuda error (apply keystream): a contribution does not "
                     "fit in the message space of its output block");

      // The Rust caller builds them sorted, anything else is a bug
      uint32_t block = contrib.output_block_index;
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

      // Preconditions of block_function. The first contribution starts the
      // block, and each next one starts where the previous one ends, so the
      // pieces tile the block without overlap
      PANIC_IF_FALSE(block_contribs[0].dst_bit_pos == 0,
                     "Cuda error (apply keystream): the first contribution of "
                     "an output block must start at bit 0");
      for (uint32_t i = 1; i < num_block_contribs; i++)
        PANIC_IF_FALSE(block_contribs[i].dst_bit_pos ==
                           block_contribs[i - 1].dst_bit_pos +
                               block_contribs[i - 1].len,
                       "Cuda error (apply keystream): the contributions of an "
                       "output block must be contiguous");
      // Packing sums whole keystream blocks, a partial one would add its
      // unused low bits to the packed value
      if (num_block_contribs > 1)
        for (uint32_t i = 0; i < num_block_contribs; i++)
          PANIC_IF_FALSE(block_contribs[i].src_bit_pos == 0,
                         "Cuda error (apply keystream): a packed output block "
                         "must use whole keystream blocks");

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

  /// @brief LUT of an output block, step 2 of the struct header.
  ///
  /// A lone contribution may take a part of its keystream block, like o2 in
  /// the OTP OPRF example. The LUT then shifts and masks x. Several
  /// contributions take whole keystream blocks, which step 1 already put in
  /// place.
  ///
  /// @param contribs     Contributions of the output block
  /// @param num_contribs Number of contributions of the output block
  /// @param x            Value of the packed block
  static Torus block_function(CudaKeystreamContributionFFI const *contribs,
                              uint32_t num_contribs, Torus x) {
    if (num_contribs == 1) {
      auto const &c = contribs[0];
      Torus xored_input = (x >> c.src_bit_pos) ^ c.input_bits;
      return xored_input & (((Torus)1 << c.len) - 1);
    }
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
