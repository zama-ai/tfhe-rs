#pragma once
#include "integer/comparison.h"
#include "integer_utilities.h"

template <typename Torus> struct int_shift_and_rotate_buffer {
  int_radix_params params;
  SHIFT_OR_ROTATE_TYPE shift_type;
  bool is_signed;

  CudaRadixCiphertextFFI *tmp_bits;
  CudaRadixCiphertextFFI *tmp_shift_bits;
  CudaRadixCiphertextFFI *tmp_rotated;
  CudaRadixCiphertextFFI *tmp_input_bits_a;
  CudaRadixCiphertextFFI *tmp_input_bits_b;
  CudaRadixCiphertextFFI *tmp_mux_inputs;

  int_bit_extract_luts_buffer<Torus> *bit_extract_luts;
  int_bit_extract_luts_buffer<Torus> *bit_extract_luts_with_offset_2;
  int_radix_lut<Torus> *mux_lut;
  int_radix_lut<Torus> *cleaning_lut;

  // Overshift handling: shifting by >= the integer's bit width yields 0, or the
  // sign (0 / -1) for an arithmetic right shift.

  /// @brief true for shifts (left/right), false for rotations.
  bool handle_overshift;
  /// @brief Scratch for the comparison "shift amount >= total_nb_bits".
  int_comparison_buffer<Torus> *overshift_compare_mem;
  /// @brief One-block ct reused by the fixup: first the boolean predicate,
  /// then the per-block condition packed into the carry.
  CudaRadixCiphertextFFI *tmp_overshift;
  /// @brief Zero-padded copy of the shift amount, used when the block count is
  /// odd (the comparison needs an even count, or one). Null when not padding.
  CudaRadixCiphertextFFI *tmp_padded_shift;
  /// @brief Number of blocks the comparison runs on: the input block count
  /// rounded up to even (or 1).
  uint32_t overshift_compare_num_blocks;
  /// @brief Constant the shift amount is compared against: total_nb_bits split
  /// into blocks, on the host.
  Torus *h_overshift_scalar_blocks;
  /// @brief Device copy of the scalar blocks.
  Torus *d_overshift_scalar_blocks;
  /// @brief Number of digits in the total_nb_bits decomposition.
  uint32_t num_overshift_scalar_blocks;
  /// @brief Moves the small condition into a block's carry
  /// (x -> (x % message_modulus) * message_modulus) so it can be added per
  /// block.
  int_radix_lut<Torus> *overshift_pack_lut;
  /// @brief Per-block finalizer: reads the packed condition and keeps the
  /// shifted value or replaces it with 0 / the sign, refreshing noise in the
  /// same PBS.

  int_radix_lut<Torus> *overshift_cleanup_lut;

  Torus offset;
  bool gpu_memory_allocated;

  int_shift_and_rotate_buffer(CudaStreams streams,
                              SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed,
                              int_radix_params params,
                              uint32_t num_radix_blocks,
                              bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    this->shift_type = shift_type;
    this->is_signed = is_signed;
    this->params = params;
    gpu_memory_allocated = allocate_gpu_memory;

    uint32_t bits_per_block = std::log2(params.message_modulus);
    uint32_t total_nb_bits =
        std::log2(params.message_modulus) * num_radix_blocks;
    uint32_t max_num_bits_that_tell_shift = std::log2(total_nb_bits);

    auto is_power_of_two = [](uint32_t n) {
      return (n > 0) && ((n & (n - 1)) == 0);
    };

    if (!is_power_of_two(total_nb_bits))
      max_num_bits_that_tell_shift += 1;

    offset = (shift_type == LEFT_SHIFT ? 0 : total_nb_bits);

    bit_extract_luts = new int_bit_extract_luts_buffer<Torus>(
        streams, params, bits_per_block, num_radix_blocks, allocate_gpu_memory,
        size_tracker);
    bit_extract_luts_with_offset_2 = new int_bit_extract_luts_buffer<Torus>(
        streams, params, bits_per_block, 2, num_radix_blocks,
        allocate_gpu_memory, size_tracker);

    mux_lut = new int_radix_lut<Torus>(streams, params, 1,
                                       bits_per_block * num_radix_blocks,
                                       allocate_gpu_memory, size_tracker);
    cleaning_lut =
        new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                 allocate_gpu_memory, size_tracker);

    tmp_bits = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_bits,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_shift_bits = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_shift_bits,
        max_num_bits_that_tell_shift * num_radix_blocks,
        params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

    tmp_rotated = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_rotated,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_input_bits_a = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_input_bits_a,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_input_bits_b = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_input_bits_b,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    tmp_mux_inputs = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), tmp_mux_inputs,
        bits_per_block * num_radix_blocks, params.big_lwe_dimension,
        size_tracker, allocate_gpu_memory);

    auto mux_lut_f = [](Torus x) -> Torus {
      // x is expected to be x = 0bcba
      // where
      // - c is the control bit
      // - b the bit value returned if c is 1
      // - a the bit value returned if c is 0
      // (any bit above c is ignored)
      x = x & 7;
      auto control_bit = x >> 2;
      auto previous_bit = (x & 2) >> 1;
      auto current_bit = x & 1;

      if (control_bit == 1)
        return previous_bit;
      else
        return current_bit;
    };
    auto active_gpu_count_mux = streams.active_gpu_subset(
        bits_per_block * num_radix_blocks, params.pbs_type);

    mux_lut->generate_and_broadcast_lut(active_gpu_count_mux, {0}, {mux_lut_f},
                                        LUT_0_FOR_ALL_BLOCKS);

    auto cleaning_lut_f = [params](Torus x) -> Torus {
      return x % params.message_modulus;
    };

    auto active_gpu_count_cleaning =
        streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
    cleaning_lut->generate_and_broadcast_lut(
        active_gpu_count_cleaning, {0}, {cleaning_lut_f}, LUT_0_FOR_ALL_BLOCKS);

    // ---- Overshift handling (shifts only, not rotations) ----
    setup_handle_overshift(streams, num_radix_blocks, total_nb_bits,
                           allocate_gpu_memory, size_tracker);
  }

  /// @brief Allocates and initializes the buffers and LUTs used to fix up the
  /// result when the shift amount is >= the integer's bit width (overshift).
  /// Only shifts (not rotations) need this; for rotations it just resets the
  /// members to their null/zero defaults.
  /// @param num_radix_blocks Number of radix blocks of the value being shifted.
  /// @param total_nb_bits Bit width of the value, i.e. the overshift threshold.
  void setup_handle_overshift(CudaStreams streams, uint32_t num_radix_blocks,
                              uint32_t total_nb_bits, bool allocate_gpu_memory,
                              uint64_t &size_tracker) {
    handle_overshift = (shift_type == LEFT_SHIFT || shift_type == RIGHT_SHIFT);
    overshift_compare_mem = nullptr;
    tmp_overshift = nullptr;
    tmp_padded_shift = nullptr;
    overshift_compare_num_blocks = 0;
    d_overshift_scalar_blocks = nullptr;
    h_overshift_scalar_blocks = nullptr;
    num_overshift_scalar_blocks = 0;
    overshift_pack_lut = nullptr;
    overshift_cleanup_lut = nullptr;

    if (handle_overshift) {
      auto message_modulus = params.message_modulus;

      // The unsigned scalar comparison requires an even number of blocks (or
      // exactly 1), so pad the comparison block count when needed.
      overshift_compare_num_blocks = num_radix_blocks;
      if (num_radix_blocks > 1 && (num_radix_blocks % 2 != 0))
        overshift_compare_num_blocks = num_radix_blocks + 1;

      overshift_compare_mem = new int_comparison_buffer<Torus>(
          streams, COMPARISON_TYPE::GE, params, overshift_compare_num_blocks,
          /*is_signed=*/false, allocate_gpu_memory, size_tracker);

      tmp_overshift = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), tmp_overshift, 1,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);

      if (overshift_compare_num_blocks != num_radix_blocks) {
        tmp_padded_shift = new CudaRadixCiphertextFFI;
        create_zero_radix_ciphertext_async<Torus>(
            streams.stream(0), streams.gpu_index(0), tmp_padded_shift,
            overshift_compare_num_blocks, params.big_lwe_dimension,
            size_tracker, allocate_gpu_memory);
      }

      // Decompose total_nb_bits into base-message_modulus digits
      // (little-endian)
      std::vector<Torus> digits;
      {
        uint32_t v = total_nb_bits;
        while (v > 0) {
          digits.push_back((Torus)(v % message_modulus));
          v /= message_modulus;
        }
        if (digits.empty())
          digits.push_back((Torus)0);
      }
      num_overshift_scalar_blocks = (uint32_t)digits.size();
      h_overshift_scalar_blocks =
          (Torus *)malloc(num_overshift_scalar_blocks * sizeof(Torus));
      for (uint32_t i = 0; i < num_overshift_scalar_blocks; i++)
        h_overshift_scalar_blocks[i] = digits[i];
      d_overshift_scalar_blocks = (Torus *)cuda_malloc_with_size_tracking_async(
          num_overshift_scalar_blocks * sizeof(Torus), streams.stream(0),
          streams.gpu_index(0), size_tracker, allocate_gpu_memory);
      cuda_memcpy_with_size_tracking_async_to_gpu(
          d_overshift_scalar_blocks, h_overshift_scalar_blocks,
          num_overshift_scalar_blocks * sizeof(Torus), streams.stream(0),
          streams.gpu_index(0), allocate_gpu_memory);

      bool arithmetic = is_signed && (shift_type == RIGHT_SHIFT);

      // Pack LUT: moves the small condition value into the carry space, clean.
      overshift_pack_lut = new int_radix_lut<Torus>(
          streams, params, 1, 1, allocate_gpu_memory, size_tracker);
      auto pack_f = [message_modulus](Torus x) -> Torus {
        return (x % message_modulus) * message_modulus;
      };
      auto active_streams_pack = streams.active_gpu_subset(1, params.pbs_type);
      overshift_pack_lut->generate_and_broadcast_lut(
          active_streams_pack, {0}, {pack_f}, LUT_0_FOR_ALL_BLOCKS);

      // Cleanup LUT: applied per result block, reads `cond` from the carry.
      overshift_cleanup_lut =
          new int_radix_lut<Torus>(streams, params, 1, num_radix_blocks,
                                   allocate_gpu_memory, size_tracker);
      std::function<Torus(Torus)> cleanup_f;
      if (arithmetic) {
        cleanup_f = [message_modulus](Torus x) -> Torus {
          Torus c = x / message_modulus; // c == (overshift << 1) | is_neg
          Torus v = x % message_modulus;
          if (c == 3)
            return message_modulus - 1; // overshift & negative -> -1
          if (c == 2)
            return (Torus)0; // overshift & positive -> 0
          return v;          // in range -> shifted value
        };
      } else {
        cleanup_f = [message_modulus](Torus x) -> Torus {
          Torus c = x / message_modulus; // c == overshift
          Torus v = x % message_modulus;
          return (c >= 1) ? (Torus)0 : v;
        };
      }
      auto active_streams_cleanup =
          streams.active_gpu_subset(num_radix_blocks, params.pbs_type);
      overshift_cleanup_lut->generate_and_broadcast_lut(
          active_streams_cleanup, {0}, {cleanup_f}, LUT_0_FOR_ALL_BLOCKS);
    }
  }

  void release(CudaStreams streams) {
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_bits, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_shift_bits, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_rotated, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_input_bits_a, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_input_bits_b, gpu_memory_allocated);
    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   tmp_mux_inputs, gpu_memory_allocated);

    bit_extract_luts->release(streams);
    bit_extract_luts_with_offset_2->release(streams);
    mux_lut->release(streams);
    cleaning_lut->release(streams);
    if (handle_overshift)
      release_handle_overshift(streams);

    delete tmp_bits;
    delete tmp_shift_bits;
    delete tmp_rotated;
    delete tmp_input_bits_a;
    delete tmp_input_bits_b;
    delete tmp_mux_inputs;
    delete bit_extract_luts;
    delete bit_extract_luts_with_offset_2;
    delete mux_lut;
    delete cleaning_lut;
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }

  /// @brief Releases the buffers and LUTs allocated by
  /// setup_handle_overshift. A no-op when overshift handling is disabled
  /// (rotations), since all members are then null.
  void release_handle_overshift(CudaStreams streams) {

    if (overshift_compare_mem) {
      overshift_compare_mem->release(streams);
      delete overshift_compare_mem;
    }
    if (tmp_overshift) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_overshift, gpu_memory_allocated);
      delete tmp_overshift;
    }
    if (tmp_padded_shift) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     tmp_padded_shift, gpu_memory_allocated);
      delete tmp_padded_shift;
    }
    if (overshift_pack_lut) {
      overshift_pack_lut->release(streams);
      delete overshift_pack_lut;
    }
    if (overshift_cleanup_lut) {
      overshift_cleanup_lut->release(streams);
      delete overshift_cleanup_lut;
    }
    if (d_overshift_scalar_blocks)
      cuda_drop_with_size_tracking_async(
          d_overshift_scalar_blocks, streams.stream(0), streams.gpu_index(0),
          gpu_memory_allocated);
    if (h_overshift_scalar_blocks)
      free(h_overshift_scalar_blocks);
  }
};
