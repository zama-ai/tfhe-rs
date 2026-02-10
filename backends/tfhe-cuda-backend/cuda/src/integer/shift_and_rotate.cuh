#ifndef CUDA_INTEGER_SHIFT_OPS_CUH
#define CUDA_INTEGER_SHIFT_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/shift_and_rotate.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "scalar_mul.cuh"

template <typename Torus>
__host__ uint64_t scratch_cuda_shift_and_rotate(
    CudaStreams streams, int_shift_and_rotate_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_shift_and_rotate_buffer<Torus>(
      streams, shift_type, is_signed, params, num_radix_blocks,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void
host_shift_and_rotate_inplace(CudaStreams streams,
                              CudaRadixCiphertextFFI *lwe_array,
                              CudaRadixCiphertextFFI const *lwe_shift,
                              int_shift_and_rotate_buffer<Torus> *mem,
                              void *const *bsks, KSTorus *const *ksks) {
  cuda_set_device(streams.gpu_index(0));

  if (lwe_array->num_radix_blocks != lwe_shift->num_radix_blocks)
    PANIC("Cuda error: lwe_shift and lwe_array num radix blocks must be "
          "the same")

  if (lwe_array->lwe_dimension != lwe_shift->lwe_dimension)
    PANIC("Cuda error: lwe_shift and lwe_array lwe_dimension must be "
          "the same")

  auto num_radix_blocks = lwe_array->num_radix_blocks;

  uint32_t bits_per_block = log2_int(mem->params.message_modulus);
  uint32_t total_nb_bits = bits_per_block * num_radix_blocks;
  if (total_nb_bits == 0)
    return;

  auto big_lwe_dimension = mem->params.big_lwe_dimension;

  if (lwe_array->lwe_dimension != big_lwe_dimension)
    PANIC("Cuda error: lwe_shift lwe_dimension must be equal to "
          "big_lwe_dimension")

  // Extract all bits
  auto bits = mem->tmp_bits;
  extract_n_bits<Torus>(streams, bits, lwe_array, bsks, ksks,
                        num_radix_blocks * bits_per_block, num_radix_blocks,
                        mem->bit_extract_luts);

  // Extract shift bits
  auto shift_bits = mem->tmp_shift_bits;
  auto is_power_of_two = [](uint32_t n) {
    return (n > 0) && ((n & (n - 1)) == 0);
  };

  // This effectively means, that if the block parameters
  // give a total_nb_bits that is not a power of two,
  // then the behaviour of shifting won't be the same
  // if shift >= total_nb_bits compared to when total_nb_bits
  // is a power of two, as will 'capture' more bits in `shift_bits`
  uint32_t max_num_bits_that_tell_shift = log2_int(total_nb_bits);
  if (!is_power_of_two(total_nb_bits))
    max_num_bits_that_tell_shift += 1;
  // Extracts bits and put them in the bit index 2 (=> bit number 3)
  // so that it is already aligned to the correct position of the cmux input
  // and we reduce noise growth
  extract_n_bits<Torus>(streams, shift_bits, lwe_shift, bsks, ksks,
                        max_num_bits_that_tell_shift, num_radix_blocks,
                        mem->bit_extract_luts_with_offset_2);

  // If signed, do an "arithmetic shift" by padding with the sign bit
  CudaRadixCiphertextFFI last_bit;
  as_radix_ciphertext_slice<Torus>(&last_bit, bits, (total_nb_bits - 1),
                                   total_nb_bits);

  // Apply op
  auto rotated_input = mem->tmp_rotated;
  auto input_bits_a = mem->tmp_input_bits_a;
  auto input_bits_b = mem->tmp_input_bits_b;
  auto mux_lut = mem->mux_lut;
  auto mux_inputs = mem->tmp_mux_inputs;

  copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                     input_bits_a, bits);
  for (int d = 0; d < max_num_bits_that_tell_shift; d++) {
    CudaRadixCiphertextFFI shift_bit;
    as_radix_ciphertext_slice<Torus>(&shift_bit, shift_bits, d, d + 1);

    copy_radix_ciphertext_async<Torus>(streams.stream(0), streams.gpu_index(0),
                                       input_bits_b, input_bits_a);
    auto rotations = 1 << d;
    switch (mem->shift_type) {
    case LEFT_SHIFT:
      // rotate right as the blocks are from LSB to MSB
      if (input_bits_b->num_radix_blocks != total_nb_bits)
        PANIC("Cuda error: incorrect number of blocks")
      host_radix_blocks_rotate_right<Torus>(
          streams, rotated_input, input_bits_b, rotations, total_nb_bits);

      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), rotated_input, 0, rotations);
      break;
    case RIGHT_SHIFT:
      // rotate left as the blocks are from LSB to MSB
      if (input_bits_b->num_radix_blocks != total_nb_bits)
        PANIC("Cuda error: incorrect number of blocks")
      host_radix_blocks_rotate_left<Torus>(streams, rotated_input, input_bits_b,
                                           rotations, total_nb_bits);

      if (mem->is_signed)
        for (int i = 0; i < rotations; i++) {
          copy_radix_ciphertext_slice_async<Torus>(
              streams.stream(0), streams.gpu_index(0), rotated_input,
              total_nb_bits - rotations + i, total_nb_bits - rotations + i + 1,
              &last_bit, 0, 1);
        }
      else {
        set_zero_radix_ciphertext_slice_async<Torus>(
            streams.stream(0), streams.gpu_index(0), rotated_input,
            total_nb_bits - rotations, total_nb_bits);
      }
      break;
    case LEFT_ROTATE:
      // rotate right as the blocks are from LSB to MSB
      host_radix_blocks_rotate_right<Torus>(
          streams, rotated_input, input_bits_b, rotations, total_nb_bits);
      break;
    case RIGHT_ROTATE:
      // rotate left as the blocks are from LSB to MSB
      host_radix_blocks_rotate_left<Torus>(streams, rotated_input, input_bits_b,
                                           rotations, total_nb_bits);
      break;
    default:
      PANIC("Unknown operation")
    }

    // host_pack bits into one block so that we have
    // control_bit|b|a
    host_pack_bivariate_blocks<Torus>(
        streams, mux_inputs, mux_lut->lwe_indexes_out.data(), rotated_input,
        input_bits_a, mux_lut->lwe_indexes_in.data(), 2, total_nb_bits,
        mem->params.message_modulus, mem->params.carry_modulus);

    // The shift bit is already properly aligned/positioned
    host_add_the_same_block_to_all_blocks<Torus>(
        streams.stream(0), streams.gpu_index(0), mux_inputs, mux_inputs,
        &shift_bit, mem->params.message_modulus, mem->params.carry_modulus);

    // we have
    // control_bit|b|a
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, input_bits_a, mux_inputs, bsks, ksks, mux_lut, total_nb_bits);
  }

  // Initializes the output
  // Copy the last bit for each radix block
  for (int i = 0; i < num_radix_blocks; i++) {
    auto last_bit_index = (bits_per_block - 1) + i * bits_per_block;
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), lwe_array, i, i + 1,
        input_bits_a, last_bit_index, last_bit_index + 1);
  }

  // Bitshift and add the other bits
  for (int i = bits_per_block - 2; i >= 0; i--) {
    host_integer_small_scalar_mul_radix<Torus>(streams, lwe_array, lwe_array, 2,
                                               mem->params.message_modulus,
                                               mem->params.carry_modulus);
    for (int j = 0; j < num_radix_blocks; j++) {
      CudaRadixCiphertextFFI block;
      CudaRadixCiphertextFFI bit_to_add;
      as_radix_ciphertext_slice<Torus>(&block, lwe_array, j, j + 1);
      as_radix_ciphertext_slice<Torus>(&bit_to_add, input_bits_a,
                                       i + j * bits_per_block,
                                       i + j * bits_per_block + 1);
      host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &block,
                           &block, &bit_to_add, 1, mem->params.message_modulus,
                           mem->params.carry_modulus);
    }

    // To give back a clean ciphertext
    auto cleaning_lut = mem->cleaning_lut;
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, lwe_array, lwe_array, bsks, ksks, cleaning_lut,
        num_radix_blocks);
  }
}
#endif
