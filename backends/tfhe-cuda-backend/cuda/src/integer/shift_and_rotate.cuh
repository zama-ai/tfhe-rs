#ifndef CUDA_INTEGER_SHIFT_OPS_CUH
#define CUDA_INTEGER_SHIFT_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "scalar_mul.cuh"
#include "types/complex/operations.cuh"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__host__ void scratch_cuda_integer_radix_shift_and_rotate_kb(
    cuda_stream_t *stream, int_shift_and_rotate_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed, bool allocate_gpu_memory) {
  cudaSetDevice(stream->gpu_index);
  *mem_ptr = new int_shift_and_rotate_buffer<Torus>(
      stream, shift_type, is_signed, params, num_radix_blocks,
      allocate_gpu_memory);
}

template <typename Torus>
__host__ void host_integer_radix_shift_and_rotate_kb_inplace(
    cuda_stream_t *stream, Torus *lwe_array, Torus *lwe_shift,
    int_shift_and_rotate_buffer<Torus> *mem, void *bsk, Torus *ksk,
    uint32_t num_radix_blocks) {
  uint32_t bits_per_block = std::log2(mem->params.message_modulus);
  uint32_t total_nb_bits = bits_per_block * num_radix_blocks;

  auto big_lwe_dimension = mem->params.big_lwe_dimension;
  auto big_lwe_size = big_lwe_dimension + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  assert(total_nb_bits > 0);

  // Extract all bits
  auto bits = mem->tmp_bits;
  extract_n_bits<Torus>(stream, bits, lwe_array, bsk, ksk, num_radix_blocks,
                        bits_per_block, mem->bit_extract_luts);

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
  uint32_t max_num_bits_that_tell_shift = std::log2(total_nb_bits);
  if (!is_power_of_two(total_nb_bits))
    max_num_bits_that_tell_shift += 1;
  // Extracts bits and put them in the bit index 2 (=> bit number 3)
  // so that it is already aligned to the correct position of the cmux input
  // and we reduce noise growth
  extract_n_bits<Torus>(stream, shift_bits, lwe_shift, bsk, ksk, 1,
                        max_num_bits_that_tell_shift,
                        mem->bit_extract_luts_with_offset_2);

  // If signed, do an "arithmetic shift" by padding with the sign bit
  auto last_bit = bits + (total_nb_bits - 1) * big_lwe_size;

  // Apply op
  auto rotated_input = mem->tmp_rotated;
  auto input_bits_a = mem->tmp_input_bits_a;
  auto input_bits_b = mem->tmp_input_bits_b;
  auto mux_lut = mem->mux_lut;
  auto mux_inputs = mem->tmp_mux_inputs;

  cuda_memcpy_async_gpu_to_gpu(input_bits_a, bits,
                               total_nb_bits * big_lwe_size_bytes, stream);
  for (int d = 0; d < max_num_bits_that_tell_shift; d++) {
    auto shift_bit = shift_bits + d * big_lwe_size;

    cuda_memcpy_async_gpu_to_gpu(input_bits_b, input_bits_a,
                                 total_nb_bits * big_lwe_size_bytes, stream);

    auto rotations = 1 << d;
    switch (mem->shift_type) {
    case LEFT_SHIFT:
      radix_blocks_rotate_right<<<total_nb_bits, 256, 0, stream->stream>>>(
          rotated_input, input_bits_b, rotations, total_nb_bits, big_lwe_size);

      if (mem->is_signed && mem->shift_type == RIGHT_SHIFT)
        for (int i = 0; i < rotations; i++)
          cuda_memcpy_async_gpu_to_gpu(rotated_input + i * big_lwe_size,
                                       last_bit, big_lwe_size_bytes, stream);
      else
        cuda_memset_async(rotated_input, 0, rotations * big_lwe_size_bytes,
                          stream);
      break;
    case RIGHT_SHIFT:
      radix_blocks_rotate_left<<<total_nb_bits, 256, 0, stream->stream>>>(
          rotated_input, input_bits_b, rotations, total_nb_bits, big_lwe_size);

      if (mem->is_signed)
        for (int i = 0; i < rotations; i++)
          cuda_memcpy_async_gpu_to_gpu(
              rotated_input + (total_nb_bits - rotations + i) * big_lwe_size,
              last_bit, big_lwe_size_bytes, stream);
      else
        cuda_memset_async(rotated_input +
                              (total_nb_bits - rotations) * big_lwe_size,
                          0, rotations * big_lwe_size_bytes, stream);
      break;
    case LEFT_ROTATE:
      radix_blocks_rotate_right<<<total_nb_bits, 256, 0, stream->stream>>>(
          rotated_input, input_bits_b, rotations, total_nb_bits, big_lwe_size);
      break;
    case RIGHT_ROTATE:
      radix_blocks_rotate_left<<<total_nb_bits, 256, 0, stream->stream>>>(
          rotated_input, input_bits_b, rotations, total_nb_bits, big_lwe_size);
      break;
    default:
      PANIC("Unknown operation")
    }

    // pack bits into one block so that we have
    // control_bit|b|a
    cuda_memset_async(mux_inputs, 0, total_nb_bits * big_lwe_size_bytes,
                      stream); // Do we need this?
    pack_bivariate_blocks(stream, mux_inputs, mux_lut->lwe_indexes_out,
                          rotated_input, input_bits_a, mux_lut->lwe_indexes_in,
                          big_lwe_dimension, 2, total_nb_bits);

    // The shift bit is already properly aligned/positioned
    for (int i = 0; i < total_nb_bits; i++)
      host_addition(stream, mux_inputs + i * big_lwe_size,
                    mux_inputs + i * big_lwe_size, shift_bit,
                    mem->params.big_lwe_dimension, 1);

    // we have
    // control_bit|b|a
    integer_radix_apply_univariate_lookup_table_kb(
        stream, input_bits_a, mux_inputs, bsk, ksk, total_nb_bits, mux_lut);
  }

  // Initializes the output
  // Copy the last bit for each radix block
  auto lwe_last_out = lwe_array;
  last_bit = input_bits_a + (bits_per_block - 1) * big_lwe_size;
  for (int i = 0; i < num_radix_blocks; i++) {
    cuda_memcpy_async_gpu_to_gpu(lwe_last_out, last_bit, big_lwe_size_bytes,
                                 stream);

    lwe_last_out += big_lwe_size;
    last_bit += bits_per_block * big_lwe_size;
  }

  // Bitshift and add the other bits
  lwe_last_out = lwe_array;
  for (int i = bits_per_block - 2; i >= 0; i--) {

    host_integer_small_scalar_mul_radix<Torus>(
        stream, lwe_last_out, lwe_last_out, 2, big_lwe_dimension,
        num_radix_blocks);

    auto block = lwe_last_out;
    auto bit_to_add = input_bits_a + i * big_lwe_size;

    for (int j = 0; j < num_radix_blocks; j++) {
      host_addition(stream, block, block, bit_to_add, big_lwe_dimension, 1);

      block += big_lwe_size;
      bit_to_add += bits_per_block * big_lwe_size;
    }

    // To give back a clean ciphertext
    auto cleaning_lut = mem->cleaning_lut;
    integer_radix_apply_univariate_lookup_table_kb(
        stream, lwe_last_out, lwe_last_out, bsk, ksk, num_radix_blocks,
        cleaning_lut);
  }
}
#endif
