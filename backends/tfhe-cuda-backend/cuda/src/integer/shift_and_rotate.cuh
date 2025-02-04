#ifndef CUDA_INTEGER_SHIFT_OPS_CUH
#define CUDA_INTEGER_SHIFT_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "scalar_mul.cuh"
#include "types/complex/operations.cuh"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__host__ void scratch_cuda_integer_radix_shift_and_rotate_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_shift_and_rotate_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    SHIFT_OR_ROTATE_TYPE shift_type, bool is_signed, bool allocate_gpu_memory) {
  *mem_ptr = new int_shift_and_rotate_buffer<Torus>(
      streams, gpu_indexes, gpu_count, shift_type, is_signed, params,
      num_radix_blocks, allocate_gpu_memory);
}

template <typename Torus>
__host__ void host_integer_radix_shift_and_rotate_kb_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array,
    CudaRadixCiphertextFFI const *lwe_shift,
    int_shift_and_rotate_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks) {
  cuda_set_device(gpu_indexes[0]);

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
  auto big_lwe_size = big_lwe_dimension + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  if (lwe_array->lwe_dimension != big_lwe_dimension)
    PANIC("Cuda error: lwe_shift lwe_dimension must be equal to "
          "big_lwe_dimension")

  // Extract all bits
  auto bits = mem->tmp_bits;
  extract_n_bits<Torus>(streams, gpu_indexes, gpu_count, bits, lwe_array, bsks,
                        ksks, num_radix_blocks * bits_per_block,
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
  extract_n_bits<Torus>(streams, gpu_indexes, gpu_count, shift_bits, lwe_shift,
                        bsks, ksks, max_num_bits_that_tell_shift,
                        mem->bit_extract_luts_with_offset_2);

  // If signed, do an "arithmetic shift" by padding with the sign bit
  CudaRadixCiphertextFFI last_bit;
  as_radix_ciphertext_slice<Torus>(&last_bit, bits, (total_nb_bits - 1),
                                   (total_nb_bits - 1));

  // Apply op
  auto rotated_input = mem->tmp_rotated;
  auto input_bits_a = mem->tmp_input_bits_a;
  auto input_bits_b = mem->tmp_input_bits_b;
  auto mux_lut = mem->mux_lut;
  auto mux_inputs = mem->tmp_mux_inputs;

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], input_bits_a,
                                     bits);
  for (int d = 0; d < max_num_bits_that_tell_shift; d++) {
    CudaRadixCiphertextFFI shift_bit;
    as_radix_ciphertext_slice<Torus>(&shift_bit, shift_bits, d, d);

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], input_bits_b,
                                       input_bits_a);
    auto rotations = 1 << d;
    switch (mem->shift_type) {
    case LEFT_SHIFT:
      // rotate right as the blocks are from LSB to MSB
      if (input_bits_b->num_radix_blocks != total_nb_bits)
        PANIC("Cuda error: incorrect number of blocks")
      host_radix_blocks_rotate_right<Torus>(streams, gpu_indexes, gpu_count,
                                            rotated_input, input_bits_b,
                                            rotations);

      cuda_memset_async((Torus *)rotated_input->ptr, 0,
                        rotations * big_lwe_size_bytes, streams[0],
                        gpu_indexes[0]);
      memset(rotated_input->degrees, 0, rotations * sizeof(uint64_t));
      memset(rotated_input->noise_levels, 0, rotations * sizeof(uint64_t));
      break;
    case RIGHT_SHIFT:
      // rotate left as the blocks are from LSB to MSB
      if (input_bits_b->num_radix_blocks != total_nb_bits)
        PANIC("Cuda error: incorrect number of blocks")
      host_radix_blocks_rotate_left<Torus>(streams, gpu_indexes, gpu_count,
                                           rotated_input, input_bits_b,
                                           rotations);

      if (mem->is_signed)
        for (int i = 0; i < rotations; i++) {
          CudaRadixCiphertextFFI slice_rotated_input;
          as_radix_ciphertext_slice<Torus>(&slice_rotated_input, rotated_input,
                                           (total_nb_bits - rotations + i),
                                           (total_nb_bits - rotations + i));

          cuda_memcpy_async_gpu_to_gpu(
              (Torus *)slice_rotated_input.ptr, (Torus *)last_bit.ptr,
              big_lwe_size_bytes, streams[0], gpu_indexes[0]);
          slice_rotated_input.degrees[0] = last_bit.degrees[0];
          slice_rotated_input.noise_levels[0] = last_bit.noise_levels[0];
        }
      else {
        CudaRadixCiphertextFFI slice_rotated_input;
        as_radix_ciphertext_slice<Torus>(&slice_rotated_input, rotated_input,
                                         (total_nb_bits - rotations),
                                         total_nb_bits);

        cuda_memset_async(slice_rotated_input.ptr, 0,
                          rotations * big_lwe_size_bytes, streams[0],
                          gpu_indexes[0]);
        memset(slice_rotated_input.degrees, 0, rotations * sizeof(uint64_t));
        memset(slice_rotated_input.noise_levels, 0,
               rotations * sizeof(uint64_t));
      }
      break;
    case LEFT_ROTATE:
      // rotate right as the blocks are from LSB to MSB
      host_radix_blocks_rotate_right<Torus>(streams, gpu_indexes, gpu_count,
                                            rotated_input, input_bits_b,
                                            rotations);
      break;
    case RIGHT_ROTATE:
      // rotate left as the blocks are from LSB to MSB
      host_radix_blocks_rotate_left<Torus>(streams, gpu_indexes, gpu_count,
                                           rotated_input, input_bits_b,
                                           rotations);
      break;
    default:
      PANIC("Unknown operation")
    }

    // host_pack bits into one block so that we have
    // control_bit|b|a
    pack_bivariate_blocks<Torus>(
        streams, gpu_indexes, gpu_count, (Torus *)mux_inputs->ptr,
        mux_lut->lwe_indexes_out, (Torus *)rotated_input->ptr,
        (Torus *)input_bits_a->ptr, mux_lut->lwe_indexes_in, big_lwe_dimension,
        2, total_nb_bits);

    // The shift bit is already properly aligned/positioned
    host_add_the_same_block_to_all_blocks<Torus>(
        streams[0], gpu_indexes[0], mux_inputs, mux_inputs, &shift_bit);

    // we have
    // control_bit|b|a
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, input_bits_a, mux_inputs, bsks, ksks,
        mux_lut, mux_inputs->num_radix_blocks);
  }

  // Initializes the output
  // Copy the last bit for each radix block
  for (int i = 0; i < num_radix_blocks; i++) {
    CudaRadixCiphertextFFI last_bit, lwe_last_out;
    as_radix_ciphertext_slice<Torus>(&last_bit, input_bits_a,
                                     (bits_per_block - 1) + i * bits_per_block,
                                     (bits_per_block - 1) + i * bits_per_block);
    as_radix_ciphertext_slice<Torus>(&lwe_last_out, lwe_array, i, i);

    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       &lwe_last_out, &last_bit);
  }

  // Bitshift and add the other bits
  for (int i = bits_per_block - 2; i >= 0; i--) {

    host_integer_small_scalar_mul_radix<Torus>(streams, gpu_indexes, gpu_count,
                                               lwe_array, lwe_array, 2);

    CudaRadixCiphertextFFI bit_to_add;
    as_radix_ciphertext_slice<Torus>(&bit_to_add, input_bits_a, i, i);
    for (int j = 0; j < num_radix_blocks; j++) {
      CudaRadixCiphertextFFI block;
      as_radix_ciphertext_slice<Torus>(&block, lwe_array, j, j);

      host_addition<Torus>(streams[0], gpu_indexes[0], &block, &block,
                           &bit_to_add);

      as_radix_ciphertext_slice<Torus>(&bit_to_add, &bit_to_add, bits_per_block,
                                       bits_per_block);
    }

    // To give back a clean ciphertext
    auto cleaning_lut = mem->cleaning_lut;
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array, lwe_array, bsks, ksks,
        cleaning_lut, lwe_array->num_radix_blocks);
  }
}
#endif
