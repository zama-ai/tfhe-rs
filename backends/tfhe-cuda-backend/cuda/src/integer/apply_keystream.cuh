#pragma once

#include "integer/apply_keystream.h"
#include "integer/integer.cuh"

/**
 * @brief Linear part of the keystream application, without PBS. One CUDA
 * block per output block, its threads stride over the LWE coefficients.
 *
 * @param packed_keystream One LWE per output block
 * @param keystream        LWEs indexed by the keystream_block_index of the
 * contributions
 * @param contributions    Sorted by output block
 * @param block_offsets    First contribution of each output block, then
 * num_contributions
 * @param lwe_size         Same for the keystream and the packed blocks
 */
template <typename Torus>
__global__ void
device_pack_keystream(Torus *packed_keystream, Torus const *keystream,
                      CudaKeystreamContributionFFI const *contributions,
                      uint32_t const *block_offsets, uint32_t lwe_size) {
  const uint32_t first = block_offsets[blockIdx.x];
  const uint32_t last = block_offsets[blockIdx.x + 1];
  Torus *packed_block = packed_keystream + (size_t)blockIdx.x * lwe_size;

  for (uint32_t i = threadIdx.x; i < lwe_size; i += blockDim.x) {
    Torus sum = 0;
    for (uint32_t c = first; c < last; c++) {
      auto const &contrib = contributions[c];
      size_t index = (size_t)contrib.keystream_block_index * lwe_size + i;
      sum += ((Torus)1 << contrib.dst_bit_pos) * keystream[index];
    }
    packed_block[i] = sum;
  }
}

template <typename Torus>
uint64_t scratch_cuda_apply_keystream(
    CudaStreams streams, int_apply_keystream_buffer<Torus> **mem_ptr,
    int_radix_params params, CudaKeystreamContributionFFI const *contributions,
    uint32_t num_contributions, uint32_t num_output_blocks,
    bool allocate_gpu_memory) {
  PUSH_RANGE("scratch apply keystream")
  uint64_t size_tracker = 0;
  *mem_ptr = new int_apply_keystream_buffer<Torus>(
      streams, params, contributions, num_contributions, num_output_blocks,
      allocate_gpu_memory, size_tracker);
  POP_RANGE()
  return size_tracker;
}

/**
 * @brief Host side of cuda_apply_keystream_64_async.
 *
 * The packing kernel only sees LWE data, so the degrees and noise levels are
 * summed here. CHECK_NOISE_LEVEL is debug only, the Rust caller checks the
 * noise budget beforehand.
 *
 * @param output    One block per output block of mem_ptr
 * @param keystream Blocks indexed by the contributions of mem_ptr, with the big
 * LWE dimension
 */
template <typename Torus, typename KSTorus>
void host_apply_keystream(CudaStreams streams, CudaRadixCiphertextFFI *output,
                          CudaRadixCiphertextFFI const *keystream,
                          int_apply_keystream_buffer<Torus> *mem_ptr,
                          void *const *bsks, KSTorus *const *ksks) {
  auto packed = mem_ptr->packed_keystream;
  PANIC_IF_FALSE(output->num_radix_blocks == mem_ptr->num_output_blocks,
                 "Cuda error (apply keystream): the output must have one block "
                 "per output block of the scratch");
  PANIC_IF_FALSE(keystream->lwe_dimension == packed->lwe_dimension,
                 "Cuda error (apply keystream): the keystream must have the "
                 "big lwe dimension");

  for (uint32_t b = 0; b < mem_ptr->num_output_blocks; b++) {
    uint64_t degree = 0;
    uint64_t noise_level = 0;
    for (uint32_t c = mem_ptr->h_block_offsets[b];
         c < mem_ptr->h_block_offsets[b + 1]; c++) {
      auto const &contrib = mem_ptr->h_contributions[c];
      uint32_t index = contrib.keystream_block_index;
      PANIC_IF_FALSE(index < keystream->num_radix_blocks,
                     "Cuda error (apply keystream): keystream block index out "
                     "of bounds");
      uint64_t factor = (uint64_t)1 << contrib.dst_bit_pos;
      degree += factor * keystream->degrees[index];
      noise_level += factor * keystream->noise_levels[index];
    }
    packed->degrees[b] = degree;
    packed->noise_levels[b] = noise_level;
    CHECK_NOISE_LEVEL(noise_level, mem_ptr->params.message_modulus,
                      mem_ptr->params.carry_modulus);
  }

  cuda_set_device(streams.gpu_index(0));
  device_pack_keystream<Torus>
      <<<mem_ptr->num_output_blocks, 512, 0, streams.stream(0)>>>(
          (Torus *)packed->ptr, (Torus const *)keystream->ptr,
          mem_ptr->d_contributions, mem_ptr->d_block_offsets,
          keystream->lwe_dimension + 1);
  check_cuda_error(cudaGetLastError());

  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, output, packed, bsks, ksks, mem_ptr->luts,
      mem_ptr->num_output_blocks);
}
