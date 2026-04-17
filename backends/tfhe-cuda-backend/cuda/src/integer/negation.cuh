#ifndef CUDA_INTEGER_NEGATE_CUH
#define CUDA_INTEGER_NEGATE_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer/integer.h"
#include "integer/integer_utilities.h"
#include "linearalgebra/negation.cuh"
#include "utils/helper.cuh"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
__global__ void device_negation(Torus *output, Torus const *input,
                                int32_t num_blocks, uint64_t lwe_dimension,
                                uint64_t message_modulus, uint64_t delta) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < lwe_dimension + 1) {
    bool is_body = (tid == lwe_dimension);

    // z = ceil( degree / 2^p ) * 2^p
    uint64_t z = (2 * message_modulus - 1) / message_modulus;
    z *= message_modulus;

    // (0,Delta*z) - ct
    output[tid] = (is_body ? z * delta - input[tid] : -input[tid]);

    for (int radix_block_id = 1; radix_block_id < num_blocks;
         radix_block_id++) {
      tid += (lwe_dimension + 1);

      // Subtract z/B to the next ciphertext to compensate for the addition of z
      uint64_t zb = z / message_modulus;

      uint64_t encoded_zb = zb * delta;

      // (0,Delta*z) - ct
      output[tid] =
          (is_body ? z * delta - (input[tid] + encoded_zb) : -input[tid]);
    }
  }
}

/** @brief Negates the first num_radix_blocks blocks of a radix-ciphertext using
 * wrapping LWE negation. Noise levels are propagated unchanged, degrees are set
 * to the worst case. This is a fully levelled negation and no PBS is performed.
 * @param output destination radix-ciphertext
 * @param input input radix-ciphertext
 * @param num_radix_blocks number of blocks to negate
 */
template <typename T>
__host__ void host_negation(cudaStream_t stream, uint32_t gpu_index,
                            CudaRadixCiphertextFFI *output,
                            CudaRadixCiphertextFFI const *input,
                            uint32_t num_radix_blocks, uint32_t message_modulus,
                            uint32_t carry_modulus) {

  cuda_set_device(gpu_index);
  int lwe_size = input->lwe_dimension + 1;
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_radix_blocks * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Negate both mask and message
  negation<T><<<grid, thds, 0, stream>>>((T *)output->ptr,
                                         (T const *)input->ptr, num_entries);
  check_cuda_error(cudaGetLastError());
  for (uint i = 0; i < num_radix_blocks; i++) {
    output->noise_levels[i] = input->noise_levels[i];
    // Unless the input degree is 0, the output degree is the worst case
    // (including padding bit = 1)
    output->degrees[i] =
        (input->degrees[i] == 0)
            ? 0
            : (uint64_t)(2 * message_modulus * carry_modulus) - 1;
    CHECK_NOISE_LEVEL(output->noise_levels[i], message_modulus, carry_modulus);
  }
}

/** @brief Negates the first num_radix_blocks blocks of a radix-ciphertext.
 * Messages are negated by computing (z*delta - ct) per block, where z =
 * ceil(degree / message_modulus) * message_modulus is a correcting term added
 * to each block body to prevent plaintext underflow. While ciphertexts are
 * negated block-wise, the degree computation computes burrowed degrees. Noise
 * levels are propagated unchanged. This is a fully levelled negation and no PBS
 * is performed.
 * @param lwe_array_out destination radix-ciphertext
 * @param lwe_array_in input radix-ciphertext
 * @param num_radix_blocks number of blocks to negate
 */
template <typename Torus>
__host__ void host_negation_with_correcting_term(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t message_modulus,
    uint32_t carry_modulus, uint32_t num_radix_blocks) {
  cuda_set_device(streams.gpu_index(0));

  if (lwe_array_out->num_radix_blocks < num_radix_blocks ||
      lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: lwe_array_in and lwe_array_out num radix blocks must be "
          "greater or equal to the number of blocks to negate")

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: lwe_array_in and lwe_array_out lwe_dimension must be "
          "the same")

  auto lwe_dimension = lwe_array_out->lwe_dimension;
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_negation<Torus><<<grid, thds, 0, streams.stream(0)>>>(
      static_cast<Torus *>(lwe_array_out->ptr),
      static_cast<Torus *>(lwe_array_in->ptr), num_radix_blocks, lwe_dimension,
      message_modulus, delta);
  check_cuda_error(cudaGetLastError());

  uint8_t zb = 0;
  for (uint i = 0; i < lwe_array_out->num_radix_blocks; i++) {
    auto input_degree = lwe_array_in->degrees[i];

    if (zb != 0) {
      input_degree += static_cast<uint64_t>(zb);
    }
    Torus z =
        std::max(static_cast<Torus>(1),
                 static_cast<Torus>(ceil(input_degree / message_modulus))) *
        message_modulus;

    lwe_array_out->degrees[i] = z - static_cast<uint64_t>(zb);
    lwe_array_out->noise_levels[i] = lwe_array_in->noise_levels[i];
    CHECK_NOISE_LEVEL(lwe_array_out->noise_levels[i], message_modulus,
                      carry_modulus);
    zb = z / message_modulus;
  }
}

#endif
