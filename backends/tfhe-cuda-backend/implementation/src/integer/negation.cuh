#ifndef CUDA_INTEGER_NEGATE_CUH
#define CUDA_INTEGER_NEGATE_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer.h"
#include "utils/kernel_dimensions.cuh"

template <typename Torus>
__global__ void
device_integer_radix_negation(Torus *output, Torus *input, int32_t num_blocks,
                              uint64_t lwe_dimension, uint64_t message_modulus,
                              uint64_t carry_modulus, uint64_t delta) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < lwe_dimension + 1) {
    bool is_body = (tid == lwe_dimension);

    // z = ceil( degree / 2^p ) * 2^p
    uint64_t z = (2 * message_modulus - 1) / message_modulus;
    __syncthreads();
    z *= message_modulus;

    // (0,Delta*z) - ct
    output[tid] = (is_body ? z * delta - input[tid] : -input[tid]);

    for (int radix_block_id = 1; radix_block_id < num_blocks;
         radix_block_id++) {
      tid += (lwe_dimension + 1);

      // Subtract z/B to the next ciphertext to compensate for the addition of z
      uint64_t zb = z / message_modulus;

      uint64_t encoded_zb = zb * delta;

      __syncthreads();

      // (0,Delta*z) - ct
      output[tid] =
          (is_body ? z * delta - (input[tid] + encoded_zb) : -input[tid]);
      __syncthreads();
    }
  }
}

template <typename Torus>
__host__ void host_integer_radix_negation(cuda_stream_t *stream, Torus *output,
                                          Torus *input, uint32_t lwe_dimension,
                                          uint32_t input_lwe_ciphertext_count,
                                          uint64_t message_modulus,
                                          uint64_t carry_modulus) {
  cudaSetDevice(stream->gpu_index);

  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);
  uint64_t shared_mem = input_lwe_ciphertext_count * sizeof(uint32_t);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_integer_radix_negation<<<grid, thds, shared_mem, stream->stream>>>(
      output, input, input_lwe_ciphertext_count, lwe_dimension, message_modulus,
      carry_modulus, delta);
  check_cuda_error(cudaGetLastError());
}

#endif
