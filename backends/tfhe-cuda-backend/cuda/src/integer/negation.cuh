#ifndef CUDA_INTEGER_NEGATE_CUH
#define CUDA_INTEGER_NEGATE_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.h"
#include "integer/integer.cuh"
#include "linear_algebra.h"
#include "programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <omp.h>
#include <sstream>
#include <string>
#include <vector>

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

template <typename Torus>
__host__ void scratch_cuda_integer_overflowing_sub_kb(
    cuda_stream_t *stream, int_overflowing_sub_memory<Torus> **mem_ptr,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  cudaSetDevice(stream->gpu_index);
  *mem_ptr = new int_overflowing_sub_memory<Torus>(stream, params, num_blocks,
                                                   allocate_gpu_memory);
}

template <typename Torus, class params>
__host__ void host_integer_overflowing_sub_kb(
    cuda_stream_t *stream, Torus *radix_lwe_out, Torus *radix_lwe_overflowed,
    Torus *radix_lwe_left, Torus *radix_lwe_right, void *bsk, uint64_t *ksk,
    int_overflowing_sub_memory<uint64_t> *mem_ptr, uint32_t num_blocks) {

  auto radix_params = mem_ptr->params;

  host_unchecked_sub_with_correcting_term(
      stream, radix_lwe_out, radix_lwe_left, radix_lwe_right,
      radix_params.big_lwe_dimension, num_blocks, radix_params.message_modulus,
      radix_params.carry_modulus, radix_params.message_modulus - 1);

  host_propagate_single_sub_borrow<Torus>(
      stream, radix_lwe_overflowed, radix_lwe_out, mem_ptr->borrow_prop_mem,
      bsk, ksk, num_blocks);
}

#endif
