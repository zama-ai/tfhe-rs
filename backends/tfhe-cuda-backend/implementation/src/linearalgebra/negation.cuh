#ifndef CUDA_NEGATE_CUH
#define CUDA_NEGATE_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "../utils/kernel_dimensions.cuh"
#include "device.h"
#include "linear_algebra.h"

template <typename T>
__global__ void negation(T *output, T *input, uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = -input[index];
  }
}

template <typename T>
__host__ void host_negation(cuda_stream_t *stream, T *output, T *input,
                            uint32_t input_lwe_dimension,
                            uint32_t input_lwe_ciphertext_count) {

  cudaSetDevice(stream->gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  negation<<<grid, thds, 0, stream->stream>>>(output, input, num_entries);
  check_cuda_error(cudaGetLastError());
}

#endif // CUDA_NEGATE_H
