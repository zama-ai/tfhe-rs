#ifndef CUDA_NEGATE_CUH
#define CUDA_NEGATE_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "../utils/helper.cuh"
#include "device.h"
#include "linear_algebra.h"

template <typename T>
__global__ void negation(T *output, T const *input, uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = -input[index];
  }
}

#endif // CUDA_NEGATE_H
