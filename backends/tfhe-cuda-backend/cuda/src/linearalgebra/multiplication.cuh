#ifndef CUDA_MULT_CUH
#define CUDA_MULT_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "../utils/kernel_dimensions.cuh"
#include "device.h"
#include "linear_algebra.h"
#include <fstream>
#include <iostream>
#include <vector>

template <typename T>
__global__ void cleartext_vec_multiplication(T *output, T const *lwe_input,
                                             T const *cleartext_input,
                                             const uint32_t input_lwe_dimension,
                                             const uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    int cleartext_index = index / (input_lwe_dimension + 1);
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] * cleartext_input[cleartext_index];
  }
}

template <typename T>
__host__ void host_cleartext_vec_multiplication(
    cudaStream_t stream, uint32_t gpu_index, T *output, T const *lwe_input,
    T const *cleartext_input, const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count) {

  cuda_set_device(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cleartext_vec_multiplication<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, cleartext_input, input_lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void
cleartext_multiplication(T *output, T const *lwe_input, T cleartext_input,
                         uint32_t input_lwe_dimension, uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] * cleartext_input;
  }
}

template <typename T>
__host__ void
host_cleartext_multiplication(cudaStream_t stream, uint32_t gpu_index,
                              T *output, T const *lwe_input, T cleartext_input,
                              uint32_t input_lwe_dimension,
                              uint32_t input_lwe_ciphertext_count) {

  cuda_set_device(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cleartext_multiplication<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, cleartext_input, input_lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}


const int BLOCK_SIZE_GEMM = 64;
const int THREADS_GEMM = 8;

template <typename Torus, typename TorusVec>
__global__ void tgemmVectorize1(int M, int N, int K, 
                                  const Torus *A, const Torus *B,
                                  Torus *C) {

  const int BM = BLOCK_SIZE_GEMM;
  const int BN = BLOCK_SIZE_GEMM;
  const int BK = THREADS_GEMM;
  const int TM = THREADS_GEMM;

  const uint cRow = blockIdx.y;
  const uint cCol = blockIdx.x;

  //const uint totalResultsBlocktile = BM * BN;
  // A thread is responsible for calculating TM elements in the blocktile
  //const uint numThreadsBlocktile = totalResultsBlocktile / TM;

  // each warp will calculate 32*TM elements, with 32 being the columnar dim.
  const int threadCol = threadIdx.x % BN;
  const int threadRow = threadIdx.x / BN;

  // allocate space for the current blocktile in SMEM
  __shared__ Torus As[BM * BK];
  __shared__ Torus Bs[BK * BN];

  // Move blocktile to beginning of A's row and B's column
  A += cRow * BM * K;
  B += cCol * BN;
  C += cRow * BM * N + cCol * BN;

  const uint innerColA = threadIdx.x % BK; // warp-level GMEM coalescing
  const uint innerRowA = threadIdx.x / BK;
  const uint innerColB = threadIdx.x % BN; // warp-level GMEM coalescing
  const uint innerRowB = threadIdx.x / BN;

  // allocate thread-local cache for results in registerfile
  Torus threadResults[TM] = {0};

  // outer loop over block tiles
  for (uint bkIdx = 0; bkIdx < K; bkIdx += BK) {
    // populate the SMEM caches
    As[innerRowA * BK + innerColA] = A[innerRowA * K + innerColA];
    Bs[innerRowB * BN + innerColB] = B[innerRowB * N + innerColB];
    __syncthreads();

    // advance blocktile
    A += BK;
    B += BK * N;

    // calculate per-thread results
    for (uint dotIdx = 0; dotIdx < BK; ++dotIdx) {
      // we make the dotproduct loop the outside loop, which facilitates
      // reuse of the Bs entry, which we can cache in a tmp var.
      Torus tmp = Bs[dotIdx * BN + threadCol];
      for (uint resIdx = 0; resIdx < TM; ++resIdx) {
        threadResults[resIdx] +=
            As[(threadRow * TM + resIdx) * BK + dotIdx] * tmp;
      }
    }
    __syncthreads();
  }

  // write out the results
  for (uint resIdx = 0; resIdx < TM; ++resIdx) {
    C[(threadRow * TM + resIdx) * N + threadCol] = threadResults[resIdx];
  }
}

#endif // CUDA_MULT_H
