#ifndef CUDA_MULT_CUH
#define CUDA_MULT_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "../utils/helper.cuh"
#include "checked_arithmetic.h"
#include "device.h"
#include "linear_algebra.h"
#include <fstream>
#include <iostream>
#include <vector>

#include "integer/compression/compression.h"

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
__global__ void cleartext_multiplication(T *output, T const *lwe_input,
                                         T cleartext_input,
                                         const uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] * cleartext_input;
  }
}

template <typename T>
__host__ void host_cleartext_multiplication(
    cudaStream_t stream, uint32_t gpu_index, T *output,
    CudaLweCiphertextListFFI const *lwe_input, T cleartext_input) {

  cuda_set_device(gpu_index);
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  uint32_t num_entries =
      lwe_input->num_radix_blocks * (lwe_input->lwe_dimension + 1);
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cleartext_multiplication<T><<<grid, thds, 0, stream>>>(
      output, (T *)lwe_input->ptr, cleartext_input, num_entries);
  check_cuda_error(cudaGetLastError());
}

const int BLOCK_SIZE_GEMM = 64;
const int THREADS_GEMM = 8;

template <typename Torus> uint64_t get_shared_mem_size_tgemm() {
  return safe_mul_sizeof<Torus>((size_t)BLOCK_SIZE_GEMM, (size_t)THREADS_GEMM,
                                (size_t)2);
}

// Multiply matrices A, B of size (M, K), (K, N) respectively
// with K as the inner dimension.
//
// A block of threads processeds blocks of size (BLOCK_SIZE_GEMM,
// BLOCK_SIZE_GEMM) splitting them in multiple tiles: (BLOCK_SIZE_GEMM,
// THREADS_GEMM)-shaped tiles of values from A, and a (THREADS_GEMM,
// BLOCK_SIZE_GEMM)-shaped tiles of values from B.
//
// This code is adapted by generalizing the 1d block-tiling
// kernel from https://github.com/siboehm/SGEMM_CUDA
// to any matrix dimension
template <typename Torus, int BLOCK_SIZE, int THREADS>
__global__ void tgemm(uint M, uint N, uint K, const Torus *A, const Torus *B,
                      uint stride_B, Torus *C, uint stride_C) {

  const int BM = BLOCK_SIZE;
  const int BN = BLOCK_SIZE;
  const int BK = THREADS;
  const int TM = THREADS;

  const uint cRow = blockIdx.y;
  const uint cCol = blockIdx.x;

  const int threadCol = threadIdx.x % BN;
  const int threadRow = threadIdx.x / BN;

  // Allocate space for the current block tile in shared memory
  __shared__ Torus As[BM * BK];
  __shared__ Torus Bs[BK * BN];

  // Initialize the pointers to the input blocks from A, B
  // Tiles from these blocks are loaded to shared memory
  A += cRow * BM * K;
  B += cCol * BN;

  // Each thread will handle multiple sub-blocks
  const uint innerColA = threadIdx.x % BK;
  const uint innerRowA = threadIdx.x / BK;
  const uint innerColB = threadIdx.x % BN;
  const uint innerRowB = threadIdx.x / BN;

  // allocate thread-local cache for results in registerfile
  Torus threadResults[TM] = {0};

  auto row_A = cRow * BM + innerRowA;
  auto col_B = cCol * BN + innerColB;

  // For each thread, loop over block tiles
  for (uint bkIdx = 0; bkIdx < K; bkIdx += BK) {
    auto col_A = bkIdx + innerColA;
    auto row_B = bkIdx + innerRowB;

    if (row_A < M && col_A < K) {
      As[innerRowA * BK + innerColA] = A[innerRowA * K + innerColA];
    } else {
      As[innerRowA * BK + innerColA] = 0;
    }

    if (col_B < N && row_B < K) {
      Bs[innerRowB * BN + innerColB] = B[innerRowB * stride_B + innerColB];
    } else {
      Bs[innerRowB * BN + innerColB] = 0;
    }
    __syncthreads();

    // Advance blocktile for the next iteration of this loop
    A += BK;
    B += BK * stride_B;

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

  // Initialize the pointer to the output block of size (BLOCK_SIZE_GEMM,
  // BLOCK_SIZE_GEMM)
  C += cRow * BM * stride_C + cCol * BN;

  // write out the results
  for (uint resIdx = 0; resIdx < TM; ++resIdx) {
    int outRow = cRow * BM + threadRow * TM + resIdx;
    int outCol = cCol * BN + threadCol;

    if (outRow >= M)
      continue;
    if (outCol >= N)
      continue;

    C[(threadRow * TM + resIdx) * stride_C + threadCol] +=
        threadResults[resIdx];
  }
}

// Multiply matrices A, B of size (M, K), (K, N) respectively
// with K as the inner dimension.
//
// A block of threads processeds blocks of size (BLOCK_SIZE_GEMM,
// BLOCK_SIZE_GEMM) splitting them in multiple tiles: (BLOCK_SIZE_GEMM,
// THREADS_GEMM)-shaped tiles of values from A, and a (THREADS_GEMM,
// BLOCK_SIZE_GEMM)-shaped tiles of values from B.
//
// This code is adapted by generalizing the 1d block-tiling
// kernel from https://github.com/siboehm/SGEMM_CUDA
// to any matrix dimension
template <typename Torus, typename IndicesType, int BLOCK_SIZE, int THREADS>
__global__ void tgemm_with_indices(uint M, uint N, uint K, const Torus *A,
                                   const Torus *B, uint stride_B, Torus *C,
                                   uint stride_C,
                                   const IndicesType *__restrict__ C_indices) {

  const int BM = BLOCK_SIZE;
  const int BN = BLOCK_SIZE;
  const int BK = THREADS;
  const int TM = THREADS;

  const uint cRow = blockIdx.y;
  const uint cCol = blockIdx.x;

  const int threadCol = threadIdx.x % BN;
  const int threadRow = threadIdx.x / BN;

  // Allocate space for the current block tile in shared memory
  __shared__ Torus As[BM * BK];
  __shared__ Torus Bs[BK * BN];

  // Initialize the pointers to the input blocks from A, B
  // Tiles from these blocks are loaded to shared memory

  A += cRow * BM * K;
  B += cCol * BN;

  // Each thread will handle multiple sub-blocks
  const uint innerColA = threadIdx.x % BK;
  const uint innerRowA = threadIdx.x / BK;
  const uint innerColB = threadIdx.x % BN;
  const uint innerRowB = threadIdx.x / BN;

  // allocate thread-local cache for results in registerfile
  Torus threadResults[TM] = {0};

  auto row_A = cRow * BM + innerRowA;
  auto col_B = cCol * BN + innerColB;

  // For each thread, loop over block tiles
  for (uint bkIdx = 0; bkIdx < K; bkIdx += BK) {
    auto col_A = bkIdx + innerColA;
    auto row_B = bkIdx + innerRowB;

    if (row_A < M && col_A < K) {
      As[innerRowA * BK + innerColA] = A[innerRowA * K + innerColA]; //
    } else {
      As[innerRowA * BK + innerColA] = 0;
    }

    if (col_B < N && row_B < K) {
      Bs[innerRowB * BN + innerColB] = B[innerRowB * stride_B + innerColB];
    } else {
      Bs[innerRowB * BN + innerColB] = 0;
    }
    __syncthreads();

    // Advance blocktile for the next iteration of this loop
    A += BK;
    B += BK * stride_B;

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
    int outRow = cRow * BM + threadRow * TM + resIdx;
    int outCol = cCol * BN + threadCol;

    if (outRow >= M)
      continue;
    if (outCol >= N)
      continue;

    C[C_indices[outRow] * stride_C + outCol] += threadResults[resIdx];
  }
}

#endif // CUDA_MULT_H
