#ifndef CUDA_MULT_CUH
#define CUDA_MULT_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "../utils/helper.cuh"
#include "checked_arithmetic.h"
#include "crypto/gadget.cuh"
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

template <typename Torus>
__device__ __forceinline__ void tgemm_atomic_add(Torus *address, Torus value) {
  static_assert(sizeof(Torus) == sizeof(unsigned int) ||
                    sizeof(Torus) == sizeof(unsigned long long int),
                "split-K tgemm atomic add supports 32-bit and 64-bit torus "
                "outputs");
  if constexpr (sizeof(Torus) == sizeof(unsigned int)) {
    atomicAdd(reinterpret_cast<unsigned int *>(address),
              static_cast<unsigned int>(value));
  } else {
    atomicAdd(reinterpret_cast<unsigned long long int *>(address),
              static_cast<unsigned long long int>(value));
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

// Tgemm version that fuses gadget decomposition on all levels like the regular
// keyswitch. By doing the decomposition within the kernel, we avoid allocating
// an intermediate array and save moving it from global to the kernel back and
// forth. Additionally, K cuda blocks work on the same output tile, each block
// solves a partial accumulator that is added to the final output using atomics.
// This improves performance when working with smaller batches because increases
// parallelism.
//
// A block of threads processes blocks of size (BLOCK_SIZE_GEMM,
// BLOCK_SIZE_GEMM) splitting them in multiple tiles: (BLOCK_SIZE_GEMM,
// THREADS_GEMM)-shaped tiles of values from A, and a (THREADS_GEMM,
// BLOCK_SIZE_GEMM)-shaped tiles of values from B.
// BlockIdx.z is used to map the partial accumulator of the same blockIdx.x,
// blockIdx.y output tile. Different split cuda blocks accumulate partial sums
// for the same C tile, so the final store uses atomic add to keep coherence
// without adding some group sync logic.
//
// In this kernel LevelCount is a compile-time constant that helps fully
// unrolling at compile time like in the regular ks. NonTrivialIndices is used
// to select the indirect accesses when using non trivial indices.
template <typename InputTorus, typename KSTorus, int BM, int BN, int BK, int TM,
          int LevelCount, int SplitK, bool NonTrivialIndices>
__global__ void tgemm_all_levels_split_k(
    uint M, uint N, uint K, const InputTorus *__restrict__ A,
    const InputTorus *__restrict__ A_indices, const KSTorus *__restrict__ B,
    uint stride_B, KSTorus *C, uint stride_C,
    const InputTorus *__restrict__ C_indices, uint32_t base_log) {

  static_assert(BN == BK * TM, "tgemm tile constraint: BN must equal BK * TM");
  static_assert(BN % BM == 0,
                "tgemm tile constraint: BN must be divisible by BM");
  static_assert(BM % TM == 0,
                "tgemm tile constraint: BM must be divisible by TM");
  static_assert(SplitK > 1, "split-K tgemm requires SplitK > 1");
  static_assert(sizeof(KSTorus) == sizeof(unsigned int) ||
                    sizeof(KSTorus) == sizeof(unsigned long long int),
                "split-K tgemm requires 32-bit or 64-bit output atomics");
  constexpr int B_LOADS = BN / BM;

  const uint cRow = blockIdx.y;
  const uint cCol = blockIdx.x;

  const int threadCol = threadIdx.x % BN;
  const int threadRow = threadIdx.x / BN;

  __shared__ KSTorus As[BM * BK];
  __shared__ KSTorus Bs[BK * BN];

  const uint innerColA = threadIdx.x % BK;
  const uint innerRowA = threadIdx.x / BK;

  // allocate thread-local cache for results in registerfile
  KSTorus threadResults[TM] = {0};

  const InputTorus mod_b_mask = (InputTorus(1) << base_log) - InputTorus(1);
  const uint row_A = cRow * BM + innerRowA;

  // Calculate the partial tile dimensions
  const uint k_tiles = (K + BK - 1) / BK;
  const uint tiles_per_split = (k_tiles + SplitK - 1) / SplitK;
  const uint tile_begin = blockIdx.z * tiles_per_split;
  const uint tile_limit = tile_begin + tiles_per_split;
  const uint tile_end = tile_limit < k_tiles ? tile_limit : k_tiles;
  if (tile_begin >= tile_end)
    return;

  // Embedding the decomposition within the kernel to avoid
  // global memory transfers
  for (uint tile = tile_begin; tile < tile_end; tile++) {
    const uint bkIdx = tile * BK;
    const uint col_A = bkIdx + innerColA;

    InputTorus raw_val = 0;
    if (row_A < M && col_A < K) {
      const uint input_row = NonTrivialIndices ? (uint)A_indices[row_A] : row_A;
      raw_val = A[input_row * (K + 1) + col_A];
    }

    InputTorus state =
        init_decomposer_state(raw_val, base_log, (uint32_t)LevelCount);

    // We use registers as cache to store all decomposition levels
    KSTorus decomposed_vals[LevelCount];
#pragma unroll
    for (int li = 0; li < LevelCount; li++) {
      decomposed_vals[li] =
          (KSTorus)decompose_one<InputTorus>(state, mod_b_mask, base_log);
    }

#pragma unroll
    for (int li = 0; li < LevelCount; li++) {
      // Each level we load our decomposition from registers cache
      As[innerRowA * BK + innerColA] = decomposed_vals[li];
      // We load the corresponding ksk
#pragma unroll
      for (int i = 0; i < B_LOADS; i++) {
        int linear_b = threadIdx.x + i * (BM * BK);
        int local_row_b = linear_b / BN;
        int local_col_b = linear_b % BN;
        int global_row_b = (int)bkIdx + local_row_b;
        int global_col_b = (int)(cCol * BN) + local_col_b;
        Bs[local_row_b * BN + local_col_b] =
            (global_col_b < (int)N && global_row_b < (int)K)
                ? B[global_row_b * stride_B + li * N + global_col_b]
                : KSTorus(0);
      }
      __syncthreads();

      // calculate per-thread results
#pragma unroll
      for (uint dotIdx = 0; dotIdx < BK; ++dotIdx) {
        // we make the dotproduct loop the outside loop, which facilitates
        // reuse of the Bs entry, which we can cache in a tmp var.
        KSTorus tmp = Bs[dotIdx * BN + threadCol];
#pragma unroll
        for (uint resIdx = 0; resIdx < TM; ++resIdx) {
          threadResults[resIdx] +=
              As[(threadRow * TM + resIdx) * BK + dotIdx] * tmp;
        }
      }
      __syncthreads();
    }
  }
  // write out the results
#pragma unroll
  for (uint resIdx = 0; resIdx < TM; ++resIdx) {
    int outRow = cRow * BM + threadRow * TM + resIdx;
    int outCol = cCol * BN + threadCol;

    if (outRow >= M)
      continue;
    if (outCol >= N)
      continue;
    const uint output_row =
        NonTrivialIndices ? (uint)C_indices[outRow] : (uint)outRow;
    // To increase parallelism SplitK blocks write the results on the same
    // output. This accumulation must use atomics to keep coherence and avoid
    // complex logic.
    tgemm_atomic_add(&C[output_row * stride_C + outCol], threadResults[resIdx]);
  }
}

#endif // CUDA_MULT_H
