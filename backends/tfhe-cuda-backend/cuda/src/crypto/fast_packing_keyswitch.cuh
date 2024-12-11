#ifndef CNCRT_FAST_KS_CUH
#define CNCRT_FAST_KS_CUH

#include "device.h"
#include "gadget.cuh"
#include "helper_multi_gpu.h"
#include "keyswitch.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include "torus.cuh"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <thread>
#include <vector>

#define CEIL_DIV(M, N) ((M) + (N)-1) / (N)

const int BLOCK_SIZE_GEMM = 64;
const int THREADS_GEMM = 8;

__host__ inline bool can_use_pks_fast_path(uint32_t lwe_dimension_in, uint32_t num_lwe,
                                    uint32_t polynomial_size,
                                    uint32_t level_count,
                                    uint32_t glwe_dimension) {
  return lwe_dimension_in % BLOCK_SIZE_GEMM == 0 &&
         num_lwe % BLOCK_SIZE_GEMM == 0 && level_count == 1 &&
         glwe_dimension == 1;
}

template <typename Torus, typename TorusVec>
__global__ void decompose_vectorize(Torus const *lwe_in, Torus *lwe_out,
                                    uint32_t lwe_dimension_in, uint32_t num_lwe,
                                    uint32_t base_log, uint32_t level_count) {

  auto read_val_idx =
      (blockIdx.x * blockDim.x + threadIdx.x) * (lwe_dimension_in + 1) +
      blockIdx.y * blockDim.y + threadIdx.y;

  auto write_val_idx =
      (blockIdx.x * blockDim.x + threadIdx.x) * lwe_dimension_in +
      blockIdx.y * blockDim.y + threadIdx.y;

  Torus a_i = lwe_in[read_val_idx];

  a_i = init_decomposer_state(a_i, base_log, level_count);

  Torus state = a_i >> (sizeof(Torus) * 8 - base_log * level_count);
  Torus mod_b_mask = (1ll << base_log) - 1ll;
  lwe_out[write_val_idx] = decompose_one<Torus>(state, mod_b_mask, base_log);
}

template <typename Torus, typename TorusVec>
__global__ void tgemm(int M, int N, int K, const Torus *A, const Torus *B,
                      Torus *C) {

  // A block of threads processeds blocks of size (BLOCK_SIZE_GEMM,
  // BLOCK_SIZE_GEMM) splitting them in multiple tiles: (BLOCK_SIZE_GEMM,
  // THREADS_GEMM)-shaped tiles of values from A, and a (THREADS_GEMM,
  // BLOCK_SIZE_GEMM)-shaped tiles of values from B.

  const int BM = BLOCK_SIZE_GEMM;
  const int BN = BLOCK_SIZE_GEMM;
  const int BK = THREADS_GEMM;
  const int TM = THREADS_GEMM;

  const uint cRow = blockIdx.y;
  const uint cCol = blockIdx.x;

  const uint totalResultsBlocktile = BM * BN;
  const int threadCol = threadIdx.x % BN;
  const int threadRow = threadIdx.x / BN;

  // Allocate space for the current block tile in shared memory
  __shared__ Torus As[BM * BK];
  __shared__ Torus Bs[BK * BN];

  // Initialize the pointers to the input blocks from A, B
  // Tiles from these blocks are loaded to shared memory
  A += cRow * BM * K;
  B += cCol * BN;

  // Initialize the pointer to the output block of size (BLOCK_SIZE_GEMM,
  // BLOCK_SIZE_GEMM)
  C += cRow * BM * N + cCol * BN;

  // Each thread will handle multiple sub-blocks
  const uint innerColA = threadIdx.x % BK;
  const uint innerRowA = threadIdx.x / BK;
  const uint innerColB = threadIdx.x % BN;
  const uint innerRowB = threadIdx.x / BN;

  // allocate thread-local cache for results in registerfile
  Torus threadResults[TM] = {0};

  // For each thread, loop over block tiles
  for (uint bkIdx = 0; bkIdx < K; bkIdx += BK) {
    // Populate the tile caches in shared memory
    As[innerRowA * BK + innerColA] = A[innerRowA * K + innerColA];
    Bs[innerRowB * BN + innerColB] = B[innerRowB * N + innerColB];
    __syncthreads();

    // Advance blocktile for the next iteration of this loop
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

template <typename Torus>
__global__ void polynomial_accumulate_monic_monomial_mul_many_neg_and_add_C(
    Torus *in_glwe_buffer, Torus *out_glwe_buffer, Torus const *lwe_array,
    uint32_t num_glwes, uint32_t polynomial_size, uint32_t glwe_dimension) {
  // Finish the keyswitching operation and prepare GLWEs for accumulation
  // 1. Finish the keyswitching computation partially performed with a GEMM:
  //  - negate the dot product between the GLWE and KSK polynomial
  //  - add the GLWE message for the N-th polynomial coeff in the message poly
  // 2. Rotate each of the GLWE . KSK poly dot products to
  //    prepare them for accumulation into a single GLWE

  uint32_t poly_id = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t degree = poly_id; // lwe 0 rotate 0, lwe 1 rotate 1, .. , lwe
                             // poly_size-1 rotate poly_size-1
  uint32_t coeffIdx = blockIdx.y * blockDim.y + threadIdx.y;

  auto in_poly =
      in_glwe_buffer + poly_id * polynomial_size * (glwe_dimension + 1);
  auto out_result =
      out_glwe_buffer + poly_id * polynomial_size * (glwe_dimension + 1);
  if (coeffIdx == 0) {
    // Add the message value of the input LWE (`C`) to the N-th coefficient
    // in the GLWE . KSK dot product
    in_poly[coeffIdx + polynomial_size] =
        lwe_array[poly_id * (polynomial_size + 1) + polynomial_size] -
        in_poly[coeffIdx + polynomial_size];
  } else {
    // Otherwise simply negate the input coefficient
    in_poly[coeffIdx + polynomial_size] = -in_poly[coeffIdx + polynomial_size];
  }
  // Negate all the coefficients for rotation
  in_poly[coeffIdx] = -in_poly[coeffIdx];

  // rotate the body
  polynomial_accumulate_monic_monomial_mul<Torus>(
      out_result, in_poly, degree, coeffIdx, polynomial_size, 1, true);
  // rotate the mask too
  polynomial_accumulate_monic_monomial_mul<Torus>(
      out_result + polynomial_size, in_poly + polynomial_size, degree, coeffIdx,
      polynomial_size, 1, true);
}

template <typename Torus, typename TorusVec>
__host__ void host_fast_packing_keyswitch_lwe_list_to_glwe(
    cudaStream_t stream, uint32_t gpu_index, Torus *glwe_out,
    Torus const *lwe_array_in, Torus const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t lwe_dimension_in, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes) {

  // Optimization of packing keyswitch when packing many LWEs

  cudaSetDevice(gpu_index);
  check_cuda_error(cudaGetLastError());

  int glwe_accumulator_size = (glwe_dimension + 1) * polynomial_size;

  // ping pong the buffer between successive calls
  // the biggest allocation is num_lwes * glwe_accumulator_size in the rotation
  // split the buffer in two parts of this size
  auto d_mem_0 = (Torus *)fp_ks_buffer;
  auto d_mem_1 = d_mem_0 + num_lwes * glwe_accumulator_size;

  // decompose LWEs
  int BLOCK_SIZE_DECOMP = 8;
  // don't decompose LWE body - the LWE has lwe_size + 1 elements. The last
  // element, the body is ignored by rounding down the number of blocks assuming
  // here that the LWE dimension is a multiple of the block size
  dim3 grid_decomp(num_lwes / BLOCK_SIZE_DECOMP,
                   lwe_dimension_in / BLOCK_SIZE_DECOMP);
  dim3 threads_decomp(BLOCK_SIZE_DECOMP, BLOCK_SIZE_DECOMP);

  // decompose inplace (assume levels == 1)
  decompose_vectorize<Torus, TorusVec>
      <<<grid_decomp, threads_decomp, 0, stream>>>(
          lwe_array_in, d_mem_0, lwe_dimension_in, num_lwes, base_log, 1);
  check_cuda_error(cudaGetLastError());

  // gemm to ks the individual LWEs to GLWEs
  dim3 grid_gemm(glwe_accumulator_size / BLOCK_SIZE_GEMM,
                 num_lwes / BLOCK_SIZE_GEMM);
  dim3 threads_gemm(BLOCK_SIZE_GEMM * THREADS_GEMM);
  uint32_t sharedMemSize = BLOCK_SIZE_GEMM * THREADS_GEMM * 2 * sizeof(Torus);
  tgemm<Torus, TorusVec><<<grid_gemm, threads_gemm, sharedMemSize, stream>>>(
      num_lwes, glwe_accumulator_size, lwe_dimension_in, d_mem_0, fp_ksk_array,
      d_mem_1);
  check_cuda_error(cudaGetLastError());

  // should we include the mask in the rotation ??
  dim3 grid_rotate(num_lwes / BLOCK_SIZE_DECOMP,
                   polynomial_size / BLOCK_SIZE_DECOMP);
  dim3 threads_rotate(BLOCK_SIZE_DECOMP, BLOCK_SIZE_DECOMP);
  // rotate the GLWEs
  polynomial_accumulate_monic_monomial_mul_many_neg_and_add_C<Torus>
      <<<grid_rotate, threads_rotate, 0, stream>>>(
          d_mem_1, d_mem_0, lwe_array_in, num_lwes, polynomial_size,
          glwe_dimension);
  check_cuda_error(cudaGetLastError());

  dim3 grid_accumulate(polynomial_size * (glwe_dimension + 1) /
                       BLOCK_SIZE_DECOMP);
  dim3 threads_accum(BLOCK_SIZE_DECOMP);

  // accumulate to a single glwe
  accumulate_glwes<Torus><<<grid_accumulate, threads_accum, 0, stream>>>(
      glwe_out, d_mem_0, glwe_dimension, polynomial_size, num_lwes);

  check_cuda_error(cudaGetLastError());
}

#endif
