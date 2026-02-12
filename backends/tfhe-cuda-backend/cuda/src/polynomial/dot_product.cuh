#ifndef CUDA_CIRCULANT_DOT_CUH
#define CUDA_CIRCULANT_DOT_CUH

#include "checked_arithmetic.h"
#include "crypto/torus.cuh"

#define CIRCULANT_BLOCKTILE 32
// Make a circulant matrix that serves to multiply a polynomial
// with another one. Each thread loads a part of the original
// polynomial into shared memory. Then each thread distributes
// values into their new positions. The elements above the diagonal
// are multiplied by -1
template <typename Torus>
__global__ void polynomial_make_circulant(Torus *result, const Torus *poly,
                                          uint32_t polynomial_size) {
  __shared__ Torus buf[2 * CIRCULANT_BLOCKTILE - 1];

  int32_t block_start = blockIdx.x * CIRCULANT_BLOCKTILE * polynomial_size +
                        blockIdx.y * CIRCULANT_BLOCKTILE;

  int32_t tid = threadIdx.x * CIRCULANT_BLOCKTILE + threadIdx.y;

  if (tid < 2 * CIRCULANT_BLOCKTILE - 1) {
    int32_t read_idx_start = (blockIdx.y - blockIdx.x) * CIRCULANT_BLOCKTILE +
                             tid - CIRCULANT_BLOCKTILE + 1;
    if (read_idx_start < 0) {
      read_idx_start = polynomial_size + read_idx_start;
    }
    buf[tid] = poly[read_idx_start];
  }
  __syncthreads();

  Torus fact = blockIdx.x * CIRCULANT_BLOCKTILE + threadIdx.x >
                       blockIdx.y * CIRCULANT_BLOCKTILE + threadIdx.y
                   ? -1
                   : 1;
  result[block_start + threadIdx.x * polynomial_size + threadIdx.y] =
      buf[threadIdx.y - threadIdx.x + CIRCULANT_BLOCKTILE - 1] * fact;
}

template <typename Torus>
__host__ void
scratch_wrapping_polynomial_mul_one_to_many(void *stream, uint32_t gpu_index,
                                            uint32_t polynomial_size,
                                            int8_t **circulant_buf) {
  // allocate circulant matrix memory
  *circulant_buf = (int8_t *)cuda_malloc_async(
      safe_mul_sizeof<Torus>((size_t)polynomial_size, (size_t)polynomial_size),
      static_cast<cudaStream_t>(stream), gpu_index);
}

template <typename Torus>
__host__ void
cleanup_wrapping_polynomial_mul_one_to_many(void *stream, uint32_t gpu_index,
                                            int8_t *circulant_buf) {
  // free circulant matrix memory
  cuda_drop_async(circulant_buf, static_cast<cudaStream_t>(stream), gpu_index);
}

// Multiply degree-N lhs polynomial with many rhs polynomials
// modulo X^N+1. This method builds a circulant matrix
// from the lhs and uses matrix multiplication to
// compute the polynomial multiplication
template <typename Torus, typename TorusVec>
__host__ void host_wrapping_polynomial_mul_one_to_many(
    cudaStream_t stream, uint32_t gpu_index, Torus *result,
    const Torus *poly_lhs, int8_t *circulant, const Torus *poly_rhs,
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t n_rhs) {

  if (polynomial_size % CIRCULANT_BLOCKTILE)
    PANIC("CUDA polynomial multiplication one to many: expected "
          "polynomial size to be a multiple of the block size");

  // convert lhs poly to circulant matrix
  dim3 grid_c(polynomial_size / CIRCULANT_BLOCKTILE,
              polynomial_size / CIRCULANT_BLOCKTILE);
  dim3 threads_c(CIRCULANT_BLOCKTILE, CIRCULANT_BLOCKTILE);
  polynomial_make_circulant<Torus><<<grid_c, threads_c, 0, stream>>>(
      (Torus *)circulant, poly_lhs, polynomial_size);
  check_cuda_error(cudaGetLastError());

  // matmul circulant matrix with poly list
  dim3 grid_gemm(CEIL_DIV(polynomial_size, BLOCK_SIZE_GEMM),
                 CEIL_DIV(polynomial_size, BLOCK_SIZE_GEMM));
  dim3 threads_gemm(BLOCK_SIZE_GEMM * THREADS_GEMM);
  uint32_t sharedMemSize = safe_mul_sizeof<Torus>(
      (size_t)BLOCK_SIZE_GEMM, (size_t)THREADS_GEMM, (size_t)2);
  if (sharedMemSize > 8192)
    PANIC("GEMM kernel error: shared memory required might be too large");

  // Write the output with a stride of the GLWE total number of values
  tgemm<Torus, BLOCK_SIZE_GEMM, THREADS_GEMM>
      <<<grid_gemm, threads_gemm, sharedMemSize, stream>>>(
          n_rhs, polynomial_size, polynomial_size, poly_rhs, (Torus *)circulant,
          polynomial_size, result, (polynomial_size * (glwe_dimension + 1)));
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, typename TorusVec>
__host__ void host_glwe_wrapping_polynomial_mul_one_to_many(
    cudaStream_t stream, uint32_t gpu_index, Torus *result,
    const Torus *glwe_lhs, int8_t *circulant, const Torus *poly_rhs,
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t n_rhs) {

  for (unsigned i = 0; i < glwe_dimension + 1; ++i) {
    host_wrapping_polynomial_mul_one_to_many<uint64_t, ulonglong4>(
        stream, gpu_index, result + i * polynomial_size,
        glwe_lhs + i * polynomial_size, circulant, poly_rhs, polynomial_size,
        glwe_dimension, n_rhs);
  }
}

#endif
