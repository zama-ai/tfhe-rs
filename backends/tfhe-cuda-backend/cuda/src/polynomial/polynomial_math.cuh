#ifndef CUDA_POLYNOMIAL_MATH_CUH
#define CUDA_POLYNOMIAL_MATH_CUH

#include "crypto/torus.cuh"
#include "parameters.cuh"
#include "types/complex/operations.cuh"
#include "linearalgebra/multiplication.cuh"

template <typename T>
__device__ T *get_chunk(T *data, int chunk_num, int chunk_size) {
  int pos = chunk_num * chunk_size;
  T *ptr = &data[pos];
  return ptr;
}

template <typename FT, class params>
__device__ void sub_polynomial(FT *result, FT *first, FT *second) {
  int tid = threadIdx.x;
  for (int i = 0; i < params::opt; i++) {
    result[tid] = first[tid] - second[tid];
    tid += params::degree / params::opt;
  }
}

template <class params, typename T>
__device__ void polynomial_product_in_fourier_domain(T *result, T *first,
                                                     T *second) {
  int tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    result[tid] = first[tid] * second[tid];
    tid += params::degree / params::opt;
  }

  if (threadIdx.x == 0) {
    result[params::degree / 2] =
        first[params::degree / 2] * second[params::degree / 2];
  }
}

// Computes result += first * second
// If init_accumulator is set, assumes that result was not initialized and does
// that with the outcome of first * second
template <class params, typename T>
__device__ void polynomial_product_accumulate_in_fourier_domain(
    T *result, T *first, const T *second, bool init_accumulator = false) {
  int tid = threadIdx.x;
  if (init_accumulator) {
    for (int i = 0; i < params::opt / 2; i++) {
      result[tid] = first[tid] * second[tid];
      tid += params::degree / params::opt;
    }
  } else {
    for (int i = 0; i < params::opt / 2; i++) {
      result[tid] += first[tid] * second[tid];
      tid += params::degree / params::opt;
    }
  }
}

// Computes result += x
// If init_accumulator is set, assumes that result was not initialized and does
// that with the outcome of first * second
template <class params>
__device__ void
polynomial_accumulate_in_fourier_domain(double2 *result, double2 *x,
                                        bool init_accumulator = false) {
  auto tid = threadIdx.x;
  if (init_accumulator) {
    for (int i = 0; i < params::opt / 2; i++) {
      result[tid] = x[tid];
      tid += params::degree / params::opt;
    }
  } else {
    for (int i = 0; i < params::opt / 2; i++) {
      result[tid] += x[tid];
      tid += params::degree / params::opt;
    }
  }
}

// This method expects to work with polynomial_size / compression_params::opt
// threads in the x-block If init_accumulator is set, assumes that result was
// not initialized and does that with the outcome of first * second
template <typename T>
__device__ void polynomial_accumulate_monic_monomial_mul(
    T *result, const T *__restrict__ poly, uint64_t monomial_degree,
    uint32_t tid, uint32_t polynomial_size, int coeff_per_thread,
    bool init_accumulator = false) {
  // monomial_degree \in [0, 2 * compression_params::degree)
  int full_cycles_count = monomial_degree / polynomial_size;
  int remainder_degrees = monomial_degree % polynomial_size;

  int pos = tid;
  for (int i = 0; i < coeff_per_thread; i++) {
    T element = poly[pos];
    int new_pos = (pos + monomial_degree) % polynomial_size;

    T x = SEL(element, -element, full_cycles_count % 2); // monomial coefficient
    x = SEL(-x, x, new_pos >= remainder_degrees);

    if (init_accumulator)
      result[new_pos] = x;
    else
      result[new_pos] += x;
    pos += polynomial_size / coeff_per_thread;
  }
}

template <typename T, class params>
__device__ void polynomial_product_accumulate_by_monomial_nosync(
    T *result, const T *__restrict__ poly, uint32_t monomial_degree) {
  // monomial_degree \in [0, 2 * params::degree)
  int full_cycles_count = monomial_degree / params::degree;
  int remainder_degrees = monomial_degree % params::degree;

// Every thread has a fixed position to track instead of "chasing" the
// position
#pragma unroll
  for (int i = 0; i < params::opt; i++) {
    int pos =
        (threadIdx.x + i * (params::degree / params::opt) - monomial_degree) &
        (params::degree - 1);

    T element = poly[pos];
    T x = SEL(element, -element, full_cycles_count % 2);
    x = SEL(-x, x,
            threadIdx.x + i * (params::degree / params::opt) >=
                remainder_degrees);

    result[i] += x;
  }
}

#define CIRCULANT_BLOCKTILE   32
// Make a circulant matrix that serves to multiply a polynomial
// with another one. Each thread loads a part of the original 
// polynomial into shared memory. Then each thread distributes 
// values into their new positions
template <typename Torus>
__global__ void polynomial_make_circulant(
  Torus* result, const Torus* poly,  
  uint32_t polynomial_size,
) {  
  extern __shared__  Torus buf[2 * CIRCULANT_BLOCKTILE - 1];

  uint32_t block_start = blockIdx.x * CIRCULANT_BLOCKTILE * polynomial_size 
        + blockIdx.y * CIRCULANT_BLOCKTILE;

  uint32_t tid = threadIdx.x * CIRCULANT_BLOCKTILE + threadIdx.y;

  if (tid < 2 * CIRCULANT_BLOCKTILE - 1) {                    
      uint32_t read_idx_start = (blockIdx.y-blockIdx.x) * CIRCULANT_BLOCKTILE + 
                            tid - CIRCULANT_BLOCKTILE + 1;
      if (read_idx_start < 0) {
          read_idx_start = N + read_idx_start
      }
      buf[tid] = poly[read_idx_start];
  }
  __syncthreads();

  result[block_start + threadIdx.x * polynomial_size + threadIdx.y] 
    = buf[threadIdx.y - threadIdx.x + CIRCULANT_BLOCKTILE - 1];
}

template <typename Torus, typename TorusVec>
__host__ void host_wrapping_polynomial_mul_one_to_many(
  cudaStream_t stream, uint32_t gpu_index, 
  Torus* result, 
  const Torus* poly_lhs,  
  const Torus* poly_rhs,
  uint32_t polynomial_size,
  uint32_t n_rhs,
) {  

  if (polynomial_size % CIRCULANT_BLOCKTILE) 
    PANIC("CUDA polynomial multiplication one to many: expected "
      "polynomial size to be a multiple of the block size");
  
  //allocate circulant matrix memory
  Torus* circulant = (Torus*)cuda_malloc_async(
      sizeof(Torus) * polynomial_size * polynomial_size, 
      stream, 
      gpu_index
  );
  check_cuda_error(cudaGetLastError());  
  
  //convert lhs poly to circulant matrix
  dim3 grid_c(polynomial_size / CIRCULANT_BLOCKTILE, polynomial_size / CIRCULANT_BLOCKTILE);
  dim3 threads_c(CIRCULANT_BLOCKTILE, CIRCULANT_BLOCKTILE);
  polynomial_make_circulant<Torus><<<grid_c, threads_c, 0, stream>>>(
    circulant, 
    poly_lhs,
    polynomial_size
  )
  check_cuda_error(cudaGetLastError());  

  //matmul circulant matrix with poly list
  dim3 grid_gemm(polynomial_size / BLOCK_SIZE_GEMM, polynomial_size / BLOCK_SIZE_GEMM);
  dim3 threads_gemm(BLOCK_SIZE_GEMM * THREADS_GEMM);
  uint32_t sharedMemSize = BLOCK_SIZE_GEMM * THREADS_GEMM * 2 * sizeof(Torus);
  tgemmVectorize1<Torus, TorusVec><<<grid_gemm, threads_gemm, sharedMemSize, stream>>>(
      polynomial_size, polynomial_size, polynomial_size, circulant, poly_rhs, result
  );
  check_cuda_error(cudaGetLastError());  

  cuda_drop_async(circulant, stream, gpu_index);
}
#endif // CNCRT_POLYNOMIAL_MATH_H
