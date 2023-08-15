#ifndef CUDA_POLYNOMIAL_MATH_CUH
#define CUDA_POLYNOMIAL_MATH_CUH

#include "crypto/torus.cuh"
#include "parameters.cuh"

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
__device__ void
polynomial_product_accumulate_in_fourier_domain(T *result, T *first, T *second,
                                                bool init_accumulator = false) {
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

// If init_accumulator is set, assumes that result was not initialized and does
// that with the outcome of first * second
template <typename T, class params>
__device__ void
polynomial_product_accumulate_by_monomial(T *result, T *poly,
                                          uint64_t monomial_degree,
                                          bool init_accumulator = false) {
  // monomial_degree \in [0, 2 * params::degree)
  int full_cycles_count = monomial_degree / params::degree;
  int remainder_degrees = monomial_degree % params::degree;

  int pos = threadIdx.x;
  for (int i = 0; i < params::opt; i++) {
    T element = poly[pos];
    int new_pos = (pos + monomial_degree) % params::degree;

    T x = SEL(element, -element, full_cycles_count % 2); // monomial coefficient
    x = SEL(-x, x, new_pos >= remainder_degrees);

    if (init_accumulator)
      result[new_pos] = x;
    else
      result[new_pos] += x;
    pos += params::degree / params::opt;
  }
}

#endif // CNCRT_POLYNOMIAL_MATH_H
