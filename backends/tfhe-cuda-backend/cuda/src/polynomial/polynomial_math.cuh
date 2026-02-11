#ifndef CUDA_POLYNOMIAL_MATH_CUH
#define CUDA_POLYNOMIAL_MATH_CUH

#include <stdio.h>

#include "crypto/torus.cuh"
#include "linearalgebra/multiplication.cuh"
#include "parameters.cuh"
#include "types/complex/operations.cuh"

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

// Computes result += first * second
// If init_accumulator is set, assumes that result was not initialized and does
// that with the outcome of first * second
// The result is always in registers and if init_accumulator true
// the first is also in registers this is tuned for 2_2 params
template <class params, typename T, bool init_accumulator>
__device__ void polynomial_product_accumulate_in_fourier_domain_2_2_params(
    T *__restrict__ result, T *__restrict__ first,
    const T *__restrict__ second) {
  int tid = threadIdx.x;
  if constexpr (init_accumulator) {
    for (int i = 0; i < params::opt / 2; i++) {
      result[i] = first[i] * __ldg(&second[tid]);
      tid += (params::degree / params::opt);
    }
  } else {
    for (int i = 0; i < params::opt / 2; i++) {
      result[i] += first[tid] * __ldg(&second[tid]);
      tid += params::degree / params::opt;
    }
  }
}

// Computes result += first * second
// If init_accumulator is set, assumes that result was not initialized and does
// that with the outcome of first * second
template <class params>
__device__ void polynomial_product_accumulate_in_fourier_domain_128(
    double *result, double *first, const double *second,
    bool init_accumulator = false) {
  int tid = threadIdx.x;
  if (init_accumulator) {
    for (int i = 0; i < params::opt / 2; i++) {
      f128 a_re(first[tid + 0 * params::degree / 2],
                first[tid + 1 * params::degree / 2]);
      f128 a_im(first[tid + 2 * params::degree / 2],
                first[tid + 3 * params::degree / 2]);
      f128 b_re(second[tid + 0 * params::degree / 2],
                second[tid + 1 * params::degree / 2]);
      f128 b_im(second[tid + 2 * params::degree / 2],
                second[tid + 3 * params::degree / 2]);
      f128 c_re, c_im;

      f128::cplx_f128_mul_assign(c_re, c_im, a_re, a_im, b_re, b_im);

      result[tid + 0 * params::degree / 2] = c_re.hi;
      result[tid + 1 * params::degree / 2] = c_re.lo;
      result[tid + 2 * params::degree / 2] = c_im.hi;
      result[tid + 3 * params::degree / 2] = c_im.lo;

      tid += params::degree / params::opt;
    }
  } else {
    for (int i = 0; i < params::opt / 2; i++) {
      f128 a_re(first[tid + 0 * params::degree / 2],
                first[tid + 1 * params::degree / 2]);
      f128 a_im(first[tid + 2 * params::degree / 2],
                first[tid + 3 * params::degree / 2]);
      f128 b_re(second[tid + 0 * params::degree / 2],
                second[tid + 1 * params::degree / 2]);
      f128 b_im(second[tid + 2 * params::degree / 2],
                second[tid + 3 * params::degree / 2]);
      f128 res_re(result[tid + 0 * params::degree / 2],
                  result[tid + 1 * params::degree / 2]);
      f128 res_im(result[tid + 2 * params::degree / 2],
                  result[tid + 3 * params::degree / 2]);
      f128 c_re, c_im;

      f128::cplx_f128_mul_assign(c_re, c_im, a_re, a_im, b_re, b_im);
      f128::cplx_f128_add_assign(res_re, res_im, res_re, res_im, c_re, c_im);

      result[tid + 0 * params::degree / 2] = res_re.hi;
      result[tid + 1 * params::degree / 2] = res_re.lo;
      result[tid + 2 * params::degree / 2] = res_im.hi;
      result[tid + 3 * params::degree / 2] = res_im.lo;

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

// Computes result += x
// If init_accumulator is set, assumes that result was not initialized and does
// that with the outcome of first * second
template <class params>
__device__ void
polynomial_accumulate_in_fourier_domain_128(double *result, double *x,
                                            bool init_accumulator = false) {
  auto tid = threadIdx.x;
  if (init_accumulator) {
    for (int i = 0; i < params::opt / 2 * 4; i++) {
      result[tid] = x[tid];
      tid += params::degree / params::opt;
    }
  } else {
    for (int i = 0; i < params::opt / 2; i++) {
      f128 res_re(result[tid + 0 * params::degree / 2],
                  result[tid + 1 * params::degree / 2]);
      f128 res_im(result[tid + 2 * params::degree / 2],
                  result[tid + 3 * params::degree / 2]);

      f128 x_re(x[tid + 0 * params::degree / 2],
                x[tid + 1 * params::degree / 2]);
      f128 x_im(x[tid + 2 * params::degree / 2],
                x[tid + 3 * params::degree / 2]);

      f128::cplx_f128_add_assign(res_re, res_im, res_re, res_im, x_re, x_im);

      result[tid + 0 * params::degree / 2] = res_re.hi;
      result[tid + 1 * params::degree / 2] = res_re.lo;
      result[tid + 2 * params::degree / 2] = res_im.hi;
      result[tid + 3 * params::degree / 2] = res_im.lo;
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

// Does the same as polynomial_accumulate_monic_monomial_mul() but result is
// being written to registers
template <typename T, class params>
__device__ void polynomial_accumulate_monic_monomial_mul_on_regs(
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

// Does the same as polynomial_accumulate_monic_monomial_mul() but result is
// being written to registers and coefficients are precalculated
template <typename T, class params>
__device__ void polynomial_accumulate_monic_monomial_mul_on_regs_precalc(
    T *result, const T *__restrict__ poly, int8_t *coefs,
    uint32_t monomial_degree) {
// Every thread has a fixed position to track instead of "chasing" the
// position
#pragma unroll
  for (int i = 0; i < params::opt; i++) {
    int pos =
        (threadIdx.x + i * (params::degree / params::opt) - monomial_degree) &
        (params::degree - 1);

    T element = poly[pos];
    result[i] +=
        coefs[threadIdx.x + i * (params::degree / params::opt)] * element;
  }
}

#endif // CNCRT_POLYNOMIAL_MATH_H
