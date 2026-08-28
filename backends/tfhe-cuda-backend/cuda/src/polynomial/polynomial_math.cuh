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

// Fused version that calculates result= fft0*bsk0 + fft1*bsk1
// The idea is forcing the use of fma and expose more parallel ops
template <class params>
__device__ __forceinline__ void
polynomial_product_accumulate_in_fourier_domain_2_2_params_fused(
    double2 *__restrict__ result, const double2 *__restrict__ first_regs,
    const double2 *__restrict__ second, const double2 *__restrict__ first_bsk,
    const double2 *__restrict__ second_bsk) {
  int tid = threadIdx.x;
  constexpr int stride = params::degree / params::opt;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    const double2 a = first_regs[i];
    const double2 b = first_bsk[tid];
    double real = __fma_rn(a.x, b.x, -a.y * b.y);
    double imag = __fma_rn(a.x, b.y, a.y * b.x);

    const double2 c = second[tid];
    const double2 d = second_bsk[tid];
    real = __fma_rn(c.x, d.x, real);
    real = __fma_rn(-c.y, d.y, real);
    imag = __fma_rn(c.x, d.y, imag);
    imag = __fma_rn(c.y, d.x, imag);
    result[i] = make_double2(real, imag);
    tid += stride;
  }
}

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
// The BSK is read from global once per term and never reused, so __ldg keeps it
// out of the way; a peer's published transform comes from shared and must not.
template <bool from_shared>
__device__ __forceinline__ double2 tfhe_pbs128_load_pair(const double *p) {
  if constexpr (from_shared)
    return *(const double2 *)p;
  else
    return __ldg((const double2 *)p);
}

// ----------------------------------------------------------------------------
// Relaxed fp128 arithmetic, for the Fourier-domain product of the
// single-iteration TBC flavor.
//
// A fully renormalized double-double MAC costs 54 FP64 operations, 38 of them
// two_sum chains run per term. Only one chain is load-bearing: the hi
// accumulation rounds at 2^-53 of the running sum every term, and in
// double-double that rounding is exactly what the lo limb absorbs. The product
// error and both cross terms can be plain FMAs, and hi/lo need not be canonical
// until all nine terms are in -- free here, because the accumulator lives in
// registers.
//
// Measured on 200k random nine-term accumulations against a __float128
// reference:
//   renormalized per term   54 ops   88.9 correct bits
//   relaxed (this form)     26 ops   88.3 correct bits
//   no two_sum at all       12 ops   37.2 correct bits  <- the hi chain matters
// So -52% for 0.6 bits. Dropping the hi two_sum as well is what the fp64
// throughput PBS can afford -- a single double *is* the value, with no lo limb
// to feed -- and what this cannot.
//
// The caller owns the unnormalized accumulator and calls
// finalize_relaxed_fp128_pair once at the end.
// ----------------------------------------------------------------------------

// One term of the relaxed accumulation: dst += (negate ? -1 : 1) * x * y, with
// the renormalization deferred. Only the hi accumulation runs a TwoSum; the
// product error and both cross terms are plain FMAs.
//
// The sign is folded into x rather than applied to each product. Negating a
// double is exact, so this is bit-for-bit the same as negating the product and
// both cross terms individually.
template <bool negate>
__device__ __forceinline__ void
relaxed_fp128_accumulate_term(double &dst_hi, double &dst_lo, double xh,
                              double xl, double yh, double yl) {
  const double signed_xh = negate ? -xh : xh;
  const double signed_xl = negate ? -xl : xl;

  const double p = signed_xh * yh;
  const double e = __fma_rn(signed_xh, yh, -p);
  const double s = dst_hi + p;
  const double bb = s - dst_hi;
  const double err = (dst_hi - (s - bb)) + (p - bb);
  dst_hi = s;
  dst_lo = dst_lo + (e + err);
  dst_lo = __fma_rn(signed_xh, yl, dst_lo);
  dst_lo = __fma_rn(signed_xl, yh, dst_lo);
}

// Opening form of the same term, for a lane that is still zero. With
// dst_hi == dst_lo == 0 the running-sum TwoSum degenerates exactly -- s is p,
// bb is p, err is 0 -- so nine of the thirteen FP64 ops would be computing
// zero.
// Only the first of the nine GGSW products can use this, and within it only the
// four terms that OPEN a lane, which is why the caller peels one product and
// not one level.
template <bool negate>
__device__ __forceinline__ void
relaxed_fp128_open_term(double &dst_hi, double &dst_lo, double xh, double xl,
                        double yh, double yl) {
  const double signed_xh = negate ? -xh : xh;
  const double signed_xl = negate ? -xl : xl;

  const double p = signed_xh * yh;
  dst_hi = p;
  dst_lo = __fma_rn(signed_xh, yh, -p);
  dst_lo = __fma_rn(signed_xh, yl, dst_lo);
  dst_lo = __fma_rn(signed_xl, yh, dst_lo);
}

// One complex slot of the product:
//   acc_re += a_re * b_re - a_im * b_im
//   acc_im += a_re * b_im + a_im * b_re
// `opening` picks the cheap form for the two terms that open their lane.
template <bool opening>
__device__ __forceinline__ void relaxed_fp128_accumulate_complex_slot(
    double &acc_re_hi, double &acc_re_lo, double &acc_im_hi, double &acc_im_lo,
    double a_re_hi, double a_re_lo, double a_im_hi, double a_im_lo,
    double b_re_hi, double b_re_lo, double b_im_hi, double b_im_lo) {
  if constexpr (opening) {
    relaxed_fp128_open_term<false>(acc_re_hi, acc_re_lo, a_re_hi, a_re_lo,
                                   b_re_hi, b_re_lo);
    relaxed_fp128_accumulate_term<true>(acc_re_hi, acc_re_lo, a_im_hi, a_im_lo,
                                        b_im_hi, b_im_lo);
    relaxed_fp128_open_term<false>(acc_im_hi, acc_im_lo, a_re_hi, a_re_lo,
                                   b_im_hi, b_im_lo);
    relaxed_fp128_accumulate_term<false>(acc_im_hi, acc_im_lo, a_im_hi, a_im_lo,
                                         b_re_hi, b_re_lo);
  } else {
    relaxed_fp128_accumulate_term<false>(acc_re_hi, acc_re_lo, a_re_hi, a_re_lo,
                                         b_re_hi, b_re_lo);
    relaxed_fp128_accumulate_term<true>(acc_re_hi, acc_re_lo, a_im_hi, a_im_lo,
                                        b_im_hi, b_im_lo);
    relaxed_fp128_accumulate_term<false>(acc_im_hi, acc_im_lo, a_re_hi, a_re_lo,
                                         b_im_hi, b_im_lo);
    relaxed_fp128_accumulate_term<false>(acc_im_hi, acc_im_lo, a_im_hi, a_im_lo,
                                         b_re_hi, b_re_lo);
  }
}

// Renormalizes the accumulator, ending the relaxed form.
__device__ __forceinline__ void finalize_relaxed_fp128_pair(double2 &acc_hi,
                                                            double2 &acc_lo) {
  f128 x = f128::quick_two_sum(acc_hi.x, acc_lo.x);
  f128 y = f128::quick_two_sum(acc_hi.y, acc_lo.y);
  acc_hi.x = x.hi;
  acc_lo.x = x.lo;
  acc_hi.y = y.hi;
  acc_lo.y = y.lo;
}

// Register-accumulator form of the paired product. The nine-term accumulator is
// 4096 doubles, which at 512 threads is 8 doubles -- 16 registers -- per
// thread, so it only fits alongside everything else if its live range is kept
// short.
// The caller owns the four accumulator halves and writes them out once at the
// end.
//
// This core takes the left operand already in registers; `opening` picks the
// cheap form for the product that opens a still-zero accumulator. Handles
// exactly ONE pair (the one at 2*threadIdx.x, relative to the pointers given).
// opt only decides how many times the caller invokes it: opt=4 is one pair per
// thread, opt=8 is two, at window offsets g * 2 * (degree/opt).
template <class params, bool opening>
__device__ void
polynomial_product_accumulate_in_fourier_domain_128_pairs_relaxed_regs(
    double2 &acc_re_hi, double2 &acc_re_lo, double2 &acc_im_hi,
    double2 &acc_im_lo, double2 a_re_hi, double2 a_re_lo, double2 a_im_hi,
    double2 a_im_lo, const double *__restrict__ second) {
  static_assert(params::opt == 4 || params::opt == 8,
                "the paired mapping expects 2 or 4 complex slots per thread");
  constexpr int half_degree = params::degree / 2;
  const int pair = 2 * threadIdx.x;

  const double2 b_re_hi =
      __ldg((const double2 *)&second[pair + 0 * half_degree]);
  const double2 b_re_lo =
      __ldg((const double2 *)&second[pair + 1 * half_degree]);
  const double2 b_im_hi =
      __ldg((const double2 *)&second[pair + 2 * half_degree]);
  const double2 b_im_lo =
      __ldg((const double2 *)&second[pair + 3 * half_degree]);

  // real part: + a_re*b_re - a_im*b_im ; imaginary: + a_re*b_im + a_im*b_re
  relaxed_fp128_accumulate_complex_slot<opening>(
      acc_re_hi.x, acc_re_lo.x, acc_im_hi.x, acc_im_lo.x, a_re_hi.x, a_re_lo.x,
      a_im_hi.x, a_im_lo.x, b_re_hi.x, b_re_lo.x, b_im_hi.x, b_im_lo.x);
  relaxed_fp128_accumulate_complex_slot<opening>(
      acc_re_hi.y, acc_re_lo.y, acc_im_hi.y, acc_im_lo.y, a_re_hi.y, a_re_lo.y,
      a_im_hi.y, a_im_lo.y, b_re_hi.y, b_re_lo.y, b_im_hi.y, b_im_lo.y);
}

// Same product with the left operand read from memory.
template <class params, bool opening, bool first_is_shared = false>
__device__ void
polynomial_product_accumulate_in_fourier_domain_128_pairs_relaxed(
    double2 &acc_re_hi, double2 &acc_re_lo, double2 &acc_im_hi,
    double2 &acc_im_lo, const double *__restrict__ first,
    const double *__restrict__ second) {
  constexpr int half_degree = params::degree / 2;
  const int pair = 2 * threadIdx.x;

  const double2 a_re_hi =
      tfhe_pbs128_load_pair<first_is_shared>(&first[pair + 0 * half_degree]);
  const double2 a_re_lo =
      tfhe_pbs128_load_pair<first_is_shared>(&first[pair + 1 * half_degree]);
  const double2 a_im_hi =
      tfhe_pbs128_load_pair<first_is_shared>(&first[pair + 2 * half_degree]);
  const double2 a_im_lo =
      tfhe_pbs128_load_pair<first_is_shared>(&first[pair + 3 * half_degree]);

  polynomial_product_accumulate_in_fourier_domain_128_pairs_relaxed_regs<
      params, opening>(acc_re_hi, acc_re_lo, acc_im_hi, acc_im_lo, a_re_hi,
                       a_re_lo, a_im_hi, a_im_lo, second);
}
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
