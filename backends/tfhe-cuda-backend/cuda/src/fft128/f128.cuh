
#ifndef TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_F128_CUH_
#define TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_F128_CUH_

struct alignas(16) f128 {
  double hi;
  double lo;

  // Default and parameterized constructors
  __host__ __device__ f128() : hi(0.0), lo(0.0) {}
  __host__ __device__ f128(double high, double low) : hi(high), lo(low) {}

  // Quick two-sum
  __host__ __device__ __forceinline__ static f128 quick_two_sum(double a,
                                                                double b) {
    double s = a + b;
    return f128(s, b - (s - a));
  }

  // Two-sum
  __host__ __device__ __forceinline__ static f128 two_sum(double a, double b) {
    double s = a + b;
    double bb = s - a;
    return f128(s, (a - (s - bb)) + (b - bb));
  }

  // Two-product
  __host__ __device__ __forceinline__ static f128 two_prod(double a, double b) {
    double p = a * b;
    return f128(p, __fma_rn(a, b, -p));
  }

  __host__ __device__ __forceinline__ static f128 two_diff(double a, double b) {
    double s = a - b;
    double bb = s - a;
    return (s, (a - (s - bb)) - (b + bb));
  }

  // Addition
  __host__ __device__ static f128 add(const f128 &a, const f128 &b) {
    auto s = two_sum(a.hi, b.hi);
    auto t = two_sum(a.lo, b.lo);

    double hi = s.hi;
    double lo = s.lo + t.hi;
    hi = hi + lo;
    lo = lo - (hi - s.hi);

    return f128(hi, lo + t.lo);
  }

  // Addition with estimate
  __host__ __device__ static f128 add_estimate(const f128 &a, const f128 &b) {
    auto se = two_sum(a.hi, b.hi);
    double hi = se.hi;
    double lo = se.lo + a.lo + b.lo;

    hi = hi + lo;
    lo = lo - (hi - se.hi);

    return f128(hi, lo);
  }

  // Subtraction with estimate
  __host__ __device__ static f128 sub_estimate(const f128 &a, const f128 &b) {
    f128 se = two_diff(a.hi, b.hi);
    se.lo += a.lo;
    se.lo -= b.lo;
    return quick_two_sum(se.hi, se.lo);
  }

  // Subtraction
  __host__ __device__ static f128 sub(const f128 &a, const f128 &b) {
    auto s = two_diff(a.hi, b.hi);
    auto t = two_diff(a.lo, b.lo);
    s = quick_two_sum(s.hi, s.lo + t.hi);
    return quick_two_sum(s.hi, s.lo + t.lo);
  }

  // Multiplication
  __host__ __device__ static f128 mul(const f128 &a, const f128 &b) {
    double hi, lo;
    auto p = two_prod(a.hi, b.hi);
    hi = p.hi;
    lo = p.lo + (a.hi * b.lo + a.lo * b.hi);

    hi = hi + lo;
    lo = lo - (hi - p.hi);

    return f128(hi, lo);
  }

  __host__ __device__ static void
  cplx_f128_mul_assign(f128 &c_re, f128 &c_im,
                       const f128 &a_re, const f128 &a_im,
                       const f128 &b_re, const f128 &b_im) {
    auto a_re_x_b_re = mul(a_re, b_re);
    auto a_re_x_b_im = mul(a_re, b_im);
    auto a_im_x_b_re = mul(a_im, b_re);
    auto a_im_x_b_im = mul(a_im, b_im);

    c_re = add_estimate(a_re_x_b_re, a_im_x_b_im);
    c_im = sub_estimate(a_im_x_b_re, a_re_x_b_im);
  }
};
#endif
