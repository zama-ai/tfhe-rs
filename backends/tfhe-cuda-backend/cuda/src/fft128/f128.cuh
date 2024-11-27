
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
};
#endif
