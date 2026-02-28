
#ifndef CUDA_FFT128_F128_CUH
#define CUDA_FFT128_F128_CUH

#include <cstdint>

struct alignas(16) f128 {
  double hi;
  double lo;

  // Default and parameterized constructors
  __host__ __device__ f128() : hi(0.0), lo(0.0) {}
  __host__ __device__ f128(double high, double low) : hi(high), lo(low) {}

  // Quick two-sum
  __host__ __device__ __forceinline__ static f128 quick_two_sum(double a,
                                                                double b) {
#ifdef __CUDA_ARCH__
    double s = __dadd_rn(a, b);
    return f128(s, __dsub_rn(b, __dsub_rn(s, a)));
#else
    double s = a + b;
    return f128(s, b - (s - a));
#endif
  }

  // Two-sum
  __host__ __device__ __forceinline__ static f128 two_sum(double a, double b) {
#ifdef __CUDA_ARCH__
    double s = __dadd_rn(a, b);
    double bb = __dsub_rn(s, a);
    return f128(s, __dadd_rn(__dsub_rn(a, __dsub_rn(s, bb)), __dsub_rn(b, bb)));
#else
    double s = a + b;
    double bb = s - a;
    return f128(s, (a - (s - bb)) + (b - bb));
#endif
  }

  // Two-product
  __host__ __device__ __forceinline__ static f128 two_prod(double a, double b) {

#ifdef __CUDA_ARCH__
    double p = __dmul_rn(a, b);
    double p2 = __fma_rn(a, b, -p);
#else
    double p = a * b;
    double p2 = fma(a, b, -p);
#endif
    return f128(p, p2);
  }

  __host__ __device__ __forceinline__ static f128 two_diff(double a, double b) {
#ifdef __CUDA_ARCH__
    double s = __dsub_rn(a, b);
    double bb = __dsub_rn(s, a);
    return f128(s, __dsub_rn(__dsub_rn(a, __dsub_rn(s, bb)), __dadd_rn(b, bb)));
#else
    double s = a - b;
    double bb = s - a;
    return f128(s, (a - (s - bb)) - (b + bb));
#endif
  }

  // Addition
  __host__ __device__ static f128 add(const f128 &a, const f128 &b) {
    auto s = two_sum(a.hi, b.hi);
    auto t = two_sum(a.lo, b.lo);

    double hi = s.hi;
#ifdef __CUDA_ARCH__
    double lo = __dadd_rn(s.lo, t.hi);
    hi = __dadd_rn(hi, lo);
    lo = __dsub_rn(lo, __dsub_rn(hi, s.hi));
#else
    double lo = s.lo + t.hi;
    hi = hi + lo;
    lo = lo - (hi - s.hi);
#endif

    return f128(hi, lo + t.lo);
  }

  // Addition with estimate
  __host__ __device__ static f128 add_estimate(const f128 &a, const f128 &b) {
    auto se = two_sum(a.hi, b.hi);
#ifdef __CUDA_ARCH__
    se.lo = __dadd_rn(se.lo, __dadd_rn(a.lo, b.lo));
#else
    se.lo += (a.lo + b.lo);
#endif

    return quick_two_sum(se.hi, se.lo);
  }

  // Subtraction with estimate
  __host__ __device__ static f128 sub_estimate(const f128 &a, const f128 &b) {
    f128 se = two_diff(a.hi, b.hi);
#ifdef __CUDA_ARCH__
    se.lo = __dadd_rn(se.lo, a.lo);
    se.lo = __dsub_rn(se.lo, b.lo);
#else
    se.lo += a.lo;
    se.lo -= b.lo;
#endif
    return quick_two_sum(se.hi, se.lo);
  }

  // Subtraction
  __host__ __device__ static f128 sub(const f128 &a, const f128 &b) {
    auto s = two_diff(a.hi, b.hi);
    auto t = two_diff(a.lo, b.lo);
#ifdef __CUDA_ARCH__
    s = quick_two_sum(s.hi, __dadd_rn(s.lo, t.hi));
    return quick_two_sum(s.hi, __dadd_rn(s.lo, t.lo));
#else
    s = quick_two_sum(s.hi, s.lo + t.hi);
    return quick_two_sum(s.hi, s.lo + t.lo);
#endif
  }

  // Multiplication
  __host__ __device__ static f128 mul(const f128 &a, const f128 &b) {
    auto p = two_prod(a.hi, b.hi);
#ifdef __CUDA_ARCH__
    double a_0_x_b_1 = __dmul_rn(a.hi, b.lo);
    double a_1_x_b_0 = __dmul_rn(a.lo, b.hi);
    p.lo = __dadd_rn(p.lo, __dadd_rn(a_0_x_b_1, a_1_x_b_0));
#else
    p.lo += (a.hi * b.lo + a.lo * b.hi);
#endif
    p = quick_two_sum(p.hi, p.lo);
    return p;
  }

  __host__ __device__ static f128 add_f64_f64(const double a, const double b) {
    return two_sum(a, b);
  }

  __host__ __device__ static f128 f128_floor(const f128 &x) {
    double x0_floor = floor(x.hi);
    if (x0_floor == x.hi) {
      return add_f64_f64(x0_floor, floor(x.lo));
    }

    return f128(x0_floor, 0.0);
  }

  __host__ __device__ static void
  cplx_f128_mul_assign(f128 &c_re, f128 &c_im, const f128 &a_re,
                       const f128 &a_im, const f128 &b_re, const f128 &b_im) {
    auto a_re_x_b_re = mul(a_re, b_re);
    auto a_re_x_b_im = mul(a_re, b_im);
    auto a_im_x_b_re = mul(a_im, b_re);
    auto a_im_x_b_im = mul(a_im, b_im);

    c_re = sub_estimate(a_re_x_b_re, a_im_x_b_im);
    c_im = add_estimate(a_im_x_b_re, a_re_x_b_im);
  }

  __host__ __device__ static void
  cplx_f128_sub_assign(f128 &c_re, f128 &c_im, const f128 &a_re,
                       const f128 &a_im, const f128 &b_re, const f128 &b_im) {
    c_re = sub_estimate(a_re, b_re);
    c_im = sub_estimate(a_im, b_im);
  }
  __host__ __device__ static void
  cplx_f128_add_assign(f128 &c_re, f128 &c_im, const f128 &a_re,
                       const f128 &a_im, const f128 &b_re, const f128 &b_im) {
    c_re = add_estimate(a_re, b_re);
    c_im = add_estimate(a_im, b_im);
  }
};

struct f128x2 {
  f128 re;
  f128 im;

  __host__ __device__ f128x2() : re(), im() {}

  __host__ __device__ f128x2(const f128 &real, const f128 &imag)
      : re(real), im(imag) {}

  __host__ __device__ f128x2(double real, double imag)
      : re(real, 0.0), im(imag, 0.0) {}

  __host__ __device__ explicit f128x2(double real)
      : re(real, 0.0), im(0.0, 0.0) {}

  __host__ __device__ f128x2(const f128x2 &other)
      : re(other.re), im(other.im) {}

  __host__ __device__ f128x2(f128x2 &&other) noexcept
      : re(std::move(other.re)), im(std::move(other.im)) {}

  __host__ __device__ f128x2 &operator=(const f128x2 &other) {
    if (this != &other) {
      re = other.re;
      im = other.im;
    }
    return *this;
  }

  __host__ __device__ f128x2 &operator=(f128x2 &&other) noexcept {
    if (this != &other) {
      re = std::move(other.re);
      im = std::move(other.im);
    }
    return *this;
  }

  __host__ __device__ f128x2 conjugate() const {
    return f128x2(re, f128(-im.hi, -im.lo));
  }

  __host__ __device__ f128 norm_squared() const {
    return f128::add(f128::mul(re, re), f128::mul(im, im));
  }

  __host__ __device__ void zero() {
    re = f128(0.0, 0.0);
    im = f128(0.0, 0.0);
  }

  // Addition
  __host__ __device__ friend f128x2 operator+(const f128x2 &a,
                                              const f128x2 &b) {
    return f128x2(f128::add(a.re, b.re), f128::add(a.im, b.im));
  }

  // Subtraction
  __host__ __device__ friend f128x2 operator-(const f128x2 &a,
                                              const f128x2 &b) {
    return f128x2(f128::sub_estimate(a.re, b.re),
                  f128::sub_estimate(a.im, b.im));
  }

  // Multiplication (complex multiplication)
  __host__ __device__ friend f128x2 operator*(const f128x2 &a,
                                              const f128x2 &b) {
    const f128 a_im_b_im = f128::mul(a.im, b.im);
    f128 real_part =
        f128::add(f128::mul(a.re, b.re), f128(-a_im_b_im.hi, -a_im_b_im.lo));
    f128 imag_part = f128::add(f128::mul(a.re, b.im), f128::mul(a.im, b.re));
    return f128x2(real_part, imag_part);
  }

  // Addition-assignment operator
  __host__ __device__ f128x2 &operator+=(const f128x2 &other) {
    re = f128::add(re, other.re);
    im = f128::add(im, other.im);
    return *this;
  }

  // Subtraction-assignment operator
  __host__ __device__ f128x2 &operator-=(const f128x2 &other) {
    re = f128::sub_estimate(re, other.re);
    im = f128::sub_estimate(im, other.im);
    return *this;
  }

  // Multiplication-assignment operator
  __host__ __device__ f128x2 &operator*=(const f128x2 &other) {
    f128 new_re =
        f128::add(f128::mul(re, other.re), f128(-f128::mul(im, other.im).hi,
                                                -f128::mul(im, other.im).lo));
    f128 new_im = f128::add(f128::mul(re, other.im), f128::mul(im, other.re));
    re = new_re;
    im = new_im;
    return *this;
  }
};

__host__ __device__ inline uint64_t double_to_bits(double d) {
#ifdef __CUDA_ARCH__
  uint64_t bits = __double_as_longlong(d);
#else
  uint64_t bits = *reinterpret_cast<uint64_t *>(&d);
#endif
  return bits;
}

__host__ __device__ inline double bits_to_double(uint64_t bits) {
#ifdef __CUDA_ARCH__
  double d = __longlong_as_double(bits);
#else
  double d = *reinterpret_cast<double *>(&bits);
#endif
  return d;
}

__host__ __device__ inline double u128_to_f64(__uint128_t x) {
  const __uint128_t ONE = 1;
  const double A = ONE << 52;
  const double B = ONE << 104;
  const double C = ONE << 76;
  // NOTE: for some reason __longlong_as_double(0x37f0000000000000ULL)
  // does not work here
  const double D = 340282366920938500000000000000000000000.;

  const __uint128_t threshold = (ONE << 104);

  if (x < threshold) {
    uint64_t A_bits = double_to_bits(A);

    __uint128_t shifted = (x << 12);
    uint64_t lower64 = static_cast<uint64_t>(shifted);
    lower64 >>= 12;

    uint64_t bits_l = A_bits | lower64;
    double l_temp = bits_to_double(bits_l);

    uint64_t B_bits = double_to_bits(B);
    uint64_t top64 = static_cast<uint64_t>(x >> 52);
    uint64_t bits_h = B_bits | top64;
    double h_temp = bits_to_double(bits_h);

#ifdef __CUDA_ARCH__
    return __dadd_rn(__dsub_rn(l_temp, A), __dsub_rn(h_temp, B));
#else
    double l = l_temp - A;
    double h = h_temp - B;

    return (l + h);
#endif

  } else {
    uint64_t C_bits = double_to_bits(C);

    __uint128_t shifted = (x >> 12);
    uint64_t lower64 = static_cast<uint64_t>(shifted);
    lower64 >>= 12;

    uint64_t x_lo = static_cast<uint64_t>(x);
    uint64_t mask_part = (x_lo & 0xFFFFFFULL);

    uint64_t bits_l = C_bits | lower64 | mask_part;
    double l_temp = bits_to_double(bits_l);

    uint64_t D_bits = double_to_bits(D);
    uint64_t top64 = static_cast<uint64_t>(x >> 76);
    uint64_t bits_h = D_bits | top64;
    double h_temp = bits_to_double(bits_h);

#ifdef __CUDA_ARCH__
    return __dadd_rn(__dsub_rn(l_temp, C), __dsub_rn(h_temp, D));
#else
    double l = l_temp - C;
    double h = h_temp - D;

    return (l + h);
#endif
  }
}

__host__ __device__ inline __uint128_t f64_to_u128(const double f) {
  const __uint128_t ONE = 1;
  const uint64_t f_bits = double_to_bits(f);
  if (f_bits < 1023ull << 52) {
    return 0;
  } else {
    const __uint128_t m = ONE << 127 | (__uint128_t)f_bits << 75;
    const uint64_t s = 1150 - (f_bits >> 52);
    if (s >= 128) {
      return 0;
    } else {
      return m >> s;
    }
  }
}

__host__ __device__ inline __uint128_t f64_to_i128(const double f) {
  // Get raw bits of the double
  const uint64_t f_bits = double_to_bits(f);

  // Remove sign bit (equivalent to Rust's !0 >> 1 mask)
  const uint64_t a = f_bits & 0x7FFFFFFFFFFFFFFFull;

  // Check if value is in [0, 1) range
  if (a < (1023ull << 52)) {
    return 0;
  }

  // Reconstruct mantissa with implicit leading 1
  const __uint128_t m =
      (__uint128_t{1} << 127) | (static_cast<__uint128_t>(a) << 75);

  // Calculate shift amount based on exponent
  const uint64_t exponent = a >> 52;
  const uint64_t s = 1150 - exponent;

  // Perform unsigned right shift
  const __uint128_t u = m >> s;

  // Apply sign (check original sign bit)
  const __int128_t result = static_cast<__int128_t>(u);
  return (f_bits >> 63) ? -result : result;
}

__host__ __device__ inline double i128_to_f64(__int128_t const x) {
  uint64_t sign = static_cast<uint64_t>(x >> 64) & (1ULL << 63);
  __uint128_t abs =
      (x < 0) ? static_cast<__uint128_t>(-x) : static_cast<__uint128_t>(x);

  return bits_to_double(double_to_bits(u128_to_f64(abs)) | sign);
}
__host__ __device__ inline f128 u128_to_signed_to_f128(__uint128_t x) {
  const double first_approx = i128_to_f64(x);
  const uint64_t sign_bit = double_to_bits(first_approx) & (1ull << 63);
  const __uint128_t first_approx_roundtrip =
      f64_to_u128((first_approx < 0) ? -first_approx : first_approx);
  const __uint128_t first_approx_roundtrip_signed =
      (sign_bit == (1ull << 63)) ? -first_approx_roundtrip
                                 : first_approx_roundtrip;

  double correction = i128_to_f64(x - first_approx_roundtrip_signed);

  return f128(first_approx, correction);
}

__host__ __device__ inline __uint128_t u128_from_torus_f128(const f128 &a) {
  auto x = f128::sub_estimate(a, f128::f128_floor(a));
  // NOTE: for some reason __longlong_as_double(0x37f0000000000000ULL)
  // does not work here
  const double normalization = 340282366920938500000000000000000000000.;
#ifdef __CUDA_ARCH__
  x.hi = __dmul_rn(x.hi, normalization);
  x.lo = __dmul_rn(x.lo, normalization);
#else
  x.hi *= normalization;
  x.lo *= normalization;
#endif

  x = f128::add_estimate(x, f128(0.5, 0.0));
  x = f128::f128_floor(x);

  __uint128_t x0 = f64_to_u128(x.hi);
  __int128_t x1 = f64_to_i128(x.lo);

  return x0 + x1;
}

// Warp shuffle for f128x2 complex numbers
__device__ inline f128x2 shfl_xor_f128x2(const f128x2 &val, int laneMask,
                                         unsigned mask = 0xFFFFFFFF) {
  f128x2 result;
  result.re.hi = __shfl_xor_sync(mask, val.re.hi, laneMask);
  result.re.lo = __shfl_xor_sync(mask, val.re.lo, laneMask);
  result.im.hi = __shfl_xor_sync(mask, val.im.hi, laneMask);
  result.im.lo = __shfl_xor_sync(mask, val.im.lo, laneMask);
  return result;
}

#endif
