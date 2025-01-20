
#ifndef TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_F128_CUH_
#define TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_F128_CUH_

#include <cstdint>
#include <cstring>

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
#ifdef __CUDA_ARCH__
    return f128(p, __fma_rn(a, b, -p));
#else
    return f128(p, fma(a, b, -p));
#endif
  }

  __host__ __device__ __forceinline__ static f128 two_diff(double a, double b) {
    double s = a - b;
    double bb = s - a;
    return f128(s, (a - (s - bb)) - (b + bb));
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
  cplx_f128_mul_assign(f128 &c_re, f128 &c_im, const f128 &a_re,
                       const f128 &a_im, const f128 &b_re, const f128 &b_im) {
    auto a_re_x_b_re = mul(a_re, b_re);
    auto a_re_x_b_im = mul(a_re, b_im);
    auto a_im_x_b_re = mul(a_im, b_re);
    auto a_im_x_b_im = mul(a_im, b_im);

    c_re = add_estimate(a_re_x_b_re, a_im_x_b_im);
    c_im = sub_estimate(a_im_x_b_re, a_re_x_b_im);
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
    return f128x2(f128::add(a.re, f128(-b.re.hi, -b.re.lo)),
                  f128::add(a.im, f128(-b.im.hi, -b.im.lo)));
  }

  // Multiplication (complex multiplication)
  __host__ __device__ friend f128x2 operator*(const f128x2 &a,
                                              const f128x2 &b) {
    f128 real_part =
        f128::add(f128::mul(a.re, b.re),
                  f128(-f128::mul(a.im, b.im).hi, -f128::mul(a.im, b.im).lo));
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
    re = f128::add(re, f128(-other.re.hi, -other.re.lo));
    im = f128::add(im, f128(-other.im.hi, -other.im.lo));
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
  uint64_t bits;
  std::memcpy(&bits, &d, sizeof(bits));
  return bits;
}

__host__ __device__ inline double bits_to_double(uint64_t bits)
{
  double d;
  std::memcpy(&d, &bits, sizeof(d));
  return d;
}


__host__ __device__ double u128_to_f64(__uint128_t x) {
  const __uint128_t ONE = 1;
  const double A = ONE << 52;
  const double B = ONE << 104;
  const double C = ONE << 76;
  const double D = 340282366920938500000000000000000000000.;

  const __uint128_t threshold = (ONE << 104);

  if (x < threshold) {
    uint64_t A_bits = double_to_bits(A);

    __uint128_t shifted = (x << 12);
    uint64_t lower64 = static_cast<uint64_t>(shifted);
    lower64 >>= 12;

    uint64_t bits_l = A_bits | lower64;
    double l_temp = bits_to_double(bits_l);
    double l = l_temp - A;

    uint64_t B_bits = double_to_bits(B);
    uint64_t top64 = static_cast<uint64_t>(x >> 52);
    uint64_t bits_h = B_bits | top64;
    double h_temp = bits_to_double(bits_h);
    double h = h_temp - B;

    return (l + h);

  } else {
    uint64_t C_bits = double_to_bits(C);

    __uint128_t shifted = (x >> 12);
    uint64_t lower64 = static_cast<uint64_t>(shifted);
    lower64 >>= 12;

    uint64_t x_lo = static_cast<uint64_t>(x);
    uint64_t mask_part = (x_lo & 0xFFFFFFULL);

    uint64_t bits_l = C_bits | lower64 | mask_part;
    double l_temp = bits_to_double(bits_l);
    double l = l_temp - C;

    uint64_t D_bits = double_to_bits(D);
    uint64_t top64 = static_cast<uint64_t>(x >> 76);
    uint64_t bits_h = D_bits | top64;
    double h_temp = bits_to_double(bits_h);
    double h = h_temp - D;

    return (l + h);
  }
}

__host__ __device__ __uint128_t f64_to_u128(const double f) {
  const __uint128_t ONE = 1;
  const uint64_t f_bits = double_to_bits(f);
  if (f_bits < 1023ull << 52) {
    return 0;
  } else {
    const __uint128_t m = ONE << 127 | (__uint128_t) f_bits << 75;
    const uint64_t s = 1150 - (f_bits >> 52);
    if (s >= 128) {
      return 0;
    } else {
      return m >> s;
    }
  }
}

__host__ __device__ double i128_to_f64(__int128_t const x) {
  uint64_t sign = static_cast<uint64_t>(x >> 64) & (1ULL << 63);
  __uint128_t abs = (x < 0)
      ? static_cast<__uint128_t>(-x)
      : static_cast<__uint128_t>(x);

  return bits_to_double(double_to_bits(u128_to_f64(abs)) | sign);

}
__host__ __device__ f128 u128_to_signed_to_f128(__uint128_t x) {
  const double first_approx = i128_to_f64(x);
  const uint64_t sign_bit = double_to_bits(first_approx) * (1ull << 64);
  const __uint128_t first_approx_roundtrip =
      f64_to_u128((first_approx < 0) ? -first_approx : first_approx);
  const __uint128_t first_approx_roundtrip_signed = (sign_bit == (1ull << 63))
      ?-first_approx_roundtrip
      :first_approx_roundtrip;

  double correction = i128_to_f64(x - first_approx_roundtrip_signed);

  return f128(first_approx, correction);
};
#endif
