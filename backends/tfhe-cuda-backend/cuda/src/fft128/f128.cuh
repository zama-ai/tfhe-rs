
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

struct f128x2 {
  f128 re;
  f128 im;

  __host__ __device__ f128x2() : re(), im() {}

  __host__ __device__ f128x2(const f128& real, const f128& imag) : re(real), im(imag) {}

  __host__ __device__ f128x2(double real, double imag) : re(real, 0.0), im(imag, 0.0) {}

  __host__ __device__ explicit f128x2(double real) : re(real, 0.0), im(0.0, 0.0) {}

  __host__ __device__ f128x2(const f128x2& other) : re(other.re), im(other.im) {}

  __host__ __device__ f128x2(f128x2&& other) noexcept : re(std::move(other.re)), im(std::move(other.im)) {}

  __host__ __device__ f128x2& operator=(const f128x2& other) {
    if (this != &other) {
      re = other.re;
      im = other.im;
    }
    return *this;
  }

  __host__ __device__ f128x2& operator=(f128x2&& other) noexcept {
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
  __host__ __device__ friend f128x2 operator+(const f128x2& a, const f128x2& b) {
    return f128x2(f128::add(a.re, b.re), f128::add(a.im, b.im));
  }

  // Subtraction
  __host__ __device__ friend f128x2 operator-(const f128x2& a, const f128x2& b) {
    return f128x2(f128::add(a.re, f128(-b.re.hi, -b.re.lo)),
                  f128::add(a.im, f128(-b.im.hi, -b.im.lo)));
  }

  // Multiplication (complex multiplication)
  __host__ __device__ friend f128x2 operator*(const f128x2& a, const f128x2& b) {
    f128 real_part = f128::add(f128::mul(a.re, b.re), f128(-f128::mul(a.im, b.im).hi, -f128::mul(a.im, b.im).lo));
    f128 imag_part = f128::add(f128::mul(a.re, b.im), f128::mul(a.im, b.re));
    return f128x2(real_part, imag_part);
  }

  // Addition-assignment operator
  __host__ __device__ f128x2& operator+=(const f128x2& other) {
    re = f128::add(re, other.re);
    im = f128::add(im, other.im);
    return *this;
  }

  // Subtraction-assignment operator
  __host__ __device__ f128x2& operator-=(const f128x2& other) {
    re = f128::add(re, f128(-other.re.hi, -other.re.lo));
    im = f128::add(im, f128(-other.im.hi, -other.im.lo));
    return *this;
  }

  // Multiplication-assignment operator
  __host__ __device__ f128x2& operator*=(const f128x2& other) {
    f128 new_re = f128::add(f128::mul(re, other.re), f128(-f128::mul(im, other.im).hi, -f128::mul(im, other.im).lo));
    f128 new_im = f128::add(f128::mul(re, other.im), f128::mul(im, other.re));
    re = new_re;
    im = new_im;
    return *this;
  }

};
#endif
