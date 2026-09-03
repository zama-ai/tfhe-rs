
#ifndef CUDA_FFT128_F128_CUH
#define CUDA_FFT128_F128_CUH

#include <cmath>
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
    double p2 = std::fma(a, b, -p);
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
    // The two cross products are accumulated with fused multiply-adds: this
    // removes the roundings of the two intermediate products, so the result is
    // at least as accurate as computing and adding them separately, for half
    // the instructions.
    // Both branches name the operation explicitly (__fma_rn on device,
    // std::fma on host) rather than letting each compiler decide whether to
    // contract `a * b + c`. Without that, the host and device paths would not
    // evaluate the same expression.
#ifdef __CUDA_ARCH__
    p.lo = __fma_rn(a.hi, b.lo, __fma_rn(a.lo, b.hi, p.lo));
#else
    p.lo = std::fma(a.hi, b.lo, std::fma(a.lo, b.hi, p.lo));
#endif
    p = quick_two_sum(p.hi, p.lo);
    return p;
  }

  // The same product without the final renormalization, and with the two cross
  // terms folded into FMAs instead of being rounded to doubles and then added.
  // Every consumer feeds the result straight into a two_sum/two_diff on the hi
  // parts, which needs only |lo| << |hi| and not a normalized pair -- and an
  // unnormalized product satisfies that, with |p.lo| bounded by a small
  // multiple of 2^-53 |p.hi|. 4 operations against mul()'s 9.
  __host__ __device__ __forceinline__ static f128 mul_raw(const f128 &a,
                                                          const f128 &b) {
    auto p = two_prod(a.hi, b.hi);
#ifdef __CUDA_ARCH__
    p.lo = __fma_rn(a.hi, b.lo, __fma_rn(a.lo, b.hi, p.lo));
#else
    p.lo = fma(a.hi, b.lo, fma(a.lo, b.hi, p.lo));
#endif
    return p;
  }

  // The same product for a left operand whose low limb is exactly zero: the
  // a.lo * b.hi cross term is dropped. With a.lo == 0.0 the omitted term is
  // fma(0.0, b.hi, p.lo), an exact zero product added to p.lo, which returns
  // p.lo itself. That holds bit for bit including the sign of a zero, because
  // two_prod never returns a negative zero low limb: its low limb is either
  // non-zero or the exactly cancelling difference a * b - a * b, and a
  // cancelling difference rounds to +0.0 under round-to-nearest. 3 operations
  // against mul_raw's 4.
  __host__ __device__ __forceinline__ static f128
  mul_raw_zero_lo(const f128 &a, const f128 &b) {
    auto p = two_prod(a.hi, b.hi);
#ifdef __CUDA_ARCH__
    p.lo = __fma_rn(a.hi, b.lo, p.lo);
#else
    p.lo = fma(a.hi, b.lo, p.lo);
#endif
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

  // One radix-2 butterfly in one pass: u <- u + v*tw, v <- u - v*tw.
  //
  // Written out rather than composed from cplx_f128_mul_assign +
  // cplx_f128_{add,sub}_assign because that composition renormalizes twice for
  // nothing. The product's four partial terms stay raw, their combination into
  // v*tw stays unnormalized, and the four results are left unnormalized too:
  // every consumer is a two_sum/two_diff or a mul_raw, none of which need a
  // canonical pair. 64 operations against the composed form's 82.
  //
  // The outputs MUST all be derived from the original u lo limbs -- assigning
  // u_re before computing v_re feeds v_re an already-updated lo.
  //
  // tw is only read, so callers may alias it with their twiddle temporary.
  __host__ __device__ __forceinline__ static void
  cplx_f128_relaxed_butterfly_assign(f128 &u_re, f128 &u_im, f128 &v_re,
                                     f128 &v_im, const f128 &tw_re,
                                     const f128 &tw_im) {
    const f128 rr = mul_raw(v_re, tw_re), ii = mul_raw(v_im, tw_im);
    const f128 ir = mul_raw(v_im, tw_re), ri = mul_raw(v_re, tw_im);
    const f128 s_re = two_diff(rr.hi, ii.hi);
    const f128 s_im = two_sum(ir.hi, ri.hi);
#ifdef __CUDA_ARCH__
    const double p_re_lo = __dadd_rn(s_re.lo, __dsub_rn(rr.lo, ii.lo));
    const double p_im_lo = __dadd_rn(s_im.lo, __dadd_rn(ir.lo, ri.lo));
    const f128 ap = two_sum(u_re.hi, s_re.hi);
    const f128 am = two_diff(u_re.hi, s_re.hi);
    const f128 bp = two_sum(u_im.hi, s_im.hi);
    const f128 bm = two_diff(u_im.hi, s_im.hi);
    const f128 nu_re(ap.hi, __dadd_rn(ap.lo, __dadd_rn(u_re.lo, p_re_lo)));
    const f128 nv_re(am.hi, __dadd_rn(am.lo, __dsub_rn(u_re.lo, p_re_lo)));
    const f128 nu_im(bp.hi, __dadd_rn(bp.lo, __dadd_rn(u_im.lo, p_im_lo)));
    const f128 nv_im(bm.hi, __dadd_rn(bm.lo, __dsub_rn(u_im.lo, p_im_lo)));
#else
    const double p_re_lo = s_re.lo + (rr.lo - ii.lo);
    const double p_im_lo = s_im.lo + (ir.lo + ri.lo);
    const f128 ap = two_sum(u_re.hi, s_re.hi);
    const f128 am = two_diff(u_re.hi, s_re.hi);
    const f128 bp = two_sum(u_im.hi, s_im.hi);
    const f128 bm = two_diff(u_im.hi, s_im.hi);
    const f128 nu_re(ap.hi, ap.lo + (u_re.lo + p_re_lo));
    const f128 nv_re(am.hi, am.lo + (u_re.lo - p_re_lo));
    const f128 nu_im(bp.hi, bp.lo + (u_im.lo + p_im_lo));
    const f128 nv_im(bm.hi, bm.lo + (u_im.lo - p_im_lo));
#endif
    u_re = nu_re;
    u_im = nu_im;
    v_re = nv_re;
    v_im = nv_im;
  }

  // cplx_f128_relaxed_butterfly_assign specialized for level 1 of the forward
  // transform, where two facts hold that the compiler cannot see. Both are
  // read out of the code rather than assumed.
  //
  // Fact 1: the only twiddle of that level is neg_twiddles[1] = exp(i*pi/4) =
  // (1 + i) * sqrt(2)/2, whose real and imaginary parts are equal bit for bit
  // in both limbs. The general butterfly loads them as two separate values, so
  // the compiler cannot relate them. Taking the shared limb pair t once makes
  // the equality explicit and collapses the four raw products into two:
  // rr = ri = P = mul_raw(v_re, t) and ii = ir = Q = mul_raw(v_im, t).
  //
  // Fact 2: the level-1 inputs are gadget decomposition digits converted to
  // f128 with an exactly zero low limb -- small_signed_to_f128 for the
  // single-iteration TBC kernel, the int32 conversion in
  // decompose_and_compress_next_level_128 for the DEFAULT step one. So u_re.lo,
  // u_im.lo, v_re.lo and v_im.lo are all exactly zero, which lets each product
  // drop one cross term (mul_raw_zero_lo above) and lets the four output low
  // limbs drop their u.lo addend: 0.0 + x == x and 0.0 - x == -x, and IEEE 754
  // defines a - b as a + (-b), so the general butterfly's
  // am.lo + (u_re.lo - p_re_lo) becomes am.lo - p_re_lo.
  //
  // 50 operations against the general butterfly's 64. Everything the identities
  // do not remove is left exactly as the general butterfly writes it -- the
  // operand order of every two_sum and two_diff, the grouping of every low-limb
  // sum -- so the two agree bit for bit. The only conceivable difference is the
  // sign of a low limb that is an exact zero, and the digest harness is the
  // check for that.
  //
  // PRECONDITION: all four input low limbs are exactly zero, and t is the
  // shared limb pair of a twiddle whose real and imaginary parts are equal.
  //
  // As in the general butterfly, all four outputs are computed before any of
  // them is assigned, and t is only read, so callers may alias it with their
  // twiddle temporary.
  __host__ __device__ __forceinline__ static void
  cplx_f128_relaxed_butterfly_level1_assign(f128 &u_re, f128 &u_im, f128 &v_re,
                                            f128 &v_im, const f128 &t) {
    const f128 P = mul_raw_zero_lo(v_re, t);
    const f128 Q = mul_raw_zero_lo(v_im, t);
    const f128 s_re = two_diff(P.hi, Q.hi);
    const f128 s_im = two_sum(Q.hi, P.hi);
#ifdef __CUDA_ARCH__
    const double p_re_lo = __dadd_rn(s_re.lo, __dsub_rn(P.lo, Q.lo));
    const double p_im_lo = __dadd_rn(s_im.lo, __dadd_rn(Q.lo, P.lo));
    const f128 ap = two_sum(u_re.hi, s_re.hi);
    const f128 am = two_diff(u_re.hi, s_re.hi);
    const f128 bp = two_sum(u_im.hi, s_im.hi);
    const f128 bm = two_diff(u_im.hi, s_im.hi);
    const f128 nu_re(ap.hi, __dadd_rn(ap.lo, p_re_lo));
    const f128 nv_re(am.hi, __dsub_rn(am.lo, p_re_lo));
    const f128 nu_im(bp.hi, __dadd_rn(bp.lo, p_im_lo));
    const f128 nv_im(bm.hi, __dsub_rn(bm.lo, p_im_lo));
#else
    const double p_re_lo = s_re.lo + (P.lo - Q.lo);
    const double p_im_lo = s_im.lo + (Q.lo + P.lo);
    const f128 ap = two_sum(u_re.hi, s_re.hi);
    const f128 am = two_diff(u_re.hi, s_re.hi);
    const f128 bp = two_sum(u_im.hi, s_im.hi);
    const f128 bm = two_diff(u_im.hi, s_im.hi);
    const f128 nu_re(ap.hi, ap.lo + p_re_lo);
    const f128 nv_re(am.hi, am.lo - p_re_lo);
    const f128 nu_im(bp.hi, bp.lo + p_im_lo);
    const f128 nv_im(bm.hi, bm.lo - p_im_lo);
#endif
    u_re = nu_re;
    u_im = nu_im;
    v_re = nv_re;
    v_im = nv_im;
  }

  // add_estimate / sub_estimate without the closing quick_two_sum, for the same
  // reason: the consumer only needs |lo| << |hi|.
  __host__ __device__ __forceinline__ static f128
  add_estimate_raw(const f128 &a, const f128 &b) {
    const f128 se = two_sum(a.hi, b.hi);
#ifdef __CUDA_ARCH__
    return f128(se.hi, __dadd_rn(se.lo, __dadd_rn(a.lo, b.lo)));
#else
    return f128(se.hi, se.lo + (a.lo + b.lo));
#endif
  }
  __host__ __device__ __forceinline__ static f128
  sub_estimate_raw(const f128 &a, const f128 &b) {
    const f128 se = two_diff(a.hi, b.hi);
#ifdef __CUDA_ARCH__
    return f128(se.hi, __dadd_rn(se.lo, __dsub_rn(a.lo, b.lo)));
#else
    return f128(se.hi, se.lo + (a.lo - b.lo));
#endif
  }

  // One inverse (Gentleman-Sande) butterfly in one pass: u <- u + v,
  // v <- (u - v) * tw. Same deferral, same 64 operations.
  __host__ __device__ __forceinline__ static void
  cplx_f128_relaxed_ibutterfly_assign(f128 &u_re, f128 &u_im, f128 &v_re,
                                      f128 &v_im, const f128 &tw_re,
                                      const f128 &tw_im) {
    f128 d_re = two_diff(u_re.hi, v_re.hi);
    f128 d_im = two_diff(u_im.hi, v_im.hi);
#ifdef __CUDA_ARCH__
    d_re.lo = __dadd_rn(d_re.lo, __dsub_rn(u_re.lo, v_re.lo));
    d_im.lo = __dadd_rn(d_im.lo, __dsub_rn(u_im.lo, v_im.lo));
#else
    d_re.lo = d_re.lo + (u_re.lo - v_re.lo);
    d_im.lo = d_im.lo + (u_im.lo - v_im.lo);
#endif
    const f128 nu_re = add_estimate_raw(u_re, v_re);
    const f128 nu_im = add_estimate_raw(u_im, v_im);
    const f128 rr = mul_raw(d_re, tw_re), ii = mul_raw(d_im, tw_im);
    const f128 ir = mul_raw(d_im, tw_re), ri = mul_raw(d_re, tw_im);
    v_re = sub_estimate_raw(rr, ii);
    v_im = add_estimate_raw(ir, ri);
    u_re = nu_re;
    u_im = nu_im;
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

  // Copy/move construction and assignment are left implicit. Declaring them
  // made f128x2 non-trivially-copyable, and the `if (this != &other)` guard is
  // redundant for a value type -- self-assigning a double is already a no-op.

  __host__ __device__ f128x2 conjugate() const {
    return f128x2(re, f128(-im.hi, -im.lo));
  }

  __host__ __device__ void zero() {
    re = f128(0.0, 0.0);
    im = f128(0.0, 0.0);
  }

  // The arithmetic operators below are the backward FFT's butterflies. They use
  // the *_estimate forms, which is the precision the forward FFT (through
  // cplx_f128_add_assign / cplx_f128_sub_assign) and the tfhe-fft CPU reference
  // already work at: the exact add/sub would only give the backward direction
  // an accuracy surplus the noise budget was never calibrated on.

  // Addition
  __host__ __device__ friend f128x2 operator+(const f128x2 &a,
                                              const f128x2 &b) {
    return f128x2(f128::add_estimate(a.re, b.re),
                  f128::add_estimate(a.im, b.im));
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
    f128 real_part =
        f128::sub_estimate(f128::mul(a.re, b.re), f128::mul(a.im, b.im));
    f128 imag_part =
        f128::add_estimate(f128::mul(a.im, b.re), f128::mul(a.re, b.im));
    return f128x2(real_part, imag_part);
  }

  // Addition-assignment operator
  __host__ __device__ f128x2 &operator+=(const f128x2 &other) {
    re = f128::add_estimate(re, other.re);
    im = f128::add_estimate(im, other.im);
    return *this;
  }

  // Subtraction-assignment operator
  __host__ __device__ f128x2 &operator-=(const f128x2 &other) {
    re = f128::sub_estimate(re, other.re);
    im = f128::sub_estimate(im, other.im);
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
// A gadget decomposition digit is a balanced residue in
// [-2^(base_log-1), 2^(base_log-1)], so for base_log <= 52 it fits an int64 and
// converts with a single signed cast -- no round-trip correction needed. The
// general converter below costs 149 instructions where these 14 suffice.
__host__ __device__ inline f128 small_signed_to_f128(__uint128_t x) {
  return f128(
      static_cast<double>(static_cast<int64_t>(static_cast<__int128_t>(x))),
      0.0);
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

__host__ __device__ inline __uint128_t u128_from_torus_f128(const f128 &in) {
  // f128_floor takes floor(hi) and only consults lo when hi is already
  // integral, so it REQUIRES a canonical pair: an un-normalized hi can floor to
  // the wrong integer, which after the 2^128 scaling below is a whole-unit
  // error. The The relaxed inverse transform leaves its outputs un-normalized,
  // so canonicalize here -- once per output element, against the three
  // operations per output per level that the deferral saves inside the
  // transform.
  const f128 a = f128::quick_two_sum(in.hi, in.lo);
  // MEASURED: the 5-op shortcut that replaced this general subtraction
  // (quick_two_sum(a.hi - fl.hi, a.lo - fl.lo)) was claimed bit-for-bit
  // identical. It is not -- it drops the rounding error two_diff would have
  // carried into the low limb, costing ~4.1 bits. That failed the
  // noise-squashing bound on BOTH PBS128 flavors, since this is reached from
  // add_to_torus_128 which the DEFAULT flavor uses too: measured variance
  // 1.47e-36 against an expectation of 7.0e-39, recovered to 5.02e-39 by
  // restoring sub_estimate.
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
