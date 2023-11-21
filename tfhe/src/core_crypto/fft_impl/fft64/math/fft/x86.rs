//! For documentation on the various intrinsics used here, refer to Intel's intrinsics guide.
//! <https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html>
//!
//! currently we dispatch based on the availability of
//!  - avx+avx2(advanced vector extensions for 256 intrinsics)+fma(fused multiply add for complex
//!  multiplication, usually comes with avx+avx2),
//!  - or the availability of avx512f[+avx512dq(doubleword/quadword intrinsics for conversion of f64
//! to/from i64. usually comes with avx512f on modern cpus)]
//!
//! more dispatch options may be added in the future

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::super::super::c64;
use super::TwistiesView;
use crate::core_crypto::commons::utils::izip;

use pulp::x86::V3;
#[cfg(feature = "nightly-avx512")]
use pulp::x86::V4;

/// Convert a vector of f64 values to a vector of i64 values.
/// See `f64_to_i64_bit_twiddles` in `fft/tests.rs` for the scalar version.
#[inline(always)]
pub fn mm256_cvtpd_epi64(simd: V3, x: __m256d) -> __m256i {
    let avx = simd.avx;
    let avx2 = simd.avx2;

    // reinterpret the bits as u64 values
    let bits = avx._mm256_castpd_si256(x);
    // mask that covers the first 52 bits
    let mantissa_mask = avx._mm256_set1_epi64x(0xFFFFFFFFFFFFF_u64 as i64);
    // mask that covers the 52nd bit
    let explicit_mantissa_bit = avx._mm256_set1_epi64x(0x10000000000000_u64 as i64);
    // mask that covers the first 11 bits
    let exp_mask = avx._mm256_set1_epi64x(0x7FF_u64 as i64);

    // extract the first 52 bits and add the implicit bit
    let mantissa = avx2._mm256_or_si256(
        avx2._mm256_and_si256(bits, mantissa_mask),
        explicit_mantissa_bit,
    );

    // extract the 52nd to 63rd (excluded) bits for the biased exponent
    let biased_exp = avx2._mm256_and_si256(avx2._mm256_srli_epi64::<52>(bits), exp_mask);

    // extract the 63rd sign bit
    let sign_is_negative_mask = avx2._mm256_sub_epi64(
        avx._mm256_setzero_si256(),
        avx2._mm256_srli_epi64::<63>(bits),
    );

    // we need to shift the mantissa by some value that may be negative, so we first shift it to
    // the left by the maximum amount, then shift it to the right by our value plus the offset we
    // just shifted by
    //
    // the 52nd bit is set to 1, so we shift to the left by 11 so the 63rd (last) bit is set.
    let mantissa_lshift = avx2._mm256_slli_epi64::<11>(mantissa);

    // shift to the right and apply the exponent bias
    // If biased_exp == 0 then we have 0 or a subnormal value which should return 0, here we will
    // shift to the right by 1086 which will return 0 as we are shifting in 0s from the left, so
    // subnormals are already covered
    let mantissa_shift = avx2._mm256_srlv_epi64(
        mantissa_lshift,
        avx2._mm256_sub_epi64(avx._mm256_set1_epi64x(1086), biased_exp),
    );

    // if the sign bit is unset, we keep our result
    let value_if_positive = mantissa_shift;
    // otherwise, we negate it
    let value_if_negative = avx2._mm256_sub_epi64(avx._mm256_setzero_si256(), value_if_positive);

    // if the biased exponent is all zeros, we have a subnormal value (or zero)

    // Select the value based on the sign mask
    avx2._mm256_blendv_epi8(value_if_positive, value_if_negative, sign_is_negative_mask)
}

/// Convert a vector of f64 values to a vector of i64 values.
/// This intrinsics is currently not available in rust, so we have our own implementation using
/// inline assembly.
///
/// The name matches Intel's convention (re-used by rust in their intrinsics) without the leading
/// `_`.
///
/// [`Intel's documentation`](`https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm512_cvtt_roundpd_epi64 `)
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub fn mm512_cvtt_roundpd_epi64(simd: V4, x: __m512d) -> __m512i {
    // This first one is required for the zmm_reg notation
    #[inline]
    #[target_feature(enable = "sse")]
    #[target_feature(enable = "sse2")]
    #[target_feature(enable = "fxsr")]
    #[target_feature(enable = "sse3")]
    #[target_feature(enable = "ssse3")]
    #[target_feature(enable = "sse4.1")]
    #[target_feature(enable = "sse4.2")]
    #[target_feature(enable = "popcnt")]
    #[target_feature(enable = "avx")]
    #[target_feature(enable = "avx2")]
    #[target_feature(enable = "bmi1")]
    #[target_feature(enable = "bmi2")]
    #[target_feature(enable = "fma")]
    #[target_feature(enable = "lzcnt")]
    #[target_feature(enable = "avx512f")]
    #[target_feature(enable = "avx512dq")]
    unsafe fn implementation(x: __m512d) -> __m512i {
        let mut as_i64x8: __m512i;

        // From Intel's documentation the syntax to use this intrinsics is
        // Instruction: vcvttpd2qq zmm, zmm
        // With Intel syntax, left operand is the destination, right operand is the source
        // For the asm! macro
        // in: indicates an input register
        // out: indicates an output register
        // zmm_reg: the avx512 register type
        // options: see https://doc.rust-lang.org/nightly/reference/inline-assembly.html#options
        // pure: no side effect
        // nomem: does not reference RAM (only registers)
        // nostrack: does not alter the state of the stack
        core::arch::asm!(
            "vcvttpd2qq {dst}, {src}",
            src = in(zmm_reg) x,
            dst = out(zmm_reg) as_i64x8,
            options(pure, nomem, nostack)
        );

        as_i64x8
    }
    let _ = simd.avx512dq;

    // SAFETY: simd contains an instance of avx512dq, that matches the target feature of
    // `implementation`
    unsafe { implementation(x) }
}

/// Convert a vector of i64 values to a vector of f64 values. Not sure how it works.
/// Ported from <https://stackoverflow.com/a/41148578>.
#[inline(always)]
pub fn mm256_cvtepi64_pd(simd: V3, x: __m256i) -> __m256d {
    let avx = simd.avx;
    let avx2 = simd.avx2;

    let mut x_hi = avx2._mm256_srai_epi32::<16>(x);
    x_hi = avx2._mm256_blend_epi16::<0x33>(x_hi, avx._mm256_setzero_si256());
    x_hi = avx2._mm256_add_epi64(
        x_hi,
        avx._mm256_castpd_si256(avx._mm256_set1_pd(442721857769029238784.0)), // 3*2^67
    );
    let x_lo = avx2._mm256_blend_epi16::<0x88>(
        x,
        avx._mm256_castpd_si256(avx._mm256_set1_pd(4503599627370496.0)),
    ); // 2^52

    let f = avx._mm256_sub_pd(
        avx._mm256_castsi256_pd(x_hi),
        avx._mm256_set1_pd(442726361368656609280.0), // 3*2^67 + 2^52
    );

    avx._mm256_add_pd(f, avx._mm256_castsi256_pd(x_lo))
}

/// Convert a vector of i64 values to a vector of f64 values.
/// This intrinsics is currently not available in rust, so we have our own implementation using
/// inline assembly.
///
/// The name matches Intel's convention (re-used by rust in their intrinsics) without the leading
/// `_`.
///
/// [`Intel's documentation`](`https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm512_cvtepi64_pd`)
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub fn mm512_cvtepi64_pd(simd: V4, x: __m512i) -> __m512d {
    // This first one is required for the zmm_reg notation
    #[inline]
    #[target_feature(enable = "sse")]
    #[target_feature(enable = "sse2")]
    #[target_feature(enable = "fxsr")]
    #[target_feature(enable = "sse3")]
    #[target_feature(enable = "ssse3")]
    #[target_feature(enable = "sse4.1")]
    #[target_feature(enable = "sse4.2")]
    #[target_feature(enable = "popcnt")]
    #[target_feature(enable = "avx")]
    #[target_feature(enable = "avx2")]
    #[target_feature(enable = "bmi1")]
    #[target_feature(enable = "bmi2")]
    #[target_feature(enable = "fma")]
    #[target_feature(enable = "lzcnt")]
    #[target_feature(enable = "avx512f")]
    #[target_feature(enable = "avx512dq")]
    unsafe fn implementation(x: __m512i) -> __m512d {
        let mut as_f64x8: __m512d;

        // From Intel's documentation the syntax to use this intrinsics is
        // Instruction: vcvtqq2pd zmm, zmm
        // With Intel syntax, left operand is the destination, right operand is the source
        // For the asm! macro
        // in: indicates an input register
        // out: indicates an output register
        // zmm_reg: the avx512 register type
        // options: see https://doc.rust-lang.org/nightly/reference/inline-assembly.html#options
        // pure: no side effect
        // nomem: does not reference RAM (only registers)
        // nostrack: does not alter the state of the stack
        core::arch::asm!(
            "vcvtqq2pd {dst}, {src}",
            src = in(zmm_reg) x,
            dst = out(zmm_reg) as_f64x8,
            options(pure, nomem, nostack)
        );

        as_f64x8
    }
    let _ = simd.avx512dq;

    // SAFETY: simd contains an instance of avx512dq, that matches the target feature of
    // `implementation`
    unsafe { implementation(x) }
}

#[cfg(feature = "nightly-avx512")]
pub fn convert_forward_integer_u32_v4(
    simd: V4,
    out: &mut [c64],
    in_re: &[u32],
    in_im: &[u32],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V4,
        out: &'a mut [c64],
        in_re: &'a [u32],
        in_im: &'a [u32],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out,
                in_re,
                in_im,
                twisties,
            } = self;

            let avx = simd.avx512f;

            let n = out.len();
            debug_assert_eq!(n % 8, 0);
            debug_assert_eq!(n, out.len());
            debug_assert_eq!(n, in_re.len());
            debug_assert_eq!(n, in_im.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let out = pulp::as_arrays_mut::<8, _>(out).0;
            let in_re = pulp::as_arrays::<8, _>(in_re).0;
            let in_im = pulp::as_arrays::<8, _>(in_im).0;
            let w_re = pulp::as_arrays::<8, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<8, _>(twisties.im).0;

            for (out, &in_re, &in_im, &w_re, &w_im) in izip!(out, in_re, in_im, w_re, w_im) {
                let in_re = pulp::cast(in_re);
                let in_im = pulp::cast(in_im);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                // convert to f64
                let in_re = avx._mm512_cvtepi32_pd(in_re);
                // convert to f64
                let in_im = avx._mm512_cvtepi32_pd(in_im);

                // perform complex multiplication
                let out_re = avx._mm512_fmsub_pd(in_re, w_re, avx._mm512_mul_pd(in_im, w_im));
                let out_im = avx._mm512_fmadd_pd(in_re, w_im, avx._mm512_mul_pd(in_im, w_re));

                // we have
                // x0 x1 x2 x3 x4 x5 x6 x7
                // y0 y1 y2 y3 y4 y5 y6 y7
                //
                // we want
                // x0 y0 x1 y1 x2 y2 x3 y3
                // x4 y4 x5 y5 x6 y6 x7 y7

                // interleave real part and imaginary part
                let idx0 = avx._mm512_setr_epi64(
                    0b0000, 0b1000, 0b0001, 0b1001, 0b0010, 0b1010, 0b0011, 0b1011,
                );
                let idx1 = avx._mm512_setr_epi64(
                    0b0100, 0b1100, 0b0101, 0b1101, 0b0110, 0b1110, 0b0111, 0b1111,
                );

                let out0 = avx._mm512_permutex2var_pd(out_re, idx0, out_im);
                let out1 = avx._mm512_permutex2var_pd(out_re, idx1, out_im);

                *out = pulp::cast([out0, out1]);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out,
        in_re,
        in_im,
        twisties,
    });
}

#[cfg(feature = "nightly-avx512")]
pub fn convert_forward_integer_u64_v4(
    simd: V4,
    out: &mut [c64],
    in_re: &[u64],
    in_im: &[u64],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V4,
        out: &'a mut [c64],
        in_re: &'a [u64],
        in_im: &'a [u64],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out,
                in_re,
                in_im,
                twisties,
            } = self;
            let avx = simd.avx512f;

            let n = out.len();
            debug_assert_eq!(n % 8, 0);
            debug_assert_eq!(n, out.len());
            debug_assert_eq!(n, in_re.len());
            debug_assert_eq!(n, in_im.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let out = pulp::as_arrays_mut::<8, _>(out).0;
            let in_re = pulp::as_arrays::<8, _>(in_re).0;
            let in_im = pulp::as_arrays::<8, _>(in_im).0;
            let w_re = pulp::as_arrays::<8, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<8, _>(twisties.im).0;

            for (out, &in_re, &in_im, &w_re, &w_im) in izip!(out, in_re, in_im, w_re, w_im) {
                let in_re = pulp::cast(in_re);
                let in_im = pulp::cast(in_im);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                // load i64 values and convert to f64
                let in_re = mm512_cvtepi64_pd(simd, in_re);
                // load i64 values and convert to f64
                let in_im = mm512_cvtepi64_pd(simd, in_im);

                // perform complex multiplication
                let out_re = avx._mm512_fmsub_pd(in_re, w_re, avx._mm512_mul_pd(in_im, w_im));
                let out_im = avx._mm512_fmadd_pd(in_re, w_im, avx._mm512_mul_pd(in_im, w_re));

                // we have
                // x0 x1 x2 x3 x4 x5 x6 x7
                // y0 y1 y2 y3 y4 y5 y6 y7
                //
                // we want
                // x0 y0 x1 y1 x2 y2 x3 y3
                // x4 y4 x5 y5 x6 y6 x7 y7

                // interleave real part and imaginary part
                let idx0 = avx._mm512_setr_epi64(
                    0b0000, 0b1000, 0b0001, 0b1001, 0b0010, 0b1010, 0b0011, 0b1011,
                );
                let idx1 = avx._mm512_setr_epi64(
                    0b0100, 0b1100, 0b0101, 0b1101, 0b0110, 0b1110, 0b0111, 0b1111,
                );

                let out0 = avx._mm512_permutex2var_pd(out_re, idx0, out_im);
                let out1 = avx._mm512_permutex2var_pd(out_re, idx1, out_im);

                *out = pulp::cast([out0, out1]);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out,
        in_re,
        in_im,
        twisties,
    });
}

pub fn convert_forward_integer_u32_v3(
    simd: V3,
    out: &mut [c64],
    in_re: &[u32],
    in_im: &[u32],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V3,
        out: &'a mut [c64],
        in_re: &'a [u32],
        in_im: &'a [u32],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out,
                in_re,
                in_im,
                twisties,
            } = self;

            let avx = simd.avx;
            let fma = simd.fma;

            let n = out.len();
            debug_assert_eq!(n % 4, 0);
            debug_assert_eq!(n, out.len());
            debug_assert_eq!(n, in_re.len());
            debug_assert_eq!(n, in_im.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let out = pulp::as_arrays_mut::<4, _>(out).0;
            let in_re = pulp::as_arrays::<4, _>(in_re).0;
            let in_im = pulp::as_arrays::<4, _>(in_im).0;
            let w_re = pulp::as_arrays::<4, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<4, _>(twisties.im).0;

            for (out, &in_re, &in_im, &w_re, &w_im) in izip!(out, in_re, in_im, w_re, w_im) {
                let in_re = pulp::cast(in_re);
                let in_im = pulp::cast(in_im);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                // load i32 values and convert to f64
                let in_re = avx._mm256_cvtepi32_pd(in_re);
                // load i32 values and convert to f64
                let in_im = avx._mm256_cvtepi32_pd(in_im);

                // perform complex multiplication
                let out_re = fma._mm256_fmsub_pd(in_re, w_re, avx._mm256_mul_pd(in_im, w_im));
                let out_im = fma._mm256_fmadd_pd(in_re, w_im, avx._mm256_mul_pd(in_im, w_re));

                // we have
                // x0 x1 x2 x3
                // y0 y1 y2 y3
                //
                // we want
                // x0 y0 x1 y1
                // x2 y2 x3 y3

                // interleave real part and imaginary part

                // unpacklo/unpackhi
                // x0 y0 x2 y2
                // x1 y1 x3 y3
                let lo = avx._mm256_unpacklo_pd(out_re, out_im);
                let hi = avx._mm256_unpackhi_pd(out_re, out_im);

                let out0 = avx._mm256_permute2f128_pd::<0b00100000>(lo, hi);
                let out1 = avx._mm256_permute2f128_pd::<0b00110001>(lo, hi);

                *out = pulp::cast([out0, out1]);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out,
        in_re,
        in_im,
        twisties,
    });
}

pub fn convert_forward_integer_u64_avx2_v3(
    simd: V3,
    out: &mut [c64],
    in_re: &[u64],
    in_im: &[u64],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V3,
        out: &'a mut [c64],
        in_re: &'a [u64],
        in_im: &'a [u64],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out,
                in_re,
                in_im,
                twisties,
            } = self;

            let avx = simd.avx;
            let fma = simd.fma;

            let n = out.len();
            debug_assert_eq!(n % 4, 0);
            debug_assert_eq!(n, out.len());
            debug_assert_eq!(n, in_re.len());
            debug_assert_eq!(n, in_im.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let out = pulp::as_arrays_mut::<4, _>(out).0;
            let in_re = pulp::as_arrays::<4, _>(in_re).0;
            let in_im = pulp::as_arrays::<4, _>(in_im).0;
            let w_re = pulp::as_arrays::<4, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<4, _>(twisties.im).0;

            for (out, &in_re, &in_im, &w_re, &w_im) in izip!(out, in_re, in_im, w_re, w_im) {
                let in_re = pulp::cast(in_re);
                let in_im = pulp::cast(in_im);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                // convert to f64
                let in_re = mm256_cvtepi64_pd(simd, in_re);
                // convert to f64
                let in_im = mm256_cvtepi64_pd(simd, in_im);

                // perform complex multiplication
                let out_re = fma._mm256_fmsub_pd(in_re, w_re, avx._mm256_mul_pd(in_im, w_im));
                let out_im = fma._mm256_fmadd_pd(in_re, w_im, avx._mm256_mul_pd(in_im, w_re));

                // we have
                // x0 x1 x2 x3
                // y0 y1 y2 y3
                //
                // we want
                // x0 y0 x1 y1
                // x2 y2 x3 y3

                // interleave real part and imaginary part

                // unpacklo/unpackhi
                // x0 y0 x2 y2
                // x1 y1 x3 y3
                let lo = avx._mm256_unpacklo_pd(out_re, out_im);
                let hi = avx._mm256_unpackhi_pd(out_re, out_im);

                let out0 = avx._mm256_permute2f128_pd::<0b00100000>(lo, hi);
                let out1 = avx._mm256_permute2f128_pd::<0b00110001>(lo, hi);

                *out = pulp::cast([out0, out1]);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out,
        in_re,
        in_im,
        twisties,
    });
}

/// Perform common work for `u32` and `u64`, used by the backward torus transformation.
///
/// This deinterleaves two vectors of c64 values into two vectors of real part and imaginary part,
/// then rounds to the nearest integer.
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub fn prologue_convert_torus_v4(
    simd: V4,
    normalization: __m512d,
    w_re: __m512d,
    w_im: __m512d,
    // re0 im0 re1 im1 re2 im2 re3 im3
    inp0: __m512d,
    // re4 im4 re5 im5 re6 im6 re7 im7
    inp1: __m512d,
    scaling: __m512d,
) -> (__m512d, __m512d) {
    let avx = simd.avx512f;
    let w_re = avx._mm512_mul_pd(normalization, w_re);
    let w_im = avx._mm512_mul_pd(normalization, w_im);

    // real indices
    let idx0 = avx._mm512_setr_epi64(
        0b0000, 0b0010, 0b0100, 0b0110, 0b1000, 0b1010, 0b1100, 0b1110,
    );
    // imaginary indices
    let idx1 = avx._mm512_setr_epi64(
        0b0001, 0b0011, 0b0101, 0b0111, 0b1001, 0b1011, 0b1101, 0b1111,
    );

    // re0 re1 re2 re3 re4 re5 re6 re7
    let inp_re = avx._mm512_permutex2var_pd(inp0, idx0, inp1);
    // im0 im1 im2 im3 im4 im5 im6 im7
    let inp_im = avx._mm512_permutex2var_pd(inp0, idx1, inp1);

    // perform complex multiplication with conj(w)
    let mul_re = avx._mm512_fmadd_pd(inp_re, w_re, avx._mm512_mul_pd(inp_im, w_im));
    let mul_im = avx._mm512_fnmadd_pd(inp_re, w_im, avx._mm512_mul_pd(inp_im, w_re));

    // round to nearest integer and suppress exceptions
    const ROUNDING: i32 = _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC;

    // get the fractional part (centered around zero) by subtracting rounded value
    let fract_re = avx._mm512_sub_pd(mul_re, avx._mm512_roundscale_pd::<ROUNDING>(mul_re));
    let fract_im = avx._mm512_sub_pd(mul_im, avx._mm512_roundscale_pd::<ROUNDING>(mul_im));
    // scale fractional part and round
    let fract_re = avx._mm512_roundscale_pd::<ROUNDING>(avx._mm512_mul_pd(scaling, fract_re));
    let fract_im = avx._mm512_roundscale_pd::<ROUNDING>(avx._mm512_mul_pd(scaling, fract_im));

    (fract_re, fract_im)
}

/// See [`convert_add_backward_torus`].
#[cfg(feature = "nightly-avx512")]
pub fn convert_add_backward_torus_u32_v4(
    simd: V4,
    out_re: &mut [u32],
    out_im: &mut [u32],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V4,
        out_re: &'a mut [u32],
        out_im: &'a mut [u32],
        inp: &'a [c64],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re,
                out_im,
                inp,
                twisties,
            } = self;
            let avx512f = simd.avx512f;
            let avx2 = simd.avx2;

            let n = out_re.len();
            debug_assert_eq!(n % 8, 0);
            debug_assert_eq!(n, out_re.len());
            debug_assert_eq!(n, out_im.len());
            debug_assert_eq!(n, inp.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let normalization = avx512f._mm512_set1_pd(1.0 / n as f64);
            let scaling = avx512f._mm512_set1_pd(2.0_f64.powi(u32::BITS as i32));
            let out_re = pulp::as_arrays_mut::<8, _>(out_re).0;
            let out_im = pulp::as_arrays_mut::<8, _>(out_im).0;
            let inp = pulp::as_arrays::<8, _>(inp).0;
            let w_re = pulp::as_arrays::<8, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<8, _>(twisties.im).0;

            for (out_re, out_im, &inp, &w_re, &w_im) in izip!(out_re, out_im, inp, w_re, w_im) {
                let inp = pulp::cast::<_, [__m512d; 2]>(inp);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                let (fract_re, fract_im) = prologue_convert_torus_v4(
                    simd,
                    normalization,
                    w_re,
                    w_im,
                    inp[0],
                    inp[1],
                    scaling,
                );

                // convert f64 to i32
                let fract_re = avx512f._mm512_cvtpd_epi32(fract_re);
                // convert f64 to i32
                let fract_im = avx512f._mm512_cvtpd_epi32(fract_im);

                // add to input and store
                *out_re = pulp::cast(avx2._mm256_add_epi32(fract_re, pulp::cast(*out_re)));
                *out_im = pulp::cast(avx2._mm256_add_epi32(fract_im, pulp::cast(*out_im)));
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out_re,
        out_im,
        inp,
        twisties,
    })
}

/// See [`convert_add_backward_torus`].
#[cfg(feature = "nightly-avx512")]
pub fn convert_add_backward_torus_u64_v4(
    simd: V4,
    out_re: &mut [u64],
    out_im: &mut [u64],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V4,
        out_re: &'a mut [u64],
        out_im: &'a mut [u64],
        inp: &'a [c64],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re,
                out_im,
                inp,
                twisties,
            } = self;
            let avx512f = simd.avx512f;

            let n = out_re.len();
            debug_assert_eq!(n % 8, 0);
            debug_assert_eq!(n, out_re.len());
            debug_assert_eq!(n, out_im.len());
            debug_assert_eq!(n, inp.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let normalization = avx512f._mm512_set1_pd(1.0 / n as f64);
            let scaling = avx512f._mm512_set1_pd(2.0_f64.powi(u64::BITS as i32));
            let out_re = pulp::as_arrays_mut::<8, _>(out_re).0;
            let out_im = pulp::as_arrays_mut::<8, _>(out_im).0;
            let inp = pulp::as_arrays::<8, _>(inp).0;
            let w_re = pulp::as_arrays::<8, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<8, _>(twisties.im).0;

            for (out_re, out_im, &inp, &w_re, &w_im) in izip!(out_re, out_im, inp, w_re, w_im) {
                let inp = pulp::cast::<_, [__m512d; 2]>(inp);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                let (fract_re, fract_im) = prologue_convert_torus_v4(
                    simd,
                    normalization,
                    w_re,
                    w_im,
                    inp[0],
                    inp[1],
                    scaling,
                );

                // convert f64 to i64
                let fract_re = mm512_cvtt_roundpd_epi64(simd, fract_re);
                // convert f64 to i64
                let fract_im = mm512_cvtt_roundpd_epi64(simd, fract_im);

                // add to input and store
                *out_re = pulp::cast(avx512f._mm512_add_epi64(fract_re, pulp::cast(*out_re)));
                *out_im = pulp::cast(avx512f._mm512_add_epi64(fract_im, pulp::cast(*out_im)));
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out_re,
        out_im,
        inp,
        twisties,
    })
}

/// Perform common work for `u32` and `u64`, used by the backward torus transformation.
///
/// This deinterleaves two vectors of c64 values into two vectors of real part and imaginary part,
/// then rounds to the nearest integer.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn prologue_convert_torus_v3(
    simd: V3,
    normalization: __m256d,
    w_re: __m256d,
    w_im: __m256d,
    // re0 im0
    inp0: __m128d,
    // re1 im1
    inp1: __m128d,
    // re2 im2
    inp2: __m128d,
    // re3 im3
    inp3: __m128d,
    scaling: __m256d,
) -> (__m256d, __m256d) {
    let avx = simd.avx;
    let fma = simd.fma;
    let sse2 = simd.sse2;

    let w_re = avx._mm256_mul_pd(normalization, w_re);
    let w_im = avx._mm256_mul_pd(normalization, w_im);

    // re0 re1
    let inp_re01 = sse2._mm_unpacklo_pd(inp0, inp1);
    // im0 im1
    let inp_im01 = sse2._mm_unpackhi_pd(inp0, inp1);
    // re2 re3
    let inp_re23 = sse2._mm_unpacklo_pd(inp2, inp3);
    // im2 im3
    let inp_im23 = sse2._mm_unpackhi_pd(inp2, inp3);

    // re0 re1 re2 re3
    let inp_re = avx._mm256_insertf128_pd::<0b1>(avx._mm256_castpd128_pd256(inp_re01), inp_re23);
    // im0 im1 im2 im3
    let inp_im = avx._mm256_insertf128_pd::<0b1>(avx._mm256_castpd128_pd256(inp_im01), inp_im23);

    // perform complex multiplication with conj(w)
    let mul_re = fma._mm256_fmadd_pd(inp_re, w_re, avx._mm256_mul_pd(inp_im, w_im));
    let mul_im = fma._mm256_fnmadd_pd(inp_re, w_im, avx._mm256_mul_pd(inp_im, w_re));

    // round to nearest integer and suppress exceptions
    const ROUNDING: i32 = _MM_FROUND_NINT | _MM_FROUND_NO_EXC;

    // get the fractional part (centered around zero) by subtracting rounded value
    let fract_re = avx._mm256_sub_pd(mul_re, avx._mm256_round_pd::<ROUNDING>(mul_re));
    let fract_im = avx._mm256_sub_pd(mul_im, avx._mm256_round_pd::<ROUNDING>(mul_im));
    // scale fractional part and round
    let fract_re = avx._mm256_round_pd::<ROUNDING>(avx._mm256_mul_pd(scaling, fract_re));
    let fract_im = avx._mm256_round_pd::<ROUNDING>(avx._mm256_mul_pd(scaling, fract_im));

    (fract_re, fract_im)
}

/// See [`convert_add_backward_torus`].
pub fn convert_add_backward_torus_u32_v3(
    simd: V3,
    out_re: &mut [u32],
    out_im: &mut [u32],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V3,
        out_re: &'a mut [u32],
        out_im: &'a mut [u32],
        inp: &'a [c64],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re,
                out_im,
                inp,
                twisties,
            } = self;
            let avx = simd.avx;
            let sse2 = simd.sse2;

            let n = out_re.len();
            debug_assert_eq!(n % 4, 0);
            debug_assert_eq!(n, out_re.len());
            debug_assert_eq!(n, out_im.len());
            debug_assert_eq!(n, inp.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let normalization = avx._mm256_set1_pd(1.0 / n as f64);
            let scaling = avx._mm256_set1_pd(2.0_f64.powi(u32::BITS as i32));
            let out_re = pulp::as_arrays_mut::<4, _>(out_re).0;
            let out_im = pulp::as_arrays_mut::<4, _>(out_im).0;
            let inp = pulp::as_arrays::<4, _>(inp).0;
            let w_re = pulp::as_arrays::<4, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<4, _>(twisties.im).0;

            for (out_re, out_im, &inp, &w_re, &w_im) in izip!(out_re, out_im, inp, w_re, w_im) {
                let inp = pulp::cast::<_, [__m128d; 4]>(inp);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                let (fract_re, fract_im) = prologue_convert_torus_v3(
                    simd,
                    normalization,
                    w_re,
                    w_im,
                    inp[0],
                    inp[1],
                    inp[2],
                    inp[3],
                    scaling,
                );

                // convert f64 to i32
                let fract_re = avx._mm256_cvtpd_epi32(fract_re);
                // convert f64 to i32
                let fract_im = avx._mm256_cvtpd_epi32(fract_im);

                // add to input and store
                *out_re = pulp::cast(sse2._mm_add_epi32(fract_re, pulp::cast(*out_re)));
                *out_im = pulp::cast(sse2._mm_add_epi32(fract_im, pulp::cast(*out_im)));
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out_re,
        out_im,
        inp,
        twisties,
    });
}

pub fn convert_add_backward_torus_u64_v3(
    simd: V3,
    out_re: &mut [u64],
    out_im: &mut [u64],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    struct Impl<'a> {
        simd: V3,
        out_re: &'a mut [u64],
        out_im: &'a mut [u64],
        inp: &'a [c64],
        twisties: TwistiesView<'a>,
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re,
                out_im,
                inp,
                twisties,
            } = self;

            let avx = simd.avx;
            let avx2 = simd.avx2;

            let n = out_re.len();
            debug_assert_eq!(n % 4, 0);
            debug_assert_eq!(n, out_re.len());
            debug_assert_eq!(n, out_im.len());
            debug_assert_eq!(n, inp.len());
            debug_assert_eq!(n, twisties.re.len());
            debug_assert_eq!(n, twisties.im.len());

            let normalization = avx._mm256_set1_pd(1.0 / n as f64);
            let scaling = avx._mm256_set1_pd(2.0_f64.powi(u64::BITS as i32));
            let out_re = pulp::as_arrays_mut::<4, _>(out_re).0;
            let out_im = pulp::as_arrays_mut::<4, _>(out_im).0;
            let inp = pulp::as_arrays::<4, _>(inp).0;
            let w_re = pulp::as_arrays::<4, _>(twisties.re).0;
            let w_im = pulp::as_arrays::<4, _>(twisties.im).0;

            for (out_re, out_im, &inp, &w_re, &w_im) in izip!(out_re, out_im, inp, w_re, w_im) {
                let inp = pulp::cast::<_, [__m128d; 4]>(inp);
                let w_re = pulp::cast(w_re);
                let w_im = pulp::cast(w_im);

                let (fract_re, fract_im) = prologue_convert_torus_v3(
                    simd,
                    normalization,
                    w_re,
                    w_im,
                    inp[0],
                    inp[1],
                    inp[2],
                    inp[3],
                    scaling,
                );

                // convert f64 to i64
                let fract_re = mm256_cvtpd_epi64(simd, fract_re);
                // convert f64 to i64
                let fract_im = mm256_cvtpd_epi64(simd, fract_im);

                // add to input and store
                *out_re = pulp::cast(avx2._mm256_add_epi64(fract_re, pulp::cast(*out_re)));
                *out_im = pulp::cast(avx2._mm256_add_epi64(fract_im, pulp::cast(*out_im)));
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out_re,
        out_im,
        inp,
        twisties,
    });
}

pub fn convert_forward_integer_u32(
    out: &mut [c64],
    in_re: &[u32],
    in_im: &[u32],
    twisties: TwistiesView<'_>,
) {
    #[cfg(feature = "nightly-avx512")]
    if let Some(simd) = V4::try_new() {
        return convert_forward_integer_u32_v4(simd, out, in_re, in_im, twisties);
    }
    if let Some(simd) = V3::try_new() {
        return convert_forward_integer_u32_v3(simd, out, in_re, in_im, twisties);
    }
    super::convert_forward_integer_scalar::<u32>(out, in_re, in_im, twisties);
}

pub fn convert_forward_integer_u64(
    out: &mut [c64],
    in_re: &[u64],
    in_im: &[u64],
    twisties: TwistiesView<'_>,
) {
    #[cfg(feature = "nightly-avx512")]
    if let Some(simd) = V4::try_new() {
        return convert_forward_integer_u64_v4(simd, out, in_re, in_im, twisties);
    }
    if let Some(simd) = V3::try_new() {
        return convert_forward_integer_u64_avx2_v3(simd, out, in_re, in_im, twisties);
    }
    super::convert_forward_integer_scalar::<u64>(out, in_re, in_im, twisties);
}

pub fn convert_add_backward_torus_u32(
    out_re: &mut [u32],
    out_im: &mut [u32],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    #[cfg(feature = "nightly-avx512")]
    if let Some(simd) = V4::try_new() {
        return convert_add_backward_torus_u32_v4(simd, out_re, out_im, inp, twisties);
    }
    if let Some(simd) = V3::try_new() {
        return convert_add_backward_torus_u32_v3(simd, out_re, out_im, inp, twisties);
    }
    super::convert_add_backward_torus_scalar::<u32>(out_re, out_im, inp, twisties);
}

pub fn convert_add_backward_torus_u64(
    out_re: &mut [u64],
    out_im: &mut [u64],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    #[cfg(feature = "nightly-avx512")]
    if let Some(simd) = V4::try_new() {
        return convert_add_backward_torus_u64_v4(simd, out_re, out_im, inp, twisties);
    }
    if let Some(simd) = V3::try_new() {
        return convert_add_backward_torus_u64_v3(simd, out_re, out_im, inp, twisties);
    }
    super::convert_add_backward_torus_scalar::<u64>(out_re, out_im, inp, twisties);
}

#[cfg(test)]
mod tests {
    use crate::core_crypto::fft_impl::fft64::math::fft::{
        convert_add_backward_torus_scalar, Twisties,
    };

    use super::*;

    #[test]
    fn convert_f64_i64() {
        if let Some(simd) = V3::try_new() {
            for v in [
                [
                    -(2.0_f64.powi(63)),
                    -(2.0_f64.powi(63)),
                    (2.0_f64.powi(63)),
                    (2.0_f64.powi(63)),
                ],
                [0.0, -0.0, 37.1242161_f64, -37.1242161_f64],
                [0.1, -0.1, 1.0, -1.0],
                [0.9, -0.9, 2.0, -2.0],
                [2.0, -2.0, 1e-310, -1e-310],
                [
                    2.0_f64.powi(62),
                    -(2.0_f64.powi(62)),
                    1.1 * 2.0_f64.powi(62),
                    1.1 * -(2.0_f64.powi(62)),
                ],
                [
                    0.9 * 2.0_f64.powi(63),
                    -(0.9 * 2.0_f64.powi(63)),
                    0.1 * 2.0_f64.powi(63),
                    0.1 * -(2.0_f64.powi(63)),
                ],
            ] {
                let target = v.map(|x| {
                    if x == 2.0f64.powi(63) {
                        // This is the proper representation in 2's complement, 2^63 gets folded
                        // onto -2^63
                        -(2i64.pow(63))
                    } else {
                        x as i64
                    }
                });

                let computed: [i64; 4] = pulp::cast(mm256_cvtpd_epi64(simd, pulp::cast(v)));
                assert_eq!(target, computed);
            }
        }
        #[cfg(feature = "nightly-avx512")]
        if let Some(simd) = V4::try_new() {
            for v in [
                [
                    -(2.0_f64.powi(63)),
                    -(2.0_f64.powi(63)),
                    (2.0_f64.powi(63)),
                    (2.0_f64.powi(63)),
                ],
                [0.0, -0.0, 37.1242161_f64, -37.1242161_f64],
                [0.1, -0.1, 1.0, -1.0],
                [0.9, -0.9, 2.0, -2.0],
                [2.0, -2.0, 1e-310, -1e-310],
                [
                    2.0_f64.powi(62),
                    -(2.0_f64.powi(62)),
                    1.1 * 2.0_f64.powi(62),
                    1.1 * -(2.0_f64.powi(62)),
                ],
                [
                    0.9 * 2.0_f64.powi(63),
                    -(0.9 * 2.0_f64.powi(63)),
                    0.1 * 2.0_f64.powi(63),
                    0.1 * -(2.0_f64.powi(63)),
                ],
            ] {
                let target = v.map(|x| {
                    if x == 2.0f64.powi(63) {
                        // This is the proper representation in 2's complement, 2^63 gets folded
                        // onto -2^63
                        -(2i64.pow(63))
                    } else {
                        x as i64
                    }
                });

                let computed: [i64; 4] =
                    pulp::cast_lossy(mm512_cvtt_roundpd_epi64(simd, pulp::cast([v, v])));
                assert_eq!(target, computed);
            }
        }
    }

    #[test]
    fn add_backward_torus_v3() {
        if let Some(simd) = V3::try_new() {
            let n = 1024;
            let z = c64 {
                re: -34384521907.303154,
                im: 19013399110.689323,
            };
            let input = vec![z; n];
            let mut out_fma_re = vec![0_u64; n];
            let mut out_fma_im = vec![0_u64; n];
            let mut out_scalar_re = vec![0_u64; n];
            let mut out_scalar_im = vec![0_u64; n];
            let twisties = Twisties::new(n);

            convert_add_backward_torus_u64_v3(
                simd,
                &mut out_fma_re,
                &mut out_fma_im,
                &input,
                twisties.as_view(),
            );

            convert_add_backward_torus_scalar(
                &mut out_scalar_re,
                &mut out_scalar_im,
                &input,
                twisties.as_view(),
            );

            for i in 0..n {
                assert!(out_fma_re[i].abs_diff(out_scalar_re[i]) < (1 << 38));
                assert!(out_fma_im[i].abs_diff(out_scalar_im[i]) < (1 << 38));
            }
        }
    }

    #[cfg(feature = "nightly-avx512")]
    #[test]
    fn add_backward_torus_v4() {
        if let Some(simd) = V4::try_new() {
            let n = 1024;
            let z = c64 {
                re: -34384521907.303154,
                im: 19013399110.689323,
            };
            let input = vec![z; n];
            let mut out_avx_re = vec![0_u64; n];
            let mut out_avx_im = vec![0_u64; n];
            let mut out_scalar_re = vec![0_u64; n];
            let mut out_scalar_im = vec![0_u64; n];
            let twisties = Twisties::new(n);

            convert_add_backward_torus_u64_v4(
                simd,
                &mut out_avx_re,
                &mut out_avx_im,
                &input,
                twisties.as_view(),
            );

            convert_add_backward_torus_scalar(
                &mut out_scalar_re,
                &mut out_scalar_im,
                &input,
                twisties.as_view(),
            );

            for i in 0..n {
                assert!(out_avx_re[i].abs_diff(out_scalar_re[i]) < (1 << 38));
                assert!(out_avx_im[i].abs_diff(out_scalar_im[i]) < (1 << 38));
            }
        }
    }
}
