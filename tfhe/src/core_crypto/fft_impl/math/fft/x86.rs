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
use std::mem::MaybeUninit;

/// Converts a vector of f64 values to a vector of i64 values.
/// See `f64_to_i64_bit_twiddles` in `fft/tests.rs` for the scalar version.
///
/// # Safety
///
///  - `is_x86_feature_detected!("avx2")` must be true.
#[inline(always)]
pub unsafe fn mm256_cvtpd_epi64(x: __m256d) -> __m256i {
    // reinterpret the bits as u64 values
    let bits = _mm256_castpd_si256(x);
    // mask that covers the first 52 bits
    let mantissa_mask = _mm256_set1_epi64x(0xFFFFFFFFFFFFF_u64 as i64);
    // mask that covers the 52nd bit
    let explicit_mantissa_bit = _mm256_set1_epi64x(0x10000000000000_u64 as i64);
    // mask that covers the first 11 bits
    let exp_mask = _mm256_set1_epi64x(0x7FF_u64 as i64);

    // extract the first 52 bits and add the implicit bit
    let mantissa = _mm256_or_si256(_mm256_and_si256(bits, mantissa_mask), explicit_mantissa_bit);

    // extract the 52nd to 63rd (excluded) bits for the biased exponent
    let biased_exp = _mm256_and_si256(_mm256_srli_epi64::<52>(bits), exp_mask);

    // extract the 63rd sign bit
    let sign_is_negative_mask =
        _mm256_sub_epi64(_mm256_setzero_si256(), _mm256_srli_epi64::<63>(bits));

    // we need to shift the mantissa by some value that may be negative, so we first shift it to
    // the left by the maximum amount, then shift it to the right by our value plus the offset we
    // just shifted by
    //
    // the 52nd bit is set to 1, so we shift to the left by 11 so the 63rd (last) bit is set.
    let mantissa_lshift = _mm256_slli_epi64::<11>(mantissa);

    // shift to the right and apply the exponent bias
    let mantissa_shift = _mm256_srlv_epi64(
        mantissa_lshift,
        _mm256_sub_epi64(_mm256_set1_epi64x(1086), biased_exp),
    );

    // if the sign bit is unset, we keep our result
    let value_if_positive = mantissa_shift;
    // otherwise, we negate it
    let value_if_negative = _mm256_sub_epi64(_mm256_setzero_si256(), value_if_positive);

    // if the biased exponent is all zeros, we have a subnormal value (or zero)

    // if it is not subnormal, we keep our results
    let value_if_non_subnormal =
        _mm256_blendv_epi8(value_if_positive, value_if_negative, sign_is_negative_mask);

    // if it is subnormal, the conversion to i64 (rounding towards zero) returns zero
    let value_if_subnormal = _mm256_setzero_si256();

    // compare the biased exponent to a zero value
    let is_subnormal = _mm256_cmpeq_epi64(biased_exp, _mm256_setzero_si256());

    // choose the result depending on subnormalness
    _mm256_blendv_epi8(value_if_non_subnormal, value_if_subnormal, is_subnormal)
}

/// Converts a vector of f64 values to a vector of i64 values.
/// See `f64_to_i64_bit_twiddles` in `fft/tests.rs` for the scalar version.
///
/// # Safety
///
///  - `is_x86_feature_detected!("avx2")` must be true.
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub unsafe fn mm512_cvtpd_epi64(x: __m512d) -> __m512i {
    // reinterpret the bits as u64 values
    let bits = _mm512_castpd_si512(x);
    // mask that covers the first 52 bits
    let mantissa_mask = _mm512_set1_epi64(0xFFFFFFFFFFFFF_u64 as i64);
    // mask that covers the 53rd bit
    let explicit_mantissa_bit = _mm512_set1_epi64(0x10000000000000_u64 as i64);
    // mask that covers the first 11 bits
    let exp_mask = _mm512_set1_epi64(0x7FF_u64 as i64);

    // extract the first 52 bits and add the implicit bit
    let mantissa = _mm512_or_si512(_mm512_and_si512(bits, mantissa_mask), explicit_mantissa_bit);

    // extract the 52nd to 63rd (excluded) bits for the biased exponent
    let biased_exp = _mm512_and_si512(_mm512_srli_epi64::<52>(bits), exp_mask);

    // extract the 63rd sign bit
    let sign_is_negative_mask =
        _mm512_cmpneq_epi64_mask(_mm512_srli_epi64::<63>(bits), _mm512_set1_epi64(1));

    // we need to shift the mantissa by some value that may be negative, so we first shift it to
    // the left by the maximum amount, then shift it to the right by our value plus the offset we
    // just shifted by
    //
    // the 53rd bit is set to 1, so we shift to the left by 10 so the 63rd (last) bit is set.
    let mantissa_lshift = _mm512_slli_epi64::<11>(mantissa);

    // shift to the right and apply the exponent bias
    let mantissa_shift = _mm512_srlv_epi64(
        mantissa_lshift,
        _mm512_sub_epi64(_mm512_set1_epi64(1086), biased_exp),
    );

    // if the sign bit is unset, we keep our result
    let value_if_positive = mantissa_shift;
    // otherwise, we negate it
    let value_if_negative = _mm512_sub_epi64(_mm512_setzero_si512(), value_if_positive);

    // if the biased exponent is all zeros, we have a subnormal value (or zero)

    // if it is not subnormal, we keep our results
    let value_if_non_subnormal =
        _mm512_mask_blend_epi64(sign_is_negative_mask, value_if_positive, value_if_negative);

    // if it is subnormal, the conversion to i64 (rounding towards zero) returns zero
    let value_if_subnormal = _mm512_setzero_si512();

    // compare the biased exponent to a zero value
    let is_subnormal = _mm512_cmpeq_epi64_mask(biased_exp, _mm512_setzero_si512());

    // choose the result depending on subnormalness
    _mm512_mask_blend_epi64(is_subnormal, value_if_non_subnormal, value_if_subnormal)
}

/// Converts a vector of i64 values to a vector of f64 values. Not sure how it works.
/// Ported from <https://stackoverflow.com/a/41148578>.
///
/// # Safety
///
///  - `is_x86_feature_detected!("avx2")` must be true.
#[inline(always)]
pub unsafe fn mm256_cvtepi64_pd(x: __m256i) -> __m256d {
    let mut x_hi = _mm256_srai_epi32::<16>(x);
    x_hi = _mm256_blend_epi16::<0x33>(x_hi, _mm256_setzero_si256());
    x_hi = _mm256_add_epi64(
        x_hi,
        _mm256_castpd_si256(_mm256_set1_pd(442721857769029238784.0)), // 3*2^67
    );
    let x_lo =
        _mm256_blend_epi16::<0x88>(x, _mm256_castpd_si256(_mm256_set1_pd(4503599627370496.0))); // 2^52

    let f = _mm256_sub_pd(
        _mm256_castsi256_pd(x_hi),
        _mm256_set1_pd(442726361368656609280.0), // 3*2^67 + 2^52
    );

    _mm256_add_pd(f, _mm256_castsi256_pd(x_lo))
}

/// Converts a vector of i64 values to a vector of f64 values.
///
/// # Safety
///
///  - `is_x86_feature_detected!("avx512dq")` must be true.
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512dq")]
#[inline]
pub unsafe fn mm512_cvtepi64_pd(x: __m512i) -> __m512d {
    // hopefully this compiles to vcvtqq2pd
    let i64x8: [i64; 8] = core::mem::transmute(x);
    let as_f64x8 = [
        i64x8[0] as f64,
        i64x8[1] as f64,
        i64x8[2] as f64,
        i64x8[3] as f64,
        i64x8[4] as f64,
        i64x8[5] as f64,
        i64x8[6] as f64,
        i64x8[7] as f64,
    ];
    core::mem::transmute(as_f64x8)
}

/// # Safety
///
///  - `is_x86_feature_detected!("avx512f")` must be true.
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512f")]
pub unsafe fn convert_forward_integer_u32_avx512f(
    out: &mut [MaybeUninit<c64>],
    in_re: &[u32],
    in_im: &[u32],
    twisties: TwistiesView<'_>,
) {
    let n = out.len();
    debug_assert_eq!(n % 8, 0);
    debug_assert_eq!(n, out.len());
    debug_assert_eq!(n, in_re.len());
    debug_assert_eq!(n, in_im.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let out = out.as_mut_ptr() as *mut f64;
    let in_re = in_re.as_ptr();
    let in_im = in_im.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 8 {
        let i = i * 8;
        // load i32 values and convert to f64
        let in_re = _mm512_cvtepi32_pd(_mm256_loadu_si256(in_re.add(i) as _));
        // load i32 values and convert to f64
        let in_im = _mm512_cvtepi32_pd(_mm256_loadu_si256(in_im.add(i) as _));
        // load f64 values
        let w_re = _mm512_loadu_pd(w_re.add(i));
        // load f64 values
        let w_im = _mm512_loadu_pd(w_im.add(i));
        let out = out.add(2 * i);

        // perform complex multiplication
        let out_re = _mm512_fmsub_pd(in_re, w_re, _mm512_mul_pd(in_im, w_im));
        let out_im = _mm512_fmadd_pd(in_re, w_im, _mm512_mul_pd(in_im, w_re));

        // we have
        // x0 x1 x2 x3 x4 x5 x6 x7
        // y0 y1 y2 y3 y4 y5 y6 y7
        //
        // we want
        // x0 y0 x1 y1 x2 y2 x3 y3
        // x4 y4 x5 y5 x6 y6 x7 y7

        // interleave real part and imaginary part
        {
            let idx0 = _mm512_setr_epi64(
                0b0000, 0b1000, 0b0001, 0b1001, 0b0010, 0b1010, 0b0011, 0b1011,
            );
            let idx1 = _mm512_setr_epi64(
                0b0100, 0b1100, 0b0101, 0b1101, 0b0110, 0b1110, 0b0111, 0b1111,
            );

            let out0 = _mm512_permutex2var_pd(out_re, idx0, out_im);
            let out1 = _mm512_permutex2var_pd(out_re, idx1, out_im);

            // store c64 values
            _mm512_storeu_pd(out, out0);
            _mm512_storeu_pd(out.add(8), out1);
        }
    }
}

/// # Safety
///
///  - `is_x86_feature_detected!("avx512f")` must be true.
///  - `is_x86_feature_detected!("avx512dq")` must be true.
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512f,avx512dq")]
pub unsafe fn convert_forward_integer_u64_avx512f_avx512dq(
    out: &mut [MaybeUninit<c64>],
    in_re: &[u64],
    in_im: &[u64],
    twisties: TwistiesView<'_>,
) {
    let n = out.len();
    debug_assert_eq!(n % 8, 0);
    debug_assert_eq!(n, out.len());
    debug_assert_eq!(n, in_re.len());
    debug_assert_eq!(n, in_im.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let out = out.as_mut_ptr() as *mut f64;
    let in_re = in_re.as_ptr();
    let in_im = in_im.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 8 {
        let i = i * 8;
        // load i64 values and convert to f64
        let in_re = mm512_cvtepi64_pd(_mm512_loadu_si512(in_re.add(i) as _));
        // load i64 values and convert to f64
        let in_im = mm512_cvtepi64_pd(_mm512_loadu_si512(in_im.add(i) as _));
        // load f64 values
        let w_re = _mm512_loadu_pd(w_re.add(i));
        // load f64 values
        let w_im = _mm512_loadu_pd(w_im.add(i));
        let out = out.add(2 * i);

        // perform complex multiplication
        let out_re = _mm512_fmsub_pd(in_re, w_re, _mm512_mul_pd(in_im, w_im));
        let out_im = _mm512_fmadd_pd(in_re, w_im, _mm512_mul_pd(in_im, w_re));

        // we have
        // x0 x1 x2 x3 x4 x5 x6 x7
        // y0 y1 y2 y3 y4 y5 y6 y7
        //
        // we want
        // x0 y0 x1 y1 x2 y2 x3 y3
        // x4 y4 x5 y5 x6 y6 x7 y7

        // interleave real part and imaginary part
        {
            let idx0 = _mm512_setr_epi64(
                0b0000, 0b1000, 0b0001, 0b1001, 0b0010, 0b1010, 0b0011, 0b1011,
            );
            let idx1 = _mm512_setr_epi64(
                0b0100, 0b1100, 0b0101, 0b1101, 0b0110, 0b1110, 0b0111, 0b1111,
            );

            let out0 = _mm512_permutex2var_pd(out_re, idx0, out_im);
            let out1 = _mm512_permutex2var_pd(out_re, idx1, out_im);

            // store c64 values
            _mm512_storeu_pd(out, out0);
            _mm512_storeu_pd(out.add(8), out1);
        }
    }
}

/// # Safety
///
///  - `is_x86_feature_detected!("fma")` must be true.
#[target_feature(enable = "avx,fma")]
pub unsafe fn convert_forward_integer_u32_fma(
    out: &mut [MaybeUninit<c64>],
    in_re: &[u32],
    in_im: &[u32],
    twisties: TwistiesView<'_>,
) {
    let n = out.len();
    debug_assert_eq!(n % 4, 0);
    debug_assert_eq!(n, out.len());
    debug_assert_eq!(n, in_re.len());
    debug_assert_eq!(n, in_im.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let out = out.as_mut_ptr() as *mut f64;
    let in_re = in_re.as_ptr();
    let in_im = in_im.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 4 {
        let i = i * 4;
        // load i32 values and convert to f64
        let in_re = _mm256_cvtepi32_pd(_mm_loadu_si128(in_re.add(i) as _));
        // load i32 values and convert to f64
        let in_im = _mm256_cvtepi32_pd(_mm_loadu_si128(in_im.add(i) as _));
        // load f64 values
        let w_re = _mm256_loadu_pd(w_re.add(i));
        // load f64 values
        let w_im = _mm256_loadu_pd(w_im.add(i));
        let out = out.add(2 * i);

        // perform complex multiplication
        let out_re = _mm256_fmsub_pd(in_re, w_re, _mm256_mul_pd(in_im, w_im));
        let out_im = _mm256_fmadd_pd(in_re, w_im, _mm256_mul_pd(in_im, w_re));

        // we have
        // x0 x1 x2 x3
        // y0 y1 y2 y3
        //
        // we want
        // x0 y0 x1 y1
        // x2 y2 x3 y3

        // interleave real part and imaginary part
        {
            // unpacklo/unpackhi
            // x0 y0 x2 y2
            // x1 y1 x3 y3
            let lo = _mm256_unpacklo_pd(out_re, out_im);
            let hi = _mm256_unpackhi_pd(out_re, out_im);

            let out0 = _mm256_permute2f128_pd::<0b00100000>(lo, hi);
            let out1 = _mm256_permute2f128_pd::<0b00110001>(lo, hi);

            // store c64 values
            _mm256_storeu_pd(out, out0);
            _mm256_storeu_pd(out.add(4), out1);
        }
    }
}

/// # Safety
///
///  - `is_x86_feature_detected!("avx2")` must be true.
///  - `is_x86_feature_detected!("fma")` must be true.
#[target_feature(enable = "avx,avx2,fma")]
pub unsafe fn convert_forward_integer_u64_avx2_fma(
    out: &mut [MaybeUninit<c64>],
    in_re: &[u64],
    in_im: &[u64],
    twisties: TwistiesView<'_>,
) {
    let n = out.len();
    debug_assert_eq!(n % 4, 0);
    debug_assert_eq!(n, out.len());
    debug_assert_eq!(n, in_re.len());
    debug_assert_eq!(n, in_im.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let out = out.as_mut_ptr() as *mut f64;
    let in_re = in_re.as_ptr();
    let in_im = in_im.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 4 {
        let i = i * 4;
        // load i64 values and convert to f64
        let in_re = mm256_cvtepi64_pd(_mm256_loadu_si256(in_re.add(i) as _));
        // load i64 values and convert to f64
        let in_im = mm256_cvtepi64_pd(_mm256_loadu_si256(in_im.add(i) as _));
        // load f64 values
        let w_re = _mm256_loadu_pd(w_re.add(i));
        // load f64 values
        let w_im = _mm256_loadu_pd(w_im.add(i));
        let out = out.add(2 * i);

        // perform complex multiplication
        let out_re = _mm256_fmsub_pd(in_re, w_re, _mm256_mul_pd(in_im, w_im));
        let out_im = _mm256_fmadd_pd(in_re, w_im, _mm256_mul_pd(in_im, w_re));

        // we have
        // x0 x1 x2 x3
        // y0 y1 y2 y3
        //
        // we want
        // x0 y0 x1 y1
        // x2 y2 x3 y3

        // interleave real part and imaginary part
        {
            // unpacklo/unpackhi
            // x0 y0 x2 y2
            // x1 y1 x3 y3
            let lo = _mm256_unpacklo_pd(out_re, out_im);
            let hi = _mm256_unpackhi_pd(out_re, out_im);

            let out0 = _mm256_permute2f128_pd::<0b00100000>(lo, hi);
            let out1 = _mm256_permute2f128_pd::<0b00110001>(lo, hi);

            // store c64 values
            _mm256_storeu_pd(out, out0);
            _mm256_storeu_pd(out.add(4), out1);
        }
    }
}

/// Performs common work for `u32` and `u64`, used by the backward torus transformation.
///
/// This deinterleaves two vectors of c64 values into two vectors of real part and imaginary part,
/// then rounds to the nearest integer.
///
/// # Safety
///
///  - `w_re.add(i)`, `w_im.add(i)`, and `inp.add(i)` must point to an array of at least 8
///  elements.
///  - `is_x86_feature_detected!("avx512f")` must be true.
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub unsafe fn convert_torus_prologue_avx512f(
    normalization: __m512d,
    w_re: *const f64,
    i: usize,
    w_im: *const f64,
    inp: *const c64,
    scaling: __m512d,
) -> (__m512d, __m512d) {
    let w_re = _mm512_mul_pd(normalization, _mm512_loadu_pd(w_re.add(i)));
    let w_im = _mm512_mul_pd(normalization, _mm512_loadu_pd(w_im.add(i)));

    // re0 im0 re1 im1 re2 im2 re3 im3
    let inp0 = _mm512_loadu_pd(inp.add(i) as _);
    // re4 im4 re5 im5 re6 im6 re7 im7
    let inp1 = _mm512_loadu_pd(inp.add(i + 4) as _);

    // real indices
    let idx0 = _mm512_setr_epi64(
        0b0000, 0b0010, 0b0100, 0b0110, 0b1000, 0b1010, 0b1100, 0b1110,
    );
    // imaginary indices
    let idx1 = _mm512_setr_epi64(
        0b0001, 0b0011, 0b0101, 0b0111, 0b1001, 0b1011, 0b1101, 0b1111,
    );

    // re0 re1 re2 re3 re4 re5 re6 re7
    let inp_re = _mm512_permutex2var_pd(inp0, idx0, inp1);
    // im0 im1 im2 im3 im4 im5 im6 im7
    let inp_im = _mm512_permutex2var_pd(inp0, idx1, inp1);

    // perform complex multiplication with conj(w)
    let mul_re = _mm512_fmadd_pd(inp_re, w_re, _mm512_mul_pd(inp_im, w_im));
    let mul_im = _mm512_fnmadd_pd(inp_re, w_im, _mm512_mul_pd(inp_im, w_re));

    // round to nearest integer and suppress exceptions
    const ROUNDING: i32 = _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC;

    // get the fractional part (centered around zero) by subtracting rounded value
    let fract_re = _mm512_sub_pd(mul_re, _mm512_roundscale_pd::<ROUNDING>(mul_re));
    let fract_im = _mm512_sub_pd(mul_im, _mm512_roundscale_pd::<ROUNDING>(mul_im));
    // scale fractional part and round
    let fract_re = _mm512_roundscale_pd::<ROUNDING>(_mm512_mul_pd(scaling, fract_re));
    let fract_im = _mm512_roundscale_pd::<ROUNDING>(_mm512_mul_pd(scaling, fract_im));

    (fract_re, fract_im)
}

/// See [`convert_add_backward_torus`].
///
/// # Safety
///
///  - Same preconditions as [`convert_add_backward_torus`].
///  - `is_x86_feature_detected!("avx512f")` must be true.
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512f")]
pub unsafe fn convert_add_backward_torus_u32_avx512f(
    out_re: &mut [MaybeUninit<u32>],
    out_im: &mut [MaybeUninit<u32>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let n = out_re.len();
    debug_assert_eq!(n % 8, 0);
    debug_assert_eq!(n, out_re.len());
    debug_assert_eq!(n, out_im.len());
    debug_assert_eq!(n, inp.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let normalization = _mm512_set1_pd(1.0 / n as f64);
    let scaling = _mm512_set1_pd(2.0_f64.powi(u32::BITS as i32));
    let out_re = out_re.as_mut_ptr() as *mut u32;
    let out_im = out_im.as_mut_ptr() as *mut u32;
    let inp = inp.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 8 {
        let i = i * 8;

        let (fract_re, fract_im) =
            convert_torus_prologue_avx512f(normalization, w_re, i, w_im, inp, scaling);

        // convert f64 to i32
        let fract_re = _mm512_cvtpd_epi32(fract_re);
        // convert f64 to i32
        let fract_im = _mm512_cvtpd_epi32(fract_im);

        // add to input and store
        _mm256_storeu_si256(
            out_re.add(i) as _,
            _mm256_add_epi32(fract_re, _mm256_loadu_si256(out_re.add(i) as _)),
        );
        // add to input and store
        _mm256_storeu_si256(
            out_im.add(i) as _,
            _mm256_add_epi32(fract_im, _mm256_loadu_si256(out_im.add(i) as _)),
        );
    }
}

/// See [`convert_add_backward_torus`].
///
/// # Safety
///
///  - Same preconditions as [`convert_add_backward_torus`].
///  - `is_x86_feature_detected!("avx512f")` must be true.
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512f")]
pub unsafe fn convert_add_backward_torus_u64_avx512f(
    out_re: &mut [MaybeUninit<u64>],
    out_im: &mut [MaybeUninit<u64>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let n = out_re.len();
    debug_assert_eq!(n % 8, 0);
    debug_assert_eq!(n, out_re.len());
    debug_assert_eq!(n, out_im.len());
    debug_assert_eq!(n, inp.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let normalization = _mm512_set1_pd(1.0 / n as f64);
    let scaling = _mm512_set1_pd(2.0_f64.powi(u64::BITS as i32));
    let out_re = out_re.as_mut_ptr() as *mut u64;
    let out_im = out_im.as_mut_ptr() as *mut u64;
    let inp = inp.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 8 {
        let i = i * 8;

        let (fract_re, fract_im) =
            convert_torus_prologue_avx512f(normalization, w_re, i, w_im, inp, scaling);

        // convert f64 to i64
        let fract_re = mm512_cvtpd_epi64(fract_re);
        // convert f64 to i64
        let fract_im = mm512_cvtpd_epi64(fract_im);

        // add to input and store
        _mm512_storeu_si512(
            out_re.add(i) as _,
            _mm512_add_epi64(fract_re, _mm512_loadu_si512(out_re.add(i) as _)),
        );
        // add to input and store
        _mm512_storeu_si512(
            out_im.add(i) as _,
            _mm512_add_epi64(fract_im, _mm512_loadu_si512(out_im.add(i) as _)),
        );
    }
}

/// Performs common work for `u32` and `u64`, used by the backward torus transformation.
///
/// This deinterleaves two vectors of c64 values into two vectors of real part and imaginary part,
/// then rounds to the nearest integer.
///
/// # Safety
///
///  - `w_re.add(i)`, `w_im.add(i)`, and `inp.add(i)` must point to an array of at least 4
///  elements.
///  - `is_x86_feature_detected!("fma")` must be true.
#[inline(always)]
pub unsafe fn convert_torus_prologue_fma(
    normalization: __m256d,
    w_re: *const f64,
    i: usize,
    w_im: *const f64,
    inp: *const c64,
    scaling: __m256d,
) -> (__m256d, __m256d) {
    let w_re = _mm256_mul_pd(normalization, _mm256_loadu_pd(w_re.add(i)));
    let w_im = _mm256_mul_pd(normalization, _mm256_loadu_pd(w_im.add(i)));

    // re0 im0
    let inp0 = _mm_loadu_pd(inp.add(i) as _);
    // re1 im1
    let inp1 = _mm_loadu_pd(inp.add(i + 1) as _);
    // re2 im2
    let inp2 = _mm_loadu_pd(inp.add(i + 2) as _);
    // re3 im3
    let inp3 = _mm_loadu_pd(inp.add(i + 3) as _);

    // re0 re1
    let inp_re01 = _mm_unpacklo_pd(inp0, inp1);
    // im0 im1
    let inp_im01 = _mm_unpackhi_pd(inp0, inp1);
    // re2 re3
    let inp_re23 = _mm_unpacklo_pd(inp2, inp3);
    // im2 im3
    let inp_im23 = _mm_unpackhi_pd(inp2, inp3);

    // re0 re1 re2 re3
    let inp_re = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_re01), inp_re23);
    // im0 im1 im2 im3
    let inp_im = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_im01), inp_im23);

    // perform complex multiplication with conj(w)
    let mul_re = _mm256_fmadd_pd(inp_re, w_re, _mm256_mul_pd(inp_im, w_im));
    let mul_im = _mm256_fnmadd_pd(inp_re, w_im, _mm256_mul_pd(inp_im, w_re));

    // round to nearest integer and suppress exceptions
    const ROUNDING: i32 = _MM_FROUND_NINT | _MM_FROUND_NO_EXC;

    // get the fractional part (centered around zero) by subtracting rounded value
    let fract_re = _mm256_sub_pd(mul_re, _mm256_round_pd::<ROUNDING>(mul_re));
    let fract_im = _mm256_sub_pd(mul_im, _mm256_round_pd::<ROUNDING>(mul_im));
    // scale fractional part and round
    let fract_re = _mm256_round_pd::<ROUNDING>(_mm256_mul_pd(scaling, fract_re));
    let fract_im = _mm256_round_pd::<ROUNDING>(_mm256_mul_pd(scaling, fract_im));

    (fract_re, fract_im)
}

/// See [`convert_add_backward_torus`].
///
/// # Safety
///
///  - Same preconditions as [`convert_add_backward_torus`].
///  - `is_x86_feature_detected!("fma")` must be true.
#[target_feature(enable = "avx,fma")]
pub unsafe fn convert_add_backward_torus_u32_fma(
    out_re: &mut [MaybeUninit<u32>],
    out_im: &mut [MaybeUninit<u32>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let n = out_re.len();
    debug_assert_eq!(n % 4, 0);
    debug_assert_eq!(n, out_re.len());
    debug_assert_eq!(n, out_im.len());
    debug_assert_eq!(n, inp.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let normalization = _mm256_set1_pd(1.0 / n as f64);
    let scaling = _mm256_set1_pd(2.0_f64.powi(u32::BITS as i32));
    let out_re = out_re.as_mut_ptr() as *mut u32;
    let out_im = out_im.as_mut_ptr() as *mut u32;
    let inp = inp.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 4 {
        let i = i * 4;

        let (fract_re, fract_im) =
            convert_torus_prologue_fma(normalization, w_re, i, w_im, inp, scaling);

        // convert f64 to i32
        let fract_re = _mm256_cvtpd_epi32(fract_re);
        // convert f64 to i32
        let fract_im = _mm256_cvtpd_epi32(fract_im);

        // add to input and store
        _mm_storeu_si128(
            out_re.add(i) as _,
            _mm_add_epi32(fract_re, _mm_loadu_si128(out_re.add(i) as _)),
        );
        // add to input and store
        _mm_storeu_si128(
            out_im.add(i) as _,
            _mm_add_epi32(fract_im, _mm_loadu_si128(out_im.add(i) as _)),
        );
    }
}

/// See [`convert_add_backward_torus`].
///
/// # Safety
///
///  - Same preconditions as [`convert_add_backward_torus`].
///  - `is_x86_feature_detected!("avx2")` must be true.
///  - `is_x86_feature_detected!("fma")` must be true.
#[target_feature(enable = "avx2,fma")]
pub unsafe fn convert_add_backward_torus_u64_fma(
    out_re: &mut [MaybeUninit<u64>],
    out_im: &mut [MaybeUninit<u64>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let n = out_re.len();
    debug_assert_eq!(n % 4, 0);
    debug_assert_eq!(n, out_re.len());
    debug_assert_eq!(n, out_im.len());
    debug_assert_eq!(n, inp.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let normalization = _mm256_set1_pd(1.0 / n as f64);
    let scaling = _mm256_set1_pd(2.0_f64.powi(u64::BITS as i32));
    let out_re = out_re.as_mut_ptr() as *mut u64;
    let out_im = out_im.as_mut_ptr() as *mut u64;
    let inp = inp.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 4 {
        let i = i * 4;

        let (fract_re, fract_im) =
            convert_torus_prologue_fma(normalization, w_re, i, w_im, inp, scaling);

        // convert f64 to i64
        let fract_re = mm256_cvtpd_epi64(fract_re);
        // convert f64 to i64
        let fract_im = mm256_cvtpd_epi64(fract_im);

        // add to input and store
        _mm256_storeu_si256(
            out_re.add(i) as _,
            _mm256_add_epi64(fract_re, _mm256_loadu_si256(out_re.add(i) as _)),
        );
        // add to input and store
        _mm256_storeu_si256(
            out_im.add(i) as _,
            _mm256_add_epi64(fract_im, _mm256_loadu_si256(out_im.add(i) as _)),
        );
    }
}

pub fn convert_forward_integer_u32(
    out: &mut [MaybeUninit<c64>],
    in_re: &[u32],
    in_im: &[u32],
    twisties: TwistiesView<'_>,
) {
    // this is a function that returns a function pointer to the right simd function
    #[allow(clippy::type_complexity)]
    let ptr_fn = || -> unsafe fn(&mut [MaybeUninit<c64>], &[u32], &[u32], TwistiesView<'_>) {
        #[cfg(feature = "nightly-avx512")]
        if is_x86_feature_detected!("avx512f") {
            return convert_forward_integer_u32_avx512f;
        }

        if is_x86_feature_detected!("fma") {
            convert_forward_integer_u32_fma
        } else {
            super::convert_forward_integer_scalar::<u32>
        }
    };
    // we call it to get the function pointer to the right simd function
    let ptr = ptr_fn();

    // SAFETY: the target x86 feature availability was checked, and `out_re` and `out_im`
    // do not hold any uninitialized values since that is a precondition of calling this
    // function
    unsafe { ptr(out, in_re, in_im, twisties) }
}

pub fn convert_forward_integer_u64(
    out: &mut [MaybeUninit<c64>],
    in_re: &[u64],
    in_im: &[u64],
    twisties: TwistiesView<'_>,
) {
    #[allow(clippy::type_complexity)]
    // this is a function that returns a function pointer to the right simd function
    let ptr_fn = || -> unsafe fn(&mut [MaybeUninit<c64>], &[u64], &[u64], TwistiesView<'_>) {
        #[cfg(feature = "nightly-avx512")]
        if is_x86_feature_detected!("avx512f") & is_x86_feature_detected!("avx512dq") {
            return convert_forward_integer_u64_avx512f_avx512dq;
        }

        if is_x86_feature_detected!("avx2") & is_x86_feature_detected!("fma") {
            convert_forward_integer_u64_avx2_fma
        } else {
            super::convert_forward_integer_scalar::<u64>
        }
    };
    // we call it to get the function pointer to the right simd function
    let ptr = ptr_fn();

    // SAFETY: the target x86 feature availability was checked, and `out_re` and `out_im`
    // do not hold any uninitialized values since that is a precondition of calling this
    // function
    unsafe { ptr(out, in_re, in_im, twisties) }
}

/// # Warning
///
/// This function is actually unsafe, but can't be marked as such since we need it to implement
/// `Fn(...)`, as there's no equivalent `unsafe Fn(...)` trait.
///
/// # Safety
///
/// - `out_re` and `out_im` must not hold any uninitialized values.
pub fn convert_add_backward_torus_u32(
    out_re: &mut [MaybeUninit<u32>],
    out_im: &mut [MaybeUninit<u32>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    // this is a function that returns a function pointer to the right simd function
    #[allow(clippy::type_complexity)]
    let ptr_fn = || -> unsafe fn (
        &mut [MaybeUninit<u32>],
        &mut [MaybeUninit<u32>],
        &[c64],
        TwistiesView<'_>,
    ) {
        #[cfg(feature = "nightly-avx512")]
        if is_x86_feature_detected!("avx512f") {
            return convert_add_backward_torus_u32_avx512f;
        }

        if is_x86_feature_detected!("fma") {
            convert_add_backward_torus_u32_fma
        } else {
            super::convert_add_backward_torus_scalar::<u32>
        }
    };
    // we call it to get the function pointer to the right simd function
    let ptr = ptr_fn();

    // SAFETY: the target x86 feature availability was checked, and `out_re` and `out_im`
    // do not hold any uninitialized values since that is a precondition of calling this
    // function
    unsafe { ptr(out_re, out_im, inp, twisties) }
}

/// # Warning
///
/// This function is actually unsafe, but can't be marked as such since we need it to implement
/// `Fn(...)`, as there's no equivalent `unsafe Fn(...)` trait.
///
/// # Safety
///
/// - `out_re` and `out_im` must not hold any uninitialized values.
pub fn convert_add_backward_torus_u64(
    out_re: &mut [MaybeUninit<u64>],
    out_im: &mut [MaybeUninit<u64>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    // this is a function that returns a function pointer to the right simd function
    #[allow(clippy::type_complexity)]
    let ptr_fn = || -> unsafe fn (
        &mut [MaybeUninit<u64>],
        &mut [MaybeUninit<u64>],
        &[c64],
        TwistiesView<'_>,
    ) {
        #[cfg(feature = "nightly-avx512")]
        if is_x86_feature_detected!("avx512f") {
            return convert_add_backward_torus_u64_avx512f;
        }

        if is_x86_feature_detected!("avx2") & is_x86_feature_detected!("fma") {
            convert_add_backward_torus_u64_fma
        } else {
            super::convert_add_backward_torus_scalar::<u64>
        }
    };
    // we call it to get the function pointer to the right simd function
    let ptr = ptr_fn();

    // SAFETY: the target x86 feature availability was checked, and `out_re` and `out_im`
    // do not hold any uninitialized values since that is a precondition of calling this
    // function
    unsafe { ptr(out_re, out_im, inp, twisties) }
}

#[cfg(test)]
mod tests {
    use std::mem::transmute;

    use crate::core_crypto::fft_impl::as_mut_uninit;
    use crate::core_crypto::fft_impl::math::fft::{convert_add_backward_torus_scalar, Twisties};

    use super::*;

    #[test]
    fn convert_f64_i64() {
        if is_x86_feature_detected!("avx2") {
            for v in [
                [
                    -(2.0_f64.powi(63)),
                    -(2.0_f64.powi(63)),
                    -(2.0_f64.powi(63)),
                    -(2.0_f64.powi(63)),
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
                let target = v.map(|x| x as i64);

                let computed: [i64; 4] = unsafe { transmute(mm256_cvtpd_epi64(transmute(v))) };
                assert_eq!(target, computed);
            }
        }
    }

    #[test]
    fn add_backward_torus_fma() {
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

        unsafe {
            convert_add_backward_torus_u64_fma(
                as_mut_uninit(&mut out_fma_re),
                as_mut_uninit(&mut out_fma_im),
                &input,
                twisties.as_view(),
            );

            convert_add_backward_torus_scalar(
                as_mut_uninit(&mut out_scalar_re),
                as_mut_uninit(&mut out_scalar_im),
                &input,
                twisties.as_view(),
            );
        }

        for i in 0..n {
            assert!(out_fma_re[i].abs_diff(out_scalar_re[i]) < (1 << 38));
            assert!(out_fma_im[i].abs_diff(out_scalar_im[i]) < (1 << 38));
        }
    }

    #[cfg(feature = "nightly-avx512")]
    #[test]
    fn add_backward_torus_avx512() {
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

        unsafe {
            convert_add_backward_torus_u64_avx512f(
                as_mut_uninit(&mut out_avx_re),
                as_mut_uninit(&mut out_avx_im),
                &input,
                twisties.as_view(),
            );

            convert_add_backward_torus_scalar(
                as_mut_uninit(&mut out_scalar_re),
                as_mut_uninit(&mut out_scalar_im),
                &input,
                twisties.as_view(),
            );
        }

        for i in 0..n {
            assert!(out_avx_re[i].abs_diff(out_scalar_re[i]) < (1 << 38));
            assert!(out_avx_im[i].abs_diff(out_scalar_im[i]) < (1 << 38));
        }
    }
}
