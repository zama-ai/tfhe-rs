use crate::core_crypto::commons::utils::izip_eq;
pub use crate::core_crypto::fft_impl::fft128::math::fft::Fft128View;
use dyn_stack::PodStack;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use pulp::{f64x4, u64x4, x86::V3};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
use pulp::{f64x8, u64x8, x86::V4};
use tfhe_fft::fft128::f128;

#[inline(always)]
pub fn zeroing_shl(x: u64, shift: u64) -> u64 {
    if shift >= 64 {
        0
    } else {
        x << shift
    }
}

#[inline(always)]
pub fn zeroing_shr(x: u64, shift: u64) -> u64 {
    if shift >= 64 {
        0
    } else {
        x >> shift
    }
}

#[inline(always)]
/// Return the arithmetic shift of the u128 value represented by lo and hi interpreted as a signed
/// value, as (res_lo, res_hi).
pub fn arithmetic_shr_split_u128(lo: u64, hi: u64, shift: u64) -> (u64, u64) {
    /// Should behave like the following intel intrinsics
    /// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_srai_epi64
    fn arithmetic_shr(x: u64, shift: u64) -> u64 {
        let signed_x = x as i64;
        if shift >= 64 {
            if signed_x >= 0 {
                0
            } else {
                // All ones as if the shift extended the sign
                u64::MAX
            }
        } else {
            (signed_x >> shift) as u64
        }
    }

    // This will zero out or fill with 1s depending on the sign bit
    let res_hi = arithmetic_shr(hi, shift);
    let res_lo = if shift < 64 {
        zeroing_shl(hi, 64 - shift) | zeroing_shr(lo, shift)
    } else {
        arithmetic_shr(hi, shift - 64)
    };

    (res_lo, res_hi)
}

#[inline(always)]
pub fn u128_to_f64((lo, hi): (u64, u64)) -> f64 {
    const A: f64 = (1u128 << 52) as f64;
    const B: f64 = (1u128 << 104) as f64;
    const C: f64 = (1u128 << 76) as f64;
    const D: f64 = u128::MAX as f64;
    if hi < 1 << 40 {
        let l = f64::from_bits(A.to_bits() | ((lo << 12) >> 12)) - A;
        let h = f64::from_bits(B.to_bits() | ((lo >> 52) | (hi << 12))) - B;
        l + h
    } else {
        let l =
            f64::from_bits(C.to_bits() | (((lo >> 12) | (hi << 52)) >> 12) | (lo & 0xFFFFFF)) - C;
        let h = f64::from_bits(D.to_bits() | (hi >> 12)) - D;
        l + h
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub fn u128_to_f64_avx2(simd: V3, (lo, hi): (u64x4, u64x4)) -> f64x4 {
    const A: f64 = (1u128 << 52) as f64;
    const B: f64 = (1u128 << 104) as f64;
    const C: f64 = (1u128 << 76) as f64;
    const D: f64 = u128::MAX as f64;

    let a = simd.splat_f64x4(A);
    let b = simd.splat_f64x4(B);
    let c = simd.splat_f64x4(C);
    let d = simd.splat_f64x4(D);

    simd.select_f64x4(
        simd.cmp_lt_u64x4(hi, simd.splat_u64x4(1 << 40)),
        {
            // cond is true
            let l = simd.sub_f64x4(
                pulp::cast(simd.or_u64x4(
                    pulp::cast(a),
                    simd.and_u64x4(lo, simd.splat_u64x4(0xFFFFFFFFFFFFF)),
                )),
                a,
            );

            let h = simd.sub_f64x4(
                pulp::cast(simd.or_u64x4(
                    pulp::cast(b),
                    simd.or_u64x4(
                        simd.shr_const_u64x4::<52>(lo),
                        simd.shl_const_u64x4::<12>(hi),
                    ),
                )),
                b,
            );

            simd.add_f64x4(l, h)
        },
        {
            // cond is false
            let x0 = pulp::cast(c);
            let x1 = simd.shr_const_u64x4::<12>(simd.or_u64x4(
                simd.shr_const_u64x4::<12>(lo),
                simd.shl_const_u64x4::<52>(hi),
            ));
            let x2 = simd.and_u64x4(lo, simd.splat_u64x4(0xFFFFFF));
            let l = simd.sub_f64x4(pulp::cast(simd.or_u64x4(x1, simd.or_u64x4(x2, x0))), c);
            let h = simd.sub_f64x4(
                pulp::cast(simd.or_u64x4(pulp::cast(d), simd.shr_const_u64x4::<12>(hi))),
                d,
            );
            simd.add_f64x4(l, h)
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub fn u128_to_f64_avx512(simd: V4, (lo, hi): (u64x8, u64x8)) -> f64x8 {
    const A: f64 = (1u128 << 52) as f64;
    const B: f64 = (1u128 << 104) as f64;
    const C: f64 = (1u128 << 76) as f64;
    const D: f64 = u128::MAX as f64;

    let a = simd.splat_f64x8(A);
    let b = simd.splat_f64x8(B);
    let c = simd.splat_f64x8(C);
    let d = simd.splat_f64x8(D);

    simd.select_f64x8(
        simd.cmp_lt_u64x8(hi, simd.splat_u64x8(1 << 40)),
        {
            // cond is true
            let l = simd.sub_f64x8(
                pulp::cast(simd.or_u64x8(
                    pulp::cast(a),
                    simd.and_u64x8(lo, simd.splat_u64x8(0xFFFFFFFFFFFFF)),
                )),
                a,
            );

            let h = simd.sub_f64x8(
                pulp::cast(simd.or_u64x8(
                    pulp::cast(b),
                    simd.or_u64x8(
                        simd.shr_const_u64x8::<52>(lo),
                        simd.shl_const_u64x8::<12>(hi),
                    ),
                )),
                b,
            );

            simd.add_f64x8(l, h)
        },
        {
            // cond is false
            let x0 = pulp::cast(c);
            let x1 = simd.shr_const_u64x8::<12>(simd.or_u64x8(
                simd.shr_const_u64x8::<12>(lo),
                simd.shl_const_u64x8::<52>(hi),
            ));
            let x2 = simd.and_u64x8(lo, simd.splat_u64x8(0xFFFFFF));
            let l = simd.sub_f64x8(pulp::cast(simd.or_u64x8(x1, simd.or_u64x8(x2, x0))), c);
            let h = simd.sub_f64x8(
                pulp::cast(simd.or_u64x8(pulp::cast(d), simd.shr_const_u64x8::<12>(hi))),
                d,
            );
            simd.add_f64x8(l, h)
        },
    )
}

#[inline(always)]
pub fn wrapping_sub((a_lo, a_hi): (u64, u64), (b_lo, b_hi): (u64, u64)) -> (u64, u64) {
    let (diff_lo, overflow) = a_lo.overflowing_sub(b_lo);
    (diff_lo, a_hi.wrapping_sub(b_hi).wrapping_sub(overflow as _))
}

#[inline(always)]
pub fn wrapping_add((a_lo, a_hi): (u64, u64), (b_lo, b_hi): (u64, u64)) -> (u64, u64) {
    let (sum_lo, overflow) = a_lo.overflowing_add(b_lo);
    (sum_lo, a_hi.wrapping_add(b_hi).wrapping_add(overflow as _))
}

#[inline(always)]
pub fn wrapping_neg((lo, hi): (u64, u64)) -> (u64, u64) {
    wrapping_add((1, 0), (!lo, !hi))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub fn wrapping_sub_avx2(
    simd: V3,
    (a_lo, a_hi): (u64x4, u64x4),
    (b_lo, b_hi): (u64x4, u64x4),
) -> (u64x4, u64x4) {
    let diff_lo = simd.wrapping_sub_u64x4(a_lo, b_lo);
    let diff_hi0 = simd.wrapping_sub_u64x4(a_hi, b_hi);
    let overflow = pulp::cast(simd.cmp_lt_u64x4(a_lo, b_lo));
    let diff_hi = simd.wrapping_add_u64x4(diff_hi0, overflow);
    (diff_lo, diff_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub fn wrapping_add_avx2(
    simd: V3,
    (a_lo, a_hi): (u64x4, u64x4),
    (b_lo, b_hi): (u64x4, u64x4),
) -> (u64x4, u64x4) {
    let sum_lo = simd.wrapping_add_u64x4(a_lo, b_lo);
    let overflow = pulp::cast(simd.cmp_lt_u64x4(sum_lo, a_lo));
    let sum_hi0 = simd.wrapping_add_u64x4(a_hi, b_hi);
    let sum_hi = simd.wrapping_sub_u64x4(sum_hi0, overflow);
    (sum_lo, sum_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub fn wrapping_neg_avx2(simd: V3, (lo, hi): (u64x4, u64x4)) -> (u64x4, u64x4) {
    wrapping_add_avx2(
        simd,
        (simd.splat_u64x4(1), simd.splat_u64x4(0)),
        (simd.not_u64x4(lo), simd.not_u64x4(hi)),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub fn wrapping_sub_avx512(
    simd: V4,
    (a_lo, a_hi): (u64x8, u64x8),
    (b_lo, b_hi): (u64x8, u64x8),
) -> (u64x8, u64x8) {
    let diff_lo = simd.wrapping_sub_u64x8(a_lo, b_lo);
    let diff_hi0 = simd.wrapping_sub_u64x8(a_hi, b_hi);
    let overflow = simd.convert_mask_b8_to_u64x8(simd.cmp_lt_u64x8(a_lo, b_lo));
    let diff_hi = simd.wrapping_add_u64x8(diff_hi0, overflow);
    (diff_lo, diff_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub fn wrapping_add_avx512(
    simd: V4,
    (a_lo, a_hi): (u64x8, u64x8),
    (b_lo, b_hi): (u64x8, u64x8),
) -> (u64x8, u64x8) {
    let sum_lo = simd.wrapping_add_u64x8(a_lo, b_lo);
    let overflow = simd.convert_mask_b8_to_u64x8(simd.cmp_lt_u64x8(sum_lo, a_lo));
    let sum_hi0 = simd.wrapping_add_u64x8(a_hi, b_hi);
    let sum_hi = simd.wrapping_sub_u64x8(sum_hi0, overflow);
    (sum_lo, sum_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub fn wrapping_neg_avx512(simd: V4, (lo, hi): (u64x8, u64x8)) -> (u64x8, u64x8) {
    wrapping_add_avx512(
        simd,
        (simd.splat_u64x8(1), simd.splat_u64x8(0)),
        (simd.not_u64x8(lo), simd.not_u64x8(hi)),
    )
}

#[inline(always)]
fn i128_to_f64((lo, hi): (u64, u64)) -> f64 {
    let sign = hi & (1u64 << 63);
    let abs = if sign == (1u64 << 63) {
        wrapping_neg((lo, hi))
    } else {
        (lo, hi)
    };
    f64::from_bits(u128_to_f64(abs).to_bits() | sign)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn i128_to_f64_avx2(simd: V3, (lo, hi): (u64x4, u64x4)) -> f64x4 {
    let sign_bit = simd.splat_u64x4(1 << 63);
    let sign = simd.and_u64x4(hi, sign_bit);
    let neg = wrapping_neg_avx2(simd, (lo, hi));

    let abs = (
        simd.select_u64x4(simd.cmp_eq_u64x4(sign, sign_bit), neg.0, lo),
        simd.select_u64x4(simd.cmp_eq_u64x4(sign, sign_bit), neg.1, hi),
    );

    simd.or_f64x4(u128_to_f64_avx2(simd, abs), pulp::cast(sign))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn i128_to_f64_avx512(simd: V4, (lo, hi): (u64x8, u64x8)) -> f64x8 {
    let sign_bit = simd.splat_u64x8(1 << 63);
    let sign = simd.cmp_eq_u64x8(simd.and_u64x8(hi, sign_bit), sign_bit);
    let neg = wrapping_neg_avx512(simd, (lo, hi));

    let abs = (
        simd.select_u64x8(sign, neg.0, lo),
        simd.select_u64x8(sign, neg.1, hi),
    );

    simd.or_f64x8(
        u128_to_f64_avx512(simd, abs),
        pulp::cast(simd.and_u64x8(hi, simd.splat_u64x8(1 << 63))),
    )
}

#[inline(always)]
pub fn f64_to_u128(f: f64) -> (u64, u64) {
    let f = f.to_bits();
    if f < 1023 << 52 {
        // >= 0, < 1
        (0u64, 0u64)
    } else {
        // >= 1, < max
        let hi = (1 << 63) | (f << 11);
        let s = 1150 - (f >> 52); // Shift based on the exponent and bias.
        if s >= 128 {
            (0u64, 0u64)
        } else if s >= 64 {
            (zeroing_shr(hi, s - 64), 0u64)
        } else {
            (zeroing_shl(hi, 64 - s), zeroing_shr(hi, s))
        }
    }
}

#[inline(always)]
pub fn f64_to_i128(f: f64) -> (u64, u64) {
    let f = f.to_bits();

    let a = f & (!0 >> 1); // Remove sign bit.
    if a < 1023 << 52 {
        // >= 0, < 1
        (0, 0)
    } else {
        // >= 1, < max
        let hi = (1 << 63) | (a << 11);
        let s = 1150 - (a >> 52); // Shift based on the exponent and bias.
        let u = if s >= 128 {
            (0, 0)
        } else if s >= 64 {
            (zeroing_shr(hi, s - 64), 0u64)
        } else {
            (zeroing_shl(hi, 64 - s), zeroing_shr(hi, s))
        };
        if (f as i64) < 0 {
            wrapping_neg(u)
        } else {
            u
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn f64_to_u128_avx2(simd: V3, f: f64x4) -> (u64x4, u64x4) {
    let f = pulp::cast(f);
    let less_than_one = simd.cmp_lt_u64x4(f, simd.splat_u64x4(1023 << 52));
    let if_not_zero = {
        let hi = simd.or_u64x4(simd.splat_u64x4(1 << 63), simd.shl_const_u64x4::<11>(f));
        let shift = simd.wrapping_sub_u64x4(simd.splat_u64x4(1150), simd.shr_const_u64x4::<52>(f));
        (
            simd.or_u64x4(
                simd.shr_dyn_u64x4(hi, simd.wrapping_sub_u64x4(shift, simd.splat_u64x4(64))),
                simd.shl_dyn_u64x4(hi, simd.wrapping_sub_u64x4(simd.splat_u64x4(64), shift)),
            ),
            simd.shr_dyn_u64x4(hi, shift),
        )
    };
    (
        simd.andnot_u64x4(pulp::cast(less_than_one), if_not_zero.0),
        simd.andnot_u64x4(pulp::cast(less_than_one), if_not_zero.1),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn f64_to_i128_avx2(simd: V3, f: f64x4) -> (u64x4, u64x4) {
    let sign_bit = simd.splat_u64x4(1 << 63);
    let f = pulp::cast(f);
    let a = simd.andnot_u64x4(sign_bit, f);

    let less_than_one = simd.cmp_lt_u64x4(a, simd.splat_u64x4(1023 << 52));
    let if_not_zero = {
        let hi = simd.or_u64x4(simd.splat_u64x4(1 << 63), simd.shl_const_u64x4::<11>(a));
        let shift = simd.wrapping_sub_u64x4(simd.splat_u64x4(1150), simd.shr_const_u64x4::<52>(a));
        let abs = (
            simd.or_u64x4(
                simd.shr_dyn_u64x4(hi, simd.wrapping_sub_u64x4(shift, simd.splat_u64x4(64))),
                simd.shl_dyn_u64x4(hi, simd.wrapping_sub_u64x4(simd.splat_u64x4(64), shift)),
            ),
            simd.shr_dyn_u64x4(hi, shift),
        );
        let neg = wrapping_neg_avx2(simd, abs);
        let mask = simd.cmp_eq_u64x4(simd.and_u64x4(sign_bit, f), sign_bit);
        (
            simd.select_u64x4(mask, neg.0, abs.0),
            simd.select_u64x4(mask, neg.1, abs.1),
        )
    };
    (
        simd.andnot_u64x4(pulp::cast(less_than_one), if_not_zero.0),
        simd.andnot_u64x4(pulp::cast(less_than_one), if_not_zero.1),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn f64_to_i128_avx512(simd: V4, f: f64x8) -> (u64x8, u64x8) {
    let sign_bit = simd.splat_u64x8(1 << 63);
    let f = pulp::cast(f);
    let a = simd.andnot_u64x8(sign_bit, f);

    let less_than_one =
        simd.convert_mask_b8_to_u64x8(simd.cmp_lt_u64x8(a, simd.splat_u64x8(1023 << 52)));
    let if_not_zero = {
        let hi = simd.or_u64x8(simd.splat_u64x8(1 << 63), simd.shl_const_u64x8::<11>(a));
        let shift = simd.wrapping_sub_u64x8(simd.splat_u64x8(1150), simd.shr_const_u64x8::<52>(a));
        let abs = (
            simd.or_u64x8(
                simd.shr_dyn_u64x8(hi, simd.wrapping_sub_u64x8(shift, simd.splat_u64x8(64))),
                simd.shl_dyn_u64x8(hi, simd.wrapping_sub_u64x8(simd.splat_u64x8(64), shift)),
            ),
            simd.shr_dyn_u64x8(hi, shift),
        );
        let neg = wrapping_neg_avx512(simd, abs);
        let mask = simd.cmp_eq_u64x8(simd.and_u64x8(f, sign_bit), sign_bit);
        (
            simd.select_u64x8(mask, neg.0, abs.0),
            simd.select_u64x8(mask, neg.1, abs.1),
        )
    };
    (
        simd.andnot_u64x8(less_than_one, if_not_zero.0),
        simd.andnot_u64x8(less_than_one, if_not_zero.1),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn f64_to_u128_avx512(simd: V4, f: f64x8) -> (u64x8, u64x8) {
    let f = pulp::cast(f);
    let less_than_one =
        simd.convert_mask_b8_to_u64x8(simd.cmp_lt_u64x8(f, simd.splat_u64x8(1023 << 52)));
    let if_not_zero = {
        let hi = simd.or_u64x8(simd.splat_u64x8(1 << 63), simd.shl_const_u64x8::<11>(f));
        let shift = simd.wrapping_sub_u64x8(simd.splat_u64x8(1150), simd.shr_const_u64x8::<52>(f));
        (
            simd.or_u64x8(
                simd.shr_dyn_u64x8(hi, simd.wrapping_sub_u64x8(shift, simd.splat_u64x8(64))),
                simd.shl_dyn_u64x8(hi, simd.wrapping_sub_u64x8(simd.splat_u64x8(64), shift)),
            ),
            simd.shr_dyn_u64x8(hi, shift),
        )
    };
    (
        simd.andnot_u64x8(less_than_one, if_not_zero.0),
        simd.andnot_u64x8(less_than_one, if_not_zero.1),
    )
}

#[inline(always)]
fn to_signed_to_f128((lo, hi): (u64, u64)) -> f128 {
    // convert to signed then to float
    let first_approx = i128_to_f64((lo, hi));

    // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS - 1)`,
    // which should fit in a `Scalar`
    //
    // we perform this step since converting back directly to a signed integer may overflow
    let sign_bit = first_approx.to_bits() & (1u64 << 63);
    let first_approx_roundtrip = f64_to_u128(first_approx.abs());

    // apply sign again to get a wraparound effect
    let first_approx_roundtrip_signed = if sign_bit == (1u64 << 63) {
        // negative
        wrapping_neg(first_approx_roundtrip)
    } else {
        // positive
        first_approx_roundtrip
    };

    let correction = i128_to_f64(wrapping_sub((lo, hi), first_approx_roundtrip_signed) as _);
    f128(first_approx, correction)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn to_signed_to_f128_avx2(simd: V3, (lo, hi): (u64x4, u64x4)) -> (f64x4, f64x4) {
    // convert to signed then to float
    let first_approx = i128_to_f64_avx2(simd, (lo, hi));

    // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS - 1)`,
    // which should fit in a `Scalar`
    //
    // we perform this step since converting back directly to a signed integer may overflow
    let sign_bit = simd.splat_u64x4(1 << 63);
    let sign = simd.and_u64x4(sign_bit, pulp::cast(first_approx));

    let first_approx_roundtrip =
        f64_to_u128_avx2(simd, simd.andnot_f64x4(pulp::cast(sign_bit), first_approx));

    // apply sign again to get a wraparound effect
    let neg = wrapping_neg_avx2(simd, first_approx_roundtrip);

    let first_approx_roundtrip_signed = (
        simd.select_u64x4(
            simd.cmp_eq_u64x4(sign, sign_bit),
            neg.0,
            first_approx_roundtrip.0,
        ),
        simd.select_u64x4(
            simd.cmp_eq_u64x4(sign, sign_bit),
            neg.1,
            first_approx_roundtrip.1,
        ),
    );

    let correction = i128_to_f64_avx2(
        simd,
        wrapping_sub_avx2(simd, (lo, hi), first_approx_roundtrip_signed),
    );
    (first_approx, correction)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn to_signed_to_f128_avx512(simd: V4, (lo, hi): (u64x8, u64x8)) -> (f64x8, f64x8) {
    // convert to signed then to float
    let first_approx = i128_to_f64_avx512(simd, (lo, hi));

    // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS - 1)`,
    // which should fit in a `Scalar`
    //
    // we perform this step since converting back directly to a signed integer may overflow
    let sign_bit = simd.splat_u64x8(1 << 63);
    let sign = simd.cmp_eq_u64x8(simd.and_u64x8(pulp::cast(first_approx), sign_bit), sign_bit);

    let first_approx_roundtrip =
        f64_to_u128_avx512(simd, simd.andnot_f64x8(pulp::cast(sign_bit), first_approx));

    // apply sign again to get a wraparound effect
    let neg = wrapping_neg_avx512(simd, first_approx_roundtrip);

    let first_approx_roundtrip_signed = (
        simd.select_u64x8(sign, neg.0, first_approx_roundtrip.0),
        simd.select_u64x8(sign, neg.1, first_approx_roundtrip.1),
    );

    let correction = i128_to_f64_avx512(
        simd,
        wrapping_sub_avx512(simd, (lo, hi), first_approx_roundtrip_signed),
    );
    (first_approx, correction)
}

#[inline(always)]
fn f128_floor(x: f128) -> f128 {
    let f128(x0, x1) = x;
    let x0_floor = x0.floor();
    if x0_floor == x0 {
        f128::add_f64_f64(x0_floor, x1.floor())
    } else {
        f128(x0_floor, 0.0)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn f128_floor_avx2(simd: V3, (x0, x1): (f64x4, f64x4)) -> (f64x4, f64x4) {
    let x0_floor = simd.floor_f64x4(x0);
    let x1_floor = simd.floor_f64x4(x1);

    two_sum_f64x4(
        simd,
        x0_floor,
        simd.select_f64x4(
            simd.cmp_eq_f64x4(x0_floor, x0),
            x1_floor,
            simd.splat_f64x4(0.0),
        ),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn f128_floor_avx512(simd: V4, (x0, x1): (f64x8, f64x8)) -> (f64x8, f64x8) {
    let x0_floor = simd.floor_f64x8(x0);
    let x1_floor = simd.floor_f64x8(x1);

    two_sum_f64x8(
        simd,
        x0_floor,
        simd.select_f64x8(
            simd.cmp_eq_f64x8(x0_floor, x0),
            x1_floor,
            simd.splat_f64x8(0.0),
        ),
    )
}

#[inline(always)]
fn f128_round(x: f128) -> f128 {
    f128_floor(f128::add_f128_f64(x, 0.5))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn f128_round_avx2(simd: V3, (x0, x1): (f64x4, f64x4)) -> (f64x4, f64x4) {
    f128_floor_avx2(simd, add_f128_f64x4(simd, x0, x1, simd.splat_f64x4(0.5)))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn f128_round_avx512(simd: V4, (x0, x1): (f64x8, f64x8)) -> (f64x8, f64x8) {
    f128_floor_avx512(simd, add_f128_f64x8(simd, x0, x1, simd.splat_f64x8(0.5)))
}

#[inline(always)]
fn from_torus_f128(x: f128) -> (u64, u64) {
    let mut x = f128::sub_estimate_f128_f128(x, f128_floor(x));

    let normalization = 2.0f64.powi(128);
    x.0 *= normalization;
    x.1 *= normalization;

    let x = f128_round(x);

    let x0 = f64_to_u128(x.0);
    let x1 = f64_to_i128(x.1);

    wrapping_add(x0, x1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn quick_two_sum_f64x4(simd: V3, a: f64x4, b: f64x4) -> (f64x4, f64x4) {
    let s = simd.add_f64x4(a, b);
    (s, simd.sub_f64x4(b, simd.sub_f64x4(s, a)))
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn two_sum_f64x4(simd: V3, a: f64x4, b: f64x4) -> (f64x4, f64x4) {
    let s = simd.add_f64x4(a, b);
    let bb = simd.sub_f64x4(s, a);
    (
        s,
        simd.add_f64x4(
            simd.sub_f64x4(a, simd.sub_f64x4(s, bb)),
            simd.sub_f64x4(b, bb),
        ),
    )
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn two_diff_f64x4(simd: V3, a: f64x4, b: f64x4) -> (f64x4, f64x4) {
    let s = simd.sub_f64x4(a, b);
    let bb = simd.sub_f64x4(s, a);
    (
        s,
        simd.sub_f64x4(
            simd.sub_f64x4(a, simd.sub_f64x4(s, bb)),
            simd.add_f64x4(b, bb),
        ),
    )
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn sub_estimate_f128x4(simd: V3, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4) {
    let (s, e) = two_diff_f64x4(simd, a0, b0);
    let e = simd.add_f64x4(e, a1);
    let e = simd.sub_f64x4(e, b1);
    quick_two_sum_f64x4(simd, s, e)
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub fn add_f128_f64x4(simd: V3, a0: f64x4, a1: f64x4, b: f64x4) -> (f64x4, f64x4) {
    let (s1, s2) = two_sum_f64x4(simd, a0, b);
    let s2 = simd.add_f64x4(s2, a1);
    quick_two_sum_f64x4(simd, s1, s2)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn quick_two_sum_f64x8(simd: V4, a: f64x8, b: f64x8) -> (f64x8, f64x8) {
    let s = simd.add_f64x8(a, b);
    (s, simd.sub_f64x8(b, simd.sub_f64x8(s, a)))
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub(crate) fn two_sum_f64x8(simd: V4, a: f64x8, b: f64x8) -> (f64x8, f64x8) {
    let s = simd.add_f64x8(a, b);
    let bb = simd.sub_f64x8(s, a);
    (
        s,
        simd.add_f64x8(
            simd.sub_f64x8(a, simd.sub_f64x8(s, bb)),
            simd.sub_f64x8(b, bb),
        ),
    )
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn two_diff_f64x8(simd: V4, a: f64x8, b: f64x8) -> (f64x8, f64x8) {
    let s = simd.sub_f64x8(a, b);
    let bb = simd.sub_f64x8(s, a);
    (
        s,
        simd.sub_f64x8(
            simd.sub_f64x8(a, simd.sub_f64x8(s, bb)),
            simd.add_f64x8(b, bb),
        ),
    )
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn sub_estimate_f128x8(simd: V4, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8) {
    let (s, e) = two_diff_f64x8(simd, a0, b0);
    let e = simd.add_f64x8(e, a1);
    let e = simd.sub_f64x8(e, b1);
    quick_two_sum_f64x8(simd, s, e)
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub fn add_f128_f64x8(simd: V4, a0: f64x8, a1: f64x8, b: f64x8) -> (f64x8, f64x8) {
    let (s1, s2) = two_sum_f64x8(simd, a0, b);
    let s2 = simd.add_f64x8(s2, a1);
    quick_two_sum_f64x8(simd, s1, s2)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn from_torus_f128_avx2(simd: V3, x: (f64x4, f64x4)) -> (u64x4, u64x4) {
    let floor = f128_floor_avx2(simd, x);
    let mut x = sub_estimate_f128x4(simd, x.0, x.1, floor.0, floor.1);

    let normalization = simd.splat_f64x4(2.0f64.powi(128));
    x.0 = simd.mul_f64x4(normalization, x.0);
    x.1 = simd.mul_f64x4(normalization, x.1);

    let x = f128_round_avx2(simd, x);

    let x0 = f64_to_u128_avx2(simd, x.0);
    let x1 = f64_to_i128_avx2(simd, x.1);

    wrapping_add_avx2(simd, x0, x1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn from_torus_f128_avx512(simd: V4, x: (f64x8, f64x8)) -> (u64x8, u64x8) {
    let floor = f128_floor_avx512(simd, x);
    let mut x = sub_estimate_f128x8(simd, x.0, x.1, floor.0, floor.1);

    let normalization = simd.splat_f64x8(2.0f64.powi(128));
    x.0 = simd.mul_f64x8(normalization, x.0);
    x.1 = simd.mul_f64x8(normalization, x.1);

    let x = f128_round_avx512(simd, x);

    let x0 = f64_to_u128_avx512(simd, x.0);
    let x1 = f64_to_i128_avx512(simd, x.1);

    wrapping_add_avx512(simd, x0, x1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn convert_forward_integer_avx2(
    simd: V3,
    out_re0: &mut [f64],
    out_re1: &mut [f64],
    out_im0: &mut [f64],
    out_im1: &mut [f64],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    struct Impl<'a> {
        simd: V3,
        out_re0: &'a mut [f64],
        out_re1: &'a mut [f64],
        out_im0: &'a mut [f64],
        out_im1: &'a mut [f64],
        in_re_lo: &'a [u64],
        in_re_hi: &'a [u64],
        in_im_lo: &'a [u64],
        in_im_hi: &'a [u64],
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re0,
                out_re1,
                out_im0,
                out_im1,
                in_re_lo,
                in_re_hi,
                in_im_lo,
                in_im_hi,
            } = self;
            let out_re0 = pulp::as_arrays_mut::<4, _>(out_re0).0;
            let out_re1 = pulp::as_arrays_mut::<4, _>(out_re1).0;
            let out_im0 = pulp::as_arrays_mut::<4, _>(out_im0).0;
            let out_im1 = pulp::as_arrays_mut::<4, _>(out_im1).0;

            let in_re_lo = pulp::as_arrays::<4, _>(in_re_lo).0;
            let in_re_hi = pulp::as_arrays::<4, _>(in_re_hi).0;
            let in_im_lo = pulp::as_arrays::<4, _>(in_im_lo).0;
            let in_im_hi = pulp::as_arrays::<4, _>(in_im_hi).0;

            for (out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi) in
                izip_eq!(out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi)
            {
                let out_re =
                    to_signed_to_f128_avx2(simd, (pulp::cast(*in_re_lo), pulp::cast(*in_re_hi)));
                let out_im =
                    to_signed_to_f128_avx2(simd, (pulp::cast(*in_im_lo), pulp::cast(*in_im_hi)));

                *out_re0 = pulp::cast(out_re.0);
                *out_re1 = pulp::cast(out_re.1);
                *out_im0 = pulp::cast(out_im.0);
                *out_im1 = pulp::cast(out_im.1);
            }
        }
    }
    simd.vectorize(Impl {
        simd,
        out_re0,
        out_re1,
        out_im0,
        out_im1,
        in_re_lo,
        in_re_hi,
        in_im_lo,
        in_im_hi,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
pub fn convert_forward_integer_avx512(
    simd: V4,
    out_re0: &mut [f64],
    out_re1: &mut [f64],
    out_im0: &mut [f64],
    out_im1: &mut [f64],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    struct Impl<'a> {
        simd: V4,
        out_re0: &'a mut [f64],
        out_re1: &'a mut [f64],
        out_im0: &'a mut [f64],
        out_im1: &'a mut [f64],
        in_re_lo: &'a [u64],
        in_re_hi: &'a [u64],
        in_im_lo: &'a [u64],
        in_im_hi: &'a [u64],
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re0,
                out_re1,
                out_im0,
                out_im1,
                in_re_lo,
                in_re_hi,
                in_im_lo,
                in_im_hi,
            } = self;

            let out_re0 = pulp::as_arrays_mut::<8, _>(out_re0).0;
            let out_re1 = pulp::as_arrays_mut::<8, _>(out_re1).0;
            let out_im0 = pulp::as_arrays_mut::<8, _>(out_im0).0;
            let out_im1 = pulp::as_arrays_mut::<8, _>(out_im1).0;

            let in_re_lo = pulp::as_arrays::<8, _>(in_re_lo).0;
            let in_re_hi = pulp::as_arrays::<8, _>(in_re_hi).0;
            let in_im_lo = pulp::as_arrays::<8, _>(in_im_lo).0;
            let in_im_hi = pulp::as_arrays::<8, _>(in_im_hi).0;

            for (out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi) in
                izip_eq!(out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi)
            {
                let out_re =
                    to_signed_to_f128_avx512(simd, (pulp::cast(*in_re_lo), pulp::cast(*in_re_hi)));
                let out_im =
                    to_signed_to_f128_avx512(simd, (pulp::cast(*in_im_lo), pulp::cast(*in_im_hi)));

                *out_re0 = pulp::cast(out_re.0);
                *out_re1 = pulp::cast(out_re.1);
                *out_im0 = pulp::cast(out_im.0);
                *out_im1 = pulp::cast(out_im.1);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out_re0,
        out_re1,
        out_im0,
        out_im1,
        in_re_lo,
        in_re_hi,
        in_im_lo,
        in_im_hi,
    });
}

pub fn convert_forward_integer_scalar(
    out_re0: &mut [f64],
    out_re1: &mut [f64],
    out_im0: &mut [f64],
    out_im1: &mut [f64],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    for (out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi) in
        izip_eq!(out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi)
    {
        let out_re = to_signed_to_f128((*in_re_lo, *in_re_hi));
        let out_im = to_signed_to_f128((*in_im_lo, *in_im_hi));

        *out_re0 = out_re.0;
        *out_re1 = out_re.1;
        *out_im0 = out_im.0;
        *out_im1 = out_im.1;
    }
}

pub fn convert_forward_integer(
    out_re0: &mut [f64],
    out_re1: &mut [f64],
    out_im0: &mut [f64],
    out_im1: &mut [f64],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "avx512")]
    if let Some(simd) = V4::try_new() {
        return convert_forward_integer_avx512(
            simd, out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi,
        );
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(simd) = V3::try_new() {
        return convert_forward_integer_avx2(
            simd, out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi,
        );
    }
    convert_forward_integer_scalar(
        out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi,
    );
}

pub fn convert_add_backward_torus_scalar(
    out_re_lo: &mut [u64],
    out_re_hi: &mut [u64],
    out_im_lo: &mut [u64],
    out_im_hi: &mut [u64],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    let norm = 1.0 / in_re0.len() as f64;
    for (out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1) in
        izip_eq!(out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1)
    {
        let in_re = f128(*in_re0 * norm, *in_re1 * norm);
        let in_im = f128(*in_im0 * norm, *in_im1 * norm);
        let out_re = wrapping_add((*out_re_lo, *out_re_hi), from_torus_f128(in_re));
        let out_im = wrapping_add((*out_im_lo, *out_im_hi), from_torus_f128(in_im));
        *out_re_lo = out_re.0;
        *out_re_hi = out_re.1;
        *out_im_lo = out_im.0;
        *out_im_hi = out_im.1;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn convert_add_backward_torus_avx2(
    simd: V3,
    out_re_lo: &mut [u64],
    out_re_hi: &mut [u64],
    out_im_lo: &mut [u64],
    out_im_hi: &mut [u64],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    struct Impl<'a> {
        simd: V3,
        out_re_lo: &'a mut [u64],
        out_re_hi: &'a mut [u64],
        out_im_lo: &'a mut [u64],
        out_im_hi: &'a mut [u64],
        in_re0: &'a [f64],
        in_re1: &'a [f64],
        in_im0: &'a [f64],
        in_im1: &'a [f64],
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re_lo,
                out_re_hi,
                out_im_lo,
                out_im_hi,
                in_re0,
                in_re1,
                in_im0,
                in_im1,
            } = self;
            let norm = simd.splat_f64x4(1.0 / in_re0.len() as f64);

            let out_re_lo = pulp::as_arrays_mut::<4, _>(out_re_lo).0;
            let out_re_hi = pulp::as_arrays_mut::<4, _>(out_re_hi).0;
            let out_im_lo = pulp::as_arrays_mut::<4, _>(out_im_lo).0;
            let out_im_hi = pulp::as_arrays_mut::<4, _>(out_im_hi).0;

            let in_re0 = pulp::as_arrays::<4, _>(in_re0).0;
            let in_re1 = pulp::as_arrays::<4, _>(in_re1).0;
            let in_im0 = pulp::as_arrays::<4, _>(in_im0).0;
            let in_im1 = pulp::as_arrays::<4, _>(in_im1).0;

            for (out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1) in
                izip_eq!(out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1)
            {
                let in_re = (
                    simd.mul_f64x4(pulp::cast(*in_re0), norm),
                    simd.mul_f64x4(pulp::cast(*in_re1), norm),
                );
                let in_im = (
                    simd.mul_f64x4(pulp::cast(*in_im0), norm),
                    simd.mul_f64x4(pulp::cast(*in_im1), norm),
                );
                let out_re = wrapping_add_avx2(
                    simd,
                    (pulp::cast(*out_re_lo), pulp::cast(*out_re_hi)),
                    from_torus_f128_avx2(simd, in_re),
                );
                let out_im = wrapping_add_avx2(
                    simd,
                    (pulp::cast(*out_im_lo), pulp::cast(*out_im_hi)),
                    from_torus_f128_avx2(simd, in_im),
                );
                *out_re_lo = pulp::cast(out_re.0);
                *out_re_hi = pulp::cast(out_re.1);
                *out_im_lo = pulp::cast(out_im.0);
                *out_im_hi = pulp::cast(out_im.1);
            }
        }
    }
    simd.vectorize(Impl {
        simd,
        out_re_lo,
        out_re_hi,
        out_im_lo,
        out_im_hi,
        in_re0,
        in_re1,
        in_im0,
        in_im1,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
pub fn convert_add_backward_torus_avx512(
    simd: V4,
    out_re_lo: &mut [u64],
    out_re_hi: &mut [u64],
    out_im_lo: &mut [u64],
    out_im_hi: &mut [u64],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    struct Impl<'a> {
        simd: V4,
        out_re_lo: &'a mut [u64],
        out_re_hi: &'a mut [u64],
        out_im_lo: &'a mut [u64],
        out_im_hi: &'a mut [u64],
        in_re0: &'a [f64],
        in_re1: &'a [f64],
        in_im0: &'a [f64],
        in_im1: &'a [f64],
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                out_re_lo,
                out_re_hi,
                out_im_lo,
                out_im_hi,
                in_re0,
                in_re1,
                in_im0,
                in_im1,
            } = self;
            let norm = simd.splat_f64x8(1.0 / in_re0.len() as f64);

            let out_re_lo = pulp::as_arrays_mut::<8, _>(out_re_lo).0;
            let out_re_hi = pulp::as_arrays_mut::<8, _>(out_re_hi).0;
            let out_im_lo = pulp::as_arrays_mut::<8, _>(out_im_lo).0;
            let out_im_hi = pulp::as_arrays_mut::<8, _>(out_im_hi).0;

            let in_re0 = pulp::as_arrays::<8, _>(in_re0).0;
            let in_re1 = pulp::as_arrays::<8, _>(in_re1).0;
            let in_im0 = pulp::as_arrays::<8, _>(in_im0).0;
            let in_im1 = pulp::as_arrays::<8, _>(in_im1).0;

            for (out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1) in
                izip_eq!(out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1)
            {
                let in_re = (
                    simd.mul_f64x8(pulp::cast(*in_re0), norm),
                    simd.mul_f64x8(pulp::cast(*in_re1), norm),
                );
                let in_im = (
                    simd.mul_f64x8(pulp::cast(*in_im0), norm),
                    simd.mul_f64x8(pulp::cast(*in_im1), norm),
                );
                let out_re = wrapping_add_avx512(
                    simd,
                    (pulp::cast(*out_re_lo), pulp::cast(*out_re_hi)),
                    from_torus_f128_avx512(simd, in_re),
                );
                let out_im = wrapping_add_avx512(
                    simd,
                    (pulp::cast(*out_im_lo), pulp::cast(*out_im_hi)),
                    from_torus_f128_avx512(simd, in_im),
                );
                *out_re_lo = pulp::cast(out_re.0);
                *out_re_hi = pulp::cast(out_re.1);
                *out_im_lo = pulp::cast(out_im.0);
                *out_im_hi = pulp::cast(out_im.1);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        out_re_lo,
        out_re_hi,
        out_im_lo,
        out_im_hi,
        in_re0,
        in_re1,
        in_im0,
        in_im1,
    });
}

pub fn convert_add_backward_torus(
    out_re_lo: &mut [u64],
    out_re_hi: &mut [u64],
    out_im_lo: &mut [u64],
    out_im_hi: &mut [u64],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "avx512")]
    if let Some(simd) = V4::try_new() {
        return convert_add_backward_torus_avx512(
            simd, out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1,
        );
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(simd) = V3::try_new() {
        return convert_add_backward_torus_avx2(
            simd, out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1,
        );
    }
    convert_add_backward_torus_scalar(
        out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1,
    );
}

impl Fft128View<'_> {
    pub fn forward_as_integer_split(
        self,
        fourier_re0: &mut [f64],
        fourier_re1: &mut [f64],
        fourier_im0: &mut [f64],
        fourier_im1: &mut [f64],
        standard_lo: &[u64],
        standard_hi: &[u64],
    ) {
        self.forward_with_conv_split(
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            standard_lo,
            standard_hi,
            convert_forward_integer,
        );
    }

    /// Perform an inverse negacyclic real FFT of `fourier` and adds the result to `standard`,
    /// viewed as torus elements.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn add_backward_as_torus_split(
        self,
        standard_lo: &mut [u64],
        standard_hi: &mut [u64],
        fourier_re0: &[f64],
        fourier_re1: &[f64],
        fourier_im0: &[f64],
        fourier_im1: &[f64],
        stack: &mut PodStack,
    ) {
        self.backward_with_conv_split(
            standard_lo,
            standard_hi,
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            convert_add_backward_torus,
            stack,
        );
    }

    fn forward_with_conv_split(
        self,
        fourier_re0: &mut [f64],
        fourier_re1: &mut [f64],
        fourier_im0: &mut [f64],
        fourier_im1: &mut [f64],
        standard_lo: &[u64],
        standard_hi: &[u64],
        conv_fn: impl Fn(&mut [f64], &mut [f64], &mut [f64], &mut [f64], &[u64], &[u64], &[u64], &[u64]),
    ) {
        let n = standard_lo.len();
        debug_assert_eq!(n, 2 * fourier_re0.len());
        debug_assert_eq!(n, 2 * fourier_re1.len());
        debug_assert_eq!(n, 2 * fourier_im0.len());
        debug_assert_eq!(n, 2 * fourier_im1.len());

        let (standard_re_lo, standard_im_lo) = standard_lo.split_at(n / 2);
        let (standard_re_hi, standard_im_hi) = standard_hi.split_at(n / 2);
        conv_fn(
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            standard_re_lo,
            standard_re_hi,
            standard_im_lo,
            standard_im_hi,
        );
        self.plan
            .fwd(fourier_re0, fourier_re1, fourier_im0, fourier_im1);
    }

    fn backward_with_conv_split(
        self,
        standard_lo: &mut [u64],
        standard_hi: &mut [u64],
        fourier_re0: &[f64],
        fourier_re1: &[f64],
        fourier_im0: &[f64],
        fourier_im1: &[f64],
        conv_fn: impl Fn(&mut [u64], &mut [u64], &mut [u64], &mut [u64], &[f64], &[f64], &[f64], &[f64]),
        stack: &mut PodStack,
    ) {
        let n = standard_lo.len();
        debug_assert_eq!(n, 2 * fourier_re0.len());
        debug_assert_eq!(n, 2 * fourier_re1.len());
        debug_assert_eq!(n, 2 * fourier_im0.len());
        debug_assert_eq!(n, 2 * fourier_im1.len());

        let (tmp_re0, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_re0.iter().copied());
        let (tmp_re1, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_re1.iter().copied());
        let (tmp_im0, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_im0.iter().copied());
        let (tmp_im1, _) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_im1.iter().copied());

        self.plan.inv(tmp_re0, tmp_re1, tmp_im0, tmp_im1);

        let (standard_re_lo, standard_im_lo) = standard_lo.split_at_mut(n / 2);
        let (standard_re_hi, standard_im_hi) = standard_hi.split_at_mut(n / 2);
        conv_fn(
            standard_re_lo,
            standard_re_hi,
            standard_im_lo,
            standard_im_hi,
            tmp_re0,
            tmp_re1,
            tmp_im0,
            tmp_im1,
        );
    }
}

/// Workaround implementation of the arithmetic shift on 64 bits integer for avx2
#[inline(always)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn mm256_sra_epi64_avx2(
    simd: pulp::x86::V3,
    input: pulp::i64x4,
    shift: pulp::u64x4,
) -> pulp::i64x4 {
    struct Sra64 {
        simd: pulp::x86::V3,
        input: pulp::i64x4,
        shift: pulp::u64x4,
    }

    impl pulp::NullaryFnOnce for Sra64 {
        type Output = pulp::i64x4;

        fn call(self) -> Self::Output {
            let Self { simd, input, shift } = self;

            // Proposed algorithm:
            // take the top bit (sign)
            // turn it into a mask m (0 -> 0, 1 -> u64::MAX)
            // compute x = a ^ m
            // compute y = shr_logical(x, b)
            // compute result = y ^ m

            let zero = simd.splat_u64x4(0);

            let input = pulp::cast(input);
            // Get the MSB giving the sign
            let sign = simd.shr_const_u64x4::<63>(input);
            // 0 if input >= 0 else == -1 == 0xFFFF_FFFF_FFFF_FFFF == u64::MAX
            let sign_mask = simd.wrapping_sub_u64x4(zero, sign);
            // If sign_mask == 0 values stays the same
            // else all bits are inverted, the nice property is that if the top bit is a 1 then it
            // becomes a 0 (see shr comment as to why it's awesome)
            let masked_input = simd.xor_u64x4(input, sign_mask);
            // If sign_mask == 0, we are shifting in 0s and the last inversion won't change anything
            // It works as expected
            // If sign_mask == -1 then the 0s we shift in will be inverted at the last step and so
            // the logical shift is acting as an arithmetic shift
            let shifted = simd.shr_dyn_u64x4(masked_input, shift);
            pulp::cast(simd.xor_u64x4(shifted, sign_mask))
        }
    }

    simd.vectorize(Sra64 { simd, input, shift })
}

#[cfg(test)]
mod tests {
    use super::*;

    // copied from the standard library
    fn next_up(this: f64) -> f64 {
        // We must use strictly integer arithmetic to prevent denormals from
        // flushing to zero after an arithmetic operation on some platforms.
        const TINY_BITS: u64 = 0x1; // Smallest positive f64.
        const CLEAR_SIGN_MASK: u64 = 0x7fff_ffff_ffff_ffff;

        let bits = this.to_bits();
        if this.is_nan() || bits == f64::INFINITY.to_bits() {
            return this;
        }

        let abs = bits & CLEAR_SIGN_MASK;
        let next_bits = if abs == 0 {
            TINY_BITS
        } else if bits == abs {
            bits + 1
        } else {
            bits - 1
        };
        f64::from_bits(next_bits)
    }

    fn ulp(x: f64) -> f64 {
        next_up(x.abs()) - x.abs()
    }

    #[test]
    fn test_f128_floor() {
        let a = f128(-11984547.0, -1.0316078675142442e-10);
        let b = f128_floor(a);

        assert!(b.1.abs() <= 0.5 * ulp(b.0));
    }

    #[test]
    fn test_arihtmetic_shr_split_u128() {
        use rand::prelude::*;

        let mut rng = rand::rng();
        for _ in 0..1000 {
            let positive = rng.gen_range(0i128..=i128::MAX);
            let negative = rng.gen_range(i128::MIN..0);

            for shift in 0..127 {
                for case in [positive, negative] {
                    let case_lo = case as u64;
                    let case_hi = (case >> 64) as u64;

                    let case_shifted = case >> shift;
                    let (res_lo, res_hi) = arithmetic_shr_split_u128(case_lo, case_hi, shift);
                    let res_as_u128 = (res_lo as u128) | ((res_hi as u128) << 64);
                    assert_eq!(res_as_u128, case_shifted as u128);
                }
            }

            // Shift hardcoded as 128
            for case in [positive, negative] {
                let expected = if case > 0 { 0u128 } else { u128::MAX };

                let case_lo = case as u64;
                let case_hi = (case >> 64) as u64;

                let (res_lo, res_hi) = arithmetic_shr_split_u128(case_lo, case_hi, 128);
                let res_as_u128 = (res_lo as u128) | ((res_hi as u128) << 64);
                assert_eq!(res_as_u128, expected);
            }
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_sra_avx2() {
        use rand::prelude::*;

        let Some(simd) = pulp::x86::V3::try_new() else {
            return;
        };

        let mut rng = rand::rng();
        for _ in 0..1000 {
            for shift in 0..63 {
                let shift = [shift as u64; 4];
                for range in [0i64..=i64::MAX, i64::MIN..=-1] {
                    let input: [i64; 4] = core::array::from_fn(|_| rng.gen_range(range.clone()));

                    let res_i64 = mm256_sra_epi64_avx2(simd, pulp::cast(input), pulp::cast(shift));
                    let res_as_array: [i64; 4] = pulp::cast(res_i64);

                    let expected: [i64; 4] = core::array::from_fn(|idx| input[idx] >> shift[idx]);

                    assert_eq!(res_as_array, expected);
                }
            }

            // Shift hardcoded as 64
            for range in [0i64..=i64::MAX, i64::MIN..=-1] {
                let shift = [64u64; 4];
                let input: [i64; 4] = core::array::from_fn(|_| rng.gen_range(range.clone()));

                let res_i64 = mm256_sra_epi64_avx2(simd, pulp::cast(input), pulp::cast(shift));
                let res_as_array: [i64; 4] = pulp::cast(res_i64);

                let expected: [i64; 4] =
                    core::array::from_fn(|idx| if input[idx] > 0 { 0 } else { -1 });

                assert_eq!(res_as_array, expected);
            }
        }
    }
}
