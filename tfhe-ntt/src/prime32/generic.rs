use super::RECURSION_THRESHOLD;
use crate::fastdiv::Div32;
use core::iter::zip;

#[allow(unused_imports)]
use pulp::*;

#[inline(always)]
pub(crate) fn add(p: u32, a: u32, b: u32) -> u32 {
    let neg_b = p - b;
    if a >= neg_b {
        a - neg_b
    } else {
        a + b
    }
}

#[inline(always)]
pub(crate) fn sub(p: u32, a: u32, b: u32) -> u32 {
    let neg_b = p - b;
    if a >= b {
        a - b
    } else {
        a + neg_b
    }
}

#[inline(always)]
pub(crate) fn mul(p: Div32, a: u32, b: u32) -> u32 {
    Div32::rem_u64(a as u64 * b as u64, p)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn add_avx2(simd: crate::V3, p: u32x8, a: u32x8, b: u32x8) -> u32x8 {
    let neg_b = simd.wrapping_sub_u32x8(p, b);
    let not_a_ge_neg_b = simd.cmp_gt_u32x8(neg_b, a);
    simd.select_u32x8(
        not_a_ge_neg_b,
        simd.wrapping_add_u32x8(a, b),
        simd.wrapping_sub_u32x8(a, neg_b),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn sub_avx2(simd: crate::V3, p: u32x8, a: u32x8, b: u32x8) -> u32x8 {
    let neg_b = simd.wrapping_sub_u32x8(p, b);
    let not_a_ge_b = simd.cmp_gt_u32x8(b, a);
    simd.select_u32x8(
        not_a_ge_b,
        simd.wrapping_add_u32x8(a, neg_b),
        simd.wrapping_sub_u32x8(a, b),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn mul_avx2(
    simd: crate::V3,
    p: u32x8,
    p_div0: u32x8,
    p_div1: u32x8,
    p_div2: u32x8,
    p_div3: u32x8,
    a: u32x8,
    b: u32x8,
) -> u32x8 {
    #[inline(always)]
    fn mul_with_carry(simd: crate::V3, l: u32x8, r: u32x8, c: u32x8) -> (u32x8, u32x8) {
        let (lo, hi) = simd.widening_mul_u32x8(l, r);
        let lo_plus_c = simd.wrapping_add_u32x8(lo, c);
        let overflow = simd.cmp_gt_u32x8(lo, lo_plus_c);
        (lo_plus_c, simd.wrapping_sub_u32x8(hi, cast(overflow)))
    }
    #[inline(always)]
    fn mul_u128_u32(
        simd: crate::V3,
        lhs0: u32x8,
        lhs1: u32x8,
        lhs2: u32x8,
        lhs3: u32x8,
        rhs: u32x8,
    ) -> (u32x8, u32x8, u32x8, u32x8, u32x8) {
        let (x0, carry) = simd.widening_mul_u32x8(lhs0, rhs);
        let (x1, carry) = mul_with_carry(simd, lhs1, rhs, carry);
        let (x2, carry) = mul_with_carry(simd, lhs2, rhs, carry);
        let (x3, carry) = mul_with_carry(simd, lhs3, rhs, carry);
        (x0, x1, x2, x3, carry)
    }

    #[inline(always)]
    fn wrapping_mul_u128_u64(
        simd: crate::V3,
        lhs0: u32x8,
        lhs1: u32x8,
        lhs2: u32x8,
        lhs3: u32x8,
        rhs0: u32x8,
        rhs1: u32x8,
    ) -> (u32x8, u32x8, u32x8, u32x8) {
        let (x0, x1, x2, x3, _) = mul_u128_u32(simd, lhs0, lhs1, lhs2, lhs3, rhs0);
        let (y0, y1, y2, _, _) = mul_u128_u32(simd, lhs0, lhs1, lhs2, lhs3, rhs1);

        let z0 = x0;

        let z1 = simd.wrapping_add_u32x8(x1, y0);
        let carry: u32x8 = cast(simd.cmp_gt_u32x8(x1, z1));

        let z2 = simd.wrapping_add_u32x8(x2, y1);
        let o0 = simd.cmp_gt_u32x8(x2, z2);
        let o1 = simd.cmp_eq_u32x8(z2, carry);
        let z2 = simd.wrapping_sub_u32x8(z2, carry);
        let carry: u32x8 = cast(simd.or_m32x8(o0, o1));

        let z3 = simd.wrapping_add_u32x8(x3, y2);
        let z3 = simd.wrapping_sub_u32x8(z3, carry);

        (z0, z1, z2, z3)
    }

    let (lo, hi) = simd.widening_mul_u32x8(a, b);
    let (low_bits0, low_bits1, low_bits2, low_bits3) =
        wrapping_mul_u128_u64(simd, p_div0, p_div1, p_div2, p_div3, lo, hi);

    mul_u128_u32(simd, low_bits0, low_bits1, low_bits2, low_bits3, p).4
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[inline(always)]
fn add_avx512(simd: crate::V4, p: u32x16, a: u32x16, b: u32x16) -> u32x16 {
    let neg_b = simd.wrapping_sub_u32x16(p, b);
    let a_ge_neg_b = simd.cmp_ge_u32x16(a, neg_b);
    simd.select_u32x16(
        a_ge_neg_b,
        simd.wrapping_sub_u32x16(a, neg_b),
        simd.wrapping_add_u32x16(a, b),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[inline(always)]
fn sub_avx512(simd: crate::V4, p: u32x16, a: u32x16, b: u32x16) -> u32x16 {
    let neg_b = simd.wrapping_sub_u32x16(p, b);
    let a_ge_b = simd.cmp_ge_u32x16(a, b);
    simd.select_u32x16(
        a_ge_b,
        simd.wrapping_sub_u32x16(a, b),
        simd.wrapping_add_u32x16(a, neg_b),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[inline(always)]
fn mul_avx512(
    simd: crate::V4,
    p: u32x16,
    p_div0: u32x16,
    p_div1: u32x16,
    p_div2: u32x16,
    p_div3: u32x16,
    a: u32x16,
    b: u32x16,
) -> u32x16 {
    #[inline(always)]
    fn mul_with_carry(simd: crate::V4, l: u32x16, r: u32x16, c: u32x16) -> (u32x16, u32x16) {
        let (lo, hi) = simd.widening_mul_u32x16(l, r);
        let lo_plus_c = simd.wrapping_add_u32x16(lo, c);
        let overflow = simd.convert_mask_b16_to_u32x16(simd.cmp_gt_u32x16(lo, lo_plus_c));
        (lo_plus_c, simd.wrapping_sub_u32x16(hi, overflow))
    }
    #[inline(always)]
    fn mul_u128_u32(
        simd: crate::V4,
        lhs0: u32x16,
        lhs1: u32x16,
        lhs2: u32x16,
        lhs3: u32x16,
        rhs: u32x16,
    ) -> (u32x16, u32x16, u32x16, u32x16, u32x16) {
        let (x0, carry) = simd.widening_mul_u32x16(lhs0, rhs);
        let (x1, carry) = mul_with_carry(simd, lhs1, rhs, carry);
        let (x2, carry) = mul_with_carry(simd, lhs2, rhs, carry);
        let (x3, carry) = mul_with_carry(simd, lhs3, rhs, carry);
        (x0, x1, x2, x3, carry)
    }

    #[inline(always)]
    fn wrapping_mul_u128_u64(
        simd: crate::V4,
        lhs0: u32x16,
        lhs1: u32x16,
        lhs2: u32x16,
        lhs3: u32x16,
        rhs0: u32x16,
        rhs1: u32x16,
    ) -> (u32x16, u32x16, u32x16, u32x16) {
        let (x0, x1, x2, x3, _) = mul_u128_u32(simd, lhs0, lhs1, lhs2, lhs3, rhs0);
        let (y0, y1, y2, _, _) = mul_u128_u32(simd, lhs0, lhs1, lhs2, lhs3, rhs1);

        let z0 = x0;

        let z1 = simd.wrapping_add_u32x16(x1, y0);
        let carry = simd.convert_mask_b16_to_u32x16(simd.cmp_gt_u32x16(x1, z1));

        let z2 = simd.wrapping_add_u32x16(x2, y1);
        let o0 = simd.cmp_gt_u32x16(x2, z2);
        let o1 = simd.cmp_eq_u32x16(z2, carry);
        let z2 = simd.wrapping_sub_u32x16(z2, carry);
        let carry = simd.convert_mask_b16_to_u32x16(b16(o0.0 | o1.0));

        let z3 = simd.wrapping_add_u32x16(x3, y2);
        let z3 = simd.wrapping_sub_u32x16(z3, carry);

        (z0, z1, z2, z3)
    }

    let (lo, hi) = simd.widening_mul_u32x16(a, b);
    let (low_bits0, low_bits1, low_bits2, low_bits3) =
        wrapping_mul_u128_u64(simd, p_div0, p_div1, p_div2, p_div3, lo, hi);

    mul_u128_u32(simd, low_bits0, low_bits1, low_bits2, low_bits3, p).4
}

pub(crate) fn fwd_breadth_first_scalar(
    data: &mut [u32],
    p: u32,
    p_div: Div32,
    twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    let n = data.len();
    debug_assert!(n.is_power_of_two());

    let mut t = n / 2;
    let mut m = 1;
    let mut w_idx = (m << recursion_depth) + recursion_half * m;

    while m < n {
        let w = &twid[w_idx..];

        for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
            let (z0, z1) = data.split_at_mut(t);

            for (z0, z1) in zip(z0, z1) {
                let z1w = mul(p_div, *z1, w1);

                (*z0, *z1) = (add(p, *z0, z1w), sub(p, *z0, z1w));
            }
        }

        t /= 2;
        m *= 2;
        w_idx *= 2;
    }
}

pub(crate) fn fwd_depth_first_scalar(
    data: &mut [u32],
    p: u32,
    p_div: Div32,
    twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    let n = data.len();
    debug_assert!(n.is_power_of_two());

    if n <= RECURSION_THRESHOLD {
        fwd_breadth_first_scalar(data, p, p_div, twid, recursion_depth, recursion_half);
    } else {
        let t = n / 2;
        let m = 1;
        let w_idx = (m << recursion_depth) + m * recursion_half;

        let w = &twid[w_idx..];

        for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
            let (z0, z1) = data.split_at_mut(t);

            for (z0, z1) in zip(z0, z1) {
                let z1w = mul(p_div, *z1, w1);

                (*z0, *z1) = (add(p, *z0, z1w), sub(p, *z0, z1w));
            }
        }

        let (data0, data1) = data.split_at_mut(n / 2);
        fwd_depth_first_scalar(
            data0,
            p,
            p_div,
            twid,
            recursion_depth + 1,
            recursion_half * 2,
        );
        fwd_depth_first_scalar(
            data1,
            p,
            p_div,
            twid,
            recursion_depth + 1,
            recursion_half * 2 + 1,
        );
    }
}

pub(crate) fn inv_breadth_first_scalar(
    data: &mut [u32],
    p: u32,
    p_div: Div32,
    inv_twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    let n = data.len();
    debug_assert!(n.is_power_of_two());

    let mut t = 1;
    let mut m = n;
    let mut w_idx = (m << recursion_depth) + recursion_half * m;

    while m > 1 {
        m /= 2;
        w_idx /= 2;

        let w = &inv_twid[w_idx..];

        for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
            let (z0, z1) = data.split_at_mut(t);

            for (z0, z1) in zip(z0, z1) {
                (*z0, *z1) = (add(p, *z0, *z1), mul(p_div, sub(p, *z0, *z1), w1));
            }
        }

        t *= 2;
    }
}

pub(crate) fn inv_depth_first_scalar(
    data: &mut [u32],
    p: u32,
    p_div: Div32,
    inv_twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    let n = data.len();
    debug_assert!(n.is_power_of_two());
    if n <= RECURSION_THRESHOLD {
        inv_breadth_first_scalar(data, p, p_div, inv_twid, recursion_depth, recursion_half);
    } else {
        let (data0, data1) = data.split_at_mut(n / 2);
        inv_depth_first_scalar(
            data0,
            p,
            p_div,
            inv_twid,
            recursion_depth + 1,
            recursion_half * 2,
        );
        inv_depth_first_scalar(
            data1,
            p,
            p_div,
            inv_twid,
            recursion_depth + 1,
            recursion_half * 2 + 1,
        );

        let t = n / 2;
        let m = 1;
        let w_idx = (m << recursion_depth) + m * recursion_half;

        let w = &inv_twid[w_idx..];

        for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
            let (z0, z1) = data.split_at_mut(t);

            for (z0, z1) in zip(z0, z1) {
                (*z0, *z1) = (add(p, *z0, *z1), mul(p_div, sub(p, *z0, *z1), w1));
            }
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn fwd_breadth_first_avx2(
    simd: crate::V3,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V3,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                twid,
                recursion_depth,
                recursion_half,
            } = self;
            let n = data.len();
            debug_assert!(n.is_power_of_two());

            let mut t = n / 2;
            let mut m = 1;
            let mut w_idx = (m << recursion_depth) + recursion_half * m;
            let p = simd.splat_u32x8(p);
            let p_div0 = simd.splat_u32x8(p_div.0);
            let p_div1 = simd.splat_u32x8(p_div.1);
            let p_div2 = simd.splat_u32x8(p_div.2);
            let p_div3 = simd.splat_u32x8(p_div.3);

            while m < n / 8 {
                let w = &twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = as_arrays_mut::<8, _>(z0).0;
                    let z1 = as_arrays_mut::<8, _>(z1).0;
                    let w1 = simd.splat_u32x8(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        let z1w = mul_avx2(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                        (z0, z1) = (add_avx2(simd, p, z0, z1w), sub_avx2(simd, p, z0, z1w));
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
                    }
                }

                t /= 2;
                m *= 2;
                w_idx *= 2;
            }

            // m = n / 8
            // t = 4
            {
                let w = as_arrays::<2, _>(&twid[w_idx..]).0;
                let data = as_arrays_mut::<8, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute4_u32x8(*w1);
                    let [mut z0, mut z1] = simd.interleave4_u32x8(cast(*z0z0z0z0z1z1z1z1));
                    let z1w = mul_avx2(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                    (z0, z1) = (add_avx2(simd, p, z0, z1w), sub_avx2(simd, p, z0, z1w));
                    *z0z0z0z0z1z1z1z1 = cast(simd.interleave4_u32x8([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 4
            // t = 2
            {
                let w = as_arrays::<4, _>(&twid[w_idx..]).0;
                let data = as_arrays_mut::<8, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u32x8(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u32x8(cast(*z0z0z1z1));
                    let z1w = mul_avx2(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                    (z0, z1) = (add_avx2(simd, p, z0, z1w), sub_avx2(simd, p, z0, z1w));
                    *z0z0z1z1 = cast(simd.interleave2_u32x8([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 2
            // t = 1
            {
                let w = as_arrays::<8, _>(&twid[w_idx..]).0;
                let data = as_arrays_mut::<8, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u32x8(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u32x8(cast(*z0z1));
                    let z1w = mul_avx2(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                    (z0, z1) = (add_avx2(simd, p, z0, z1w), sub_avx2(simd, p, z0, z1w));
                    *z0z1 = cast(simd.interleave1_u32x8([z0, z1]));
                }
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        twid,
        recursion_depth,
        recursion_half,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn fwd_depth_first_avx2(
    simd: crate::V3,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V3,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                twid,
                recursion_depth,
                recursion_half,
            } = self;

            let n = data.len();
            debug_assert!(n.is_power_of_two());

            if n <= RECURSION_THRESHOLD {
                fwd_breadth_first_avx2(simd, data, p, p_div, twid, recursion_depth, recursion_half);
            } else {
                {
                    let t = n / 2;
                    let m = 1;
                    let w_idx = (m << recursion_depth) + m * recursion_half;
                    let w = &twid[w_idx..];
                    let p = simd.splat_u32x8(p);
                    let p_div0 = simd.splat_u32x8(p_div.0);
                    let p_div1 = simd.splat_u32x8(p_div.1);
                    let p_div2 = simd.splat_u32x8(p_div.2);
                    let p_div3 = simd.splat_u32x8(p_div.3);

                    for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                        let (z0, z1) = data.split_at_mut(t);
                        let z0 = as_arrays_mut::<8, _>(z0).0;
                        let z1 = as_arrays_mut::<8, _>(z1).0;
                        let w1 = simd.splat_u32x8(w1);

                        for (z0_, z1_) in zip(z0, z1) {
                            let mut z0 = cast(*z0_);
                            let mut z1 = cast(*z1_);
                            let z1w = mul_avx2(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                            (z0, z1) = (add_avx2(simd, p, z0, z1w), sub_avx2(simd, p, z0, z1w));
                            *z0_ = cast(z0);
                            *z1_ = cast(z1);
                        }
                    }
                }

                let (data0, data1) = data.split_at_mut(n / 2);
                fwd_depth_first_avx2(
                    simd,
                    data0,
                    p,
                    p_div,
                    twid,
                    recursion_depth + 1,
                    recursion_half * 2,
                );
                fwd_depth_first_avx2(
                    simd,
                    data1,
                    p,
                    p_div,
                    twid,
                    recursion_depth + 1,
                    recursion_half * 2 + 1,
                );
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        twid,
        recursion_depth,
        recursion_half,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn inv_breadth_first_avx2(
    simd: crate::V3,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    inv_twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V3,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        inv_twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                inv_twid,
                recursion_depth,
                recursion_half,
            } = self;
            let n = data.len();
            debug_assert!(n.is_power_of_two());

            let mut t = 1;
            let mut m = n;
            let mut w_idx = (m << recursion_depth) + recursion_half * m;
            let p = simd.splat_u32x8(p);
            let p_div0 = simd.splat_u32x8(p_div.0);
            let p_div1 = simd.splat_u32x8(p_div.1);
            let p_div2 = simd.splat_u32x8(p_div.2);
            let p_div3 = simd.splat_u32x8(p_div.3);

            // m = n / 2
            // t = 1
            {
                m /= 2;
                w_idx /= 2;

                let w = as_arrays::<8, _>(&inv_twid[w_idx..]).0;
                let data = as_arrays_mut::<8, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u32x8(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u32x8(cast(*z0z1));
                    (z0, z1) = (
                        add_avx2(simd, p, z0, z1),
                        mul_avx2(
                            simd,
                            p,
                            p_div0,
                            p_div1,
                            p_div2,
                            p_div3,
                            sub_avx2(simd, p, z0, z1),
                            w1,
                        ),
                    );
                    *z0z1 = cast(simd.interleave1_u32x8([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 4
            // t = 2
            {
                m /= 2;
                w_idx /= 2;

                let w = as_arrays::<4, _>(&inv_twid[w_idx..]).0;
                let data = as_arrays_mut::<8, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u32x8(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u32x8(cast(*z0z0z1z1));
                    (z0, z1) = (
                        add_avx2(simd, p, z0, z1),
                        mul_avx2(
                            simd,
                            p,
                            p_div0,
                            p_div1,
                            p_div2,
                            p_div3,
                            sub_avx2(simd, p, z0, z1),
                            w1,
                        ),
                    );
                    *z0z0z1z1 = cast(simd.interleave2_u32x8([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 8
            // t = 4
            {
                m /= 2;
                w_idx /= 2;

                let w = as_arrays::<2, _>(&inv_twid[w_idx..]).0;
                let data = as_arrays_mut::<8, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute4_u32x8(*w1);
                    let [mut z0, mut z1] = simd.interleave4_u32x8(cast(*z0z0z0z0z1z1z1z1));
                    (z0, z1) = (
                        add_avx2(simd, p, z0, z1),
                        mul_avx2(
                            simd,
                            p,
                            p_div0,
                            p_div1,
                            p_div2,
                            p_div3,
                            sub_avx2(simd, p, z0, z1),
                            w1,
                        ),
                    );
                    *z0z0z0z0z1z1z1z1 = cast(simd.interleave4_u32x8([z0, z1]));
                }

                t *= 2;
            }

            while m > 1 {
                m /= 2;
                w_idx /= 2;

                let w = &inv_twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = as_arrays_mut::<8, _>(z0).0;
                    let z1 = as_arrays_mut::<8, _>(z1).0;
                    let w1 = simd.splat_u32x8(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        (z0, z1) = (
                            add_avx2(simd, p, z0, z1),
                            mul_avx2(
                                simd,
                                p,
                                p_div0,
                                p_div1,
                                p_div2,
                                p_div3,
                                sub_avx2(simd, p, z0, z1),
                                w1,
                            ),
                        );
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
                    }
                }

                t *= 2;
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        inv_twid,
        recursion_depth,
        recursion_half,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn inv_depth_first_avx2(
    simd: crate::V3,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    inv_twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V3,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        inv_twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                inv_twid,
                recursion_depth,
                recursion_half,
            } = self;

            let n = data.len();
            debug_assert!(n.is_power_of_two());

            if n <= RECURSION_THRESHOLD {
                inv_breadth_first_avx2(
                    simd,
                    data,
                    p,
                    p_div,
                    inv_twid,
                    recursion_depth,
                    recursion_half,
                );
            } else {
                let (data0, data1) = data.split_at_mut(n / 2);
                inv_depth_first_avx2(
                    simd,
                    data0,
                    p,
                    p_div,
                    inv_twid,
                    recursion_depth + 1,
                    recursion_half * 2,
                );
                inv_depth_first_avx2(
                    simd,
                    data1,
                    p,
                    p_div,
                    inv_twid,
                    recursion_depth + 1,
                    recursion_half * 2 + 1,
                );

                {
                    let t = n / 2;
                    let m = 1;
                    let w_idx = (m << recursion_depth) + m * recursion_half;
                    let w = &inv_twid[w_idx..];
                    let p = simd.splat_u32x8(p);
                    let p_div0 = simd.splat_u32x8(p_div.0);
                    let p_div1 = simd.splat_u32x8(p_div.1);
                    let p_div2 = simd.splat_u32x8(p_div.2);
                    let p_div3 = simd.splat_u32x8(p_div.3);

                    for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                        let (z0, z1) = data.split_at_mut(t);
                        let z0 = as_arrays_mut::<8, _>(z0).0;
                        let z1 = as_arrays_mut::<8, _>(z1).0;
                        let w1 = simd.splat_u32x8(w1);

                        for (z0_, z1_) in zip(z0, z1) {
                            let mut z0 = cast(*z0_);
                            let mut z1 = cast(*z1_);
                            (z0, z1) = (
                                add_avx2(simd, p, z0, z1),
                                mul_avx2(
                                    simd,
                                    p,
                                    p_div0,
                                    p_div1,
                                    p_div2,
                                    p_div3,
                                    sub_avx2(simd, p, z0, z1),
                                    w1,
                                ),
                            );
                            *z0_ = cast(z0);
                            *z1_ = cast(z1);
                        }
                    }
                }
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        inv_twid,
        recursion_depth,
        recursion_half,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn fwd_breadth_first_avx512(
    simd: crate::V4,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V4,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                twid,
                recursion_depth,
                recursion_half,
            } = self;
            let n = data.len();
            debug_assert!(n.is_power_of_two());

            let mut t = n / 2;
            let mut m = 1;
            let mut w_idx = (m << recursion_depth) + recursion_half * m;
            let p = simd.splat_u32x16(p);
            let p_div0 = simd.splat_u32x16(p_div.0);
            let p_div1 = simd.splat_u32x16(p_div.1);
            let p_div2 = simd.splat_u32x16(p_div.2);
            let p_div3 = simd.splat_u32x16(p_div.3);

            while m < n / 16 {
                let w = &twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = as_arrays_mut::<16, _>(z0).0;
                    let z1 = as_arrays_mut::<16, _>(z1).0;
                    let w1 = simd.splat_u32x16(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        let z1w = mul_avx512(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                        (z0, z1) = (add_avx512(simd, p, z0, z1w), sub_avx512(simd, p, z0, z1w));
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
                    }
                }

                t /= 2;
                m *= 2;
                w_idx *= 2;
            }

            // m = n / 16
            // t = 8
            {
                let w = as_arrays::<2, _>(&twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute8_u32x16(*w1);
                    let [mut z0, mut z1] =
                        simd.interleave8_u32x16(cast(*z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1));
                    let z1w = mul_avx512(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                    (z0, z1) = (add_avx512(simd, p, z0, z1w), sub_avx512(simd, p, z0, z1w));
                    *z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1 = cast(simd.interleave8_u32x16([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 8
            // t = 4
            {
                let w = as_arrays::<4, _>(&twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute4_u32x16(*w1);
                    let [mut z0, mut z1] = simd.interleave4_u32x16(cast(*z0z0z0z0z1z1z1z1));
                    let z1w = mul_avx512(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                    (z0, z1) = (add_avx512(simd, p, z0, z1w), sub_avx512(simd, p, z0, z1w));
                    *z0z0z0z0z1z1z1z1 = cast(simd.interleave4_u32x16([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 4
            // t = 2
            {
                let w = as_arrays::<8, _>(&twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u32x16(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u32x16(cast(*z0z0z1z1));
                    let z1w = mul_avx512(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                    (z0, z1) = (add_avx512(simd, p, z0, z1w), sub_avx512(simd, p, z0, z1w));
                    *z0z0z1z1 = cast(simd.interleave2_u32x16([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 2
            // t = 1
            {
                let w = as_arrays::<16, _>(&twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u32x16(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u32x16(cast(*z0z1));
                    let z1w = mul_avx512(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                    (z0, z1) = (add_avx512(simd, p, z0, z1w), sub_avx512(simd, p, z0, z1w));
                    *z0z1 = cast(simd.interleave1_u32x16([z0, z1]));
                }
            }
        }
    }
    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        twid,
        recursion_depth,
        recursion_half,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn fwd_depth_first_avx512(
    simd: crate::V4,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V4,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                twid,
                recursion_depth,
                recursion_half,
            } = self;

            let n = data.len();
            debug_assert!(n.is_power_of_two());

            if n <= RECURSION_THRESHOLD {
                fwd_breadth_first_avx512(
                    simd,
                    data,
                    p,
                    p_div,
                    twid,
                    recursion_depth,
                    recursion_half,
                );
            } else {
                {
                    let t = n / 2;
                    let m = 1;
                    let w_idx = (m << recursion_depth) + m * recursion_half;
                    let w = &twid[w_idx..];
                    let p = simd.splat_u32x16(p);
                    let p_div0 = simd.splat_u32x16(p_div.0);
                    let p_div1 = simd.splat_u32x16(p_div.1);
                    let p_div2 = simd.splat_u32x16(p_div.2);
                    let p_div3 = simd.splat_u32x16(p_div.3);

                    for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                        let (z0, z1) = data.split_at_mut(t);
                        let z0 = as_arrays_mut::<16, _>(z0).0;
                        let z1 = as_arrays_mut::<16, _>(z1).0;
                        let w1 = simd.splat_u32x16(w1);

                        for (z0_, z1_) in zip(z0, z1) {
                            let mut z0 = cast(*z0_);
                            let mut z1 = cast(*z1_);
                            let z1w = mul_avx512(simd, p, p_div0, p_div1, p_div2, p_div3, z1, w1);
                            (z0, z1) = (add_avx512(simd, p, z0, z1w), sub_avx512(simd, p, z0, z1w));
                            *z0_ = cast(z0);
                            *z1_ = cast(z1);
                        }
                    }
                }

                let (data0, data1) = data.split_at_mut(n / 2);
                fwd_depth_first_avx512(
                    simd,
                    data0,
                    p,
                    p_div,
                    twid,
                    recursion_depth + 1,
                    recursion_half * 2,
                );
                fwd_depth_first_avx512(
                    simd,
                    data1,
                    p,
                    p_div,
                    twid,
                    recursion_depth + 1,
                    recursion_half * 2 + 1,
                );
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        twid,
        recursion_depth,
        recursion_half,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn inv_breadth_first_avx512(
    simd: crate::V4,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    inv_twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V4,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        inv_twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                inv_twid,
                recursion_depth,
                recursion_half,
            } = self;
            let n = data.len();
            debug_assert!(n.is_power_of_two());

            let mut t = 1;
            let mut m = n;
            let mut w_idx = (m << recursion_depth) + recursion_half * m;
            let p = simd.splat_u32x16(p);
            let p_div0 = simd.splat_u32x16(p_div.0);
            let p_div1 = simd.splat_u32x16(p_div.1);
            let p_div2 = simd.splat_u32x16(p_div.2);
            let p_div3 = simd.splat_u32x16(p_div.3);

            // m = n / 2
            // t = 1
            {
                m /= 2;
                w_idx /= 2;

                let w = as_arrays::<16, _>(&inv_twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u32x16(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u32x16(cast(*z0z1));
                    (z0, z1) = (
                        add_avx512(simd, p, z0, z1),
                        mul_avx512(
                            simd,
                            p,
                            p_div0,
                            p_div1,
                            p_div2,
                            p_div3,
                            sub_avx512(simd, p, z0, z1),
                            w1,
                        ),
                    );
                    *z0z1 = cast(simd.interleave1_u32x16([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 4
            // t = 2
            {
                m /= 2;
                w_idx /= 2;

                let w = as_arrays::<8, _>(&inv_twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u32x16(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u32x16(cast(*z0z0z1z1));
                    (z0, z1) = (
                        add_avx512(simd, p, z0, z1),
                        mul_avx512(
                            simd,
                            p,
                            p_div0,
                            p_div1,
                            p_div2,
                            p_div3,
                            sub_avx512(simd, p, z0, z1),
                            w1,
                        ),
                    );
                    *z0z0z1z1 = cast(simd.interleave2_u32x16([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 8
            // t = 4
            {
                m /= 2;
                w_idx /= 2;

                let w = as_arrays::<4, _>(&inv_twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute4_u32x16(*w1);
                    let [mut z0, mut z1] = simd.interleave4_u32x16(cast(*z0z0z0z0z1z1z1z1));
                    (z0, z1) = (
                        add_avx512(simd, p, z0, z1),
                        mul_avx512(
                            simd,
                            p,
                            p_div0,
                            p_div1,
                            p_div2,
                            p_div3,
                            sub_avx512(simd, p, z0, z1),
                            w1,
                        ),
                    );
                    *z0z0z0z0z1z1z1z1 = cast(simd.interleave4_u32x16([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 16
            // t = 8
            {
                m /= 2;
                w_idx /= 2;

                let w = as_arrays::<2, _>(&inv_twid[w_idx..]).0;
                let data = as_arrays_mut::<16, _>(data).0;
                let data = as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute8_u32x16(*w1);
                    let [mut z0, mut z1] =
                        simd.interleave8_u32x16(cast(*z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1));
                    (z0, z1) = (
                        add_avx512(simd, p, z0, z1),
                        mul_avx512(
                            simd,
                            p,
                            p_div0,
                            p_div1,
                            p_div2,
                            p_div3,
                            sub_avx512(simd, p, z0, z1),
                            w1,
                        ),
                    );
                    *z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1 = cast(simd.interleave8_u32x16([z0, z1]));
                }

                t *= 2;
            }

            while m > 1 {
                m /= 2;
                w_idx /= 2;

                let w = &inv_twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = as_arrays_mut::<16, _>(z0).0;
                    let z1 = as_arrays_mut::<16, _>(z1).0;
                    let w1 = simd.splat_u32x16(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        (z0, z1) = (
                            add_avx512(simd, p, z0, z1),
                            mul_avx512(
                                simd,
                                p,
                                p_div0,
                                p_div1,
                                p_div2,
                                p_div3,
                                sub_avx512(simd, p, z0, z1),
                                w1,
                            ),
                        );
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
                    }
                }

                t *= 2;
            }
        }
    }
    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        inv_twid,
        recursion_depth,
        recursion_half,
    });
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn inv_depth_first_avx512(
    simd: crate::V4,
    data: &mut [u32],
    p: u32,
    p_div: (u32, u32, u32, u32),
    inv_twid: &[u32],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a> {
        simd: crate::V4,
        data: &'a mut [u32],
        p: u32,
        p_div: (u32, u32, u32, u32),
        inv_twid: &'a [u32],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data,
                p,
                p_div,
                inv_twid,
                recursion_depth,
                recursion_half,
            } = self;

            let n = data.len();
            debug_assert!(n.is_power_of_two());

            if n <= RECURSION_THRESHOLD {
                inv_breadth_first_avx512(
                    simd,
                    data,
                    p,
                    p_div,
                    inv_twid,
                    recursion_depth,
                    recursion_half,
                );
            } else {
                let (data0, data1) = data.split_at_mut(n / 2);
                inv_depth_first_avx512(
                    simd,
                    data0,
                    p,
                    p_div,
                    inv_twid,
                    recursion_depth + 1,
                    recursion_half * 2,
                );
                inv_depth_first_avx512(
                    simd,
                    data1,
                    p,
                    p_div,
                    inv_twid,
                    recursion_depth + 1,
                    recursion_half * 2 + 1,
                );

                {
                    let t = n / 2;
                    let m = 1;
                    let w_idx = (m << recursion_depth) + m * recursion_half;
                    let w = &inv_twid[w_idx..];
                    let p = simd.splat_u32x16(p);
                    let p_div0 = simd.splat_u32x16(p_div.0);
                    let p_div1 = simd.splat_u32x16(p_div.1);
                    let p_div2 = simd.splat_u32x16(p_div.2);
                    let p_div3 = simd.splat_u32x16(p_div.3);

                    for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                        let (z0, z1) = data.split_at_mut(t);
                        let z0 = as_arrays_mut::<16, _>(z0).0;
                        let z1 = as_arrays_mut::<16, _>(z1).0;
                        let w1 = simd.splat_u32x16(w1);

                        for (z0_, z1_) in zip(z0, z1) {
                            let mut z0 = cast(*z0_);
                            let mut z1 = cast(*z1_);
                            (z0, z1) = (
                                add_avx512(simd, p, z0, z1),
                                mul_avx512(
                                    simd,
                                    p,
                                    p_div0,
                                    p_div1,
                                    p_div2,
                                    p_div3,
                                    sub_avx512(simd, p, z0, z1),
                                    w1,
                                ),
                            );
                            *z0_ = cast(z0);
                            *z1_ = cast(z1);
                        }
                    }
                }
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data,
        p,
        p_div,
        inv_twid,
        recursion_depth,
        recursion_half,
    });
}

pub(crate) fn fwd_scalar(data: &mut [u32], p: u32, p_div: Div32, twid: &[u32]) {
    fwd_depth_first_scalar(data, p, p_div, twid, 0, 0);
}
pub(crate) fn inv_scalar(data: &mut [u32], p: u32, p_div: Div32, inv_twid: &[u32]) {
    inv_depth_first_scalar(data, p, p_div, inv_twid, 0, 0);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn fwd_avx2(simd: crate::V3, data: &mut [u32], p: u32, p_div: Div32, twid: &[u32]) {
    let p_div = p_div.double_reciprocal;
    let p_div = (
        p_div as u32,
        (p_div >> 32) as u32,
        (p_div >> 64) as u32,
        (p_div >> 96) as u32,
    );
    fwd_depth_first_avx2(simd, data, p, p_div, twid, 0, 0);
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn inv_avx2(simd: crate::V3, data: &mut [u32], p: u32, p_div: Div32, inv_twid: &[u32]) {
    let p_div = p_div.double_reciprocal;
    let p_div = (
        p_div as u32,
        (p_div >> 32) as u32,
        (p_div >> 64) as u32,
        (p_div >> 96) as u32,
    );
    inv_depth_first_avx2(simd, data, p, p_div, inv_twid, 0, 0);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn fwd_avx512(simd: crate::V4, data: &mut [u32], p: u32, p_div: Div32, twid: &[u32]) {
    let p_div = p_div.double_reciprocal;
    let p_div = (
        p_div as u32,
        (p_div >> 32) as u32,
        (p_div >> 64) as u32,
        (p_div >> 96) as u32,
    );
    fwd_depth_first_avx512(simd, data, p, p_div, twid, 0, 0);
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn inv_avx512(
    simd: crate::V4,
    data: &mut [u32],
    p: u32,
    p_div: Div32,
    inv_twid: &[u32],
) {
    let p_div = p_div.double_reciprocal;
    let p_div = (
        p_div as u32,
        (p_div >> 32) as u32,
        (p_div >> 64) as u32,
        (p_div >> 96) as u32,
    );
    inv_depth_first_avx512(simd, data, p, p_div, inv_twid, 0, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prime::largest_prime_in_arithmetic_progression64,
        prime32::{
            init_negacyclic_twiddles,
            tests::{mul, random_lhs_rhs_with_negacyclic_convolution},
        },
    };
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_product() {
        for n in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 31, 1 << 32).unwrap()
                as u32;

            let (lhs, rhs, negacyclic_convolution) =
                random_lhs_rhs_with_negacyclic_convolution(n, p);

            let mut twid = vec![0u32; n];
            let mut inv_twid = vec![0u32; n];
            init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

            let mut prod = vec![0u32; n];
            let mut lhs_fourier = lhs.clone();
            let mut rhs_fourier = rhs.clone();

            fwd_scalar(&mut lhs_fourier, p, Div32::new(p), &twid);
            fwd_scalar(&mut rhs_fourier, p, Div32::new(p), &twid);

            for i in 0..n {
                prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
            }

            inv_scalar(&mut prod, p, Div32::new(p), &inv_twid);
            let result = prod;

            for i in 0..n {
                assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u32));
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_product_avx2() {
        if let Some(simd) = crate::V3::try_new() {
            for n in [32, 64, 128, 256, 512, 1024] {
                let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 31, 1 << 32)
                    .unwrap() as u32;

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u32; n];
                let mut inv_twid = vec![0u32; n];
                init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

                let mut prod = vec![0u32; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                fwd_avx2(simd, &mut lhs_fourier, p, Div32::new(p), &twid);
                fwd_avx2(simd, &mut rhs_fourier, p, Div32::new(p), &twid);

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_avx2(simd, &mut prod, p, Div32::new(p), &inv_twid);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u32));
                }
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly")]
    #[test]
    fn test_product_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            for n in [32, 64, 128, 256, 512, 1024] {
                let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 31, 1 << 32)
                    .unwrap() as u32;

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u32; n];
                let mut inv_twid = vec![0u32; n];
                init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

                let mut prod = vec![0u32; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                fwd_avx512(simd, &mut lhs_fourier, p, Div32::new(p), &twid);
                fwd_avx512(simd, &mut rhs_fourier, p, Div32::new(p), &twid);

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_avx512(simd, &mut prod, p, Div32::new(p), &inv_twid);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u32));
                }
            }
        }
    }
}
