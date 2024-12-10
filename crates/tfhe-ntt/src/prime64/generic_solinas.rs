use super::RECURSION_THRESHOLD;
use crate::fastdiv::Div64;
use core::{fmt::Debug, iter::zip};

#[allow(unused_imports)]
use pulp::*;

pub(crate) trait PrimeModulus: Debug + Copy {
    type Div: Debug + Copy;

    fn add(self, a: u64, b: u64) -> u64;
    fn sub(self, a: u64, b: u64) -> u64;
    fn mul(p: Self::Div, a: u64, b: u64) -> u64;
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) trait PrimeModulusV3: Debug + Copy {
    type Div: Debug + Copy;

    fn add(self, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4;
    fn sub(self, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4;
    fn mul(p: Self::Div, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4;
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) trait PrimeModulusV4: Debug + Copy {
    type Div: Debug + Copy;

    fn add(self, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8;
    fn sub(self, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8;
    fn mul(p: Self::Div, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8;
}

#[derive(Copy, Clone, Debug)]
pub struct Solinas;

impl Solinas {
    pub const P: u64 = ((1u128 << 64) - (1u128 << 32) + 1u128) as u64;
}

impl PrimeModulus for u64 {
    type Div = Div64;

    #[inline(always)]
    fn add(self, a: u64, b: u64) -> u64 {
        let p = self;
        // a + b >= p
        // implies
        // a >= p - b

        let neg_b = p - b;
        if a >= neg_b {
            a - neg_b
        } else {
            a + b
        }
    }

    #[inline(always)]
    fn sub(self, a: u64, b: u64) -> u64 {
        let p = self;
        let neg_b = p - b;
        if a >= b {
            a - b
        } else {
            a + neg_b
        }
    }

    #[inline(always)]
    fn mul(p: Self::Div, a: u64, b: u64) -> u64 {
        Div64::rem_u128(a as u128 * b as u128, p)
    }
}

impl PrimeModulus for Solinas {
    type Div = ();

    #[inline(always)]
    fn add(self, a: u64, b: u64) -> u64 {
        let p = Self::P;
        let neg_b = p - b;
        if a >= neg_b {
            a - neg_b
        } else {
            a + b
        }
    }

    #[inline(always)]
    fn sub(self, a: u64, b: u64) -> u64 {
        let p = Self::P;
        let neg_b = p - b;
        if a >= b {
            a - b
        } else {
            a + neg_b
        }
    }

    #[inline(always)]
    fn mul(p: Self::Div, a: u64, b: u64) -> u64 {
        let _ = p;
        let p = Self::P;

        let wide = a as u128 * b as u128;

        // https://cp4space.hatsya.com/2021/09/01/an-efficient-prime-for-number-theoretic-transforms/
        let lo = wide as u64;
        let hi = (wide >> 64) as u64;
        let mid = hi & 0x0000_0000_FFFF_FFFF;
        let hi = (hi & 0xFFFF_FFFF_0000_0000) >> 32;

        let mut low2 = lo.wrapping_sub(hi);
        if hi > lo {
            low2 = low2.wrapping_add(p);
        }

        let mut product = mid << 32;
        product -= mid;

        let mut result = low2.wrapping_add(product);
        if (result < product) || (result >= p) {
            result = result.wrapping_sub(p);
        }
        result
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl PrimeModulusV3 for u64 {
    type Div = (u64, u64, u64, u64, u64);

    #[inline(always)]
    fn add(self, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4 {
        let p = simd.splat_u64x4(self);
        let neg_b = simd.wrapping_sub_u64x4(p, b);
        let not_a_ge_neg_b = simd.cmp_gt_u64x4(neg_b, a);
        simd.select_u64x4(
            not_a_ge_neg_b,
            simd.wrapping_add_u64x4(a, b),
            simd.wrapping_sub_u64x4(a, neg_b),
        )
    }

    #[inline(always)]
    fn sub(self, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4 {
        let p = simd.splat_u64x4(self);
        let neg_b = simd.wrapping_sub_u64x4(p, b);
        let not_a_ge_b = simd.cmp_gt_u64x4(b, a);
        simd.select_u64x4(
            not_a_ge_b,
            simd.wrapping_add_u64x4(a, neg_b),
            simd.wrapping_sub_u64x4(a, b),
        )
    }

    #[inline(always)]
    fn mul(p: Self::Div, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4 {
        #[inline(always)]
        fn mul_with_carry(simd: crate::V3, l: u64x4, r: u64x4, c: u64x4) -> (u64x4, u64x4) {
            let (lo, hi) = simd.widening_mul_u64x4(l, r);
            let lo_plus_c = simd.wrapping_add_u64x4(lo, c);
            let overflow = cast(simd.cmp_gt_u64x4(lo, lo_plus_c));
            (lo_plus_c, simd.wrapping_sub_u64x4(hi, overflow))
        }

        #[inline(always)]
        fn mul_u256_u64(
            simd: crate::V3,
            lhs0: u64x4,
            lhs1: u64x4,
            lhs2: u64x4,
            lhs3: u64x4,
            rhs: u64x4,
        ) -> (u64x4, u64x4, u64x4, u64x4, u64x4) {
            let (x0, carry) = simd.widening_mul_u64x4(lhs0, rhs);
            let (x1, carry) = mul_with_carry(simd, lhs1, rhs, carry);
            let (x2, carry) = mul_with_carry(simd, lhs2, rhs, carry);
            let (x3, carry) = mul_with_carry(simd, lhs3, rhs, carry);
            (x0, x1, x2, x3, carry)
        }

        #[inline(always)]
        fn wrapping_mul_u256_u128(
            simd: crate::V3,
            lhs0: u64x4,
            lhs1: u64x4,
            lhs2: u64x4,
            lhs3: u64x4,
            rhs0: u64x4,
            rhs1: u64x4,
        ) -> (u64x4, u64x4, u64x4, u64x4) {
            let (x0, x1, x2, x3, _) = mul_u256_u64(simd, lhs0, lhs1, lhs2, lhs3, rhs0);
            let (y0, y1, y2, _, _) = mul_u256_u64(simd, lhs0, lhs1, lhs2, lhs3, rhs1);

            let z0 = x0;

            let z1 = simd.wrapping_add_u64x4(x1, y0);
            let carry = cast(simd.cmp_gt_u64x4(x1, z1));

            let z2 = simd.wrapping_add_u64x4(x2, y1);
            let o0 = cast(simd.cmp_gt_u64x4(x2, z2));
            let o1 = cast(simd.cmp_eq_u64x4(z2, carry));
            let z2 = simd.wrapping_sub_u64x4(z2, carry);
            let carry = simd.or_u64x4(o0, o1);

            let z3 = simd.wrapping_add_u64x4(x3, y2);
            let z3 = simd.wrapping_sub_u64x4(z3, carry);

            (z0, z1, z2, z3)
        }

        let (p, p_div0, p_div1, p_div2, p_div3) = p;

        let p = simd.splat_u64x4(p as _);
        let p_div0 = simd.splat_u64x4(p_div0 as _);
        let p_div1 = simd.splat_u64x4(p_div1 as _);
        let p_div2 = simd.splat_u64x4(p_div2 as _);
        let p_div3 = simd.splat_u64x4(p_div3 as _);

        let (lo, hi) = simd.widening_mul_u64x4(a, b);
        let (low_bits0, low_bits1, low_bits2, low_bits3) =
            wrapping_mul_u256_u128(simd, p_div0, p_div1, p_div2, p_div3, lo, hi);

        mul_u256_u64(simd, low_bits0, low_bits1, low_bits2, low_bits3, p).4
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl PrimeModulusV3 for Solinas {
    type Div = ();

    #[inline(always)]
    fn add(self, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4 {
        let p = simd.splat_u64x4(Self::P);
        let neg_b = simd.wrapping_sub_u64x4(p, b);
        let not_a_ge_neg_b = simd.cmp_gt_u64x4(neg_b, a);
        simd.select_u64x4(
            not_a_ge_neg_b,
            simd.wrapping_add_u64x4(a, b),
            simd.wrapping_sub_u64x4(a, neg_b),
        )
    }

    #[inline(always)]
    fn sub(self, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4 {
        let p = simd.splat_u64x4(Self::P);
        let neg_b = simd.wrapping_sub_u64x4(p, b);
        let not_a_ge_b = simd.cmp_gt_u64x4(b, a);
        simd.select_u64x4(
            not_a_ge_b,
            simd.wrapping_add_u64x4(a, neg_b),
            simd.wrapping_sub_u64x4(a, b),
        )
    }

    #[inline(always)]
    fn mul(p: Self::Div, simd: crate::V3, a: u64x4, b: u64x4) -> u64x4 {
        let _ = p;

        let p = simd.splat_u64x4(Self::P as _);

        // https://cp4space.hatsya.com/2021/09/01/an-efficient-prime-for-number-theoretic-transforms/
        let (lo, hi) = simd.widening_mul_u64x4(a, b);
        let mid = simd.and_u64x4(hi, simd.splat_u64x4(0x0000_0000_FFFF_FFFF));
        let hi = simd.and_u64x4(hi, simd.splat_u64x4(0xFFFF_FFFF_0000_0000));
        let hi = simd.shr_const_u64x4::<32>(hi);

        let low2 = simd.wrapping_sub_u64x4(lo, hi);
        let low2 = simd.select_u64x4(
            simd.cmp_gt_u64x4(hi, lo),
            simd.wrapping_add_u64x4(low2, p),
            low2,
        );

        let product = simd.shl_const_u64x4::<32>(mid);
        let product = simd.wrapping_sub_u64x4(product, mid);

        let result = simd.wrapping_add_u64x4(low2, product);

        // (result < product) || (result >= p)
        // (result < product) || !(p > result)
        // !(!(result < product) && (p > result))
        let product_gt_result = simd.cmp_gt_u64x4(product, result);
        let p_gt_result = simd.cmp_gt_u64x4(p, result);
        let not_cond = simd.andnot_m64x4(product_gt_result, p_gt_result);

        simd.select_u64x4(not_cond, result, simd.wrapping_sub_u64x4(result, p))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl PrimeModulusV4 for u64 {
    type Div = (u64, u64, u64, u64, u64);

    #[inline(always)]
    fn add(self, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8 {
        let p = simd.splat_u64x8(self);
        let neg_b = simd.wrapping_sub_u64x8(p, b);
        let a_ge_neg_b = simd.cmp_ge_u64x8(a, neg_b);
        simd.select_u64x8(
            a_ge_neg_b,
            simd.wrapping_sub_u64x8(a, neg_b),
            simd.wrapping_add_u64x8(a, b),
        )
    }

    #[inline(always)]
    fn sub(self, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8 {
        let p = simd.splat_u64x8(self);
        let neg_b = simd.wrapping_sub_u64x8(p, b);
        let a_ge_b = simd.cmp_ge_u64x8(a, b);
        simd.select_u64x8(
            a_ge_b,
            simd.wrapping_sub_u64x8(a, b),
            simd.wrapping_add_u64x8(a, neg_b),
        )
    }

    #[inline(always)]
    fn mul(p: Self::Div, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8 {
        #[inline(always)]
        fn mul_with_carry(simd: crate::V4, l: u64x8, r: u64x8, c: u64x8) -> (u64x8, u64x8) {
            let (lo, hi) = simd.widening_mul_u64x8(l, r);
            let lo_plus_c = simd.wrapping_add_u64x8(lo, c);
            let overflow = simd.cmp_gt_u64x8(lo, lo_plus_c);

            (
                lo_plus_c,
                simd.wrapping_sub_u64x8(hi, simd.convert_mask_b8_to_u64x8(overflow)),
            )
        }

        #[inline(always)]
        fn mul_u256_u64(
            simd: crate::V4,
            lhs0: u64x8,
            lhs1: u64x8,
            lhs2: u64x8,
            lhs3: u64x8,
            rhs: u64x8,
        ) -> (u64x8, u64x8, u64x8, u64x8, u64x8) {
            let (x0, carry) = simd.widening_mul_u64x8(lhs0, rhs);
            let (x1, carry) = mul_with_carry(simd, lhs1, rhs, carry);
            let (x2, carry) = mul_with_carry(simd, lhs2, rhs, carry);
            let (x3, carry) = mul_with_carry(simd, lhs3, rhs, carry);
            (x0, x1, x2, x3, carry)
        }

        #[inline(always)]
        fn wrapping_mul_u256_u128(
            simd: crate::V4,
            lhs0: u64x8,
            lhs1: u64x8,
            lhs2: u64x8,
            lhs3: u64x8,
            rhs0: u64x8,
            rhs1: u64x8,
        ) -> (u64x8, u64x8, u64x8, u64x8) {
            let (x0, x1, x2, x3, _) = mul_u256_u64(simd, lhs0, lhs1, lhs2, lhs3, rhs0);
            let (y0, y1, y2, _, _) = mul_u256_u64(simd, lhs0, lhs1, lhs2, lhs3, rhs1);

            let z0 = x0;

            let z1 = simd.wrapping_add_u64x8(x1, y0);
            let carry = simd.convert_mask_b8_to_u64x8(simd.cmp_gt_u64x8(x1, z1));

            let z2 = simd.wrapping_add_u64x8(x2, y1);
            let o0 = simd.cmp_gt_u64x8(x2, z2);
            let o1 = simd.cmp_eq_u64x8(z2, carry);
            let z2 = simd.wrapping_sub_u64x8(z2, carry);
            let carry = simd.convert_mask_b8_to_u64x8(b8(o0.0 | o1.0));

            let z3 = simd.wrapping_add_u64x8(x3, y2);
            let z3 = simd.wrapping_sub_u64x8(z3, carry);

            (z0, z1, z2, z3)
        }

        let (p, p_div0, p_div1, p_div2, p_div3) = p;

        let p = simd.splat_u64x8(p);
        let p_div0 = simd.splat_u64x8(p_div0);
        let p_div1 = simd.splat_u64x8(p_div1);
        let p_div2 = simd.splat_u64x8(p_div2);
        let p_div3 = simd.splat_u64x8(p_div3);

        let (lo, hi) = simd.widening_mul_u64x8(a, b);
        let (low_bits0, low_bits1, low_bits2, low_bits3) =
            wrapping_mul_u256_u128(simd, p_div0, p_div1, p_div2, p_div3, lo, hi);

        mul_u256_u64(simd, low_bits0, low_bits1, low_bits2, low_bits3, p).4
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl PrimeModulusV4 for Solinas {
    type Div = ();

    #[inline(always)]
    fn add(self, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8 {
        PrimeModulusV4::add(Self::P, simd, a, b)
    }

    #[inline(always)]
    fn sub(self, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8 {
        PrimeModulusV4::sub(Self::P, simd, a, b)
    }

    #[inline(always)]
    fn mul(p: Self::Div, simd: crate::V4, a: u64x8, b: u64x8) -> u64x8 {
        let _ = p;

        let p = simd.splat_u64x8(Self::P);

        // https://cp4space.hatsya.com/2021/09/01/an-efficient-prime-for-number-theoretic-transforms/
        let (lo, hi) = simd.widening_mul_u64x8(a, b);
        let mid = simd.and_u64x8(hi, simd.splat_u64x8(0x0000_0000_FFFF_FFFF));
        let hi = simd.and_u64x8(hi, simd.splat_u64x8(0xFFFF_FFFF_0000_0000));
        let hi = simd.shr_const_u64x8::<32>(hi);

        let low2 = simd.wrapping_sub_u64x8(lo, hi);
        let low2 = simd.select_u64x8(
            simd.cmp_gt_u64x8(hi, lo),
            simd.wrapping_add_u64x8(low2, p),
            low2,
        );

        let product = simd.shl_const_u64x8::<32>(mid);
        let product = simd.wrapping_sub_u64x8(product, mid);

        let result = simd.wrapping_add_u64x8(low2, product);

        // (result < product) || (result >= p)
        // (result < product) || !(p > result)
        // !(!(result < product) && (p > result))
        let product_gt_result = simd.cmp_gt_u64x8(product, result);
        let p_gt_result = simd.cmp_gt_u64x8(p, result);
        let not_cond = b8(!product_gt_result.0 & p_gt_result.0);

        simd.select_u64x8(not_cond, result, simd.wrapping_sub_u64x8(result, p))
    }
}

pub(crate) fn fwd_breadth_first_scalar<P: PrimeModulus>(
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
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
                let z1w = P::mul(p_div, *z1, w1);

                (*z0, *z1) = (p.add(*z0, z1w), p.sub(*z0, z1w));
            }
        }

        t /= 2;
        m *= 2;
        w_idx *= 2;
    }
}

pub(crate) fn inv_breadth_first_scalar<P: PrimeModulus>(
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    inv_twid: &[u64],
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
                (*z0, *z1) = (p.add(*z0, *z1), P::mul(p_div, p.sub(*z0, *z1), w1));
            }
        }

        t *= 2;
    }
}

pub(crate) fn inv_depth_first_scalar<P: PrimeModulus>(
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    inv_twid: &[u64],
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
                (*z0, *z1) = (p.add(*z0, *z1), P::mul(p_div, p.sub(*z0, *z1), w1));
            }
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn fwd_breadth_first_avx2<P: PrimeModulusV3>(
    simd: crate::V3,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV3> {
        simd: crate::V3,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV3> pulp::NullaryFnOnce for Impl<'_, P> {
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
            while m < n / 4 {
                let w = &twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<4, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<4, _>(z1).0;
                    let w1 = simd.splat_u64x4(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        let z1w = P::mul(p_div, simd, z1, w1);
                        (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
                    }
                }

                t /= 2;
                m *= 2;
                w_idx *= 2;
            }

            // m = n / 4
            // t = 2
            {
                let w = pulp::as_arrays::<2, _>(&twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<4, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u64x4(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u64x4(cast(*z0z0z1z1));
                    let z1w = P::mul(p_div, simd, z1, w1);
                    (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                    *z0z0z1z1 = cast(simd.interleave2_u64x4([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 2
            // t = 1
            {
                let w = pulp::as_arrays::<4, _>(&twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<4, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u64x4(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u64x4(cast(*z0z1));
                    let z1w = P::mul(p_div, simd, z1, w1);
                    (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                    *z0z1 = cast(simd.interleave1_u64x4([z0, z1]));
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
pub(crate) fn inv_breadth_first_avx2<P: PrimeModulusV3>(
    simd: crate::V3,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    inv_twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV3> {
        simd: crate::V3,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        inv_twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV3> pulp::NullaryFnOnce for Impl<'_, P> {
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

            // m = n / 2
            // t = 1
            {
                m /= 2;
                w_idx /= 2;

                let w = pulp::as_arrays::<4, _>(&inv_twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<4, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u64x4(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u64x4(cast(*z0z1));
                    (z0, z1) = (
                        p.add(simd, z0, z1),
                        P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
                    );
                    *z0z1 = cast(simd.interleave1_u64x4([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 4
            // t = 2
            {
                m /= 2;
                w_idx /= 2;

                let w = pulp::as_arrays::<2, _>(&inv_twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<4, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u64x4(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u64x4(cast(*z0z0z1z1));
                    (z0, z1) = (
                        p.add(simd, z0, z1),
                        P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
                    );
                    *z0z0z1z1 = cast(simd.interleave2_u64x4([z0, z1]));
                }

                t *= 2;
            }

            while m > 1 {
                m /= 2;
                w_idx /= 2;

                let w = &inv_twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<4, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<4, _>(z1).0;
                    let w1 = simd.splat_u64x4(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        (z0, z1) = (
                            p.add(simd, z0, z1),
                            P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
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
pub(crate) fn fwd_breadth_first_avx512<P: PrimeModulusV4>(
    simd: crate::V4,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV4> {
        simd: crate::V4,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV4> pulp::NullaryFnOnce for Impl<'_, P> {
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
            while m < n / 8 {
                let w = &twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<8, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<8, _>(z1).0;
                    let w1 = simd.splat_u64x8(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        let z1w = P::mul(p_div, simd, z1, w1);
                        (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
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
                let w = pulp::as_arrays::<2, _>(&twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<8, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute4_u64x8(*w1);
                    let [mut z0, mut z1] = simd.interleave4_u64x8(cast(*z0z0z0z0z1z1z1z1));
                    let z1w = P::mul(p_div, simd, z1, w1);
                    (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                    *z0z0z0z0z1z1z1z1 = cast(simd.interleave4_u64x8([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 4
            // t = 2
            {
                let w = pulp::as_arrays::<4, _>(&twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<8, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u64x8(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u64x8(cast(*z0z0z1z1));
                    let z1w = P::mul(p_div, simd, z1, w1);
                    (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                    *z0z0z1z1 = cast(simd.interleave2_u64x8([z0, z1]));
                }

                w_idx *= 2;
            }

            // m = n / 2
            // t = 1
            {
                let w = pulp::as_arrays::<8, _>(&twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<8, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u64x8(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u64x8(cast(*z0z1));
                    let z1w = P::mul(p_div, simd, z1, w1);
                    (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                    *z0z1 = cast(simd.interleave1_u64x8([z0, z1]));
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
pub(crate) fn fwd_depth_first_avx512<P: PrimeModulusV4>(
    simd: crate::V4,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV4> {
        simd: crate::V4,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV4> pulp::NullaryFnOnce for Impl<'_, P> {
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
                let t = n / 2;
                let m = 1;
                let w_idx = (m << recursion_depth) + m * recursion_half;

                let w = &twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<8, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<8, _>(z1).0;
                    let w1 = simd.splat_u64x8(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        let z1w = P::mul(p_div, simd, z1, w1);
                        (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
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
pub(crate) fn inv_depth_first_avx512<P: PrimeModulusV4>(
    simd: crate::V4,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    inv_twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV4> {
        simd: crate::V4,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        inv_twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV4> pulp::NullaryFnOnce for Impl<'_, P> {
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

                let t = n / 2;
                let m = 1;
                let w_idx = (m << recursion_depth) + m * recursion_half;

                let w = &inv_twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<8, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<8, _>(z1).0;
                    let w1 = simd.splat_u64x8(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        (z0, z1) = (
                            p.add(simd, z0, z1),
                            P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
                        );
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
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
pub(crate) fn inv_depth_first_avx2<P: PrimeModulusV3>(
    simd: crate::V3,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    inv_twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV3> {
        simd: crate::V3,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        inv_twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV3> pulp::NullaryFnOnce for Impl<'_, P> {
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

                let t = n / 2;
                let m = 1;
                let w_idx = (m << recursion_depth) + m * recursion_half;

                let w = &inv_twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<4, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<4, _>(z1).0;
                    let w1 = simd.splat_u64x4(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        (z0, z1) = (
                            p.add(simd, z0, z1),
                            P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
                        );
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
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
pub(crate) fn fwd_depth_first_avx2<P: PrimeModulusV3>(
    simd: crate::V3,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV3> {
        simd: crate::V3,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV3> pulp::NullaryFnOnce for Impl<'_, P> {
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
                let t = n / 2;
                let m = 1;
                let w_idx = (m << recursion_depth) + m * recursion_half;

                let w = &twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<4, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<4, _>(z1).0;
                    let w1 = simd.splat_u64x4(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        let z1w = P::mul(p_div, simd, z1, w1);
                        (z0, z1) = (p.add(simd, z0, z1w), p.sub(simd, z0, z1w));
                        *z0_ = cast(z0);
                        *z1_ = cast(z1);
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

pub(crate) fn fwd_depth_first_scalar<P: PrimeModulus>(
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
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
                let z1w = P::mul(p_div, *z1, w1);

                (*z0, *z1) = (p.add(*z0, z1w), p.sub(*z0, z1w));
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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn fwd_avx512<P: PrimeModulusV4>(
    simd: crate::V4,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
) {
    fwd_depth_first_avx512(simd, data, p, p_div, twid, 0, 0);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn fwd_avx2<P: PrimeModulusV3>(
    simd: crate::V3,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
) {
    fwd_depth_first_avx2(simd, data, p, p_div, twid, 0, 0);
}

pub(crate) fn fwd_scalar<P: PrimeModulus>(data: &mut [u64], p: P, p_div: P::Div, twid: &[u64]) {
    fwd_depth_first_scalar(data, p, p_div, twid, 0, 0);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn inv_avx512<P: PrimeModulusV4>(
    simd: crate::V4,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
) {
    inv_depth_first_avx512(simd, data, p, p_div, twid, 0, 0);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn inv_avx2<P: PrimeModulusV3>(
    simd: crate::V3,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    twid: &[u64],
) {
    inv_depth_first_avx2(simd, data, p, p_div, twid, 0, 0);
}

pub(crate) fn inv_scalar<P: PrimeModulus>(data: &mut [u64], p: P, p_div: P::Div, twid: &[u64]) {
    inv_depth_first_scalar(data, p, p_div, twid, 0, 0);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn inv_breadth_first_avx512<P: PrimeModulusV4>(
    simd: crate::V4,
    data: &mut [u64],
    p: P,
    p_div: P::Div,
    inv_twid: &[u64],
    recursion_depth: usize,
    recursion_half: usize,
) {
    struct Impl<'a, P: PrimeModulusV4> {
        simd: crate::V4,
        data: &'a mut [u64],
        p: P,
        p_div: P::Div,
        inv_twid: &'a [u64],
        recursion_depth: usize,
        recursion_half: usize,
    }
    impl<P: PrimeModulusV4> pulp::NullaryFnOnce for Impl<'_, P> {
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

            // m = n / 2
            // t = 1
            {
                m /= 2;
                w_idx /= 2;

                let w = pulp::as_arrays::<8, _>(&inv_twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<8, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z1, w1) in zip(data, w) {
                    let w1 = simd.permute1_u64x8(*w1);
                    let [mut z0, mut z1] = simd.interleave1_u64x8(cast(*z0z1));
                    (z0, z1) = (
                        p.add(simd, z0, z1),
                        P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
                    );
                    *z0z1 = cast(simd.interleave1_u64x8([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 4
            // t = 2
            {
                m /= 2;
                w_idx /= 2;

                let w = pulp::as_arrays::<4, _>(&inv_twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<8, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z0z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute2_u64x8(*w1);
                    let [mut z0, mut z1] = simd.interleave2_u64x8(cast(*z0z0z1z1));
                    (z0, z1) = (
                        p.add(simd, z0, z1),
                        P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
                    );
                    *z0z0z1z1 = cast(simd.interleave2_u64x8([z0, z1]));
                }

                t *= 2;
            }

            // m = n / 8
            // t = 4
            {
                m /= 2;
                w_idx /= 2;

                let w = pulp::as_arrays::<2, _>(&inv_twid[w_idx..]).0;
                let data = pulp::as_arrays_mut::<8, _>(data).0;
                let data = pulp::as_arrays_mut::<2, _>(data).0;

                for (z0z0z0z0z1z1z1z1, w1) in zip(data, w) {
                    let w1 = simd.permute4_u64x8(*w1);
                    let [mut z0, mut z1] = simd.interleave4_u64x8(cast(*z0z0z0z0z1z1z1z1));
                    (z0, z1) = (
                        p.add(simd, z0, z1),
                        P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
                    );
                    *z0z0z0z0z1z1z1z1 = cast(simd.interleave4_u64x8([z0, z1]));
                }

                t *= 2;
            }

            while m > 1 {
                m /= 2;
                w_idx /= 2;

                let w = &inv_twid[w_idx..];

                for (data, &w1) in zip(data.chunks_exact_mut(2 * t), w) {
                    let (z0, z1) = data.split_at_mut(t);
                    let z0 = pulp::as_arrays_mut::<8, _>(z0).0;
                    let z1 = pulp::as_arrays_mut::<8, _>(z1).0;
                    let w1 = simd.splat_u64x8(w1);

                    for (z0_, z1_) in zip(z0, z1) {
                        let mut z0 = cast(*z0_);
                        let mut z1 = cast(*z1_);
                        (z0, z1) = (
                            p.add(simd, z0, z1),
                            P::mul(p_div, simd, p.sub(simd, z0, z1), w1),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prime64::{
        init_negacyclic_twiddles,
        tests::{mul, random_lhs_rhs_with_negacyclic_convolution},
    };
    use alloc::vec;

    extern crate alloc;

    #[test]
    fn test_product() {
        for n in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            let p = Solinas::P;

            let (lhs, rhs, negacyclic_convolution) =
                random_lhs_rhs_with_negacyclic_convolution(n, p);

            let mut twid = vec![0u64; n];
            let mut inv_twid = vec![0u64; n];
            init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

            let mut prod = vec![0u64; n];
            let mut lhs_fourier = lhs.clone();
            let mut rhs_fourier = rhs.clone();

            fwd_breadth_first_scalar(&mut lhs_fourier, p, Div64::new(p), &twid, 0, 0);
            fwd_breadth_first_scalar(&mut rhs_fourier, p, Div64::new(p), &twid, 0, 0);

            for i in 0..n {
                prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
            }

            inv_breadth_first_scalar(&mut prod, p, Div64::new(p), &inv_twid, 0, 0);
            let result = prod;

            for i in 0..n {
                assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_product_avx2() {
        if let Some(simd) = crate::V3::try_new() {
            for n in [8, 16, 32, 64, 128, 256, 512, 1024] {
                let p = Solinas::P;

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u64; n];
                let mut inv_twid = vec![0u64; n];
                init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

                let mut prod = vec![0u64; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                let crate::u256 { x0, x1, x2, x3 } = Div64::new(p).double_reciprocal;
                fwd_breadth_first_avx2(simd, &mut lhs_fourier, p, (p, x0, x1, x2, x3), &twid, 0, 0);
                fwd_breadth_first_avx2(simd, &mut rhs_fourier, p, (p, x0, x1, x2, x3), &twid, 0, 0);

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_breadth_first_avx2(simd, &mut prod, p, (p, x0, x1, x2, x3), &inv_twid, 0, 0);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
                }
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly")]
    #[test]
    fn test_product_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            for n in [16, 32, 64, 128, 256, 512, 1024] {
                let p = Solinas::P;

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u64; n];
                let mut inv_twid = vec![0u64; n];
                init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

                let mut prod = vec![0u64; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                let crate::u256 { x0, x1, x2, x3 } = Div64::new(p).double_reciprocal;
                fwd_breadth_first_avx512(
                    simd,
                    &mut lhs_fourier,
                    p,
                    (p, x0, x1, x2, x3),
                    &twid,
                    0,
                    0,
                );
                fwd_breadth_first_avx512(
                    simd,
                    &mut rhs_fourier,
                    p,
                    (p, x0, x1, x2, x3),
                    &twid,
                    0,
                    0,
                );

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_breadth_first_avx512(simd, &mut prod, p, (p, x0, x1, x2, x3), &inv_twid, 0, 0);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
                }
            }
        }
    }

    #[test]
    fn test_product_solinas() {
        for n in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            let p = Solinas::P;

            let (lhs, rhs, negacyclic_convolution) =
                random_lhs_rhs_with_negacyclic_convolution(n, p);

            let mut twid = vec![0u64; n];
            let mut inv_twid = vec![0u64; n];
            init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

            let mut prod = vec![0u64; n];
            let mut lhs_fourier = lhs.clone();
            let mut rhs_fourier = rhs.clone();

            fwd_breadth_first_scalar(&mut lhs_fourier, Solinas, (), &twid, 0, 0);
            fwd_breadth_first_scalar(&mut rhs_fourier, Solinas, (), &twid, 0, 0);

            for i in 0..n {
                prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
            }

            inv_breadth_first_scalar(&mut prod, Solinas, (), &inv_twid, 0, 0);
            let result = prod;

            for i in 0..n {
                assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_product_solinas_avx2() {
        if let Some(simd) = crate::V3::try_new() {
            for n in [8, 16, 32, 64, 128, 256, 512, 1024] {
                let p = Solinas::P;

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u64; n];
                let mut inv_twid = vec![0u64; n];
                init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

                let mut prod = vec![0u64; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                fwd_breadth_first_avx2(simd, &mut lhs_fourier, Solinas, (), &twid, 0, 0);
                fwd_breadth_first_avx2(simd, &mut rhs_fourier, Solinas, (), &twid, 0, 0);

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_breadth_first_avx2(simd, &mut prod, Solinas, (), &inv_twid, 0, 0);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
                }
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly")]
    #[test]
    fn test_product_solinas_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            for n in [16, 32, 64, 128, 256, 512, 1024] {
                let p = Solinas::P;

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u64; n];
                let mut inv_twid = vec![0u64; n];
                init_negacyclic_twiddles(p, n, &mut twid, &mut inv_twid);

                let mut prod = vec![0u64; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                fwd_breadth_first_avx512(simd, &mut lhs_fourier, Solinas, (), &twid, 0, 0);
                fwd_breadth_first_avx512(simd, &mut rhs_fourier, Solinas, (), &twid, 0, 0);

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_breadth_first_avx512(simd, &mut prod, Solinas, (), &inv_twid, 0, 0);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
                }
            }
        }
    }
}
