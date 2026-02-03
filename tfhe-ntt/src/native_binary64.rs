use aligned_vec::avec;

#[allow(unused_imports)]
use pulp::*;

pub(crate) use crate::native32::mul_mod32;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) use crate::native32::mul_mod32_avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
pub(crate) use crate::native32::{mul_mod32_avx512, mul_mod52_avx512};

/// Negacyclic NTT plan for multiplying two 32bit polynomials, where the RHS contains binary
/// coefficients.
#[derive(Clone, Debug)]
pub struct Plan32(
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
);

/// Negacyclic NTT plan for multiplying two 32bit polynomials, where the RHS contains binary
/// coefficients.
/// This can be more efficient than [`Plan32`], but requires the AVX512 instruction set.
#[cfg(all(feature = "avx512", any(target_arch = "x86", target_arch = "x86_64")))]
#[derive(Clone, Debug)]
pub struct Plan52(crate::prime64::Plan, crate::prime64::Plan, crate::V4IFma);

#[inline(always)]
#[allow(dead_code)]
fn reconstruct_32bit_012(mod_p0: u32, mod_p1: u32, mod_p2: u32) -> u64 {
    use crate::primes32::*;

    let v0 = mod_p0;
    let v1 = mul_mod32(P1, P0_INV_MOD_P1, 2 * P1 + mod_p1 - v0);
    let v2 = mul_mod32(
        P2,
        P01_INV_MOD_P2,
        2 * P2 + mod_p2 - (v0 + mul_mod32(P2, P0, v1)),
    );

    let sign = v2 > (P2 / 2);

    const _0: u64 = P0 as u64;
    const _01: u64 = _0.wrapping_mul(P1 as u64);
    const _012: u64 = _01.wrapping_mul(P2 as u64);

    let pos = (v0 as u64)
        .wrapping_add((v1 as u64).wrapping_mul(_0))
        .wrapping_add((v2 as u64).wrapping_mul(_01));

    let neg = pos.wrapping_sub(_012);

    if sign {
        neg
    } else {
        pos
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
#[inline(always)]
fn reconstruct_32bit_012_avx2(
    simd: crate::V3,
    mod_p0: u32x8,
    mod_p1: u32x8,
    mod_p2: u32x8,
) -> [u64x4; 2] {
    use crate::primes32::*;

    let p0 = simd.splat_u32x8(P0);
    let p1 = simd.splat_u32x8(P1);
    let p2 = simd.splat_u32x8(P2);
    let two_p1 = simd.splat_u32x8(2 * P1);
    let two_p2 = simd.splat_u32x8(2 * P2);
    let half_p2 = simd.splat_u32x8(P2 / 2);

    let p0_inv_mod_p1 = simd.splat_u32x8(P0_INV_MOD_P1);
    let p0_inv_mod_p1_shoup = simd.splat_u32x8(P0_INV_MOD_P1_SHOUP);
    let p0_mod_p2_shoup = simd.splat_u32x8(P0_MOD_P2_SHOUP);

    let p01_inv_mod_p2 = simd.splat_u32x8(P01_INV_MOD_P2);
    let p01_inv_mod_p2_shoup = simd.splat_u32x8(P01_INV_MOD_P2_SHOUP);

    let p01 = simd.splat_u64x4((P0 as u64).wrapping_mul(P1 as u64));
    let p012 = simd.splat_u64x4((P0 as u64).wrapping_mul(P1 as u64).wrapping_mul(P2 as u64));

    let v0 = mod_p0;
    let v1 = mul_mod32_avx2(
        simd,
        p1,
        simd.wrapping_sub_u32x8(simd.wrapping_add_u32x8(two_p1, mod_p1), v0),
        p0_inv_mod_p1,
        p0_inv_mod_p1_shoup,
    );
    let v2 = mul_mod32_avx2(
        simd,
        p2,
        simd.wrapping_sub_u32x8(
            simd.wrapping_add_u32x8(two_p2, mod_p2),
            simd.wrapping_add_u32x8(v0, mul_mod32_avx2(simd, p2, v1, p0, p0_mod_p2_shoup)),
        ),
        p01_inv_mod_p2,
        p01_inv_mod_p2_shoup,
    );

    let sign = simd.cmp_gt_u32x8(v2, half_p2);
    let sign: [i32x4; 2] = pulp::cast(sign);
    // sign extend so that -1i32 becomes -1i64
    let sign0: m64x4 = unsafe { core::mem::transmute(simd.convert_i32x4_to_i64x4(sign[0])) };
    let sign1: m64x4 = unsafe { core::mem::transmute(simd.convert_i32x4_to_i64x4(sign[1])) };

    let v0: [u32x4; 2] = pulp::cast(v0);
    let v1: [u32x4; 2] = pulp::cast(v1);
    let v2: [u32x4; 2] = pulp::cast(v2);
    let v00 = simd.convert_u32x4_to_u64x4(v0[0]);
    let v01 = simd.convert_u32x4_to_u64x4(v0[1]);
    let v10 = simd.convert_u32x4_to_u64x4(v1[0]);
    let v11 = simd.convert_u32x4_to_u64x4(v1[1]);
    let v20 = simd.convert_u32x4_to_u64x4(v2[0]);
    let v21 = simd.convert_u32x4_to_u64x4(v2[1]);

    let pos0 = v00;
    let pos0 = simd.wrapping_add_u64x4(pos0, simd.mul_low_32_bits_u64x4(pulp::cast(p0), v10));
    let pos0 = simd.wrapping_add_u64x4(
        pos0,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p01, v20),
    );

    let pos1 = v01;
    let pos1 = simd.wrapping_add_u64x4(pos1, simd.mul_low_32_bits_u64x4(pulp::cast(p0), v11));
    let pos1 = simd.wrapping_add_u64x4(
        pos1,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p01, v21),
    );

    let neg0 = simd.wrapping_sub_u64x4(pos0, p012);
    let neg1 = simd.wrapping_sub_u64x4(pos1, p012);

    [
        simd.select_u64x4(sign0, neg0, pos0),
        simd.select_u64x4(sign1, neg1, pos1),
    ]
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[allow(dead_code)]
#[inline(always)]
fn reconstruct_32bit_012_avx512(
    simd: crate::V4IFma,
    mod_p0: u32x16,
    mod_p1: u32x16,
    mod_p2: u32x16,
) -> [u64x8; 2] {
    use crate::primes32::*;

    let p0 = simd.splat_u32x16(P0);
    let p1 = simd.splat_u32x16(P1);
    let p2 = simd.splat_u32x16(P2);
    let two_p1 = simd.splat_u32x16(2 * P1);
    let two_p2 = simd.splat_u32x16(2 * P2);
    let half_p2 = simd.splat_u32x16(P2 / 2);

    let p0_inv_mod_p1 = simd.splat_u32x16(P0_INV_MOD_P1);
    let p0_inv_mod_p1_shoup = simd.splat_u32x16(P0_INV_MOD_P1_SHOUP);
    let p0_mod_p2_shoup = simd.splat_u32x16(P0_MOD_P2_SHOUP);

    let p01_inv_mod_p2 = simd.splat_u32x16(P01_INV_MOD_P2);
    let p01_inv_mod_p2_shoup = simd.splat_u32x16(P01_INV_MOD_P2_SHOUP);

    let p01 = simd.splat_u64x8((P0 as u64).wrapping_mul(P1 as u64));
    let p012 = simd.splat_u64x8((P0 as u64).wrapping_mul(P1 as u64).wrapping_mul(P2 as u64));

    let v0 = mod_p0;
    let v1 = mul_mod32_avx512(
        simd,
        p1,
        simd.wrapping_sub_u32x16(simd.wrapping_add_u32x16(two_p1, mod_p1), v0),
        p0_inv_mod_p1,
        p0_inv_mod_p1_shoup,
    );
    let v2 = mul_mod32_avx512(
        simd,
        p2,
        simd.wrapping_sub_u32x16(
            simd.wrapping_add_u32x16(two_p2, mod_p2),
            simd.wrapping_add_u32x16(v0, mul_mod32_avx512(simd, p2, v1, p0, p0_mod_p2_shoup)),
        ),
        p01_inv_mod_p2,
        p01_inv_mod_p2_shoup,
    );

    let sign = simd.cmp_gt_u32x16(v2, half_p2).0;
    let sign0 = b8(sign as u8);
    let sign1 = b8((sign >> 8) as u8);
    let v0: [u32x8; 2] = pulp::cast(v0);
    let v1: [u32x8; 2] = pulp::cast(v1);
    let v2: [u32x8; 2] = pulp::cast(v2);
    let v00 = simd.convert_u32x8_to_u64x8(v0[0]);
    let v01 = simd.convert_u32x8_to_u64x8(v0[1]);
    let v10 = simd.convert_u32x8_to_u64x8(v1[0]);
    let v11 = simd.convert_u32x8_to_u64x8(v1[1]);
    let v20 = simd.convert_u32x8_to_u64x8(v2[0]);
    let v21 = simd.convert_u32x8_to_u64x8(v2[1]);

    let pos0 = v00;
    let pos0 = simd.wrapping_add_u64x8(pos0, simd.mul_low_32_bits_u64x8(pulp::cast(p0), v10));
    let pos0 = simd.wrapping_add_u64x8(pos0, simd.wrapping_mul_u64x8(p01, v20));

    let pos1 = v01;
    let pos1 = simd.wrapping_add_u64x8(pos1, simd.mul_low_32_bits_u64x8(pulp::cast(p0), v11));
    let pos1 = simd.wrapping_add_u64x8(pos1, simd.wrapping_mul_u64x8(p01, v21));

    let neg0 = simd.wrapping_sub_u64x8(pos0, p012);
    let neg1 = simd.wrapping_sub_u64x8(pos1, p012);

    [
        simd.select_u64x8(sign0, neg0, pos0),
        simd.select_u64x8(sign1, neg1, pos1),
    ]
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn reconstruct_52bit_01_avx512(simd: crate::V4IFma, mod_p0: u64x8, mod_p1: u64x8) -> u64x8 {
    use crate::primes52::*;

    let p0 = simd.splat_u64x8(P0);
    let p1 = simd.splat_u64x8(P1);
    let neg_p1 = simd.splat_u64x8(P1.wrapping_neg());
    let two_p1 = simd.splat_u64x8(2 * P1);
    let half_p1 = simd.splat_u64x8(P1 / 2);

    let p0_inv_mod_p1 = simd.splat_u64x8(P0_INV_MOD_P1);
    let p0_inv_mod_p1_shoup = simd.splat_u64x8(P0_INV_MOD_P1_SHOUP);

    let p01 = simd.splat_u64x8(P0.wrapping_mul(P1));

    let v0 = mod_p0;
    let v1 = mul_mod52_avx512(
        simd,
        p1,
        neg_p1,
        simd.wrapping_sub_u64x8(simd.wrapping_add_u64x8(two_p1, mod_p1), v0),
        p0_inv_mod_p1,
        p0_inv_mod_p1_shoup,
    );

    let sign = simd.cmp_gt_u64x8(v1, half_p1);

    let pos = simd.wrapping_add_u64x8(v0, simd.wrapping_mul_u64x8(v1, p0));
    let neg = simd.wrapping_sub_u64x8(pos, p01);

    simd.select_u64x8(sign, neg, pos)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn reconstruct_slice_32bit_012_avx2(
    simd: crate::V3,
    value: &mut [u64],
    mod_p0: &[u32],
    mod_p1: &[u32],
    mod_p2: &[u32],
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let value = pulp::as_arrays_mut::<8, _>(value).0;
            let mod_p0 = pulp::as_arrays::<8, _>(mod_p0).0;
            let mod_p1 = pulp::as_arrays::<8, _>(mod_p1).0;
            let mod_p2 = pulp::as_arrays::<8, _>(mod_p2).0;
            for (value, &mod_p0, &mod_p1, &mod_p2) in crate::izip!(value, mod_p0, mod_p1, mod_p2) {
                *value = cast(reconstruct_32bit_012_avx2(
                    simd,
                    cast(mod_p0),
                    cast(mod_p1),
                    cast(mod_p2),
                ));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
fn reconstruct_slice_32bit_012_avx512(
    simd: crate::V4IFma,
    value: &mut [u64],
    mod_p0: &[u32],
    mod_p1: &[u32],
    mod_p2: &[u32],
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let value = pulp::as_arrays_mut::<16, _>(value).0;
            let mod_p0 = pulp::as_arrays::<16, _>(mod_p0).0;
            let mod_p1 = pulp::as_arrays::<16, _>(mod_p1).0;
            let mod_p2 = pulp::as_arrays::<16, _>(mod_p2).0;
            for (value, &mod_p0, &mod_p1, &mod_p2) in crate::izip!(value, mod_p0, mod_p1, mod_p2) {
                *value = cast(reconstruct_32bit_012_avx512(
                    simd,
                    cast(mod_p0),
                    cast(mod_p1),
                    cast(mod_p2),
                ));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
fn reconstruct_slice_52bit_01_avx512(
    simd: crate::V4IFma,
    value: &mut [u64],
    mod_p0: &[u64],
    mod_p1: &[u64],
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let value = pulp::as_arrays_mut::<8, _>(value).0;
            let mod_p0 = pulp::as_arrays::<8, _>(mod_p0).0;
            let mod_p1 = pulp::as_arrays::<8, _>(mod_p1).0;
            for (value, &mod_p0, &mod_p1) in crate::izip!(value, mod_p0, mod_p1) {
                *value = cast(reconstruct_52bit_01_avx512(
                    simd,
                    cast(mod_p0),
                    cast(mod_p1),
                ));
            }
        },
    );
}

impl Plan32 {
    /// Returns a negacyclic NTT plan for the given polynomial size, or `None` if no
    /// suitable roots of unity can be found for the wanted parameters.
    pub fn try_new(n: usize) -> Option<Self> {
        use crate::{prime32::Plan, primes32::*};
        Some(Self(
            Plan::try_new(n, P0)?,
            Plan::try_new(n, P1)?,
            Plan::try_new(n, P2)?,
        ))
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.0.ntt_size()
    }

    pub fn fwd(&self, value: &[u64], mod_p0: &mut [u32], mod_p1: &mut [u32], mod_p2: &mut [u32]) {
        for (value, mod_p0, mod_p1, mod_p2) in
            crate::izip!(value, &mut *mod_p0, &mut *mod_p1, &mut *mod_p2)
        {
            *mod_p0 = (value % crate::primes32::P0 as u64) as u32;
            *mod_p1 = (value % crate::primes32::P1 as u64) as u32;
            *mod_p2 = (value % crate::primes32::P2 as u64) as u32;
        }
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
        self.2.fwd(mod_p2);
    }
    pub fn fwd_binary(
        &self,
        value: &[u64],
        mod_p0: &mut [u32],
        mod_p1: &mut [u32],
        mod_p2: &mut [u32],
    ) {
        for (value, mod_p0, mod_p1, mod_p2) in
            crate::izip!(value, &mut *mod_p0, &mut *mod_p1, &mut *mod_p2)
        {
            *mod_p0 = *value as u32;
            *mod_p1 = *value as u32;
            *mod_p2 = *value as u32;
        }
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
        self.2.fwd(mod_p2);
    }

    pub fn inv(
        &self,
        value: &mut [u64],
        mod_p0: &mut [u32],
        mod_p1: &mut [u32],
        mod_p2: &mut [u32],
    ) {
        self.0.inv(mod_p0);
        self.1.inv(mod_p1);
        self.2.inv(mod_p2);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(feature = "avx512")]
            if let Some(simd) = crate::V4IFma::try_new() {
                reconstruct_slice_32bit_012_avx512(simd, value, mod_p0, mod_p1, mod_p2);
                return;
            }
            if let Some(simd) = crate::V3::try_new() {
                reconstruct_slice_32bit_012_avx2(simd, value, mod_p0, mod_p1, mod_p2);
                return;
            }
        }

        for (value, &mod_p0, &mod_p1, &mod_p2) in crate::izip!(value, &*mod_p0, &*mod_p1, &*mod_p2)
        {
            *value = reconstruct_32bit_012(mod_p0, mod_p1, mod_p2);
        }
    }

    /// Computes the negacyclic polynomial product of `lhs` and `rhs`, and stores the result in
    /// `prod`.
    pub fn negacyclic_polymul(&self, prod: &mut [u64], lhs: &[u64], rhs_binary: &[u64]) {
        let n = prod.len();
        assert_eq!(n, lhs.len());
        assert_eq!(n, rhs_binary.len());

        let mut lhs0 = avec![0; n];
        let mut lhs1 = avec![0; n];
        let mut lhs2 = avec![0; n];

        let mut rhs0 = avec![0; n];
        let mut rhs1 = avec![0; n];
        let mut rhs2 = avec![0; n];

        self.fwd(lhs, &mut lhs0, &mut lhs1, &mut lhs2);
        self.fwd_binary(rhs_binary, &mut rhs0, &mut rhs1, &mut rhs2);

        self.0.mul_assign_normalize(&mut lhs0, &rhs0);
        self.1.mul_assign_normalize(&mut lhs1, &rhs1);
        self.2.mul_assign_normalize(&mut lhs2, &rhs2);

        self.inv(prod, &mut lhs0, &mut lhs1, &mut lhs2);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
impl Plan52 {
    #[inline(always)]
    pub fn is_available() -> bool {
        crate::V4IFma::try_new().is_some()
    }

    /// Returns a negacyclic NTT plan for the given polynomial size, or `None` if no
    /// suitable roots of unity can be found for the wanted parameters, or if the AVX512
    /// instruction set isn't detected.
    pub fn try_new(n: usize) -> Option<Self> {
        use crate::{prime64::Plan, primes52::*};
        let simd = crate::V4IFma::try_new()?;
        Some(Self(Plan::try_new(n, P0)?, Plan::try_new(n, P1)?, simd))
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.0.ntt_size()
    }

    pub fn fwd(&self, value: &[u64], mod_p0: &mut [u64], mod_p1: &mut [u64]) {
        use crate::primes52::*;
        self.2.vectorize(
            #[inline(always)]
            || {
                for (&value, mod_p0, mod_p1) in crate::izip!(value, &mut *mod_p0, &mut *mod_p1) {
                    *mod_p0 = value % P0;
                    *mod_p1 = value % P1;
                }
            },
        );
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
    }
    pub fn fwd_binary(&self, value: &[u64], mod_p0: &mut [u64], mod_p1: &mut [u64]) {
        self.2.vectorize(
            #[inline(always)]
            || {
                for (&value, mod_p0, mod_p1) in crate::izip!(value, &mut *mod_p0, &mut *mod_p1) {
                    *mod_p0 = value;
                    *mod_p1 = value;
                }
            },
        );
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
    }

    pub fn inv(&self, value: &mut [u64], mod_p0: &mut [u64], mod_p1: &mut [u64]) {
        self.0.inv(mod_p0);
        self.1.inv(mod_p1);

        reconstruct_slice_52bit_01_avx512(self.2, value, mod_p0, mod_p1);
    }

    /// Computes the negacyclic polynomial product of `lhs` and `rhs`, and stores the result in
    /// `prod`.
    pub fn negacyclic_polymul(&self, prod: &mut [u64], lhs: &[u64], rhs_binary: &[u64]) {
        let n = prod.len();
        assert_eq!(n, lhs.len());
        assert_eq!(n, rhs_binary.len());

        let mut lhs0 = avec![0; n];
        let mut lhs1 = avec![0; n];

        let mut rhs0 = avec![0; n];
        let mut rhs1 = avec![0; n];

        self.fwd(lhs, &mut lhs0, &mut lhs1);
        self.fwd_binary(rhs_binary, &mut rhs0, &mut rhs1);

        self.0.mul_assign_normalize(&mut lhs0, &rhs0);
        self.1.mul_assign_normalize(&mut lhs1, &rhs1);

        self.inv(prod, &mut lhs0, &mut lhs1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prime64::tests::negacyclic_convolution;
    use alloc::{vec, vec::Vec};
    use rand::random;

    extern crate alloc;

    #[test]
    fn reconstruct_32bit() {
        for n in [32, 64, 256, 1024, 2048] {
            let plan = Plan32::try_new(n).unwrap();

            let lhs = (0..n).map(|_| random::<u64>()).collect::<Vec<_>>();
            let rhs = (0..n).map(|_| random::<u64>() % 2).collect::<Vec<_>>();
            let negacyclic_convolution = negacyclic_convolution(n, 0, &lhs, &rhs);

            let mut prod = vec![0; n];
            plan.negacyclic_polymul(&mut prod, &lhs, &rhs);
            assert_eq!(prod, negacyclic_convolution);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "avx512")]
    #[test]
    fn reconstruct_52bit() {
        for n in [32, 64, 256, 1024, 2048] {
            if let Some(plan) = Plan52::try_new(n) {
                let lhs = (0..n).map(|_| random::<u64>()).collect::<Vec<_>>();
                let rhs = (0..n).map(|_| random::<u64>() % 2).collect::<Vec<_>>();
                let negacyclic_convolution = negacyclic_convolution(n, 0, &lhs, &rhs);

                let mut prod = vec![0; n];
                plan.negacyclic_polymul(&mut prod, &lhs, &rhs);
                assert_eq!(prod, negacyclic_convolution);
            }
        }
    }
}
