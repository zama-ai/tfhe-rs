use aligned_vec::avec;

#[allow(unused_imports)]
use pulp::*;

pub(crate) use crate::native32::mul_mod32;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) use crate::native32::mul_mod32_avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
pub(crate) use crate::native32::{mul_mod32_avx512, mul_mod52_avx512};

/// Negacyclic NTT plan for multiplying two 64bit polynomials.
#[derive(Clone, Debug)]
pub struct Plan32(
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
);

/// Negacyclic NTT plan for multiplying two 64bit polynomials.  
/// This can be more efficient than [`Plan32`], but requires the AVX512 instruction set.
#[cfg(all(feature = "avx512", any(target_arch = "x86", target_arch = "x86_64")))]
#[derive(Clone, Debug)]
pub struct Plan52(
    crate::prime64::Plan,
    crate::prime64::Plan,
    crate::prime64::Plan,
    crate::V4IFma,
);

#[inline(always)]
pub(crate) fn mul_mod64(p_neg: u64, a: u64, b: u64, b_shoup: u64) -> u64 {
    let q = ((a as u128 * b_shoup as u128) >> 64) as u64;
    let r = a.wrapping_mul(b).wrapping_add(p_neg.wrapping_mul(q));
    r.min(r.wrapping_add(p_neg))
}

#[inline(always)]
#[allow(dead_code)]
fn reconstruct_32bit_01234(mod_p0: u32, mod_p1: u32, mod_p2: u32, mod_p3: u32, mod_p4: u32) -> u64 {
    use crate::primes32::*;

    let v0 = mod_p0;
    let v1 = mul_mod32(P1, P0_INV_MOD_P1, 2 * P1 + mod_p1 - v0);
    let v2 = mul_mod32(
        P2,
        P01_INV_MOD_P2,
        2 * P2 + mod_p2 - (v0 + mul_mod32(P2, P0, v1)),
    );
    let v3 = mul_mod32(
        P3,
        P012_INV_MOD_P3,
        2 * P3 + mod_p3 - (v0 + mul_mod32(P3, P0, v1 + mul_mod32(P3, P1, v2))),
    );
    let v4 = mul_mod32(
        P4,
        P0123_INV_MOD_P4,
        2 * P4 + mod_p4
            - (v0 + mul_mod32(P4, P0, v1 + mul_mod32(P4, P1, v2 + mul_mod32(P4, P2, v3)))),
    );

    let sign = v4 > (P4 / 2);

    const _0: u64 = P0 as u64;
    const _01: u64 = _0.wrapping_mul(P1 as u64);
    const _012: u64 = _01.wrapping_mul(P2 as u64);
    const _0123: u64 = _012.wrapping_mul(P3 as u64);
    const _01234: u64 = _0123.wrapping_mul(P4 as u64);

    let pos = (v0 as u64)
        .wrapping_add((v1 as u64).wrapping_mul(_0))
        .wrapping_add((v2 as u64).wrapping_mul(_01))
        .wrapping_add((v3 as u64).wrapping_mul(_012))
        .wrapping_add((v4 as u64).wrapping_mul(_0123));

    let neg = pos.wrapping_sub(_01234);

    if sign {
        neg
    } else {
        pos
    }
}

#[inline(always)]
fn reconstruct_32bit_01234_v2(
    mod_p0: u32,
    mod_p1: u32,
    mod_p2: u32,
    mod_p3: u32,
    mod_p4: u32,
) -> u64 {
    use crate::primes32::*;

    let mod_p12 = {
        let v1 = mod_p1;
        let v2 = mul_mod32(P2, P1_INV_MOD_P2, 2 * P2 + mod_p2 - v1);
        v1 as u64 + (v2 as u64 * P1 as u64)
    };
    let mod_p34 = {
        let v3 = mod_p3;
        let v4 = mul_mod32(P4, P3_INV_MOD_P4, 2 * P4 + mod_p4 - v3);
        v3 as u64 + (v4 as u64 * P3 as u64)
    };

    let v0 = mod_p0 as u64;
    let v12 = mul_mod64(
        P12.wrapping_neg(),
        2 * P12 + mod_p12 - v0,
        P0_INV_MOD_P12,
        P0_INV_MOD_P12_SHOUP,
    );
    let v34 = mul_mod64(
        P34.wrapping_neg(),
        2 * P34 + mod_p34 - (v0 + mul_mod64(P34.wrapping_neg(), v12, P0 as u64, P0_MOD_P34_SHOUP)),
        P012_INV_MOD_P34,
        P012_INV_MOD_P34_SHOUP,
    );

    let sign = v34 > (P34 / 2);

    const _0: u64 = P0 as u64;
    const _012: u64 = _0.wrapping_mul(P12);
    const _01234: u64 = _012.wrapping_mul(P34);

    let pos = v0
        .wrapping_add(v12.wrapping_mul(_0))
        .wrapping_add(v34.wrapping_mul(_012));
    let neg = pos.wrapping_sub(_01234);

    if sign {
        neg
    } else {
        pos
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn mul_mod32_v2_avx2(
    simd: crate::V3,
    p: u64x4,
    a: u64x4,
    b: u64x4,
    b_shoup: u64x4,
) -> u64x4 {
    let shoup_q = simd.shr_const_u64x4::<32>(simd.mul_low_32_bits_u64x4(a, b_shoup));
    let t = simd.and_u64x4(
        simd.splat_u64x4((1u64 << 32) - 1),
        simd.wrapping_sub_u64x4(
            simd.mul_low_32_bits_u64x4(a, b),
            simd.mul_low_32_bits_u64x4(shoup_q, p),
        ),
    );
    simd.small_mod_u64x4(p, t)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub(crate) fn mul_mod32_v2_avx512(
    simd: crate::V4IFma,
    p: u64x8,
    a: u64x8,
    b: u64x8,
    b_shoup: u64x8,
) -> u64x8 {
    let shoup_q = simd.shr_const_u64x8::<32>(simd.mul_low_32_bits_u64x8(a, b_shoup));
    let t = simd.and_u64x8(
        simd.splat_u64x8((1u64 << 32) - 1),
        simd.wrapping_sub_u64x8(
            simd.mul_low_32_bits_u64x8(a, b),
            simd.mul_low_32_bits_u64x8(shoup_q, p),
        ),
    );
    simd.small_mod_u64x8(p, t)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn mul_mod64_avx2(
    simd: crate::V3,
    p: u64x4,
    a: u64x4,
    b: u64x4,
    b_shoup: u64x4,
) -> u64x4 {
    let q = simd.widening_mul_u64x4(a, b_shoup).1;
    let r = simd.wrapping_sub_u64x4(
        simd.widening_mul_u64x4(a, b).0,
        simd.widening_mul_u64x4(p, q).0,
    );
    simd.small_mod_u64x4(p, r)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
pub(crate) fn mul_mod64_avx512(
    simd: crate::V4IFma,
    p: u64x8,
    a: u64x8,
    b: u64x8,
    b_shoup: u64x8,
) -> u64x8 {
    let q = simd.widening_mul_u64x8(a, b_shoup).1;
    let r = simd.wrapping_sub_u64x8(simd.wrapping_mul_u64x8(a, b), simd.wrapping_mul_u64x8(p, q));
    simd.small_mod_u64x8(p, r)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn reconstruct_32bit_01234_v2_avx2(
    simd: crate::V3,
    mod_p0: u32x4,
    mod_p1: u32x4,
    mod_p2: u32x4,
    mod_p3: u32x4,
    mod_p4: u32x4,
) -> u64x4 {
    use crate::primes32::*;

    let p0 = simd.splat_u64x4(P0 as u64);
    let p1 = simd.splat_u64x4(P1 as u64);
    let p2 = simd.splat_u64x4(P2 as u64);
    let p3 = simd.splat_u64x4(P3 as u64);
    let p4 = simd.splat_u64x4(P4 as u64);
    let p12 = simd.splat_u64x4(P12);
    let p34 = simd.splat_u64x4(P34);
    let p012 = simd.splat_u64x4((P0 as u64).wrapping_mul(P12));
    let p01234 = simd.splat_u64x4((P0 as u64).wrapping_mul(P12).wrapping_mul(P34));

    let two_p2 = simd.splat_u64x4(2 * P2 as u64);
    let two_p4 = simd.splat_u64x4(2 * P4 as u64);
    let two_p12 = simd.splat_u64x4(2 * P12);
    let two_p34 = simd.splat_u64x4(2 * P34);
    let half_p34 = simd.splat_u64x4(P34 / 2);

    let p0_inv_mod_p12 = simd.splat_u64x4(P0_INV_MOD_P12);
    let p0_inv_mod_p12_shoup = simd.splat_u64x4(P0_INV_MOD_P12_SHOUP);
    let p1_inv_mod_p2 = simd.splat_u64x4(P1_INV_MOD_P2 as u64);
    let p1_inv_mod_p2_shoup = simd.splat_u64x4(P1_INV_MOD_P2_SHOUP as u64);
    let p3_inv_mod_p4 = simd.splat_u64x4(P3_INV_MOD_P4 as u64);
    let p3_inv_mod_p4_shoup = simd.splat_u64x4(P3_INV_MOD_P4_SHOUP as u64);

    let p012_inv_mod_p34 = simd.splat_u64x4(P012_INV_MOD_P34);
    let p012_inv_mod_p34_shoup = simd.splat_u64x4(P012_INV_MOD_P34_SHOUP);
    let p0_mod_p34_shoup = simd.splat_u64x4(P0_MOD_P34_SHOUP);

    let mod_p0 = simd.convert_u32x4_to_u64x4(mod_p0);
    let mod_p1 = simd.convert_u32x4_to_u64x4(mod_p1);
    let mod_p2 = simd.convert_u32x4_to_u64x4(mod_p2);
    let mod_p3 = simd.convert_u32x4_to_u64x4(mod_p3);
    let mod_p4 = simd.convert_u32x4_to_u64x4(mod_p4);

    let mod_p12 = {
        let v1 = mod_p1;
        let v2 = mul_mod32_v2_avx2(
            simd,
            p2,
            simd.wrapping_sub_u64x4(simd.wrapping_add_u64x4(two_p2, mod_p2), v1),
            p1_inv_mod_p2,
            p1_inv_mod_p2_shoup,
        );
        simd.wrapping_add_u64x4(v1, simd.mul_low_32_bits_u64x4(v2, p1))
    };
    let mod_p34 = {
        let v3 = mod_p3;
        let v4 = mul_mod32_v2_avx2(
            simd,
            p4,
            simd.wrapping_sub_u64x4(simd.wrapping_add_u64x4(two_p4, mod_p4), v3),
            p3_inv_mod_p4,
            p3_inv_mod_p4_shoup,
        );
        simd.wrapping_add_u64x4(v3, simd.mul_low_32_bits_u64x4(v4, p3))
    };

    let v0 = mod_p0;
    let v12 = mul_mod64_avx2(
        simd,
        p12,
        simd.wrapping_sub_u64x4(simd.wrapping_add_u64x4(two_p12, mod_p12), v0),
        p0_inv_mod_p12,
        p0_inv_mod_p12_shoup,
    );
    let v34 = mul_mod64_avx2(
        simd,
        p34,
        simd.wrapping_sub_u64x4(
            simd.wrapping_add_u64x4(two_p34, mod_p34),
            simd.wrapping_add_u64x4(v0, mul_mod64_avx2(simd, p34, v12, p0, p0_mod_p34_shoup)),
        ),
        p012_inv_mod_p34,
        p012_inv_mod_p34_shoup,
    );

    let sign = simd.cmp_gt_u64x4(v34, half_p34);
    let pos = v0;
    let pos = simd.wrapping_add_u64x4(
        pos,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(v12, p0),
    );
    let pos = simd.wrapping_add_u64x4(pos, simd.widening_mul_u64x4(v34, p012).0);
    let neg = simd.wrapping_sub_u64x4(pos, p01234);
    simd.select_u64x4(sign, neg, pos)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
#[inline(always)]
fn reconstruct_32bit_01234_avx2(
    simd: crate::V3,
    mod_p0: u32x8,
    mod_p1: u32x8,
    mod_p2: u32x8,
    mod_p3: u32x8,
    mod_p4: u32x8,
) -> [u64x4; 2] {
    use crate::primes32::*;

    let p0 = simd.splat_u32x8(P0);
    let p1 = simd.splat_u32x8(P1);
    let p2 = simd.splat_u32x8(P2);
    let p3 = simd.splat_u32x8(P3);
    let p4 = simd.splat_u32x8(P4);
    let two_p1 = simd.splat_u32x8(2 * P1);
    let two_p2 = simd.splat_u32x8(2 * P2);
    let two_p3 = simd.splat_u32x8(2 * P3);
    let two_p4 = simd.splat_u32x8(2 * P4);
    let half_p4 = simd.splat_u32x8(P4 / 2);

    let p0_inv_mod_p1 = simd.splat_u32x8(P0_INV_MOD_P1);
    let p0_inv_mod_p1_shoup = simd.splat_u32x8(P0_INV_MOD_P1_SHOUP);
    let p0_mod_p2_shoup = simd.splat_u32x8(P0_MOD_P2_SHOUP);
    let p0_mod_p3_shoup = simd.splat_u32x8(P0_MOD_P3_SHOUP);
    let p1_mod_p3_shoup = simd.splat_u32x8(P1_MOD_P3_SHOUP);
    let p0_mod_p4_shoup = simd.splat_u32x8(P0_MOD_P4_SHOUP);
    let p1_mod_p4_shoup = simd.splat_u32x8(P1_MOD_P4_SHOUP);
    let p2_mod_p4_shoup = simd.splat_u32x8(P2_MOD_P4_SHOUP);

    let p01_inv_mod_p2 = simd.splat_u32x8(P01_INV_MOD_P2);
    let p01_inv_mod_p2_shoup = simd.splat_u32x8(P01_INV_MOD_P2_SHOUP);
    let p012_inv_mod_p3 = simd.splat_u32x8(P012_INV_MOD_P3);
    let p012_inv_mod_p3_shoup = simd.splat_u32x8(P012_INV_MOD_P3_SHOUP);
    let p0123_inv_mod_p4 = simd.splat_u32x8(P0123_INV_MOD_P4);
    let p0123_inv_mod_p4_shoup = simd.splat_u32x8(P0123_INV_MOD_P4_SHOUP);

    let p01 = simd.splat_u64x4((P0 as u64).wrapping_mul(P1 as u64));
    let p012 = simd.splat_u64x4((P0 as u64).wrapping_mul(P1 as u64).wrapping_mul(P2 as u64));
    let p0123 = simd.splat_u64x4(
        (P0 as u64)
            .wrapping_mul(P1 as u64)
            .wrapping_mul(P2 as u64)
            .wrapping_mul(P3 as u64),
    );
    let p01234 = simd.splat_u64x4(
        (P0 as u64)
            .wrapping_mul(P1 as u64)
            .wrapping_mul(P2 as u64)
            .wrapping_mul(P3 as u64)
            .wrapping_mul(P4 as u64),
    );

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
    let v3 = mul_mod32_avx2(
        simd,
        p3,
        simd.wrapping_sub_u32x8(
            simd.wrapping_add_u32x8(two_p3, mod_p3),
            simd.wrapping_add_u32x8(
                v0,
                mul_mod32_avx2(
                    simd,
                    p3,
                    simd.wrapping_add_u32x8(v1, mul_mod32_avx2(simd, p3, v2, p1, p1_mod_p3_shoup)),
                    p0,
                    p0_mod_p3_shoup,
                ),
            ),
        ),
        p012_inv_mod_p3,
        p012_inv_mod_p3_shoup,
    );
    let v4 = mul_mod32_avx2(
        simd,
        p4,
        simd.wrapping_sub_u32x8(
            simd.wrapping_add_u32x8(two_p4, mod_p4),
            simd.wrapping_add_u32x8(
                v0,
                mul_mod32_avx2(
                    simd,
                    p4,
                    simd.wrapping_add_u32x8(
                        v1,
                        mul_mod32_avx2(
                            simd,
                            p4,
                            simd.wrapping_add_u32x8(
                                v2,
                                mul_mod32_avx2(simd, p4, v3, p2, p2_mod_p4_shoup),
                            ),
                            p1,
                            p1_mod_p4_shoup,
                        ),
                    ),
                    p0,
                    p0_mod_p4_shoup,
                ),
            ),
        ),
        p0123_inv_mod_p4,
        p0123_inv_mod_p4_shoup,
    );

    let sign = simd.cmp_gt_u32x8(v4, half_p4);
    let sign: [i32x4; 2] = pulp::cast(sign);
    // sign extend so that -1i32 becomes -1i64
    let sign0: m64x4 = unsafe { core::mem::transmute(simd.convert_i32x4_to_i64x4(sign[0])) };
    let sign1: m64x4 = unsafe { core::mem::transmute(simd.convert_i32x4_to_i64x4(sign[1])) };

    let v0: [u32x4; 2] = pulp::cast(v0);
    let v1: [u32x4; 2] = pulp::cast(v1);
    let v2: [u32x4; 2] = pulp::cast(v2);
    let v3: [u32x4; 2] = pulp::cast(v3);
    let v4: [u32x4; 2] = pulp::cast(v4);
    let v00 = simd.convert_u32x4_to_u64x4(v0[0]);
    let v01 = simd.convert_u32x4_to_u64x4(v0[1]);
    let v10 = simd.convert_u32x4_to_u64x4(v1[0]);
    let v11 = simd.convert_u32x4_to_u64x4(v1[1]);
    let v20 = simd.convert_u32x4_to_u64x4(v2[0]);
    let v21 = simd.convert_u32x4_to_u64x4(v2[1]);
    let v30 = simd.convert_u32x4_to_u64x4(v3[0]);
    let v31 = simd.convert_u32x4_to_u64x4(v3[1]);
    let v40 = simd.convert_u32x4_to_u64x4(v4[0]);
    let v41 = simd.convert_u32x4_to_u64x4(v4[1]);

    let pos0 = v00;
    let pos0 = simd.wrapping_add_u64x4(pos0, simd.mul_low_32_bits_u64x4(pulp::cast(p0), v10));
    let pos0 = simd.wrapping_add_u64x4(
        pos0,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p01, v20),
    );
    let pos0 = simd.wrapping_add_u64x4(
        pos0,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p012, v30),
    );
    let pos0 = simd.wrapping_add_u64x4(
        pos0,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p0123, v40),
    );

    let pos1 = v01;
    let pos1 = simd.wrapping_add_u64x4(pos1, simd.mul_low_32_bits_u64x4(pulp::cast(p0), v11));
    let pos1 = simd.wrapping_add_u64x4(
        pos1,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p01, v21),
    );
    let pos1 = simd.wrapping_add_u64x4(
        pos1,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p012, v31),
    );
    let pos1 = simd.wrapping_add_u64x4(
        pos1,
        simd.wrapping_mul_lhs_with_low_32_bits_of_rhs_u64x4(p0123, v41),
    );

    let neg0 = simd.wrapping_sub_u64x4(pos0, p01234);
    let neg1 = simd.wrapping_sub_u64x4(pos1, p01234);

    [
        simd.select_u64x4(sign0, neg0, pos0),
        simd.select_u64x4(sign1, neg1, pos1),
    ]
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[allow(dead_code)]
#[inline(always)]
fn reconstruct_32bit_01234_avx512(
    simd: crate::V4IFma,
    mod_p0: u32x16,
    mod_p1: u32x16,
    mod_p2: u32x16,
    mod_p3: u32x16,
    mod_p4: u32x16,
) -> [u64x8; 2] {
    use crate::primes32::*;

    let p0 = simd.splat_u32x16(P0);
    let p1 = simd.splat_u32x16(P1);
    let p2 = simd.splat_u32x16(P2);
    let p3 = simd.splat_u32x16(P3);
    let p4 = simd.splat_u32x16(P4);
    let two_p1 = simd.splat_u32x16(2 * P1);
    let two_p2 = simd.splat_u32x16(2 * P2);
    let two_p3 = simd.splat_u32x16(2 * P3);
    let two_p4 = simd.splat_u32x16(2 * P4);
    let half_p4 = simd.splat_u32x16(P4 / 2);

    let p0_inv_mod_p1 = simd.splat_u32x16(P0_INV_MOD_P1);
    let p0_inv_mod_p1_shoup = simd.splat_u32x16(P0_INV_MOD_P1_SHOUP);
    let p0_mod_p2_shoup = simd.splat_u32x16(P0_MOD_P2_SHOUP);
    let p0_mod_p3_shoup = simd.splat_u32x16(P0_MOD_P3_SHOUP);
    let p1_mod_p3_shoup = simd.splat_u32x16(P1_MOD_P3_SHOUP);
    let p0_mod_p4_shoup = simd.splat_u32x16(P0_MOD_P4_SHOUP);
    let p1_mod_p4_shoup = simd.splat_u32x16(P1_MOD_P4_SHOUP);
    let p2_mod_p4_shoup = simd.splat_u32x16(P2_MOD_P4_SHOUP);

    let p01_inv_mod_p2 = simd.splat_u32x16(P01_INV_MOD_P2);
    let p01_inv_mod_p2_shoup = simd.splat_u32x16(P01_INV_MOD_P2_SHOUP);
    let p012_inv_mod_p3 = simd.splat_u32x16(P012_INV_MOD_P3);
    let p012_inv_mod_p3_shoup = simd.splat_u32x16(P012_INV_MOD_P3_SHOUP);
    let p0123_inv_mod_p4 = simd.splat_u32x16(P0123_INV_MOD_P4);
    let p0123_inv_mod_p4_shoup = simd.splat_u32x16(P0123_INV_MOD_P4_SHOUP);

    let p01 = simd.splat_u64x8((P0 as u64).wrapping_mul(P1 as u64));
    let p012 = simd.splat_u64x8((P0 as u64).wrapping_mul(P1 as u64).wrapping_mul(P2 as u64));
    let p0123 = simd.splat_u64x8(
        (P0 as u64)
            .wrapping_mul(P1 as u64)
            .wrapping_mul(P2 as u64)
            .wrapping_mul(P3 as u64),
    );
    let p01234 = simd.splat_u64x8(
        (P0 as u64)
            .wrapping_mul(P1 as u64)
            .wrapping_mul(P2 as u64)
            .wrapping_mul(P3 as u64)
            .wrapping_mul(P4 as u64),
    );

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
    let v3 = mul_mod32_avx512(
        simd,
        p3,
        simd.wrapping_sub_u32x16(
            simd.wrapping_add_u32x16(two_p3, mod_p3),
            simd.wrapping_add_u32x16(
                v0,
                mul_mod32_avx512(
                    simd,
                    p3,
                    simd.wrapping_add_u32x16(
                        v1,
                        mul_mod32_avx512(simd, p3, v2, p1, p1_mod_p3_shoup),
                    ),
                    p0,
                    p0_mod_p3_shoup,
                ),
            ),
        ),
        p012_inv_mod_p3,
        p012_inv_mod_p3_shoup,
    );
    let v4 = mul_mod32_avx512(
        simd,
        p4,
        simd.wrapping_sub_u32x16(
            simd.wrapping_add_u32x16(two_p4, mod_p4),
            simd.wrapping_add_u32x16(
                v0,
                mul_mod32_avx512(
                    simd,
                    p4,
                    simd.wrapping_add_u32x16(
                        v1,
                        mul_mod32_avx512(
                            simd,
                            p4,
                            simd.wrapping_add_u32x16(
                                v2,
                                mul_mod32_avx512(simd, p4, v3, p2, p2_mod_p4_shoup),
                            ),
                            p1,
                            p1_mod_p4_shoup,
                        ),
                    ),
                    p0,
                    p0_mod_p4_shoup,
                ),
            ),
        ),
        p0123_inv_mod_p4,
        p0123_inv_mod_p4_shoup,
    );

    let sign = simd.cmp_gt_u32x16(v4, half_p4).0;
    let sign0 = b8(sign as u8);
    let sign1 = b8((sign >> 8) as u8);
    let v0: [u32x8; 2] = pulp::cast(v0);
    let v1: [u32x8; 2] = pulp::cast(v1);
    let v2: [u32x8; 2] = pulp::cast(v2);
    let v3: [u32x8; 2] = pulp::cast(v3);
    let v4: [u32x8; 2] = pulp::cast(v4);
    let v00 = simd.convert_u32x8_to_u64x8(v0[0]);
    let v01 = simd.convert_u32x8_to_u64x8(v0[1]);
    let v10 = simd.convert_u32x8_to_u64x8(v1[0]);
    let v11 = simd.convert_u32x8_to_u64x8(v1[1]);
    let v20 = simd.convert_u32x8_to_u64x8(v2[0]);
    let v21 = simd.convert_u32x8_to_u64x8(v2[1]);
    let v30 = simd.convert_u32x8_to_u64x8(v3[0]);
    let v31 = simd.convert_u32x8_to_u64x8(v3[1]);
    let v40 = simd.convert_u32x8_to_u64x8(v4[0]);
    let v41 = simd.convert_u32x8_to_u64x8(v4[1]);

    let pos0 = v00;
    let pos0 = simd.wrapping_add_u64x8(pos0, simd.mul_low_32_bits_u64x8(pulp::cast(p0), v10));
    let pos0 = simd.wrapping_add_u64x8(pos0, simd.wrapping_mul_u64x8(p01, v20));
    let pos0 = simd.wrapping_add_u64x8(pos0, simd.wrapping_mul_u64x8(p012, v30));
    let pos0 = simd.wrapping_add_u64x8(pos0, simd.wrapping_mul_u64x8(p0123, v40));

    let pos1 = v01;
    let pos1 = simd.wrapping_add_u64x8(pos1, simd.mul_low_32_bits_u64x8(pulp::cast(p0), v11));
    let pos1 = simd.wrapping_add_u64x8(pos1, simd.wrapping_mul_u64x8(p01, v21));
    let pos1 = simd.wrapping_add_u64x8(pos1, simd.wrapping_mul_u64x8(p012, v31));
    let pos1 = simd.wrapping_add_u64x8(pos1, simd.wrapping_mul_u64x8(p0123, v41));

    let neg0 = simd.wrapping_sub_u64x8(pos0, p01234);
    let neg1 = simd.wrapping_sub_u64x8(pos1, p01234);

    [
        simd.select_u64x8(sign0, neg0, pos0),
        simd.select_u64x8(sign1, neg1, pos1),
    ]
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn reconstruct_32bit_01234_v2_avx512(
    simd: crate::V4IFma,
    mod_p0: u32x8,
    mod_p1: u32x8,
    mod_p2: u32x8,
    mod_p3: u32x8,
    mod_p4: u32x8,
) -> u64x8 {
    use crate::primes32::*;

    let p0 = simd.splat_u64x8(P0 as u64);
    let p1 = simd.splat_u64x8(P1 as u64);
    let p2 = simd.splat_u64x8(P2 as u64);
    let p3 = simd.splat_u64x8(P3 as u64);
    let p4 = simd.splat_u64x8(P4 as u64);
    let p12 = simd.splat_u64x8(P12);
    let p34 = simd.splat_u64x8(P34);
    let p012 = simd.splat_u64x8((P0 as u64).wrapping_mul(P12));
    let p01234 = simd.splat_u64x8((P0 as u64).wrapping_mul(P12).wrapping_mul(P34));

    let two_p2 = simd.splat_u64x8(2 * P2 as u64);
    let two_p4 = simd.splat_u64x8(2 * P4 as u64);
    let two_p12 = simd.splat_u64x8(2 * P12);
    let two_p34 = simd.splat_u64x8(2 * P34);
    let half_p34 = simd.splat_u64x8(P34 / 2);

    let p0_inv_mod_p12 = simd.splat_u64x8(P0_INV_MOD_P12);
    let p0_inv_mod_p12_shoup = simd.splat_u64x8(P0_INV_MOD_P12_SHOUP);
    let p1_inv_mod_p2 = simd.splat_u64x8(P1_INV_MOD_P2 as u64);
    let p1_inv_mod_p2_shoup = simd.splat_u64x8(P1_INV_MOD_P2_SHOUP as u64);
    let p3_inv_mod_p4 = simd.splat_u64x8(P3_INV_MOD_P4 as u64);
    let p3_inv_mod_p4_shoup = simd.splat_u64x8(P3_INV_MOD_P4_SHOUP as u64);

    let p012_inv_mod_p34 = simd.splat_u64x8(P012_INV_MOD_P34);
    let p012_inv_mod_p34_shoup = simd.splat_u64x8(P012_INV_MOD_P34_SHOUP);
    let p0_mod_p34_shoup = simd.splat_u64x8(P0_MOD_P34_SHOUP);

    let mod_p0 = simd.convert_u32x8_to_u64x8(mod_p0);
    let mod_p1 = simd.convert_u32x8_to_u64x8(mod_p1);
    let mod_p2 = simd.convert_u32x8_to_u64x8(mod_p2);
    let mod_p3 = simd.convert_u32x8_to_u64x8(mod_p3);
    let mod_p4 = simd.convert_u32x8_to_u64x8(mod_p4);

    let mod_p12 = {
        let v1 = mod_p1;
        let v2 = mul_mod32_v2_avx512(
            simd,
            p2,
            simd.wrapping_sub_u64x8(simd.wrapping_add_u64x8(two_p2, mod_p2), v1),
            p1_inv_mod_p2,
            p1_inv_mod_p2_shoup,
        );
        simd.wrapping_add_u64x8(v1, simd.wrapping_mul_u64x8(v2, p1))
    };
    let mod_p34 = {
        let v3 = mod_p3;
        let v4 = mul_mod32_v2_avx512(
            simd,
            p4,
            simd.wrapping_sub_u64x8(simd.wrapping_add_u64x8(two_p4, mod_p4), v3),
            p3_inv_mod_p4,
            p3_inv_mod_p4_shoup,
        );
        simd.wrapping_add_u64x8(v3, simd.wrapping_mul_u64x8(v4, p3))
    };

    let v0 = mod_p0;
    let v12 = mul_mod64_avx512(
        simd,
        p12,
        simd.wrapping_sub_u64x8(simd.wrapping_add_u64x8(two_p12, mod_p12), v0),
        p0_inv_mod_p12,
        p0_inv_mod_p12_shoup,
    );
    let v34 = mul_mod64_avx512(
        simd,
        p34,
        simd.wrapping_sub_u64x8(
            simd.wrapping_add_u64x8(two_p34, mod_p34),
            simd.wrapping_add_u64x8(v0, mul_mod64_avx512(simd, p34, v12, p0, p0_mod_p34_shoup)),
        ),
        p012_inv_mod_p34,
        p012_inv_mod_p34_shoup,
    );

    let sign = simd.cmp_gt_u64x8(v34, half_p34);
    let pos = v0;
    let pos = simd.wrapping_add_u64x8(pos, simd.wrapping_mul_u64x8(v12, p0));
    let pos = simd.wrapping_add_u64x8(pos, simd.wrapping_mul_u64x8(v34, p012));

    let neg = simd.wrapping_sub_u64x8(pos, p01234);

    simd.select_u64x8(sign, neg, pos)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
#[inline(always)]
fn reconstruct_52bit_012_avx512(
    simd: crate::V4IFma,
    mod_p0: u64x8,
    mod_p1: u64x8,
    mod_p2: u64x8,
) -> u64x8 {
    use crate::primes52::*;

    let p0 = simd.splat_u64x8(P0);
    let p1 = simd.splat_u64x8(P1);
    let p2 = simd.splat_u64x8(P2);
    let neg_p1 = simd.splat_u64x8(P1.wrapping_neg());
    let neg_p2 = simd.splat_u64x8(P2.wrapping_neg());
    let two_p1 = simd.splat_u64x8(2 * P1);
    let two_p2 = simd.splat_u64x8(2 * P2);
    let half_p2 = simd.splat_u64x8(P2 / 2);

    let p0_inv_mod_p1 = simd.splat_u64x8(P0_INV_MOD_P1);
    let p0_inv_mod_p1_shoup = simd.splat_u64x8(P0_INV_MOD_P1_SHOUP);
    let p0_mod_p2_shoup = simd.splat_u64x8(P0_MOD_P2_SHOUP);
    let p01_inv_mod_p2 = simd.splat_u64x8(P01_INV_MOD_P2);
    let p01_inv_mod_p2_shoup = simd.splat_u64x8(P01_INV_MOD_P2_SHOUP);

    let p01 = simd.splat_u64x8(P0.wrapping_mul(P1));
    let p012 = simd.splat_u64x8(P0.wrapping_mul(P1).wrapping_mul(P2));

    let v0 = mod_p0;
    let v1 = mul_mod52_avx512(
        simd,
        p1,
        neg_p1,
        simd.wrapping_sub_u64x8(simd.wrapping_add_u64x8(two_p1, mod_p1), v0),
        p0_inv_mod_p1,
        p0_inv_mod_p1_shoup,
    );
    let v2 = mul_mod52_avx512(
        simd,
        p2,
        neg_p2,
        simd.wrapping_sub_u64x8(
            simd.wrapping_add_u64x8(two_p2, mod_p2),
            simd.wrapping_add_u64x8(
                v0,
                mul_mod52_avx512(simd, p2, neg_p2, v1, p0, p0_mod_p2_shoup),
            ),
        ),
        p01_inv_mod_p2,
        p01_inv_mod_p2_shoup,
    );

    let sign = simd.cmp_gt_u64x8(v2, half_p2);

    let pos = simd.wrapping_add_u64x8(
        simd.wrapping_add_u64x8(v0, simd.wrapping_mul_u64x8(v1, p0)),
        simd.wrapping_mul_u64x8(v2, p01),
    );
    let neg = simd.wrapping_sub_u64x8(pos, p012);

    simd.select_u64x8(sign, neg, pos)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn reconstruct_slice_32bit_01234_avx2(
    simd: crate::V3,
    value: &mut [u64],
    mod_p0: &[u32],
    mod_p1: &[u32],
    mod_p2: &[u32],
    mod_p3: &[u32],
    mod_p4: &[u32],
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let value = pulp::as_arrays_mut::<4, _>(value).0;
            let mod_p0 = pulp::as_arrays::<4, _>(mod_p0).0;
            let mod_p1 = pulp::as_arrays::<4, _>(mod_p1).0;
            let mod_p2 = pulp::as_arrays::<4, _>(mod_p2).0;
            let mod_p3 = pulp::as_arrays::<4, _>(mod_p3).0;
            let mod_p4 = pulp::as_arrays::<4, _>(mod_p4).0;
            for (value, &mod_p0, &mod_p1, &mod_p2, &mod_p3, &mod_p4) in
                crate::izip!(value, mod_p0, mod_p1, mod_p2, mod_p3, mod_p4)
            {
                *value = cast(reconstruct_32bit_01234_v2_avx2(
                    simd,
                    cast(mod_p0),
                    cast(mod_p1),
                    cast(mod_p2),
                    cast(mod_p3),
                    cast(mod_p4),
                ));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
fn reconstruct_slice_32bit_01234_avx512(
    simd: crate::V4IFma,
    value: &mut [u64],
    mod_p0: &[u32],
    mod_p1: &[u32],
    mod_p2: &[u32],
    mod_p3: &[u32],
    mod_p4: &[u32],
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let value = pulp::as_arrays_mut::<8, _>(value).0;
            let mod_p0 = pulp::as_arrays::<8, _>(mod_p0).0;
            let mod_p1 = pulp::as_arrays::<8, _>(mod_p1).0;
            let mod_p2 = pulp::as_arrays::<8, _>(mod_p2).0;
            let mod_p3 = pulp::as_arrays::<8, _>(mod_p3).0;
            let mod_p4 = pulp::as_arrays::<8, _>(mod_p4).0;
            for (value, &mod_p0, &mod_p1, &mod_p2, &mod_p3, &mod_p4) in
                crate::izip!(value, mod_p0, mod_p1, mod_p2, mod_p3, mod_p4)
            {
                *value = cast(reconstruct_32bit_01234_v2_avx512(
                    simd,
                    cast(mod_p0),
                    cast(mod_p1),
                    cast(mod_p2),
                    cast(mod_p3),
                    cast(mod_p4),
                ));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
fn reconstruct_slice_52bit_012_avx512(
    simd: crate::V4IFma,
    value: &mut [u64],
    mod_p0: &[u64],
    mod_p1: &[u64],
    mod_p2: &[u64],
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let value = pulp::as_arrays_mut::<8, _>(value).0;
            let mod_p0 = pulp::as_arrays::<8, _>(mod_p0).0;
            let mod_p1 = pulp::as_arrays::<8, _>(mod_p1).0;
            let mod_p2 = pulp::as_arrays::<8, _>(mod_p2).0;
            for (value, &mod_p0, &mod_p1, &mod_p2) in crate::izip!(value, mod_p0, mod_p1, mod_p2) {
                *value = cast(reconstruct_52bit_012_avx512(
                    simd,
                    cast(mod_p0),
                    cast(mod_p1),
                    cast(mod_p2),
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
            Plan::try_new(n, P3)?,
            Plan::try_new(n, P4)?,
        ))
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.0.ntt_size()
    }

    #[inline]
    pub fn ntt_0(&self) -> &crate::prime32::Plan {
        &self.0
    }
    #[inline]
    pub fn ntt_1(&self) -> &crate::prime32::Plan {
        &self.1
    }
    #[inline]
    pub fn ntt_2(&self) -> &crate::prime32::Plan {
        &self.2
    }
    #[inline]
    pub fn ntt_3(&self) -> &crate::prime32::Plan {
        &self.3
    }
    #[inline]
    pub fn ntt_4(&self) -> &crate::prime32::Plan {
        &self.4
    }

    pub fn fwd(
        &self,
        value: &[u64],
        mod_p0: &mut [u32],
        mod_p1: &mut [u32],
        mod_p2: &mut [u32],
        mod_p3: &mut [u32],
        mod_p4: &mut [u32],
    ) {
        for (value, mod_p0, mod_p1, mod_p2, mod_p3, mod_p4) in crate::izip!(
            value,
            &mut *mod_p0,
            &mut *mod_p1,
            &mut *mod_p2,
            &mut *mod_p3,
            &mut *mod_p4
        ) {
            *mod_p0 = (value % crate::primes32::P0 as u64) as u32;
            *mod_p1 = (value % crate::primes32::P1 as u64) as u32;
            *mod_p2 = (value % crate::primes32::P2 as u64) as u32;
            *mod_p3 = (value % crate::primes32::P3 as u64) as u32;
            *mod_p4 = (value % crate::primes32::P4 as u64) as u32;
        }
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
        self.2.fwd(mod_p2);
        self.3.fwd(mod_p3);
        self.4.fwd(mod_p4);
    }

    pub fn inv(
        &self,
        value: &mut [u64],
        mod_p0: &mut [u32],
        mod_p1: &mut [u32],
        mod_p2: &mut [u32],
        mod_p3: &mut [u32],
        mod_p4: &mut [u32],
    ) {
        self.0.inv(mod_p0);
        self.1.inv(mod_p1);
        self.2.inv(mod_p2);
        self.3.inv(mod_p3);
        self.4.inv(mod_p4);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(feature = "avx512")]
            if let Some(simd) = crate::V4IFma::try_new() {
                reconstruct_slice_32bit_01234_avx512(
                    simd, value, mod_p0, mod_p1, mod_p2, mod_p3, mod_p4,
                );
                return;
            }
            if let Some(simd) = crate::V3::try_new() {
                reconstruct_slice_32bit_01234_avx2(
                    simd, value, mod_p0, mod_p1, mod_p2, mod_p3, mod_p4,
                );
                return;
            }
        }

        for (value, &mod_p0, &mod_p1, &mod_p2, &mod_p3, &mod_p4) in
            crate::izip!(value, &*mod_p0, &*mod_p1, &*mod_p2, &*mod_p3, &*mod_p4)
        {
            *value = reconstruct_32bit_01234_v2(mod_p0, mod_p1, mod_p2, mod_p3, mod_p4);
        }
    }

    /// Computes the negacyclic polynomial product of `lhs` and `rhs`, and stores the result in
    /// `prod`.
    pub fn negacyclic_polymul(&self, prod: &mut [u64], lhs: &[u64], rhs: &[u64]) {
        let n = prod.len();
        assert_eq!(n, lhs.len());
        assert_eq!(n, rhs.len());

        let mut lhs0 = avec![0; n];
        let mut lhs1 = avec![0; n];
        let mut lhs2 = avec![0; n];
        let mut lhs3 = avec![0; n];
        let mut lhs4 = avec![0; n];

        let mut rhs0 = avec![0; n];
        let mut rhs1 = avec![0; n];
        let mut rhs2 = avec![0; n];
        let mut rhs3 = avec![0; n];
        let mut rhs4 = avec![0; n];

        self.fwd(lhs, &mut lhs0, &mut lhs1, &mut lhs2, &mut lhs3, &mut lhs4);
        self.fwd(rhs, &mut rhs0, &mut rhs1, &mut rhs2, &mut rhs3, &mut rhs4);

        self.0.mul_assign_normalize(&mut lhs0, &rhs0);
        self.1.mul_assign_normalize(&mut lhs1, &rhs1);
        self.2.mul_assign_normalize(&mut lhs2, &rhs2);
        self.3.mul_assign_normalize(&mut lhs3, &rhs3);
        self.4.mul_assign_normalize(&mut lhs4, &rhs4);

        self.inv(prod, &mut lhs0, &mut lhs1, &mut lhs2, &mut lhs3, &mut lhs4);
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
        Some(Self(
            Plan::try_new(n, P0)?,
            Plan::try_new(n, P1)?,
            Plan::try_new(n, P2)?,
            simd,
        ))
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.0.ntt_size()
    }

    #[inline]
    pub fn ntt_0(&self) -> &crate::prime64::Plan {
        &self.0
    }
    #[inline]
    pub fn ntt_1(&self) -> &crate::prime64::Plan {
        &self.1
    }
    #[inline]
    pub fn ntt_2(&self) -> &crate::prime64::Plan {
        &self.2
    }

    pub fn fwd(&self, value: &[u64], mod_p0: &mut [u64], mod_p1: &mut [u64], mod_p2: &mut [u64]) {
        use crate::primes52::*;
        self.3.vectorize(
            #[inline(always)]
            || {
                for (&value, mod_p0, mod_p1, mod_p2) in
                    crate::izip!(value, &mut *mod_p0, &mut *mod_p1, &mut *mod_p2)
                {
                    *mod_p0 = value % P0;
                    *mod_p1 = value % P1;
                    *mod_p2 = value % P2;
                }
            },
        );
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
        self.2.fwd(mod_p2);
    }

    pub fn inv(
        &self,
        value: &mut [u64],
        mod_p0: &mut [u64],
        mod_p1: &mut [u64],
        mod_p2: &mut [u64],
    ) {
        self.0.inv(mod_p0);
        self.1.inv(mod_p1);
        self.2.inv(mod_p2);

        reconstruct_slice_52bit_012_avx512(self.3, value, mod_p0, mod_p1, mod_p2);
    }

    /// Computes the negacyclic polynomial product of `lhs` and `rhs`, and stores the result in
    /// `prod`.
    pub fn negacyclic_polymul(&self, prod: &mut [u64], lhs: &[u64], rhs: &[u64]) {
        let n = prod.len();
        assert_eq!(n, lhs.len());
        assert_eq!(n, rhs.len());

        let mut lhs0 = avec![0; n];
        let mut lhs1 = avec![0; n];
        let mut lhs2 = avec![0; n];

        let mut rhs0 = avec![0; n];
        let mut rhs1 = avec![0; n];
        let mut rhs2 = avec![0; n];

        self.fwd(lhs, &mut lhs0, &mut lhs1, &mut lhs2);
        self.fwd(rhs, &mut rhs0, &mut rhs1, &mut rhs2);

        self.0.mul_assign_normalize(&mut lhs0, &rhs0);
        self.1.mul_assign_normalize(&mut lhs1, &rhs1);
        self.2.mul_assign_normalize(&mut lhs2, &rhs2);

        self.inv(prod, &mut lhs0, &mut lhs1, &mut lhs2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prime64::tests::random_lhs_rhs_with_negacyclic_convolution;
    use alloc::{vec, vec::Vec};
    use rand::random;

    extern crate alloc;

    #[test]
    fn reconstruct_32bit() {
        for n in [32, 64, 256, 1024, 2048] {
            for _ in 0..10_000 {
                let value = (0..n).map(|_| random::<u64>()).collect::<Vec<_>>();
                let mut value_roundtrip = vec![0; n];
                let mut mod_p0 = vec![0; n];
                let mut mod_p1 = vec![0; n];
                let mut mod_p2 = vec![0; n];
                let mut mod_p3 = vec![0; n];
                let mut mod_p4 = vec![0; n];

                let plan = Plan32::try_new(n).unwrap();
                plan.fwd(
                    &value,
                    &mut mod_p0,
                    &mut mod_p1,
                    &mut mod_p2,
                    &mut mod_p3,
                    &mut mod_p4,
                );
                plan.inv(
                    &mut value_roundtrip,
                    &mut mod_p0,
                    &mut mod_p1,
                    &mut mod_p2,
                    &mut mod_p3,
                    &mut mod_p4,
                );
                for (&value, &value_roundtrip) in crate::izip!(&value, &value_roundtrip) {
                    assert_eq!(value_roundtrip, value.wrapping_mul(n as u64));
                }

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, 0);

                let mut prod = vec![0; n];
                plan.negacyclic_polymul(&mut prod, &lhs, &rhs);
                assert_eq!(prod, negacyclic_convolution);
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "avx512")]
    #[test]
    fn reconstruct_52bit() {
        for n in [32, 64, 256, 1024, 2048] {
            if let Some(plan) = Plan52::try_new(n) {
                for _ in 0..10_000 {
                    let value = (0..n).map(|_| random::<u64>()).collect::<Vec<_>>();
                    let mut value_roundtrip = vec![0; n];
                    let mut mod_p0 = vec![0; n];
                    let mut mod_p1 = vec![0; n];
                    let mut mod_p2 = vec![0; n];

                    plan.fwd(&value, &mut mod_p0, &mut mod_p1, &mut mod_p2);
                    plan.inv(&mut value_roundtrip, &mut mod_p0, &mut mod_p1, &mut mod_p2);
                    for (&value, &value_roundtrip) in crate::izip!(&value, &value_roundtrip) {
                        assert_eq!(value_roundtrip, value.wrapping_mul(n as u64));
                    }

                    let (lhs, rhs, negacyclic_convolution) =
                        random_lhs_rhs_with_negacyclic_convolution(n, 0);

                    let mut prod = vec![0; n];
                    plan.negacyclic_polymul(&mut prod, &lhs, &rhs);
                    assert_eq!(prod, negacyclic_convolution);
                }
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn reconstruct_32bit_avx() {
        for n in [16, 32, 64, 256, 1024, 2048] {
            for _ in 0..10_000 {
                use crate::primes32::*;

                let mut value = vec![0; n];
                let mut value_avx2 = vec![0; n];
                #[cfg(feature = "avx512")]
                let mut value_avx512 = vec![0; n];
                let mod_p0 = (0..n).map(|_| random::<u32>() % P0).collect::<Vec<_>>();
                let mod_p1 = (0..n).map(|_| random::<u32>() % P1).collect::<Vec<_>>();
                let mod_p2 = (0..n).map(|_| random::<u32>() % P2).collect::<Vec<_>>();
                let mod_p3 = (0..n).map(|_| random::<u32>() % P3).collect::<Vec<_>>();
                let mod_p4 = (0..n).map(|_| random::<u32>() % P4).collect::<Vec<_>>();

                for (value, &mod_p0, &mod_p1, &mod_p2, &mod_p3, &mod_p4) in
                    crate::izip!(&mut value, &mod_p0, &mod_p1, &mod_p2, &mod_p3, &mod_p4)
                {
                    *value = reconstruct_32bit_01234_v2(mod_p0, mod_p1, mod_p2, mod_p3, mod_p4);
                }

                if let Some(simd) = crate::V3::try_new() {
                    reconstruct_slice_32bit_01234_avx2(
                        simd,
                        &mut value_avx2,
                        &mod_p0,
                        &mod_p1,
                        &mod_p2,
                        &mod_p3,
                        &mod_p4,
                    );
                    assert_eq!(value, value_avx2);
                }
                #[cfg(feature = "avx512")]
                if let Some(simd) = crate::V4IFma::try_new() {
                    reconstruct_slice_32bit_01234_avx512(
                        simd,
                        &mut value_avx512,
                        &mod_p0,
                        &mod_p1,
                        &mod_p2,
                        &mod_p3,
                        &mod_p4,
                    );
                    assert_eq!(value, value_avx512);
                }
            }
        }
    }
}
