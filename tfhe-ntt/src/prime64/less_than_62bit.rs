#[allow(unused_imports)]
use pulp::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[inline(always)]
pub(crate) fn fwd_butterfly_avx512(
    simd: crate::V4,
    z0: u64x8,
    z1: u64x8,
    w: u64x8,
    w_shoup: u64x8,
    p: u64x8,
    neg_p: u64x8,
    two_p: u64x8,
) -> (u64x8, u64x8) {
    let _ = p;
    let z0 = simd.small_mod_u64x8(two_p, z0);
    let shoup_q = simd.widening_mul_u64x8(z1, w_shoup).1;
    let t = simd.wrapping_add_u64x8(
        simd.wrapping_mul_u64x8(z1, w),
        simd.wrapping_mul_u64x8(shoup_q, neg_p),
    );
    (
        simd.wrapping_add_u64x8(z0, t),
        simd.wrapping_add_u64x8(simd.wrapping_sub_u64x8(z0, t), two_p),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[inline(always)]
pub(crate) fn fwd_last_butterfly_avx512(
    simd: crate::V4,
    z0: u64x8,
    z1: u64x8,
    w: u64x8,
    w_shoup: u64x8,
    p: u64x8,
    neg_p: u64x8,
    two_p: u64x8,
) -> (u64x8, u64x8) {
    let _ = p;
    let z0 = simd.small_mod_u64x8(two_p, z0);
    let z0 = simd.small_mod_u64x8(p, z0);
    let shoup_q = simd.widening_mul_u64x8(z1, w_shoup).1;
    let t = simd.wrapping_add_u64x8(
        simd.wrapping_mul_u64x8(z1, w),
        simd.wrapping_mul_u64x8(shoup_q, neg_p),
    );
    let t = simd.small_mod_u64x8(p, t);
    (
        simd.small_mod_u64x8(p, simd.wrapping_add_u64x8(z0, t)),
        simd.small_mod_u64x8(
            p,
            simd.wrapping_add_u64x8(simd.wrapping_sub_u64x8(z0, t), p),
        ),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn fwd_butterfly_avx2(
    simd: crate::V3,
    z0: u64x4,
    z1: u64x4,
    w: u64x4,
    w_shoup: u64x4,
    p: u64x4,
    neg_p: u64x4,
    two_p: u64x4,
) -> (u64x4, u64x4) {
    let _ = p;
    let z0 = simd.small_mod_u64x4(two_p, z0);
    let shoup_q = simd.widening_mul_u64x4(z1, w_shoup).1;
    let t = simd.wrapping_add_u64x4(
        simd.widening_mul_u64x4(z1, w).0,
        simd.widening_mul_u64x4(shoup_q, neg_p).0,
    );
    (
        simd.wrapping_add_u64x4(z0, t),
        simd.wrapping_add_u64x4(simd.wrapping_sub_u64x4(z0, t), two_p),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn fwd_last_butterfly_avx2(
    simd: crate::V3,
    z0: u64x4,
    z1: u64x4,
    w: u64x4,
    w_shoup: u64x4,
    p: u64x4,
    neg_p: u64x4,
    two_p: u64x4,
) -> (u64x4, u64x4) {
    let _ = p;
    let z0 = simd.small_mod_u64x4(two_p, z0);
    let z0 = simd.small_mod_u64x4(p, z0);
    let shoup_q = simd.widening_mul_u64x4(z1, w_shoup).1;
    let t = simd.wrapping_add_u64x4(
        simd.widening_mul_u64x4(z1, w).0,
        simd.widening_mul_u64x4(shoup_q, neg_p).0,
    );
    let t = simd.small_mod_u64x4(p, t);
    (
        simd.small_mod_u64x4(p, simd.wrapping_add_u64x4(z0, t)),
        simd.small_mod_u64x4(
            p,
            simd.wrapping_add_u64x4(simd.wrapping_sub_u64x4(z0, t), p),
        ),
    )
}

#[inline(always)]
pub(crate) fn fwd_butterfly_scalar(
    z0: u64,
    z1: u64,
    w: u64,
    w_shoup: u64,
    p: u64,
    neg_p: u64,
    two_p: u64,
) -> (u64, u64) {
    let _ = p;
    let z0 = z0.min(z0.wrapping_sub(two_p));
    let shoup_q = ((z1 as u128 * w_shoup as u128) >> 64) as u64;
    let t = u64::wrapping_add(z1.wrapping_mul(w), shoup_q.wrapping_mul(neg_p));
    (z0.wrapping_add(t), z0.wrapping_sub(t).wrapping_add(two_p))
}

#[inline(always)]
pub(crate) fn fwd_last_butterfly_scalar(
    z0: u64,
    z1: u64,
    w: u64,
    w_shoup: u64,
    p: u64,
    neg_p: u64,
    two_p: u64,
) -> (u64, u64) {
    let _ = p;
    let z0 = z0.min(z0.wrapping_sub(two_p));
    let z0 = z0.min(z0.wrapping_sub(p));
    let shoup_q = ((z1 as u128 * w_shoup as u128) >> 64) as u64;
    let t = u64::wrapping_add(z1.wrapping_mul(w), shoup_q.wrapping_mul(neg_p));
    let t = t.min(t.wrapping_sub(p));
    let res = (z0.wrapping_add(t), z0.wrapping_sub(t).wrapping_add(p));
    (
        res.0.min(res.0.wrapping_sub(p)),
        res.1.min(res.1.wrapping_sub(p)),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[inline(always)]
pub(crate) fn inv_butterfly_avx512(
    simd: crate::V4,
    z0: u64x8,
    z1: u64x8,
    w: u64x8,
    w_shoup: u64x8,
    p: u64x8,
    neg_p: u64x8,
    two_p: u64x8,
) -> (u64x8, u64x8) {
    let _ = p;

    let y0 = simd.wrapping_add_u64x8(z0, z1);
    let y0 = simd.small_mod_u64x8(two_p, y0);
    let t = simd.wrapping_add_u64x8(simd.wrapping_sub_u64x8(z0, z1), two_p);

    let shoup_q = simd.widening_mul_u64x8(t, w_shoup).1;
    let y1 = simd.wrapping_add_u64x8(
        simd.wrapping_mul_u64x8(t, w),
        simd.wrapping_mul_u64x8(shoup_q, neg_p),
    );

    (y0, y1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[inline(always)]
pub(crate) fn inv_last_butterfly_avx512(
    simd: crate::V4,
    z0: u64x8,
    z1: u64x8,
    w: u64x8,
    w_shoup: u64x8,
    p: u64x8,
    neg_p: u64x8,
    two_p: u64x8,
) -> (u64x8, u64x8) {
    let _ = p;

    let y0 = simd.wrapping_add_u64x8(z0, z1);
    let y0 = simd.small_mod_u64x8(two_p, y0);
    let y0 = simd.small_mod_u64x8(p, y0);
    let t = simd.wrapping_add_u64x8(simd.wrapping_sub_u64x8(z0, z1), two_p);

    let shoup_q = simd.widening_mul_u64x8(t, w_shoup).1;
    let y1 = simd.wrapping_add_u64x8(
        simd.wrapping_mul_u64x8(t, w),
        simd.wrapping_mul_u64x8(shoup_q, neg_p),
    );
    let y1 = simd.small_mod_u64x8(p, y1);

    (y0, y1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn inv_butterfly_avx2(
    simd: crate::V3,
    z0: u64x4,
    z1: u64x4,
    w: u64x4,
    w_shoup: u64x4,
    p: u64x4,
    neg_p: u64x4,
    two_p: u64x4,
) -> (u64x4, u64x4) {
    let _ = p;

    let y0 = simd.wrapping_add_u64x4(z0, z1);
    let y0 = simd.small_mod_u64x4(two_p, y0);
    let t = simd.wrapping_add_u64x4(simd.wrapping_sub_u64x4(z0, z1), two_p);

    let shoup_q = simd.widening_mul_u64x4(t, w_shoup).1;
    let y1 = simd.wrapping_add_u64x4(
        simd.widening_mul_u64x4(t, w).0,
        simd.widening_mul_u64x4(shoup_q, neg_p).0,
    );

    (y0, y1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn inv_last_butterfly_avx2(
    simd: crate::V3,
    z0: u64x4,
    z1: u64x4,
    w: u64x4,
    w_shoup: u64x4,
    p: u64x4,
    neg_p: u64x4,
    two_p: u64x4,
) -> (u64x4, u64x4) {
    let _ = p;

    let y0 = simd.wrapping_add_u64x4(z0, z1);
    let y0 = simd.small_mod_u64x4(two_p, y0);
    let y0 = simd.small_mod_u64x4(p, y0);
    let t = simd.wrapping_add_u64x4(simd.wrapping_sub_u64x4(z0, z1), two_p);

    let shoup_q = simd.widening_mul_u64x4(t, w_shoup).1;
    let y1 = simd.wrapping_add_u64x4(
        simd.widening_mul_u64x4(t, w).0,
        simd.widening_mul_u64x4(shoup_q, neg_p).0,
    );
    let y1 = simd.small_mod_u64x4(p, y1);

    (y0, y1)
}

#[inline(always)]
pub(crate) fn inv_butterfly_scalar(
    z0: u64,
    z1: u64,
    w: u64,
    w_shoup: u64,
    p: u64,
    neg_p: u64,
    two_p: u64,
) -> (u64, u64) {
    let _ = p;

    let y0 = z0.wrapping_add(z1);
    let y0 = y0.min(y0.wrapping_sub(two_p));
    let t = z0.wrapping_sub(z1).wrapping_add(two_p);
    let shoup_q = ((t as u128 * w_shoup as u128) >> 64) as u64;
    let y1 = u64::wrapping_add(t.wrapping_mul(w), shoup_q.wrapping_mul(neg_p));
    (y0, y1)
}

#[inline(always)]
pub(crate) fn inv_last_butterfly_scalar(
    z0: u64,
    z1: u64,
    w: u64,
    w_shoup: u64,
    p: u64,
    neg_p: u64,
    two_p: u64,
) -> (u64, u64) {
    let _ = p;

    let y0 = z0.wrapping_add(z1);
    let y0 = y0.min(y0.wrapping_sub(two_p));
    let y0 = y0.min(y0.wrapping_sub(p));
    let t = z0.wrapping_sub(z1).wrapping_add(two_p);
    let shoup_q = ((t as u128 * w_shoup as u128) >> 64) as u64;
    let y1 = u64::wrapping_add(t.wrapping_mul(w), shoup_q.wrapping_mul(neg_p));
    let y1 = y1.min(y1.wrapping_sub(p));
    (y0, y1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn fwd_avx512(
    simd: crate::V4,
    p: u64,
    data: &mut [u64],
    twid: &[u64],
    twid_shoup: &[u64],
) {
    super::shoup::fwd_depth_first_avx512(
        simd,
        p,
        data,
        twid,
        twid_shoup,
        0,
        0,
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            fwd_butterfly_avx512(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            fwd_last_butterfly_avx512(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
pub(crate) fn inv_avx512(
    simd: crate::V4,
    p: u64,
    data: &mut [u64],
    twid: &[u64],
    twid_shoup: &[u64],
) {
    super::shoup::inv_depth_first_avx512(
        simd,
        p,
        data,
        twid,
        twid_shoup,
        0,
        0,
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            inv_butterfly_avx512(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            inv_last_butterfly_avx512(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn fwd_avx2(
    simd: crate::V3,
    p: u64,
    data: &mut [u64],
    twid: &[u64],
    twid_shoup: &[u64],
) {
    super::shoup::fwd_depth_first_avx2(
        simd,
        p,
        data,
        twid,
        twid_shoup,
        0,
        0,
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            fwd_butterfly_avx2(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            fwd_last_butterfly_avx2(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn inv_avx2(
    simd: crate::V3,
    p: u64,
    data: &mut [u64],
    twid: &[u64],
    twid_shoup: &[u64],
) {
    super::shoup::inv_depth_first_avx2(
        simd,
        p,
        data,
        twid,
        twid_shoup,
        0,
        0,
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            inv_butterfly_avx2(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
        #[inline(always)]
        |simd, z0, z1, w, w_shoup, p, neg_p, two_p| {
            inv_last_butterfly_avx2(simd, z0, z1, w, w_shoup, p, neg_p, two_p)
        },
    )
}

pub(crate) fn fwd_scalar(p: u64, data: &mut [u64], twid: &[u64], twid_shoup: &[u64]) {
    super::shoup::fwd_depth_first_scalar(
        p,
        data,
        twid,
        twid_shoup,
        0,
        0,
        #[inline(always)]
        |z0, z1, w, w_shoup, p, neg_p, two_p| {
            fwd_butterfly_scalar(z0, z1, w, w_shoup, p, neg_p, two_p)
        },
        #[inline(always)]
        |z0, z1, w, w_shoup, p, neg_p, two_p| {
            fwd_last_butterfly_scalar(z0, z1, w, w_shoup, p, neg_p, two_p)
        },
    )
}

pub(crate) fn inv_scalar(p: u64, data: &mut [u64], twid: &[u64], twid_shoup: &[u64]) {
    super::shoup::inv_depth_first_scalar(
        p,
        data,
        twid,
        twid_shoup,
        0,
        0,
        #[inline(always)]
        |z0, z1, w, w_shoup, p, neg_p, two_p| {
            inv_butterfly_scalar(z0, z1, w, w_shoup, p, neg_p, two_p)
        },
        #[inline(always)]
        |z0, z1, w, w_shoup, p, neg_p, two_p| {
            inv_last_butterfly_scalar(z0, z1, w, w_shoup, p, neg_p, two_p)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prime::largest_prime_in_arithmetic_progression64,
        prime64::{
            init_negacyclic_twiddles_shoup,
            tests::{mul, random_lhs_rhs_with_negacyclic_convolution},
        },
    };
    use alloc::vec;

    extern crate alloc;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly")]
    #[test]
    fn test_product_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            for n in [16, 32, 64, 128, 256, 512, 1024] {
                let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 61, 1 << 62)
                    .unwrap();

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u64; n];
                let mut twid_shoup = vec![0u64; n];
                let mut inv_twid = vec![0u64; n];
                let mut inv_twid_shoup = vec![0u64; n];
                init_negacyclic_twiddles_shoup(
                    p,
                    n,
                    64,
                    &mut twid,
                    &mut twid_shoup,
                    &mut inv_twid,
                    &mut inv_twid_shoup,
                );

                let mut prod = vec![0u64; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                fwd_avx512(simd, p, &mut lhs_fourier, &twid, &twid_shoup);
                fwd_avx512(simd, p, &mut rhs_fourier, &twid, &twid_shoup);
                for x in &lhs_fourier {
                    assert!(*x < p);
                }
                for x in &rhs_fourier {
                    assert!(*x < p);
                }

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_avx512(simd, p, &mut prod, &inv_twid, &inv_twid_shoup);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
                }
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_product_avx2() {
        use crate::prime64::tests::mul;

        if let Some(simd) = crate::V3::try_new() {
            for n in [16, 32, 64, 128, 256, 512, 1024] {
                let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 61, 1 << 62)
                    .unwrap();

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut twid = vec![0u64; n];
                let mut twid_shoup = vec![0u64; n];
                let mut inv_twid = vec![0u64; n];
                let mut inv_twid_shoup = vec![0u64; n];
                init_negacyclic_twiddles_shoup(
                    p,
                    n,
                    64,
                    &mut twid,
                    &mut twid_shoup,
                    &mut inv_twid,
                    &mut inv_twid_shoup,
                );

                let mut prod = vec![0u64; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                fwd_avx2(simd, p, &mut lhs_fourier, &twid, &twid_shoup);
                fwd_avx2(simd, p, &mut rhs_fourier, &twid, &twid_shoup);
                for x in &lhs_fourier {
                    assert!(*x < p);
                }
                for x in &rhs_fourier {
                    assert!(*x < p);
                }

                for i in 0..n {
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }

                inv_avx2(simd, p, &mut prod, &inv_twid, &inv_twid_shoup);
                let result = prod;

                for i in 0..n {
                    assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
                }
            }
        }
    }

    #[test]
    fn test_product_scalar() {
        for n in [16, 32, 64, 128, 256, 512, 1024] {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 61, 1 << 62).unwrap();

            let (lhs, rhs, negacyclic_convolution) =
                random_lhs_rhs_with_negacyclic_convolution(n, p);

            let mut twid = vec![0u64; n];
            let mut twid_shoup = vec![0u64; n];
            let mut inv_twid = vec![0u64; n];
            let mut inv_twid_shoup = vec![0u64; n];
            init_negacyclic_twiddles_shoup(
                p,
                n,
                64,
                &mut twid,
                &mut twid_shoup,
                &mut inv_twid,
                &mut inv_twid_shoup,
            );

            let mut prod = vec![0u64; n];
            let mut lhs_fourier = lhs.clone();
            let mut rhs_fourier = rhs.clone();

            fwd_scalar(p, &mut lhs_fourier, &twid, &twid_shoup);
            fwd_scalar(p, &mut rhs_fourier, &twid, &twid_shoup);
            for x in &lhs_fourier {
                assert!(*x < p);
            }
            for x in &rhs_fourier {
                assert!(*x < p);
            }

            for i in 0..n {
                prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
            }

            inv_scalar(p, &mut prod, &inv_twid, &inv_twid_shoup);
            let result = prod;

            for i in 0..n {
                assert_eq!(result[i], mul(p, negacyclic_convolution[i], n as u64));
            }
        }
    }
}
