use pulp::u64x8;

#[inline(always)]
pub(crate) fn fwd_butterfly_avx512(
    simd: crate::V4IFma,
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
    let shoup_q = simd.widening_mul_u52x8(z1, w_shoup).1;
    let t = simd.wrapping_mul_add_u52x8(shoup_q, neg_p, simd.widening_mul_u52x8(z1, w).0);
    (
        simd.wrapping_add_u64x8(z0, t),
        simd.wrapping_add_u64x8(simd.wrapping_sub_u64x8(z0, t), two_p),
    )
}

#[inline(always)]
pub(crate) fn fwd_last_butterfly_avx512(
    simd: crate::V4IFma,
    z0: u64x8,
    z1: u64x8,
    w: u64x8,
    w_shoup: u64x8,
    p: u64x8,
    neg_p: u64x8,
    two_p: u64x8,
) -> (u64x8, u64x8) {
    let z0 = simd.small_mod_u64x8(two_p, z0);
    let z0 = simd.small_mod_u64x8(p, z0);
    let shoup_q = simd.widening_mul_u52x8(z1, w_shoup).1;
    let t = simd.wrapping_mul_add_u52x8(shoup_q, neg_p, simd.widening_mul_u52x8(z1, w).0);
    let t = simd.small_mod_u64x8(p, t);
    (
        simd.small_mod_u64x8(p, simd.wrapping_add_u64x8(z0, t)),
        simd.small_mod_u64x8(
            p,
            simd.wrapping_add_u64x8(simd.wrapping_sub_u64x8(z0, t), p),
        ),
    )
}

#[inline(always)]
pub(crate) fn inv_butterfly_avx512(
    simd: crate::V4IFma,
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

    let shoup_q = simd.widening_mul_u52x8(t, w_shoup).1;
    let y1 = simd.wrapping_mul_add_u52x8(shoup_q, neg_p, simd.widening_mul_u52x8(t, w).0);

    (y0, y1)
}

#[inline(always)]
pub(crate) fn inv_last_butterfly_avx512(
    simd: crate::V4IFma,
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

    let shoup_q = simd.widening_mul_u52x8(t, w_shoup).1;
    let y1 = simd.wrapping_mul_add_u52x8(shoup_q, neg_p, simd.widening_mul_u52x8(t, w).0);
    let y1 = simd.small_mod_u64x8(p, y1);

    (y0, y1)
}

pub(crate) fn fwd_avx512(
    simd: crate::V4IFma,
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

pub(crate) fn inv_avx512(
    simd: crate::V4IFma,
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

    #[test]
    fn test_product() {
        if let Some(simd) = crate::V4IFma::try_new() {
            for n in [16, 32, 64, 128, 256, 512, 1024] {
                let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 49, 1 << 50)
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
                    52,
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
}
