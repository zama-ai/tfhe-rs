use crate::{bit_rev, fastdiv::Div64, prime::is_prime64, roots::find_primitive_root64};
use aligned_vec::{avec, ABox};

#[allow(unused_imports)]
use pulp::*;

const RECURSION_THRESHOLD: usize = 1024;

mod generic_solinas;
mod shoup;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
mod less_than_50bit;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
mod less_than_51bit;

mod less_than_62bit;
mod less_than_63bit;

pub use generic_solinas::Solinas;

use self::generic_solinas::PrimeModulus;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl crate::V3 {
    #[inline(always)]
    fn interleave2_u64x4(self, z0z0z1z1: [u64x4; 2]) -> [u64x4; 2] {
        let avx = self.avx;
        [
            cast(
                avx._mm256_permute2f128_si256::<0b0010_0000>(cast(z0z0z1z1[0]), cast(z0z0z1z1[1])),
            ),
            cast(
                avx._mm256_permute2f128_si256::<0b0011_0001>(cast(z0z0z1z1[0]), cast(z0z0z1z1[1])),
            ),
        ]
    }

    #[inline(always)]
    fn permute2_u64x4(self, w: [u64; 2]) -> u64x4 {
        let avx = self.avx;
        let w00 = self.sse2._mm_set1_epi64x(w[0] as _);
        let w11 = self.sse2._mm_set1_epi64x(w[1] as _);
        cast(avx._mm256_insertf128_si256::<0b1>(avx._mm256_castsi128_si256(w00), w11))
    }

    #[inline(always)]
    fn interleave1_u64x4(self, z0z1: [u64x4; 2]) -> [u64x4; 2] {
        let avx = self.avx2;
        [
            cast(avx._mm256_unpacklo_epi64(cast(z0z1[0]), cast(z0z1[1]))),
            cast(avx._mm256_unpackhi_epi64(cast(z0z1[0]), cast(z0z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute1_u64x4(self, w: [u64; 4]) -> u64x4 {
        let avx = self.avx;
        let w0123 = pulp::cast(w);
        let w0101 = avx._mm256_permute2f128_si256::<0b0000_0000>(w0123, w0123);
        let w2323 = avx._mm256_permute2f128_si256::<0b0011_0011>(w0123, w0123);
        cast(avx._mm256_castpd_si256(avx._mm256_shuffle_pd::<0b1100>(
            avx._mm256_castsi256_pd(w0101),
            avx._mm256_castsi256_pd(w2323),
        )))
    }

    #[inline(always)]
    pub fn small_mod_u64x4(self, modulus: u64x4, x: u64x4) -> u64x4 {
        self.select_u64x4(
            self.cmp_gt_u64x4(modulus, x),
            x,
            self.wrapping_sub_u64x4(x, modulus),
        )
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl crate::V4 {
    #[inline(always)]
    fn interleave4_u64x8(self, z0z0z0z0z1z1z1z1: [u64x8; 2]) -> [u64x8; 2] {
        let avx = self.avx512f;
        let idx_0 = avx._mm512_setr_epi64(0x0, 0x1, 0x2, 0x3, 0x8, 0x9, 0xa, 0xb);
        let idx_1 = avx._mm512_setr_epi64(0x4, 0x5, 0x6, 0x7, 0xc, 0xd, 0xe, 0xf);
        [
            cast(avx._mm512_permutex2var_epi64(
                cast(z0z0z0z0z1z1z1z1[0]),
                idx_0,
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
            cast(avx._mm512_permutex2var_epi64(
                cast(z0z0z0z0z1z1z1z1[0]),
                idx_1,
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
        ]
    }

    #[inline(always)]
    fn permute4_u64x8(self, w: [u64; 2]) -> u64x8 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let w01xxxxxx = avx._mm512_castsi128_si512(w);
        let idx = avx._mm512_setr_epi64(0, 0, 0, 0, 1, 1, 1, 1);
        cast(avx._mm512_permutexvar_epi64(idx, w01xxxxxx))
    }

    #[inline(always)]
    fn interleave2_u64x8(self, z0z0z1z1: [u64x8; 2]) -> [u64x8; 2] {
        let avx = self.avx512f;
        let idx_0 = avx._mm512_setr_epi64(0x0, 0x1, 0x8, 0x9, 0x4, 0x5, 0xc, 0xd);
        let idx_1 = avx._mm512_setr_epi64(0x2, 0x3, 0xa, 0xb, 0x6, 0x7, 0xe, 0xf);
        [
            cast(avx._mm512_permutex2var_epi64(cast(z0z0z1z1[0]), idx_0, cast(z0z0z1z1[1]))),
            cast(avx._mm512_permutex2var_epi64(cast(z0z0z1z1[0]), idx_1, cast(z0z0z1z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute2_u64x8(self, w: [u64; 4]) -> u64x8 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let w0123xxxx = avx._mm512_castsi256_si512(w);
        let idx = avx._mm512_setr_epi64(0, 0, 2, 2, 1, 1, 3, 3);
        cast(avx._mm512_permutexvar_epi64(idx, w0123xxxx))
    }

    #[inline(always)]
    fn interleave1_u64x8(self, z0z1: [u64x8; 2]) -> [u64x8; 2] {
        let avx = self.avx512f;
        [
            cast(avx._mm512_unpacklo_epi64(cast(z0z1[0]), cast(z0z1[1]))),
            cast(avx._mm512_unpackhi_epi64(cast(z0z1[0]), cast(z0z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute1_u64x8(self, w: [u64; 8]) -> u64x8 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let idx = avx._mm512_setr_epi64(0, 4, 1, 5, 2, 6, 3, 7);
        cast(avx._mm512_permutexvar_epi64(idx, w))
    }

    #[inline(always)]
    pub fn small_mod_u64x8(self, modulus: u64x8, x: u64x8) -> u64x8 {
        self.select_u64x8(
            self.cmp_gt_u64x8(modulus, x),
            x,
            self.wrapping_sub_u64x8(x, modulus),
        )
    }
}

fn init_negacyclic_twiddles(p: u64, n: usize, twid: &mut [u64], inv_twid: &mut [u64]) {
    let div = Div64::new(p);
    let w = find_primitive_root64(div, 2 * n as u64).unwrap();
    let mut k = 0;
    let mut wk = 1u64;

    let nbits = n.trailing_zeros();
    while k < n {
        let fwd_idx = bit_rev(nbits, k);

        twid[fwd_idx] = wk;

        let inv_idx = bit_rev(nbits, (n - k) % n);
        if k == 0 {
            inv_twid[inv_idx] = wk;
        } else {
            let x = p.wrapping_sub(wk);
            inv_twid[inv_idx] = x;
        }

        wk = Div64::rem_u128(wk as u128 * w as u128, div);
        k += 1;
    }
}

fn init_negacyclic_twiddles_shoup(
    p: u64,
    n: usize,
    max_bits: u32,
    twid: &mut [u64],
    twid_shoup: &mut [u64],
    inv_twid: &mut [u64],
    inv_twid_shoup: &mut [u64],
) {
    let div = Div64::new(p);
    let w = find_primitive_root64(div, 2 * n as u64).unwrap();
    let mut k = 0;
    let mut wk = 1u64;

    let nbits = n.trailing_zeros();
    while k < n {
        let fwd_idx = bit_rev(nbits, k);

        let wk_shoup = Div64::div_u128((wk as u128) << max_bits, div) as u64;
        twid[fwd_idx] = wk;
        twid_shoup[fwd_idx] = wk_shoup;

        let inv_idx = bit_rev(nbits, (n - k) % n);
        if k == 0 {
            inv_twid[inv_idx] = wk;
            inv_twid_shoup[inv_idx] = wk_shoup;
        } else {
            let x = p.wrapping_sub(wk);
            inv_twid[inv_idx] = x;
            inv_twid_shoup[inv_idx] = Div64::div_u128((x as u128) << max_bits, div) as u64;
        }

        wk = Div64::rem_u128(wk as u128 * w as u128, div);
        k += 1;
    }
}

/// Negacyclic NTT plan for 64bit primes.
#[derive(Clone)]
pub struct Plan {
    twid: ABox<[u64]>,
    twid_shoup: ABox<[u64]>,
    inv_twid: ABox<[u64]>,
    inv_twid_shoup: ABox<[u64]>,
    p: u64,
    p_div: Div64,

    // used for elementwise product
    p_barrett: u64,
    big_q: u64,

    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
}

impl core::fmt::Debug for Plan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plan")
            .field("ntt_size", &self.ntt_size())
            .field("modulus", &self.modulus())
            .finish()
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn mul_assign_normalize_ifma(
    simd: crate::V4IFma,
    lhs: &mut [u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
) {
    simd.vectorize(
        #[inline(always)]
        || {
            let lhs = pulp::as_arrays_mut::<8, _>(lhs).0;
            let rhs = pulp::as_arrays::<8, _>(rhs).0;

            let big_q_m1 = simd.splat_u64x8(big_q - 1);
            let big_q_m1_complement = simd.splat_u64x8(52 - (big_q - 1));
            let n_inv_mod_p = simd.splat_u64x8(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u64x8(n_inv_mod_p_shoup);
            let p_barrett = simd.splat_u64x8(p_barrett);
            let neg_p = simd.splat_u64x8(p.wrapping_neg());
            let p = simd.splat_u64x8(p);
            let zero = simd.splat_u64x8(0);

            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = cast(*lhs_);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u52x8(lhs, rhs);
                let c1 = simd.or_u64x8(
                    simd.shr_dyn_u64x8(lo, big_q_m1),
                    simd.shl_dyn_u64x8(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u52x8(c1, p_barrett).1;
                // lo - p * c3
                let prod = simd.wrapping_mul_add_u52x8(neg_p, c3, lo);

                // normalization
                let shoup_q = simd.widening_mul_u52x8(prod, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_mul_add_u52x8(
                    shoup_q,
                    neg_p,
                    simd.wrapping_mul_add_u52x8(prod, n_inv_mod_p, zero),
                );

                *lhs_ = cast(simd.small_mod_u64x8(p, t));
            }
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn mul_accumulate_ifma(
    simd: crate::V4IFma,
    acc: &mut [u64],
    lhs: &[u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
) {
    simd.vectorize(
        #[inline(always)]
        || {
            let acc = pulp::as_arrays_mut::<8, _>(acc).0;
            let lhs = pulp::as_arrays::<8, _>(lhs).0;
            let rhs = pulp::as_arrays::<8, _>(rhs).0;

            let big_q_m1 = simd.splat_u64x8(big_q - 1);
            let big_q_m1_complement = simd.splat_u64x8(52 - (big_q - 1));
            let p_barrett = simd.splat_u64x8(p_barrett);
            let neg_p = simd.splat_u64x8(p.wrapping_neg());
            let p = simd.splat_u64x8(p);

            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let lhs = cast(*lhs);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u52x8(lhs, rhs);
                let c1 = simd.or_u64x8(
                    simd.shr_dyn_u64x8(lo, big_q_m1),
                    simd.shl_dyn_u64x8(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u52x8(c1, p_barrett).1;
                // lo - p * c3
                let prod = simd.wrapping_mul_add_u52x8(neg_p, c3, lo);
                let prod = simd.small_mod_u64x8(p, prod);

                *acc = cast(simd.small_mod_u64x8(p, simd.wrapping_add_u64x8(prod, cast(*acc))));
            }
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn mul_assign_normalize_avx512(
    simd: crate::V4,
    lhs: &mut [u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let lhs = pulp::as_arrays_mut::<8, _>(lhs).0;
            let rhs = pulp::as_arrays::<8, _>(rhs).0;

            let big_q_m1 = simd.splat_u64x8(big_q - 1);
            let big_q_m1_complement = simd.splat_u64x8(64 - (big_q - 1));
            let n_inv_mod_p = simd.splat_u64x8(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u64x8(n_inv_mod_p_shoup);
            let p_barrett = simd.splat_u64x8(p_barrett);
            let p = simd.splat_u64x8(p);

            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = cast(*lhs_);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u64x8(lhs, rhs);
                let c1 = simd.or_u64x8(
                    simd.shr_dyn_u64x8(lo, big_q_m1),
                    simd.shl_dyn_u64x8(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u64x8(c1, p_barrett).1;
                let prod = simd.wrapping_sub_u64x8(lo, simd.wrapping_mul_u64x8(p, c3));

                // normalization
                let shoup_q = simd.widening_mul_u64x8(prod, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u64x8(
                    simd.wrapping_mul_u64x8(prod, n_inv_mod_p),
                    simd.wrapping_mul_u64x8(shoup_q, p),
                );

                *lhs_ = cast(simd.small_mod_u64x8(p, t));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn mul_accumulate_avx512(
    simd: crate::V4,
    acc: &mut [u64],
    lhs: &[u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
) {
    simd.vectorize(
        #[inline(always)]
        || {
            let acc = pulp::as_arrays_mut::<8, _>(acc).0;
            let lhs = pulp::as_arrays::<8, _>(lhs).0;
            let rhs = pulp::as_arrays::<8, _>(rhs).0;

            let big_q_m1 = simd.splat_u64x8(big_q - 1);
            let big_q_m1_complement = simd.splat_u64x8(64 - (big_q - 1));
            let p_barrett = simd.splat_u64x8(p_barrett);
            let p = simd.splat_u64x8(p);

            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let lhs = cast(*lhs);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u64x8(lhs, rhs);
                let c1 = simd.or_u64x8(
                    simd.shr_dyn_u64x8(lo, big_q_m1),
                    simd.shl_dyn_u64x8(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u64x8(c1, p_barrett).1;
                // lo - p * c3
                let prod = simd.wrapping_sub_u64x8(lo, simd.wrapping_mul_u64x8(p, c3));
                let prod = simd.small_mod_u64x8(p, prod);

                *acc = cast(simd.small_mod_u64x8(p, simd.wrapping_add_u64x8(prod, cast(*acc))));
            }
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn mul_assign_normalize_avx2(
    simd: crate::V3,
    lhs: &mut [u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let lhs = pulp::as_arrays_mut::<4, _>(lhs).0;
            let rhs = pulp::as_arrays::<4, _>(rhs).0;
            let big_q_m1 = simd.splat_u64x4(big_q - 1);
            let big_q_m1_complement = simd.splat_u64x4(64 - (big_q - 1));
            let n_inv_mod_p = simd.splat_u64x4(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u64x4(n_inv_mod_p_shoup);
            let p_barrett = simd.splat_u64x4(p_barrett);
            let p = simd.splat_u64x4(p);

            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = cast(*lhs_);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u64x4(lhs, rhs);
                let c1 = simd.or_u64x4(
                    simd.shr_dyn_u64x4(lo, big_q_m1),
                    simd.shl_dyn_u64x4(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u64x4(c1, p_barrett).1;
                let prod = simd.wrapping_sub_u64x4(lo, simd.widening_mul_u64x4(p, c3).0);

                // normalization
                let shoup_q = simd.widening_mul_u64x4(prod, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u64x4(
                    simd.widening_mul_u64x4(prod, n_inv_mod_p).0,
                    simd.widening_mul_u64x4(shoup_q, p).0,
                );

                *lhs_ = cast(simd.small_mod_u64x4(p, t));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn mul_accumulate_avx2(
    simd: crate::V3,
    acc: &mut [u64],
    lhs: &[u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
) {
    simd.vectorize(
        #[inline(always)]
        || {
            let acc = pulp::as_arrays_mut::<4, _>(acc).0;
            let lhs = pulp::as_arrays::<4, _>(lhs).0;
            let rhs = pulp::as_arrays::<4, _>(rhs).0;

            let big_q_m1 = simd.splat_u64x4(big_q - 1);
            let big_q_m1_complement = simd.splat_u64x4(64 - (big_q - 1));
            let p_barrett = simd.splat_u64x4(p_barrett);
            let p = simd.splat_u64x4(p);

            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let lhs = cast(*lhs);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u64x4(lhs, rhs);
                let c1 = simd.or_u64x4(
                    simd.shr_dyn_u64x4(lo, big_q_m1),
                    simd.shl_dyn_u64x4(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u64x4(c1, p_barrett).1;
                // lo - p * c3
                let prod = simd.wrapping_sub_u64x4(lo, simd.widening_mul_u64x4(p, c3).0);
                let prod = simd.small_mod_u64x4(p, prod);

                *acc = cast(simd.small_mod_u64x4(p, simd.wrapping_add_u64x4(prod, cast(*acc))));
            }
        },
    )
}

fn mul_assign_normalize_scalar(
    lhs: &mut [u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
) {
    let big_q_m1 = big_q - 1;

    for (lhs_, rhs) in crate::izip!(lhs, rhs) {
        let lhs = *lhs_;
        let rhs = *rhs;

        let d = lhs as u128 * rhs as u128;
        let c1 = (d >> big_q_m1) as u64;
        let c3 = ((c1 as u128 * p_barrett as u128) >> 64) as u64;
        let prod = (d as u64).wrapping_sub(p.wrapping_mul(c3));

        let shoup_q = (((prod as u128) * (n_inv_mod_p_shoup as u128)) >> 64) as u64;
        let t = u64::wrapping_sub(prod.wrapping_mul(n_inv_mod_p), shoup_q.wrapping_mul(p));

        *lhs_ = t.min(t.wrapping_sub(p));
    }
}

fn mul_accumulate_scalar(
    acc: &mut [u64],
    lhs: &[u64],
    rhs: &[u64],
    p: u64,
    p_barrett: u64,
    big_q: u64,
) {
    let big_q_m1 = big_q - 1;

    for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
        let lhs = *lhs;
        let rhs = *rhs;

        let d = lhs as u128 * rhs as u128;
        let c1 = (d >> big_q_m1) as u64;
        let c3 = ((c1 as u128 * p_barrett as u128) >> 64) as u64;
        let prod = (d as u64).wrapping_sub(p.wrapping_mul(c3));
        let prod = prod.min(prod.wrapping_sub(p));

        let acc_ = prod + *acc;
        *acc = acc_.min(acc_.wrapping_sub(p));
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn normalize_ifma(
    simd: crate::V4IFma,
    values: &mut [u64],
    p: u64,
    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
) {
    simd.vectorize(
        #[inline(always)]
        || {
            let values = pulp::as_arrays_mut::<8, _>(values).0;

            let n_inv_mod_p = simd.splat_u64x8(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u64x8(n_inv_mod_p_shoup);
            let neg_p = simd.splat_u64x8(p.wrapping_neg());
            let p = simd.splat_u64x8(p);
            let zero = simd.splat_u64x8(0);

            for val_ in values {
                let val = cast(*val_);

                // normalization
                let shoup_q = simd.widening_mul_u52x8(val, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_mul_add_u52x8(
                    shoup_q,
                    neg_p,
                    simd.wrapping_mul_add_u52x8(val, n_inv_mod_p, zero),
                );

                *val_ = cast(simd.small_mod_u64x8(p, t));
            }
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn normalize_avx512(
    simd: crate::V4,
    values: &mut [u64],
    p: u64,
    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let values = pulp::as_arrays_mut::<8, _>(values).0;

            let n_inv_mod_p = simd.splat_u64x8(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u64x8(n_inv_mod_p_shoup);
            let p = simd.splat_u64x8(p);

            for val_ in values {
                let val = cast(*val_);

                // normalization
                let shoup_q = simd.widening_mul_u64x8(val, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u64x8(
                    simd.wrapping_mul_u64x8(val, n_inv_mod_p),
                    simd.wrapping_mul_u64x8(shoup_q, p),
                );

                *val_ = cast(simd.small_mod_u64x8(p, t));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn normalize_avx2(
    simd: crate::V3,
    values: &mut [u64],
    p: u64,
    n_inv_mod_p: u64,
    n_inv_mod_p_shoup: u64,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let values = pulp::as_arrays_mut::<4, _>(values).0;

            let n_inv_mod_p = simd.splat_u64x4(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u64x4(n_inv_mod_p_shoup);
            let p = simd.splat_u64x4(p);

            for val_ in values {
                let val = cast(*val_);

                // normalization
                let shoup_q = simd.widening_mul_u64x4(val, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u64x4(
                    simd.widening_mul_u64x4(val, n_inv_mod_p).0,
                    simd.widening_mul_u64x4(shoup_q, p).0,
                );

                *val_ = cast(simd.small_mod_u64x4(p, t));
            }
        },
    );
}

fn normalize_scalar(values: &mut [u64], p: u64, n_inv_mod_p: u64, n_inv_mod_p_shoup: u64) {
    for val_ in values {
        let val = *val_;

        let shoup_q = (((val as u128) * (n_inv_mod_p_shoup as u128)) >> 64) as u64;
        let t = u64::wrapping_sub(val.wrapping_mul(n_inv_mod_p), shoup_q.wrapping_mul(p));

        *val_ = t.min(t.wrapping_sub(p));
    }
}

impl Plan {
    /// Returns a negacyclic NTT plan for the given polynomial size and modulus, or `None` if no
    /// suitable roots of unity can be found for the wanted parameters.
    pub fn try_new(polynomial_size: usize, modulus: u64) -> Option<Self> {
        let p_div = Div64::new(modulus);
        // 16 = 8x2 = max_register_size * ntt_radix,
        // as SIMD registers can contain at most 8*u64
        // and the implementation assumes that SIMD registers are full
        if polynomial_size < 16
            || !polynomial_size.is_power_of_two()
            || !is_prime64(modulus)
            || find_primitive_root64(p_div, 2 * polynomial_size as u64).is_none()
        {
            None
        } else {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            let has_ifma = (modulus < (1u64 << 51)) && crate::V4IFma::try_new().is_some();
            #[cfg(not(all(
                any(target_arch = "x86", target_arch = "x86_64"),
                feature = "nightly",
            )))]
            let has_ifma = false;

            let bits = if has_ifma { 52 } else { 64 };

            let mut twid = avec![0u64; polynomial_size].into_boxed_slice();
            let mut inv_twid = avec![0u64; polynomial_size].into_boxed_slice();
            let (mut twid_shoup, mut inv_twid_shoup) = if modulus < (1u64 << 63) {
                (
                    avec![0u64; polynomial_size].into_boxed_slice(),
                    avec![0u64; polynomial_size].into_boxed_slice(),
                )
            } else {
                (avec![].into_boxed_slice(), avec![].into_boxed_slice())
            };

            if modulus < (1u64 << 63) {
                init_negacyclic_twiddles_shoup(
                    modulus,
                    polynomial_size,
                    bits,
                    &mut twid,
                    &mut twid_shoup,
                    &mut inv_twid,
                    &mut inv_twid_shoup,
                );
            } else {
                init_negacyclic_twiddles(modulus, polynomial_size, &mut twid, &mut inv_twid);
            }

            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, modulus - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << bits) / modulus as u128) as u64;
            let big_q = (modulus.ilog2() + 1) as u64;
            let big_l = big_q + (bits - 1) as u64;
            let p_barrett = ((1u128 << big_l) / modulus as u128) as u64;

            Some(Self {
                twid,
                twid_shoup,
                inv_twid_shoup,
                inv_twid,
                p: modulus,
                p_div,
                p_barrett,
                big_q,
                n_inv_mod_p,
                n_inv_mod_p_shoup,
            })
        }
    }

    pub(crate) fn p_div(&self) -> Div64 {
        self.p_div
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.twid.len()
    }

    /// Returns the modulus of the negacyclic NTT plan.
    #[inline]
    pub fn modulus(&self) -> u64 {
        self.p
    }

    /// Applies a forward negacyclic NTT transform in place to the given buffer.
    ///
    /// # Note
    /// On entry, the buffer holds the polynomial coefficients in standard order. On exit, the
    /// buffer holds the negacyclic NTT transform coefficients in bit reversed order.
    pub fn fwd(&self, buf: &mut [u64]) {
        assert_eq!(buf.len(), self.ntt_size());
        let p = self.p;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[cfg(feature = "nightly")]
        if p < (1u64 << 50) {
            if let Some(simd) = crate::V4IFma::try_new() {
                less_than_50bit::fwd_avx512(simd, p, buf, &self.twid, &self.twid_shoup);
                return;
            }
        } else if p < (1u64 << 51) {
            if let Some(simd) = crate::V4IFma::try_new() {
                less_than_51bit::fwd_avx512(simd, p, buf, &self.twid, &self.twid_shoup);
                return;
            }
        }

        if p < (1u64 << 62) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_62bit::fwd_avx512(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_62bit::fwd_avx2(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
            }
            less_than_62bit::fwd_scalar(p, buf, &self.twid, &self.twid_shoup);
        } else if p < (1u64 << 63) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_63bit::fwd_avx512(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_63bit::fwd_avx2(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
            }
            less_than_63bit::fwd_scalar(p, buf, &self.twid, &self.twid_shoup);
        } else if p == Solinas::P {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    generic_solinas::fwd_avx512(simd, buf, Solinas, (), &self.twid);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    generic_solinas::fwd_avx2(simd, buf, Solinas, (), &self.twid);
                    return;
                }
            }
            generic_solinas::fwd_scalar(buf, Solinas, (), &self.twid);
        } else {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                let crate::u256 { x0, x1, x2, x3 } = self.p_div.double_reciprocal;
                let p_div = (p, x0, x1, x2, x3);
                generic_solinas::fwd_avx512(simd, buf, p, p_div, &self.twid);
                return;
            }
            generic_solinas::fwd_scalar(buf, p, self.p_div, &self.twid);
        }
    }

    /// Applies an inverse negacyclic NTT transform in place to the given buffer.
    ///
    /// # Note
    /// On entry, the buffer holds the negacyclic NTT transform coefficients in bit reversed order.
    /// On exit, the buffer holds the polynomial coefficients in standard order.
    pub fn inv(&self, buf: &mut [u64]) {
        assert_eq!(buf.len(), self.ntt_size());
        let p = self.p;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[cfg(feature = "nightly")]
        if p < (1u64 << 50) {
            if let Some(simd) = crate::V4IFma::try_new() {
                less_than_50bit::inv_avx512(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                return;
            }
        } else if p < (1u64 << 51) {
            if let Some(simd) = crate::V4IFma::try_new() {
                less_than_51bit::inv_avx512(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                return;
            }
        }

        if p < (1u64 << 62) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_62bit::inv_avx512(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_62bit::inv_avx2(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
            }
            less_than_62bit::inv_scalar(p, buf, &self.inv_twid, &self.inv_twid_shoup);
        } else if p < (1u64 << 63) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_63bit::inv_avx512(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_63bit::inv_avx2(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
            }
            less_than_63bit::inv_scalar(p, buf, &self.inv_twid, &self.inv_twid_shoup);
        } else if p == Solinas::P {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    generic_solinas::inv_avx512(simd, buf, Solinas, (), &self.inv_twid);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    generic_solinas::inv_avx2(simd, buf, Solinas, (), &self.inv_twid);
                    return;
                }
            }
            generic_solinas::inv_scalar(buf, Solinas, (), &self.inv_twid);
        } else {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                let crate::u256 { x0, x1, x2, x3 } = self.p_div.double_reciprocal;
                let p_div = (p, x0, x1, x2, x3);
                generic_solinas::inv_avx512(simd, buf, p, p_div, &self.inv_twid);
                return;
            }
            generic_solinas::inv_scalar(buf, p, self.p_div, &self.inv_twid);
        }
    }

    /// Computes the elementwise product of `lhs` and `rhs`, multiplied by the inverse of the
    /// polynomial modulo the NTT modulus, and stores the result in `lhs`.
    pub fn mul_assign_normalize(&self, lhs: &mut [u64], rhs: &[u64]) {
        let p = self.p;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[cfg(feature = "nightly")]
        let has_ifma = (p < (1u64 << 51)) && crate::V4IFma::try_new().is_some();

        if p < (1 << 63) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if has_ifma {
                // p < 2^51
                let simd = crate::V4IFma::try_new().unwrap();
                mul_assign_normalize_ifma(
                    simd,
                    lhs,
                    rhs,
                    p,
                    self.p_barrett,
                    self.big_q,
                    self.n_inv_mod_p,
                    self.n_inv_mod_p_shoup,
                );
                return;
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                mul_assign_normalize_avx512(
                    simd,
                    lhs,
                    rhs,
                    p,
                    self.p_barrett,
                    self.big_q,
                    self.n_inv_mod_p,
                    self.n_inv_mod_p_shoup,
                );
                return;
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if let Some(simd) = crate::V3::try_new() {
                mul_assign_normalize_avx2(
                    simd,
                    lhs,
                    rhs,
                    p,
                    self.p_barrett,
                    self.big_q,
                    self.n_inv_mod_p,
                    self.n_inv_mod_p_shoup,
                );
                return;
            }

            mul_assign_normalize_scalar(
                lhs,
                rhs,
                p,
                self.p_barrett,
                self.big_q,
                self.n_inv_mod_p,
                self.n_inv_mod_p_shoup,
            );
        } else if p == Solinas::P {
            let n_inv_mod_p = self.n_inv_mod_p;
            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = *lhs_;
                let rhs = *rhs;
                let prod = <Solinas as PrimeModulus>::mul((), lhs, rhs);
                let prod = <Solinas as PrimeModulus>::mul((), prod, n_inv_mod_p);
                *lhs_ = prod;
            }
        } else {
            let p_div = self.p_div;
            let n_inv_mod_p = self.n_inv_mod_p;
            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = *lhs_;
                let rhs = *rhs;
                let prod = <u64 as PrimeModulus>::mul(p_div, lhs, rhs);
                let prod = <u64 as PrimeModulus>::mul(p_div, prod, n_inv_mod_p);
                *lhs_ = prod;
            }
        }
    }

    /// Multiplies the values by the inverse of the polynomial modulo the NTT modulus, and stores
    /// the result in `values`.
    pub fn normalize(&self, values: &mut [u64]) {
        let p = self.p;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[cfg(feature = "nightly")]
        let has_ifma = (p < (1u64 << 51)) && crate::V4IFma::try_new().is_some();

        if p < (1 << 63) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if has_ifma {
                // p < 2^51
                let simd = crate::V4IFma::try_new().unwrap();
                normalize_ifma(simd, values, p, self.n_inv_mod_p, self.n_inv_mod_p_shoup);
                return;
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                normalize_avx512(simd, values, p, self.n_inv_mod_p, self.n_inv_mod_p_shoup);
                return;
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if let Some(simd) = crate::V3::try_new() {
                normalize_avx2(simd, values, p, self.n_inv_mod_p, self.n_inv_mod_p_shoup);
                return;
            }

            normalize_scalar(values, p, self.n_inv_mod_p, self.n_inv_mod_p_shoup);
        } else if p == Solinas::P {
            let n_inv_mod_p = self.n_inv_mod_p;
            for val in values {
                let prod = <Solinas as PrimeModulus>::mul((), *val, n_inv_mod_p);
                *val = prod;
            }
        } else {
            let n_inv_mod_p = self.n_inv_mod_p;
            let p_div = self.p_div;
            for val in values {
                let prod = <u64 as PrimeModulus>::mul(p_div, *val, n_inv_mod_p);
                *val = prod;
            }
        }
    }

    /// Computes the elementwise product of `lhs` and `rhs` and accumulates the result to `acc`.
    pub fn mul_accumulate(&self, acc: &mut [u64], lhs: &[u64], rhs: &[u64]) {
        let p = self.p;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[cfg(feature = "nightly")]
        let has_ifma = (p < (1u64 << 51)) && crate::V4IFma::try_new().is_some();

        if p < (1 << 63) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if has_ifma {
                // p < 2^51
                let simd = crate::V4IFma::try_new().unwrap();
                mul_accumulate_ifma(simd, acc, lhs, rhs, p, self.p_barrett, self.big_q);
                return;
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                mul_accumulate_avx512(simd, acc, lhs, rhs, p, self.p_barrett, self.big_q);
                return;
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if let Some(simd) = crate::V3::try_new() {
                mul_accumulate_avx2(simd, acc, lhs, rhs, p, self.p_barrett, self.big_q);
                return;
            }

            mul_accumulate_scalar(acc, lhs, rhs, p, self.p_barrett, self.big_q);
        } else if p == Solinas::P {
            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let prod = <Solinas as PrimeModulus>::mul((), *lhs, *rhs);
                *acc = <Solinas as PrimeModulus>::add(Solinas, *acc, prod);
            }
        } else {
            let p_div = self.p_div;
            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let prod = <u64 as PrimeModulus>::mul(p_div, *lhs, *rhs);
                *acc = <u64 as PrimeModulus>::add(p, *acc, prod);
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        fastdiv::Div64, prime::largest_prime_in_arithmetic_progression64,
        prime64::generic_solinas::PrimeModulus,
    };
    use alloc::{vec, vec::Vec};
    use rand::random;

    extern crate alloc;

    pub fn add(p: u64, a: u64, b: u64) -> u64 {
        let neg_b = p.wrapping_sub(b);
        if a >= neg_b {
            a - neg_b
        } else {
            a + b
        }
    }

    pub fn sub(p: u64, a: u64, b: u64) -> u64 {
        let neg_b = p.wrapping_sub(b);
        if a >= b {
            a - b
        } else {
            a + neg_b
        }
    }

    pub fn mul(p: u64, a: u64, b: u64) -> u64 {
        let wide = a as u128 * b as u128;
        if p == 0 {
            wide as u64
        } else {
            (wide % p as u128) as u64
        }
    }

    pub fn negacyclic_convolution(n: usize, p: u64, lhs: &[u64], rhs: &[u64]) -> vec::Vec<u64> {
        let mut full_convolution = vec![0u64; 2 * n];
        let mut negacyclic_convolution = vec![0u64; n];
        for i in 0..n {
            for j in 0..n {
                full_convolution[i + j] = add(p, full_convolution[i + j], mul(p, lhs[i], rhs[j]));
            }
        }
        for i in 0..n {
            negacyclic_convolution[i] = sub(p, full_convolution[i], full_convolution[i + n]);
        }
        negacyclic_convolution
    }

    pub fn random_lhs_rhs_with_negacyclic_convolution(
        n: usize,
        p: u64,
    ) -> (vec::Vec<u64>, vec::Vec<u64>, vec::Vec<u64>) {
        let mut lhs = vec![0u64; n];
        let mut rhs = vec![0u64; n];

        for x in &mut lhs {
            *x = random();
            if p != 0 {
                *x %= p;
            }
        }
        for x in &mut rhs {
            *x = random();
            if p != 0 {
                *x %= p;
            }
        }

        let lhs = lhs;
        let rhs = rhs;

        let negacyclic_convolution = negacyclic_convolution(n, p, &lhs, &rhs);
        (lhs, rhs, negacyclic_convolution)
    }

    #[test]
    fn test_product() {
        for n in [16, 32, 64, 128, 256, 512, 1024] {
            for p in [
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 49, 1 << 50).unwrap(),
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 51).unwrap(),
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 61, 1 << 62).unwrap(),
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 62, 1 << 63).unwrap(),
                Solinas::P,
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 63, u64::MAX).unwrap(),
            ] {
                let plan = Plan::try_new(n, p).unwrap();

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut prod = vec![0u64; n];
                let mut lhs_fourier = lhs.clone();
                let mut rhs_fourier = rhs.clone();

                plan.fwd(&mut lhs_fourier);
                plan.fwd(&mut rhs_fourier);

                for x in &lhs_fourier {
                    assert!(*x < p);
                }
                for x in &rhs_fourier {
                    assert!(*x < p);
                }

                for i in 0..n {
                    prod[i] =
                        <u64 as PrimeModulus>::mul(Div64::new(p), lhs_fourier[i], rhs_fourier[i]);
                }
                plan.inv(&mut prod);

                plan.mul_assign_normalize(&mut lhs_fourier, &rhs_fourier);
                plan.inv(&mut lhs_fourier);

                for x in &prod {
                    assert!(*x < p);
                }

                for i in 0..n {
                    assert_eq!(
                        prod[i],
                        <u64 as PrimeModulus>::mul(
                            Div64::new(p),
                            negacyclic_convolution[i],
                            n as u64
                        ),
                    );
                }
                assert_eq!(lhs_fourier, negacyclic_convolution);
            }
        }
    }

    #[test]
    fn test_normalize_scalar() {
        let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
        let p_div = Div64::new(p);
        let polynomial_size = 128;

        let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
        let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 64) / p as u128) as u64;

        let mut val = (0..polynomial_size)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Vec<_>>();
        let mut val_target = val.clone();

        let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

        for val in val_target.iter_mut() {
            *val = mul(*val, n_inv_mod_p);
        }

        normalize_scalar(&mut val, p, n_inv_mod_p, n_inv_mod_p_shoup);
        assert_eq!(val, val_target);
    }

    #[test]
    fn test_mul_assign_normalize_scalar() {
        let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
        let p_div = Div64::new(p);
        let polynomial_size = 128;

        let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
        let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 64) / p as u128) as u64;
        let big_q = (p.ilog2() + 1) as u64;
        let big_l = big_q + 63;
        let p_barrett = ((1u128 << big_l) / p as u128) as u64;

        let mut lhs = (0..polynomial_size)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Vec<_>>();
        let mut lhs_target = lhs.clone();
        let rhs = (0..polynomial_size)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Vec<_>>();

        let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

        for (lhs, rhs) in lhs_target.iter_mut().zip(&rhs) {
            *lhs = mul(mul(*lhs, *rhs), n_inv_mod_p);
        }

        mul_assign_normalize_scalar(
            &mut lhs,
            &rhs,
            p,
            p_barrett,
            big_q,
            n_inv_mod_p,
            n_inv_mod_p_shoup,
        );
        assert_eq!(lhs, lhs_target);
    }

    #[test]
    fn test_mul_accumulate_scalar() {
        let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
        let polynomial_size = 128;

        let big_q = (p.ilog2() + 1) as u64;
        let big_l = big_q + 63;
        let p_barrett = ((1u128 << big_l) / p as u128) as u64;

        let mut acc = (0..polynomial_size)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Vec<_>>();
        let mut acc_target = acc.clone();
        let lhs = (0..polynomial_size)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Vec<_>>();
        let rhs = (0..polynomial_size)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Vec<_>>();

        let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
        let add = |a: u64, b: u64| <u64 as PrimeModulus>::add(p, a, b);

        for (acc, lhs, rhs) in crate::izip!(&mut acc_target, &lhs, &rhs) {
            *acc = add(mul(*lhs, *rhs), *acc);
        }

        mul_accumulate_scalar(&mut acc, &lhs, &rhs, p, p_barrett, big_q);
        assert_eq!(acc, acc_target);
    }

    #[test]
    fn test_mul_accumulate() {
        for p in [
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 51).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 61).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 62).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 63).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, u64::MAX).unwrap(),
        ] {
            let polynomial_size = 128;

            let mut acc = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut acc_target = acc.clone();
            let lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
            let add = |a: u64, b: u64| ((a as u128 + b as u128) % p as u128) as u64;

            for (acc, lhs, rhs) in crate::izip!(&mut acc_target, &lhs, &rhs) {
                *acc = add(mul(*lhs, *rhs), *acc);
            }

            Plan::try_new(polynomial_size, p)
                .unwrap()
                .mul_accumulate(&mut acc, &lhs, &rhs);
            assert_eq!(acc, acc_target);
        }
    }

    #[test]
    fn test_mul_assign_normalize() {
        for p in [
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 51).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 61).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 62).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 63).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, u64::MAX).unwrap(),
        ] {
            let polynomial_size = 128;
            let p_div = Div64::new(p);
            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);

            let mut lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut lhs_target = lhs.clone();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for (lhs, rhs) in lhs_target.iter_mut().zip(&rhs) {
                *lhs = mul(mul(*lhs, *rhs), n_inv_mod_p);
            }

            Plan::try_new(polynomial_size, p)
                .unwrap()
                .mul_assign_normalize(&mut lhs, &rhs);
            assert_eq!(lhs, lhs_target);
        }
    }

    #[test]
    fn test_normalize() {
        for p in [
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 51).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 61).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 62).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 63).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, u64::MAX).unwrap(),
        ] {
            let polynomial_size = 128;
            let p_div = Div64::new(p);
            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);

            let mut val = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut val_target = val.clone();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for val in &mut val_target {
                *val = mul(*val, n_inv_mod_p);
            }

            Plan::try_new(polynomial_size, p)
                .unwrap()
                .normalize(&mut val);
            assert_eq!(val, val_target);
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(test)]
mod x86_tests {
    use super::*;
    use crate::prime::largest_prime_in_arithmetic_progression64;
    use alloc::vec::Vec;
    use rand::random as rnd;

    extern crate alloc;

    #[test]
    fn test_interleaves_and_permutes_u64x4() {
        if let Some(simd) = crate::V3::try_new() {
            let a = u64x4(rnd(), rnd(), rnd(), rnd());
            let b = u64x4(rnd(), rnd(), rnd(), rnd());

            assert_eq!(
                simd.interleave2_u64x4([a, b]),
                [u64x4(a.0, a.1, b.0, b.1), u64x4(a.2, a.3, b.2, b.3)],
            );
            assert_eq!(
                simd.interleave2_u64x4(simd.interleave2_u64x4([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd()];
            assert_eq!(simd.permute2_u64x4(w), u64x4(w[0], w[0], w[1], w[1]));

            assert_eq!(
                simd.interleave1_u64x4([a, b]),
                [u64x4(a.0, b.0, a.2, b.2), u64x4(a.1, b.1, a.3, b.3)],
            );
            assert_eq!(
                simd.interleave1_u64x4(simd.interleave1_u64x4([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd()];
            assert_eq!(simd.permute1_u64x4(w), u64x4(w[0], w[2], w[1], w[3]));
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_interleaves_and_permutes_u64x8() {
        if let Some(simd) = crate::V4::try_new() {
            let a = u64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            let b = u64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());

            assert_eq!(
                simd.interleave4_u64x8([a, b]),
                [
                    u64x8(a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3),
                    u64x8(a.4, a.5, a.6, a.7, b.4, b.5, b.6, b.7),
                ],
            );
            assert_eq!(
                simd.interleave4_u64x8(simd.interleave4_u64x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd()];
            assert_eq!(
                simd.permute4_u64x8(w),
                u64x8(w[0], w[0], w[0], w[0], w[1], w[1], w[1], w[1]),
            );

            assert_eq!(
                simd.interleave2_u64x8([a, b]),
                [
                    u64x8(a.0, a.1, b.0, b.1, a.4, a.5, b.4, b.5),
                    u64x8(a.2, a.3, b.2, b.3, a.6, a.7, b.6, b.7),
                ],
            );
            assert_eq!(
                simd.interleave2_u64x8(simd.interleave2_u64x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute2_u64x8(w),
                u64x8(w[0], w[0], w[2], w[2], w[1], w[1], w[3], w[3]),
            );

            assert_eq!(
                simd.interleave1_u64x8([a, b]),
                [
                    u64x8(a.0, b.0, a.2, b.2, a.4, b.4, a.6, b.6),
                    u64x8(a.1, b.1, a.3, b.3, a.5, b.5, a.7, b.7),
                ],
            );
            assert_eq!(
                simd.interleave1_u64x8(simd.interleave1_u64x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute1_u64x8(w),
                u64x8(w[0], w[4], w[1], w[5], w[2], w[6], w[3], w[7]),
            );
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_mul_assign_normalize_ifma() {
        if let Some(simd) = crate::V4IFma::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 51).unwrap();
            let p_div = Div64::new(p);
            let polynomial_size = 128;

            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 52) / p as u128) as u64;
            let big_q = (p.ilog2() + 1) as u64;
            let big_l = big_q + 51;
            let p_barrett = ((1u128 << big_l) / p as u128) as u64;

            let mut lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut lhs_target = lhs.clone();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for (lhs, rhs) in lhs_target.iter_mut().zip(&rhs) {
                *lhs = mul(mul(*lhs, *rhs), n_inv_mod_p);
            }

            mul_assign_normalize_ifma(
                simd,
                &mut lhs,
                &rhs,
                p,
                p_barrett,
                big_q,
                n_inv_mod_p,
                n_inv_mod_p_shoup,
            );
            assert_eq!(lhs, lhs_target);
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_mul_assign_normalize_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
            let p_div = Div64::new(p);
            let polynomial_size = 128;

            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 64) / p as u128) as u64;
            let big_q = (p.ilog2() + 1) as u64;
            let big_l = big_q + 63;
            let p_barrett = ((1u128 << big_l) / p as u128) as u64;

            let mut lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut lhs_target = lhs.clone();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for (lhs, rhs) in lhs_target.iter_mut().zip(&rhs) {
                *lhs = mul(mul(*lhs, *rhs), n_inv_mod_p);
            }

            mul_assign_normalize_avx512(
                simd,
                &mut lhs,
                &rhs,
                p,
                p_barrett,
                big_q,
                n_inv_mod_p,
                n_inv_mod_p_shoup,
            );
            assert_eq!(lhs, lhs_target);
        }
    }

    #[test]
    fn test_mul_assign_normalize_avx2() {
        if let Some(simd) = crate::V3::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
            let p_div = Div64::new(p);
            let polynomial_size = 128;

            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 64) / p as u128) as u64;
            let big_q = (p.ilog2() + 1) as u64;
            let big_l = big_q + 63;
            let p_barrett = ((1u128 << big_l) / p as u128) as u64;

            let mut lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut lhs_target = lhs.clone();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for (lhs, rhs) in lhs_target.iter_mut().zip(&rhs) {
                *lhs = mul(mul(*lhs, *rhs), n_inv_mod_p);
            }

            mul_assign_normalize_avx2(
                simd,
                &mut lhs,
                &rhs,
                p,
                p_barrett,
                big_q,
                n_inv_mod_p,
                n_inv_mod_p_shoup,
            );
            assert_eq!(lhs, lhs_target);
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_mul_accumulate_ifma() {
        if let Some(simd) = crate::V4IFma::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 51).unwrap();
            let polynomial_size = 128;

            let big_q = (p.ilog2() + 1) as u64;
            let big_l = big_q + 51;
            let p_barrett = ((1u128 << big_l) / p as u128) as u64;

            let mut acc = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut acc_target = acc.clone();
            let lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
            let add = |a: u64, b: u64| <u64 as PrimeModulus>::add(p, a, b);

            for (acc, lhs, rhs) in crate::izip!(&mut acc_target, &lhs, &rhs) {
                *acc = add(mul(*lhs, *rhs), *acc);
            }

            mul_accumulate_ifma(simd, &mut acc, &lhs, &rhs, p, p_barrett, big_q);
            assert_eq!(acc, acc_target);
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_mul_accumulate_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
            let polynomial_size = 128;

            let big_q = (p.ilog2() + 1) as u64;
            let big_l = big_q + 63;
            let p_barrett = ((1u128 << big_l) / p as u128) as u64;

            let mut acc = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut acc_target = acc.clone();
            let lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
            let add = |a: u64, b: u64| <u64 as PrimeModulus>::add(p, a, b);

            for (acc, lhs, rhs) in crate::izip!(&mut acc_target, &lhs, &rhs) {
                *acc = add(mul(*lhs, *rhs), *acc);
            }

            mul_accumulate_avx512(simd, &mut acc, &lhs, &rhs, p, p_barrett, big_q);
            assert_eq!(acc, acc_target);
        }
    }

    #[test]
    fn test_mul_accumulate_avx2() {
        if let Some(simd) = crate::V3::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
            let polynomial_size = 128;

            let big_q = (p.ilog2() + 1) as u64;
            let big_l = big_q + 63;
            let p_barrett = ((1u128 << big_l) / p as u128) as u64;

            let mut acc = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut acc_target = acc.clone();
            let lhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
            let add = |a: u64, b: u64| <u64 as PrimeModulus>::add(p, a, b);

            for (acc, lhs, rhs) in crate::izip!(&mut acc_target, &lhs, &rhs) {
                *acc = add(mul(*lhs, *rhs), *acc);
            }

            mul_accumulate_avx2(simd, &mut acc, &lhs, &rhs, p, p_barrett, big_q);
            assert_eq!(acc, acc_target);
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_normalize_ifma() {
        if let Some(simd) = crate::V4IFma::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 51).unwrap();
            let p_div = Div64::new(p);
            let polynomial_size = 128;

            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 52) / p as u128) as u64;

            let mut val = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut val_target = val.clone();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for val in val_target.iter_mut() {
                *val = mul(*val, n_inv_mod_p);
            }

            normalize_ifma(simd, &mut val, p, n_inv_mod_p, n_inv_mod_p_shoup);
            assert_eq!(val, val_target);
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_normalize_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
            let p_div = Div64::new(p);
            let polynomial_size = 128;

            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 64) / p as u128) as u64;

            let mut val = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut val_target = val.clone();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for val in val_target.iter_mut() {
                *val = mul(*val, n_inv_mod_p);
            }

            normalize_avx512(simd, &mut val, p, n_inv_mod_p, n_inv_mod_p_shoup);
            assert_eq!(val, val_target);
        }
    }

    #[test]
    fn test_normalize_avx2() {
        if let Some(simd) = crate::V3::try_new() {
            let p =
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 63).unwrap();
            let p_div = Div64::new(p);
            let polynomial_size = 128;

            let n_inv_mod_p = crate::prime::exp_mod64(p_div, polynomial_size as u64, p - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 64) / p as u128) as u64;

            let mut val = (0..polynomial_size)
                .map(|_| rand::random::<u64>() % p)
                .collect::<Vec<_>>();
            let mut val_target = val.clone();

            let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;

            for val in val_target.iter_mut() {
                *val = mul(*val, n_inv_mod_p);
            }

            normalize_avx2(simd, &mut val, p, n_inv_mod_p, n_inv_mod_p_shoup);
            assert_eq!(val, val_target);
        }
    }

    #[test]
    fn test_plan_crash_github_11() {
        assert!(Plan::try_new(2048, 1024).is_none());
    }
}
