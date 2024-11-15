use crate::{
    bit_rev,
    fastdiv::{Div32, Div64},
    prime::is_prime64,
    roots::find_primitive_root64,
};
use aligned_vec::{avec, ABox};

#[allow(unused_imports)]
use pulp::*;

const RECURSION_THRESHOLD: usize = 2048;

mod generic;
mod shoup;

mod less_than_30bit;
mod less_than_31bit;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl crate::V3 {
    #[inline(always)]
    fn interleave4_u32x8(self, z0z0z0z0z1z1z1z1: [u32x8; 2]) -> [u32x8; 2] {
        let avx = self.avx;
        [
            cast(avx._mm256_permute2f128_si256::<0b0010_0000>(
                cast(z0z0z0z0z1z1z1z1[0]),
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
            cast(avx._mm256_permute2f128_si256::<0b0011_0001>(
                cast(z0z0z0z0z1z1z1z1[0]),
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
        ]
    }

    #[inline(always)]
    fn permute4_u32x8(self, w: [u32; 2]) -> u32x8 {
        let avx = self.avx;
        let w0 = self.sse2._mm_set1_epi32(w[0] as i32);
        let w1 = self.sse2._mm_set1_epi32(w[1] as i32);
        cast(avx._mm256_insertf128_si256::<1>(avx._mm256_castsi128_si256(w0), w1))
    }

    #[inline(always)]
    fn interleave2_u32x8(self, z0z0z1z1: [u32x8; 2]) -> [u32x8; 2] {
        let avx = self.avx2;
        [
            cast(avx._mm256_unpacklo_epi64(cast(z0z0z1z1[0]), cast(z0z0z1z1[1]))),
            cast(avx._mm256_unpackhi_epi64(cast(z0z0z1z1[0]), cast(z0z0z1z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute2_u32x8(self, w: [u32; 4]) -> u32x8 {
        let avx = self.avx;
        let w0123 = pulp::cast(w);
        let w0022 = self.sse2._mm_castps_si128(self.sse3._mm_moveldup_ps(w0123));
        let w1133 = self.sse2._mm_castps_si128(self.sse3._mm_movehdup_ps(w0123));
        cast(avx._mm256_insertf128_si256::<1>(avx._mm256_castsi128_si256(w0022), w1133))
    }

    #[inline(always)]
    fn interleave1_u32x8(self, z0z0z1z1: [u32x8; 2]) -> [u32x8; 2] {
        let avx = self.avx2;
        let x = [
            // 00 10 01 11 04 14 05 15 08 18 09 19 0c 1c 0d 1d
            (avx._mm256_unpacklo_epi32(cast(z0z0z1z1[0]), cast(z0z0z1z1[1]))),
            // 02 12 03 13 06 16 07 17 0a 1a 0b 1b 0e 1e 0f 1f
            avx._mm256_unpackhi_epi32(cast(z0z0z1z1[0]), cast(z0z0z1z1[1])),
        ];
        [
            // 00 10 02 12 04 14 06 16 08 18 0a 1a 0c 1c 0c 1c
            cast(avx._mm256_unpacklo_epi64(x[0], x[1])),
            // 01 11 03 13 05 15 07 17 09 19 0b 1b 0d 1d 0f 1f
            cast(avx._mm256_unpackhi_epi64(x[0], x[1])),
        ]
    }

    #[inline(always)]
    fn permute1_u32x8(self, w: [u32; 8]) -> u32x8 {
        let avx = self.avx;
        let [w0123, w4567]: [u32x4; 2] = pulp::cast(w);
        let w0415 = self.sse2._mm_unpacklo_epi32(cast(w0123), cast(w4567));
        let w2637 = self.sse2._mm_unpackhi_epi32(cast(w0123), cast(w4567));
        cast(avx._mm256_insertf128_si256::<1>(avx._mm256_castsi128_si256(w0415), w2637))
    }

    #[inline(always)]
    pub fn small_mod_u32x8(self, modulus: u32x8, x: u32x8) -> u32x8 {
        self.select_u32x8(
            self.cmp_gt_u32x8(modulus, x),
            x,
            self.wrapping_sub_u32x8(x, modulus),
        )
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl crate::V4 {
    #[inline(always)]
    fn interleave8_u32x16(self, z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1: [u32x16; 2]) -> [u32x16; 2] {
        let avx = self.avx512f;
        let idx_0 = avx._mm512_setr_epi32(
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        );
        let idx_1 = avx._mm512_setr_epi32(
            0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        );
        [
            cast(avx._mm512_permutex2var_epi32(
                cast(z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1[0]),
                idx_0,
                cast(z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1[1]),
            )),
            cast(avx._mm512_permutex2var_epi32(
                cast(z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1[0]),
                idx_1,
                cast(z0z0z0z0z0z0z0z0z1z1z1z1z1z1z1z1[1]),
            )),
        ]
    }

    #[inline(always)]
    fn permute8_u32x16(self, w: [u32; 2]) -> u32x16 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let w01xxxxxxxxxxxxxx = avx._mm512_set1_epi64(w);
        let idx = avx._mm512_setr_epi32(0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1);
        cast(avx._mm512_permutexvar_epi32(idx, w01xxxxxxxxxxxxxx))
    }

    #[inline(always)]
    fn interleave4_u32x16(self, z0z0z0z0z1z1z1z1: [u32x16; 2]) -> [u32x16; 2] {
        let avx = self.avx512f;
        let idx_0 = avx._mm512_setr_epi32(
            0x0, 0x1, 0x2, 0x3, 0x10, 0x11, 0x12, 0x13, 0x8, 0x9, 0xa, 0xb, 0x18, 0x19, 0x1a, 0x1b,
        );
        let idx_1 = avx._mm512_setr_epi32(
            0x4, 0x5, 0x6, 0x7, 0x14, 0x15, 0x16, 0x17, 0xc, 0xd, 0xe, 0xf, 0x1c, 0x1d, 0x1e, 0x1f,
        );
        [
            cast(avx._mm512_permutex2var_epi32(
                cast(z0z0z0z0z1z1z1z1[0]),
                idx_0,
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
            cast(avx._mm512_permutex2var_epi32(
                cast(z0z0z0z0z1z1z1z1[0]),
                idx_1,
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
        ]
    }

    #[inline(always)]
    fn permute4_u32x16(self, w: [u32; 4]) -> u32x16 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let w0123xxxxxxxxxxxx = avx._mm512_castsi128_si512(w);
        let idx = avx._mm512_setr_epi32(0, 0, 0, 0, 2, 2, 2, 2, 1, 1, 1, 1, 3, 3, 3, 3);
        cast(avx._mm512_permutexvar_epi32(idx, w0123xxxxxxxxxxxx))
    }

    #[inline(always)]
    fn interleave2_u32x16(self, z0z0z1z1: [u32x16; 2]) -> [u32x16; 2] {
        let avx = self.avx512f;
        [
            // 00 01 10 11 04 05 14 15 08 09 18 19 0c 0d 1c 1d
            cast(avx._mm512_unpacklo_epi64(cast(z0z0z1z1[0]), cast(z0z0z1z1[1]))),
            // 02 03 12 13 06 07 16 17 0a 0b 1a 1b 0e 0f 1e 1f
            cast(avx._mm512_unpackhi_epi64(cast(z0z0z1z1[0]), cast(z0z0z1z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute2_u32x16(self, w: [u32; 8]) -> u32x16 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let w01234567xxxxxxxx = avx._mm512_castsi256_si512(w);
        let idx = avx._mm512_setr_epi32(0, 0, 4, 4, 1, 1, 5, 5, 2, 2, 6, 6, 3, 3, 7, 7);
        cast(avx._mm512_permutexvar_epi32(idx, w01234567xxxxxxxx))
    }

    #[inline(always)]
    fn interleave1_u32x16(self, z0z1: [u32x16; 2]) -> [u32x16; 2] {
        let avx = self.avx512f;
        let x = [
            // 00 10 01 11 04 14 05 15 08 18 09 19 0c 1c 0d 1d
            avx._mm512_unpacklo_epi32(cast(z0z1[0]), cast(z0z1[1])),
            // 02 12 03 13 06 16 07 17 0a 1a 0b 1b 0e 1e 0f 1f
            avx._mm512_unpackhi_epi32(cast(z0z1[0]), cast(z0z1[1])),
        ];
        [
            // 00 10 02 12 04 14 06 16 08 18 0a 1a 0c 1c 0c 1c
            cast(avx._mm512_unpacklo_epi64(x[0], x[1])),
            // 01 11 03 13 05 15 07 17 09 19 0b 1b 0d 1d 0f 1f
            cast(avx._mm512_unpackhi_epi64(x[0], x[1])),
        ]
    }

    #[inline(always)]
    fn permute1_u32x16(self, w: [u32; 16]) -> u32x16 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let idx = avx._mm512_setr_epi32(
            0x0, 0x8, 0x1, 0x9, 0x2, 0xa, 0x3, 0xb, 0x4, 0xc, 0x5, 0xd, 0x6, 0xe, 0x7, 0xf,
        );
        cast(avx._mm512_permutexvar_epi32(idx, w))
    }

    #[inline(always)]
    pub fn small_mod_u32x16(self, modulus: u32x16, x: u32x16) -> u32x16 {
        self.select_u32x16(
            self.cmp_gt_u32x16(modulus, x),
            x,
            self.wrapping_sub_u32x16(x, modulus),
        )
    }
}

fn init_negacyclic_twiddles(p: u32, n: usize, twid: &mut [u32], inv_twid: &mut [u32]) {
    let div = Div32::new(p);
    let w = find_primitive_root64(Div64::new(p as u64), 2 * n as u64).unwrap() as u32;
    let mut k = 0;
    let mut wk = 1u32;

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

        wk = Div32::rem_u64(wk as u64 * w as u64, div);
        k += 1;
    }
}

fn init_negacyclic_twiddles_shoup(
    p: u32,
    n: usize,
    twid: &mut [u32],
    twid_shoup: &mut [u32],
    inv_twid: &mut [u32],
    inv_twid_shoup: &mut [u32],
) {
    let div = Div32::new(p);
    let w = find_primitive_root64(Div64::new(p as u64), 2 * n as u64).unwrap() as u32;
    let mut k = 0;
    let mut wk = 1u32;

    let nbits = n.trailing_zeros();
    while k < n {
        let fwd_idx = bit_rev(nbits, k);

        let wk_shoup = Div32::div_u64((wk as u64) << 32, div) as u32;
        twid[fwd_idx] = wk;
        twid_shoup[fwd_idx] = wk_shoup;

        let inv_idx = bit_rev(nbits, (n - k) % n);
        if k == 0 {
            inv_twid[inv_idx] = wk;
            inv_twid_shoup[inv_idx] = wk_shoup;
        } else {
            let x = p.wrapping_sub(wk);
            inv_twid[inv_idx] = x;
            inv_twid_shoup[inv_idx] = Div32::div_u64((x as u64) << 32, div) as u32;
        }

        wk = Div32::rem_u64(wk as u64 * w as u64, div);
        k += 1;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn mul_assign_normalize_avx512(
    simd: crate::V4,
    lhs: &mut [u32],
    rhs: &[u32],
    p: u32,
    p_barrett: u32,
    big_q: u32,
    n_inv_mod_p: u32,
    n_inv_mod_p_shoup: u32,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let lhs = pulp::as_arrays_mut::<16, _>(lhs).0;
            let rhs = pulp::as_arrays::<16, _>(rhs).0;
            let big_q_m1 = simd.splat_u32x16(big_q - 1);
            let big_q_m1_complement = simd.splat_u32x16(32 - (big_q - 1));
            let n_inv_mod_p = simd.splat_u32x16(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u32x16(n_inv_mod_p_shoup);
            let p_barrett = simd.splat_u32x16(p_barrett);
            let p = simd.splat_u32x16(p);

            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = cast(*lhs_);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u32x16(lhs, rhs);
                let c1 = simd.or_u32x16(
                    simd.shr_dyn_u32x16(lo, big_q_m1),
                    simd.shl_dyn_u32x16(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u32x16(c1, p_barrett).1;
                let prod = simd.wrapping_sub_u32x16(lo, simd.wrapping_mul_u32x16(p, c3));

                // normalization
                let shoup_q = simd.widening_mul_u32x16(prod, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u32x16(
                    simd.wrapping_mul_u32x16(prod, n_inv_mod_p),
                    simd.wrapping_mul_u32x16(shoup_q, p),
                );

                *lhs_ = cast(simd.small_mod_u32x16(p, t));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn mul_assign_normalize_avx2(
    simd: crate::V3,
    lhs: &mut [u32],
    rhs: &[u32],
    p: u32,
    p_barrett: u32,
    big_q: u32,
    n_inv_mod_p: u32,
    n_inv_mod_p_shoup: u32,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let lhs = pulp::as_arrays_mut::<8, _>(lhs).0;
            let rhs = pulp::as_arrays::<8, _>(rhs).0;
            let big_q_m1 = simd.splat_u32x8(big_q - 1);
            let big_q_m1_complement = simd.splat_u32x8(32 - (big_q - 1));
            let n_inv_mod_p = simd.splat_u32x8(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u32x8(n_inv_mod_p_shoup);
            let p_barrett = simd.splat_u32x8(p_barrett);
            let p = simd.splat_u32x8(p);

            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = cast(*lhs_);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u32x8(lhs, rhs);
                let c1 = simd.or_u32x8(
                    simd.shr_dyn_u32x8(lo, big_q_m1),
                    simd.shl_dyn_u32x8(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u32x8(c1, p_barrett).1;
                let prod = simd.wrapping_sub_u32x8(lo, simd.wrapping_mul_u32x8(p, c3));

                // normalization
                let shoup_q = simd.widening_mul_u32x8(prod, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u32x8(
                    simd.wrapping_mul_u32x8(prod, n_inv_mod_p),
                    simd.wrapping_mul_u32x8(shoup_q, p),
                );

                *lhs_ = cast(simd.small_mod_u32x8(p, t));
            }
        },
    );
}

fn mul_assign_normalize_scalar(
    lhs: &mut [u32],
    rhs: &[u32],
    p: u32,
    p_barrett: u32,
    big_q: u32,
    n_inv_mod_p: u32,
    n_inv_mod_p_shoup: u32,
) {
    let big_q_m1 = big_q - 1;

    for (lhs_, rhs) in crate::izip!(lhs, rhs) {
        let lhs = *lhs_;
        let rhs = *rhs;

        let d = lhs as u64 * rhs as u64;
        let c1 = (d >> big_q_m1) as u32;
        let c3 = ((c1 as u64 * p_barrett as u64) >> 32) as u32;
        let prod = (d as u32).wrapping_sub(p.wrapping_mul(c3));

        let shoup_q = (((prod as u64) * (n_inv_mod_p_shoup as u64)) >> 32) as u32;
        let t = u32::wrapping_sub(prod.wrapping_mul(n_inv_mod_p), shoup_q.wrapping_mul(p));

        *lhs_ = t.min(t.wrapping_sub(p));
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn normalize_avx512(
    simd: crate::V4,
    values: &mut [u32],
    p: u32,
    n_inv_mod_p: u32,
    n_inv_mod_p_shoup: u32,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let values = pulp::as_arrays_mut::<16, _>(values).0;

            let n_inv_mod_p = simd.splat_u32x16(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u32x16(n_inv_mod_p_shoup);
            let p = simd.splat_u32x16(p);

            for val_ in values {
                let val = cast(*val_);

                // normalization
                let shoup_q = simd.widening_mul_u32x16(val, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u32x16(
                    simd.wrapping_mul_u32x16(val, n_inv_mod_p),
                    simd.wrapping_mul_u32x16(shoup_q, p),
                );

                *val_ = cast(simd.small_mod_u32x16(p, t));
            }
        },
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn normalize_avx2(
    simd: crate::V3,
    values: &mut [u32],
    p: u32,
    n_inv_mod_p: u32,
    n_inv_mod_p_shoup: u32,
) {
    simd.vectorize(
        #[inline(always)]
        move || {
            let values = pulp::as_arrays_mut::<8, _>(values).0;

            let n_inv_mod_p = simd.splat_u32x8(n_inv_mod_p);
            let n_inv_mod_p_shoup = simd.splat_u32x8(n_inv_mod_p_shoup);
            let p = simd.splat_u32x8(p);

            for val_ in values {
                let val = cast(*val_);

                // normalization
                let shoup_q = simd.widening_mul_u32x8(val, n_inv_mod_p_shoup).1;
                let t = simd.wrapping_sub_u32x8(
                    simd.widening_mul_u32x8(val, n_inv_mod_p).0,
                    simd.widening_mul_u32x8(shoup_q, p).0,
                );

                *val_ = cast(simd.small_mod_u32x8(p, t));
            }
        },
    );
}

fn normalize_scalar(values: &mut [u32], p: u32, n_inv_mod_p: u32, n_inv_mod_p_shoup: u32) {
    for val_ in values {
        let val = *val_;

        let shoup_q = (((val as u64) * (n_inv_mod_p_shoup as u64)) >> 32) as u32;
        let t = u32::wrapping_sub(val.wrapping_mul(n_inv_mod_p), shoup_q.wrapping_mul(p));

        *val_ = t.min(t.wrapping_sub(p));
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
fn mul_accumulate_avx512(
    simd: crate::V4,
    acc: &mut [u32],
    lhs: &[u32],
    rhs: &[u32],
    p: u32,
    p_barrett: u32,
    big_q: u32,
) {
    simd.vectorize(
        #[inline(always)]
        || {
            let acc = pulp::as_arrays_mut::<16, _>(acc).0;
            let lhs = pulp::as_arrays::<16, _>(lhs).0;
            let rhs = pulp::as_arrays::<16, _>(rhs).0;

            let big_q_m1 = simd.splat_u32x16(big_q - 1);
            let big_q_m1_complement = simd.splat_u32x16(32 - (big_q - 1));
            let p_barrett = simd.splat_u32x16(p_barrett);
            let p = simd.splat_u32x16(p);

            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let lhs = cast(*lhs);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u32x16(lhs, rhs);
                let c1 = simd.or_u32x16(
                    simd.shr_dyn_u32x16(lo, big_q_m1),
                    simd.shl_dyn_u32x16(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u32x16(c1, p_barrett).1;
                // lo - p * c3
                let prod = simd.wrapping_sub_u32x16(lo, simd.wrapping_mul_u32x16(p, c3));
                let prod = simd.small_mod_u32x16(p, prod);

                *acc = cast(simd.small_mod_u32x16(p, simd.wrapping_add_u32x16(prod, cast(*acc))));
            }
        },
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn mul_accumulate_avx2(
    simd: crate::V3,
    acc: &mut [u32],
    lhs: &[u32],
    rhs: &[u32],
    p: u32,
    p_barrett: u32,
    big_q: u32,
) {
    simd.vectorize(
        #[inline(always)]
        || {
            let acc = pulp::as_arrays_mut::<8, _>(acc).0;
            let lhs = pulp::as_arrays::<8, _>(lhs).0;
            let rhs = pulp::as_arrays::<8, _>(rhs).0;

            let big_q_m1 = simd.splat_u32x8(big_q - 1);
            let big_q_m1_complement = simd.splat_u32x8(32 - (big_q - 1));
            let p_barrett = simd.splat_u32x8(p_barrett);
            let p = simd.splat_u32x8(p);

            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let lhs = cast(*lhs);
                let rhs = cast(*rhs);

                // lhs × rhs
                let (lo, hi) = simd.widening_mul_u32x8(lhs, rhs);
                let c1 = simd.or_u32x8(
                    simd.shr_dyn_u32x8(lo, big_q_m1),
                    simd.shl_dyn_u32x8(hi, big_q_m1_complement),
                );
                let c3 = simd.widening_mul_u32x8(c1, p_barrett).1;
                // lo - p * c3
                let prod = simd.wrapping_sub_u32x8(lo, simd.wrapping_mul_u32x8(p, c3));
                let prod = simd.small_mod_u32x8(p, prod);

                *acc = cast(simd.small_mod_u32x8(p, simd.wrapping_add_u32x8(prod, cast(*acc))));
            }
        },
    )
}

fn mul_accumulate_scalar(
    acc: &mut [u32],
    lhs: &[u32],
    rhs: &[u32],
    p: u32,
    p_barrett: u32,
    big_q: u32,
) {
    let big_q_m1 = big_q - 1;

    for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
        let lhs = *lhs;
        let rhs = *rhs;

        let d = lhs as u64 * rhs as u64;
        let c1 = (d >> big_q_m1) as u32;
        let c3 = ((c1 as u64 * p_barrett as u64) >> 32) as u32;
        let prod = (d as u32).wrapping_sub(p.wrapping_mul(c3));
        let prod = prod.min(prod.wrapping_sub(p));

        let acc_ = prod + *acc;
        *acc = acc_.min(acc_.wrapping_sub(p));
    }
}

/// Negacyclic NTT plan for 32bit primes.
#[derive(Clone)]
pub struct Plan {
    twid: ABox<[u32]>,
    twid_shoup: ABox<[u32]>,
    inv_twid: ABox<[u32]>,
    inv_twid_shoup: ABox<[u32]>,
    p: u32,
    p_div: Div32,

    // used for elementwise product
    p_barrett: u32,
    big_q: u32,

    n_inv_mod_p: u32,
    n_inv_mod_p_shoup: u32,
}

impl core::fmt::Debug for Plan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plan")
            .field("ntt_size", &self.ntt_size())
            .field("modulus", &self.modulus())
            .finish()
    }
}

impl Plan {
    /// Returns a negacyclic NTT plan for the given polynomial size and modulus, or `None` if no
    /// suitable roots of unity can be found for the wanted parameters.
    pub fn try_new(polynomial_size: usize, modulus: u32) -> Option<Self> {
        let p_div = Div32::new(modulus);
        // 32 = 16x2 = max_register_size * ntt_radix,
        // as SIMD registers can contain at most 16*u32
        // and the implementation assumes that SIMD registers are full
        if polynomial_size < 32
            || !polynomial_size.is_power_of_two()
            || !is_prime64(modulus as u64)
            || find_primitive_root64(Div64::new(modulus as u64), 2 * polynomial_size as u64)
                .is_none()
        {
            None
        } else {
            let mut twid = avec![0u32; polynomial_size].into_boxed_slice();
            let mut inv_twid = avec![0u32; polynomial_size].into_boxed_slice();
            let (mut twid_shoup, mut inv_twid_shoup) = if modulus < (1u32 << 31) {
                (
                    avec![0u32; polynomial_size].into_boxed_slice(),
                    avec![0u32; polynomial_size].into_boxed_slice(),
                )
            } else {
                (avec![].into_boxed_slice(), avec![].into_boxed_slice())
            };

            if modulus < (1u32 << 31) {
                init_negacyclic_twiddles_shoup(
                    modulus,
                    polynomial_size,
                    &mut twid,
                    &mut twid_shoup,
                    &mut inv_twid,
                    &mut inv_twid_shoup,
                );
            } else {
                init_negacyclic_twiddles(modulus, polynomial_size, &mut twid, &mut inv_twid);
            }

            let n_inv_mod_p = crate::prime::exp_mod32(p_div, polynomial_size as u32, modulus - 2);
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u64) << 32) / modulus as u64) as u32;
            let big_q = modulus.ilog2() + 1;
            let big_l = big_q + 31;
            let p_barrett = ((1u64 << big_l) / modulus as u64) as u32;

            Some(Self {
                twid,
                twid_shoup,
                inv_twid_shoup,
                inv_twid,
                p: modulus,
                p_div,
                n_inv_mod_p,
                n_inv_mod_p_shoup,
                p_barrett,
                big_q,
            })
        }
    }

    pub(crate) fn p_div(&self) -> Div32 {
        self.p_div
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.twid.len()
    }

    /// Returns the modulus of the negacyclic NTT plan.
    #[inline]
    pub fn modulus(&self) -> u32 {
        self.p
    }

    /// Applies a forward negacyclic NTT transform in place to the given buffer.
    ///
    /// # Note
    /// On entry, the buffer holds the polynomial coefficients in standard order. On exit, the
    /// buffer holds the negacyclic NTT transform coefficients in bit reversed order.
    pub fn fwd(&self, buf: &mut [u32]) {
        assert_eq!(buf.len(), self.ntt_size());
        let p = self.p;

        if p < (1u32 << 30) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_30bit::fwd_avx512(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_30bit::fwd_avx2(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
            }
            less_than_30bit::fwd_scalar(p, buf, &self.twid, &self.twid_shoup);
        } else if p < (1u32 << 31) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_31bit::fwd_avx512(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_31bit::fwd_avx2(simd, p, buf, &self.twid, &self.twid_shoup);
                    return;
                }
            }
            less_than_31bit::fwd_scalar(p, buf, &self.twid, &self.twid_shoup);
        } else {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                generic::fwd_avx512(simd, buf, p, self.p_div, &self.twid);
                return;
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if let Some(simd) = crate::V3::try_new() {
                generic::fwd_avx2(simd, buf, p, self.p_div, &self.twid);
                return;
            }
            generic::fwd_scalar(buf, p, self.p_div, &self.twid);
        }
    }

    /// Applies an inverse negacyclic NTT transform in place to the given buffer.
    ///
    /// # Note
    /// On entry, the buffer holds the negacyclic NTT transform coefficients in bit reversed order.
    /// On exit, the buffer holds the polynomial coefficients in standard order.
    pub fn inv(&self, buf: &mut [u32]) {
        assert_eq!(buf.len(), self.ntt_size());
        let p = self.p;

        if p < (1u32 << 30) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_30bit::inv_avx512(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_30bit::inv_avx2(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
            }
            less_than_30bit::inv_scalar(p, buf, &self.inv_twid, &self.inv_twid_shoup);
        } else if p < (1u32 << 31) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                #[cfg(feature = "nightly")]
                if let Some(simd) = crate::V4::try_new() {
                    less_than_31bit::inv_avx512(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
                if let Some(simd) = crate::V3::try_new() {
                    less_than_31bit::inv_avx2(simd, p, buf, &self.inv_twid, &self.inv_twid_shoup);
                    return;
                }
            }
            less_than_31bit::inv_scalar(p, buf, &self.inv_twid, &self.inv_twid_shoup);
        } else {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                generic::inv_avx512(simd, buf, p, self.p_div, &self.inv_twid);
                return;
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if let Some(simd) = crate::V3::try_new() {
                generic::inv_avx2(simd, buf, p, self.p_div, &self.inv_twid);
                return;
            }
            generic::inv_scalar(buf, p, self.p_div, &self.inv_twid);
        }
    }

    /// Computes the elementwise product of `lhs` and `rhs`, multiplied by the inverse of the
    /// polynomial modulo the NTT modulus, and stores the result in `lhs`.
    pub fn mul_assign_normalize(&self, lhs: &mut [u32], rhs: &[u32]) {
        if self.p < (1 << 31) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                mul_assign_normalize_avx512(
                    simd,
                    lhs,
                    rhs,
                    self.p,
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
                    self.p,
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
                self.p,
                self.p_barrett,
                self.big_q,
                self.n_inv_mod_p,
                self.n_inv_mod_p_shoup,
            );
        } else {
            let p_div = self.p_div;
            let n_inv_mod_p = self.n_inv_mod_p;
            for (lhs_, rhs) in crate::izip!(lhs, rhs) {
                let lhs = *lhs_;
                let rhs = *rhs;
                let prod = Div32::rem_u64(lhs as u64 * rhs as u64, p_div);
                let prod = Div32::rem_u64(prod as u64 * n_inv_mod_p as u64, p_div);
                *lhs_ = prod;
            }
        }
    }

    /// Multiplies the values by the inverse of the polynomial modulo the NTT modulus, and stores
    /// the result in `values`.
    pub fn normalize(&self, values: &mut [u32]) {
        if self.p < (1 << 31) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                normalize_avx512(
                    simd,
                    values,
                    self.p,
                    self.n_inv_mod_p,
                    self.n_inv_mod_p_shoup,
                );
                return;
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if let Some(simd) = crate::V3::try_new() {
                normalize_avx2(
                    simd,
                    values,
                    self.p,
                    self.n_inv_mod_p,
                    self.n_inv_mod_p_shoup,
                );
                return;
            }
            normalize_scalar(values, self.p, self.n_inv_mod_p, self.n_inv_mod_p_shoup);
        } else {
            let p_div = self.p_div;
            let n_inv_mod_p = self.n_inv_mod_p;
            for values in values {
                let prod = Div32::rem_u64(*values as u64 * n_inv_mod_p as u64, p_div);
                *values = prod;
            }
        }
    }

    /// Computes the elementwise product of `lhs` and `rhs` and accumulates the result to `acc`.
    pub fn mul_accumulate(&self, acc: &mut [u32], lhs: &[u32], rhs: &[u32]) {
        if self.p < (1 << 31) {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            #[cfg(feature = "nightly")]
            if let Some(simd) = crate::V4::try_new() {
                mul_accumulate_avx512(simd, acc, lhs, rhs, self.p, self.p_barrett, self.big_q);
                return;
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if let Some(simd) = crate::V3::try_new() {
                mul_accumulate_avx2(simd, acc, lhs, rhs, self.p, self.p_barrett, self.big_q);
                return;
            }
            mul_accumulate_scalar(acc, lhs, rhs, self.p, self.p_barrett, self.big_q);
        } else {
            let p = self.p;
            let p_div = self.p_div;
            for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
                let prod = generic::mul(p_div, *lhs, *rhs);
                *acc = generic::add(p, *acc, prod);
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::prime::largest_prime_in_arithmetic_progression64;
    use alloc::{vec, vec::Vec};
    use rand::random;

    extern crate alloc;

    pub fn add(p: u32, a: u32, b: u32) -> u32 {
        let neg_b = p.wrapping_sub(b);
        if a >= neg_b {
            a - neg_b
        } else {
            a + b
        }
    }

    pub fn sub(p: u32, a: u32, b: u32) -> u32 {
        let neg_b = p.wrapping_sub(b);
        if a >= b {
            a - b
        } else {
            a + neg_b
        }
    }

    pub fn mul(p: u32, a: u32, b: u32) -> u32 {
        let wide = a as u64 * b as u64;
        if p == 0 {
            wide as u32
        } else {
            (wide % p as u64) as u32
        }
    }

    pub fn negacyclic_convolution(n: usize, p: u32, lhs: &[u32], rhs: &[u32]) -> vec::Vec<u32> {
        let mut full_convolution = vec![0u32; 2 * n];
        let mut negacyclic_convolution = vec![0u32; n];
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
        p: u32,
    ) -> (vec::Vec<u32>, vec::Vec<u32>, vec::Vec<u32>) {
        let mut lhs = vec![0u32; n];
        let mut rhs = vec![0u32; n];

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
        for n in [32, 64, 128, 256, 512, 1024] {
            for p in [
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 29, 1 << 30).unwrap(),
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap(),
                largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 31, 1 << 32).unwrap(),
            ] {
                let p = p as u32;
                let plan = Plan::try_new(n, p).unwrap();

                let (lhs, rhs, negacyclic_convolution) =
                    random_lhs_rhs_with_negacyclic_convolution(n, p);

                let mut prod = vec![0u32; n];
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
                    prod[i] = mul(p, lhs_fourier[i], rhs_fourier[i]);
                }
                plan.inv(&mut prod);

                plan.mul_assign_normalize(&mut lhs_fourier, &rhs_fourier);
                plan.inv(&mut lhs_fourier);

                for x in &prod {
                    assert!(*x < p);
                }

                for i in 0..n {
                    assert_eq!(prod[i], mul(p, negacyclic_convolution[i], n as u32),);
                }
                assert_eq!(lhs_fourier, negacyclic_convolution);
            }
        }
    }

    #[test]
    fn test_mul_assign_normalize_scalar() {
        let p =
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap() as u32;
        let p_div = Div64::new(p as u64);
        let polynomial_size = 128;

        let n_inv_mod_p =
            crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;
        let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 32) / p as u128) as u32;
        let big_q = p.ilog2() + 1;
        let big_l = big_q + 31;
        let p_barrett = ((1u128 << big_l) / p as u128) as u32;

        let mut lhs = (0..polynomial_size)
            .map(|_| rand::random::<u32>() % p)
            .collect::<Vec<_>>();
        let mut lhs_target = lhs.clone();
        let rhs = (0..polynomial_size)
            .map(|_| rand::random::<u32>() % p)
            .collect::<Vec<_>>();

        let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;

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
        let p =
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap() as u32;
        let polynomial_size = 128;

        let big_q = p.ilog2() + 1;
        let big_l = big_q + 31;
        let p_barrett = ((1u128 << big_l) / p as u128) as u32;

        let mut acc = (0..polynomial_size)
            .map(|_| rand::random::<u32>() % p)
            .collect::<Vec<_>>();
        let mut acc_target = acc.clone();
        let lhs = (0..polynomial_size)
            .map(|_| rand::random::<u32>() % p)
            .collect::<Vec<_>>();
        let rhs = (0..polynomial_size)
            .map(|_| rand::random::<u32>() % p)
            .collect::<Vec<_>>();

        let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;
        let add = |a: u32, b: u32| (a + b) % p;

        for (acc, lhs, rhs) in crate::izip!(&mut acc_target, &lhs, &rhs) {
            *acc = add(mul(*lhs, *rhs), *acc);
        }

        mul_accumulate_scalar(&mut acc, &lhs, &rhs, p, p_barrett, big_q);
        assert_eq!(acc, acc_target);
    }

    #[test]
    fn test_normalize_scalar() {
        let p =
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap() as u32;
        let p_div = Div64::new(p as u64);
        let polynomial_size = 128;

        let n_inv_mod_p =
            crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;
        let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 32) / p as u128) as u32;

        let mut val = (0..polynomial_size)
            .map(|_| rand::random::<u32>() % p)
            .collect::<Vec<_>>();
        let mut val_target = val.clone();

        let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;

        for val in val_target.iter_mut() {
            *val = mul(*val, n_inv_mod_p);
        }

        normalize_scalar(&mut val, p, n_inv_mod_p, n_inv_mod_p_shoup);
        assert_eq!(val, val_target);
    }

    #[test]
    fn test_mul_accumulate() {
        for p in [
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 31).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, u32::MAX as u64).unwrap(),
        ] {
            let p = p as u32;
            let polynomial_size = 128;

            let mut acc = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut acc_target = acc.clone();
            let lhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u32, b: u32| ((a as u64 * b as u64) % p as u64) as u32;
            let add = |a: u32, b: u32| ((a as u64 + b as u64) % p as u64) as u32;

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
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 31).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, u32::MAX as u64).unwrap(),
        ] {
            let p = p as u32;
            let polynomial_size = 128;
            let p_div = Div64::new(p as u64);
            let n_inv_mod_p =
                crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;

            let mut lhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut lhs_target = lhs.clone();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u32, b: u32| ((a as u64 * b as u64) % p as u64) as u32;

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
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, 1 << 31).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 0, u32::MAX as u64).unwrap(),
        ] {
            let p = p as u32;
            let polynomial_size = 128;
            let p_div = Div64::new(p as u64);
            let n_inv_mod_p =
                crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;

            let mut val = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut val_target = val.clone();

            let mul = |a: u32, b: u32| ((a as u64 * b as u64) % p as u64) as u32;

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
    fn test_interleaves_and_permutes_u32x8() {
        if let Some(simd) = crate::V3::try_new() {
            let a = u32x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            let b = u32x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());

            assert_eq!(
                simd.interleave4_u32x8([a, b]),
                [
                    u32x8(a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3),
                    u32x8(a.4, a.5, a.6, a.7, b.4, b.5, b.6, b.7),
                ],
            );
            assert_eq!(
                simd.interleave4_u32x8(simd.interleave4_u32x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd()];
            assert_eq!(
                simd.permute4_u32x8(w),
                u32x8(w[0], w[0], w[0], w[0], w[1], w[1], w[1], w[1]),
            );

            assert_eq!(
                simd.interleave2_u32x8([a, b]),
                [
                    u32x8(a.0, a.1, b.0, b.1, a.4, a.5, b.4, b.5),
                    u32x8(a.2, a.3, b.2, b.3, a.6, a.7, b.6, b.7),
                ],
            );
            assert_eq!(
                simd.interleave2_u32x8(simd.interleave2_u32x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute2_u32x8(w),
                u32x8(w[0], w[0], w[2], w[2], w[1], w[1], w[3], w[3]),
            );

            assert_eq!(
                simd.interleave1_u32x8([a, b]),
                [
                    u32x8(a.0, b.0, a.2, b.2, a.4, b.4, a.6, b.6),
                    u32x8(a.1, b.1, a.3, b.3, a.5, b.5, a.7, b.7),
                ],
            );
            assert_eq!(
                simd.interleave1_u32x8(simd.interleave1_u32x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute1_u32x8(w),
                u32x8(w[0], w[4], w[1], w[5], w[2], w[6], w[3], w[7]),
            );
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_interleaves_and_permutes_u32x16() {
        if let Some(simd) = crate::V4::try_new() {
            #[rustfmt::skip]
            let a = u32x16(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            #[rustfmt::skip]
            let b = u32x16(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());

            assert_eq!(
                simd.interleave8_u32x16([a, b]),
                [
                    u32x16(
                        a.0, a.1, a.2, a.3, a.4, a.5, a.6, a.7, b.0, b.1, b.2, b.3, b.4, b.5, b.6,
                        b.7,
                    ),
                    u32x16(
                        a.8, a.9, a.10, a.11, a.12, a.13, a.14, a.15, b.8, b.9, b.10, b.11, b.12,
                        b.13, b.14, b.15,
                    ),
                ],
            );
            assert_eq!(
                simd.interleave8_u32x16(simd.interleave8_u32x16([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd()];
            assert_eq!(
                simd.permute8_u32x16(w),
                u32x16(
                    w[0], w[0], w[0], w[0], w[0], w[0], w[0], w[0], w[1], w[1], w[1], w[1], w[1],
                    w[1], w[1], w[1],
                ),
            );

            assert_eq!(
                simd.interleave4_u32x16([a, b]),
                [
                    u32x16(
                        a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3, a.8, a.9, a.10, a.11, b.8, b.9,
                        b.10, b.11,
                    ),
                    u32x16(
                        a.4, a.5, a.6, a.7, b.4, b.5, b.6, b.7, a.12, a.13, a.14, a.15, b.12, b.13,
                        b.14, b.15,
                    ),
                ],
            );
            assert_eq!(
                simd.interleave4_u32x16(simd.interleave4_u32x16([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute4_u32x16(w),
                u32x16(
                    w[0], w[0], w[0], w[0], w[2], w[2], w[2], w[2], w[1], w[1], w[1], w[1], w[3],
                    w[3], w[3], w[3],
                ),
            );

            assert_eq!(
                simd.interleave2_u32x16([a, b]),
                [
                    u32x16(
                        a.0, a.1, b.0, b.1, a.4, a.5, b.4, b.5, a.8, a.9, b.8, b.9, a.12, a.13,
                        b.12, b.13,
                    ),
                    u32x16(
                        a.2, a.3, b.2, b.3, a.6, a.7, b.6, b.7, a.10, a.11, b.10, b.11, a.14, a.15,
                        b.14, b.15,
                    ),
                ],
            );
            assert_eq!(
                simd.interleave2_u32x16(simd.interleave2_u32x16([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute2_u32x16(w),
                u32x16(
                    w[0], w[0], w[4], w[4], w[1], w[1], w[5], w[5], w[2], w[2], w[6], w[6], w[3],
                    w[3], w[7], w[7],
                ),
            );

            assert_eq!(
                simd.interleave1_u32x16([a, b]),
                [
                    u32x16(
                        a.0, b.0, a.2, b.2, a.4, b.4, a.6, b.6, a.8, b.8, a.10, b.10, a.12, b.12,
                        a.14, b.14,
                    ),
                    u32x16(
                        a.1, b.1, a.3, b.3, a.5, b.5, a.7, b.7, a.9, b.9, a.11, b.11, a.13, b.13,
                        a.15, b.15,
                    ),
                ],
            );
            assert_eq!(
                simd.interleave1_u32x16(simd.interleave1_u32x16([a, b])),
                [a, b],
            );
            #[rustfmt::skip]
            let w = [rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute1_u32x16(w),
                u32x16(
                    w[0], w[8], w[1], w[9], w[2], w[10], w[3], w[11], w[4], w[12], w[5], w[13],
                    w[6], w[14], w[7], w[15],
                ),
            );
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_mul_assign_normalize_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap()
                as u32;
            let p_div = Div64::new(p as u64);
            let polynomial_size = 128;

            let n_inv_mod_p =
                crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 32) / p as u128) as u32;
            let big_q = p.ilog2() + 1;
            let big_l = big_q + 31;
            let p_barrett = ((1u128 << big_l) / p as u128) as u32;

            let mut lhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut lhs_target = lhs.clone();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;

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
            let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap()
                as u32;
            let p_div = Div64::new(p as u64);
            let polynomial_size = 128;

            let n_inv_mod_p =
                crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 32) / p as u128) as u32;
            let big_q = p.ilog2() + 1;
            let big_l = big_q + 31;
            let p_barrett = ((1u128 << big_l) / p as u128) as u32;

            let mut lhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut lhs_target = lhs.clone();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;

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
    fn test_mul_accumulate_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap()
                as u32;
            let polynomial_size = 128;

            let big_q = p.ilog2() + 1;
            let big_l = big_q + 31;
            let p_barrett = ((1u128 << big_l) / p as u128) as u32;

            let mut acc = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut acc_target = acc.clone();
            let lhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;
            let add = |a: u32, b: u32| (a + b) % p;

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
            let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap()
                as u32;
            let polynomial_size = 128;

            let big_q = p.ilog2() + 1;
            let big_l = big_q + 31;
            let p_barrett = ((1u128 << big_l) / p as u128) as u32;

            let mut acc = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut acc_target = acc.clone();
            let lhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let rhs = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();

            let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;
            let add = |a: u32, b: u32| (a + b) % p;

            for (acc, lhs, rhs) in crate::izip!(&mut acc_target, &lhs, &rhs) {
                *acc = add(mul(*lhs, *rhs), *acc);
            }

            mul_accumulate_avx2(simd, &mut acc, &lhs, &rhs, p, p_barrett, big_q);
            assert_eq!(acc, acc_target);
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_normalize_avx512() {
        if let Some(simd) = crate::V4::try_new() {
            let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap()
                as u32;
            let p_div = Div64::new(p as u64);
            let polynomial_size = 128;

            let n_inv_mod_p =
                crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 32) / p as u128) as u32;

            let mut val = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut val_target = val.clone();

            let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;

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
            let p = largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap()
                as u32;
            let p_div = Div64::new(p as u64);
            let polynomial_size = 128;

            let n_inv_mod_p =
                crate::prime::exp_mod64(p_div, polynomial_size as u64, p as u64 - 2) as u32;
            let n_inv_mod_p_shoup = (((n_inv_mod_p as u128) << 32) / p as u128) as u32;

            let mut val = (0..polynomial_size)
                .map(|_| rand::random::<u32>() % p)
                .collect::<Vec<_>>();
            let mut val_target = val.clone();

            let mul = |a: u32, b: u32| ((a as u128 * b as u128) % p as u128) as u32;

            for val in val_target.iter_mut() {
                *val = mul(*val, n_inv_mod_p);
            }

            normalize_avx2(simd, &mut val, p, n_inv_mod_p, n_inv_mod_p_shoup);
            assert_eq!(val, val_target);
        }
    }
}
