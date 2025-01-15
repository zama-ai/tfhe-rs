use crate::{
    fastdiv::{Div32, Div64},
    izip, prime32, prime64,
};

// for no_std environments
extern crate alloc;
type Box<T> = alloc::boxed::Box<T>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwdMode {
    Generic,
    Bounded(u64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InvMode {
    Replace,
    Accumulate,
}

fn modular_inv_u32(modulus: Div32, n: u32) -> u32 {
    let modulus_div = modulus;
    let modulus = modulus.divisor();

    let mut old_r = Div32::rem(n, modulus_div);
    let mut r = modulus;

    let mut old_s = 1u32;
    let mut s = 0u32;

    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);
        (old_s, s) = (
            s,
            sub_mod_u32(modulus, old_s, mul_mod_u32(modulus_div, q, s)),
        );
    }

    old_s
}

fn modular_inv_u64(modulus: Div64, n: u64) -> u64 {
    let modulus_div = modulus;
    let modulus = modulus.divisor();

    let mut old_r = Div64::rem(n, modulus_div);
    let mut r = modulus;

    let mut old_s = 1u64;
    let mut s = 0u64;

    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);
        (old_s, s) = (
            s,
            sub_mod_u64(modulus, old_s, mul_mod_u64(modulus_div, q, s)),
        );
    }

    old_s
}

#[inline]
fn sub_mod_u64(modulus: u64, a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a.wrapping_sub(b).wrapping_add(modulus)
    }
}

#[inline]
fn sub_mod_u32(modulus: u32, a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a.wrapping_sub(b).wrapping_add(modulus)
    }
}

#[inline]
fn add_mod_u64(modulus: u64, a: u64, b: u64) -> u64 {
    let (sum, overflow) = a.overflowing_add(b);
    if sum >= modulus || overflow {
        sum.wrapping_sub(modulus)
    } else {
        sum
    }
}

#[inline]
fn add_mod_u64_less_than_2_63(modulus: u64, a: u64, b: u64) -> u64 {
    debug_assert!(modulus < 1 << 63);

    let sum = a + b;
    if sum >= modulus {
        sum - modulus
    } else {
        sum
    }
}

#[inline]
fn add_mod_u32(modulus: u32, a: u32, b: u32) -> u32 {
    let (sum, overflow) = a.overflowing_add(b);
    if sum >= modulus || overflow {
        sum.wrapping_sub(modulus)
    } else {
        sum
    }
}

#[inline]
fn mul_mod_u64(modulus: Div64, a: u64, b: u64) -> u64 {
    Div64::rem_u128(a as u128 * b as u128, modulus)
}

#[inline]
fn mul_mod_u32(modulus: Div32, a: u32, b: u32) -> u32 {
    Div32::rem_u64(a as u64 * b as u64, modulus)
}

#[inline]
fn shoup_mul_mod_u32(modulus: u32, a: u32, b: u32, b_shoup: u32) -> u32 {
    debug_assert!(modulus < 1 << 31);
    let q = ((a as u64 * b_shoup as u64) >> 32) as u32;
    let mut r = u32::wrapping_sub(b.wrapping_mul(a), q.wrapping_mul(modulus));
    if r >= modulus {
        r -= modulus
    }
    r
}

/// Negacyclic NTT plan for 64bit product of distinct primes.
#[derive(Clone, Debug)]
pub struct Plan {
    polynomial_size: usize,
    modulus: u64,
    modular_inverses: Box<[u64]>,
    plan_32: Box<[prime32::Plan]>,
    plan_64: Box<[prime64::Plan]>,
    div_32: Box<[Div32]>,
    div_64: Box<[Div64]>,
}

impl Plan {
    /// Returns a negacyclic NTT plan for the given polynomial size and modulus (product of the
    /// given distinct primes), or `None` if no suitable roots of unity can be found for the
    /// wanted parameters.
    pub fn try_new(
        polynomial_size: usize,
        modulus: u64,
        factors: impl AsRef<[u64]>,
    ) -> Option<Self> {
        fn try_new_impl(polynomial_size: usize, modulus: u64, primes: &mut [u64]) -> Option<Plan> {
            if polynomial_size % 2 != 0 {
                return None;
            }

            // check for zeros/duplicates
            primes.sort_unstable();

            let mut prev = 0;
            for &factor in &*primes {
                if factor == prev {
                    return None;
                }
                prev = factor;
            }

            let start = primes.partition_point(|&modulus| modulus == 1);
            let primes = &primes[start..];

            if primes
                .iter()
                .try_fold(1u64, |prod, &modulus| prod.checked_mul(modulus))
                != Some(modulus)
            {
                return None;
            };

            let mid = primes.partition_point(|&modulus| modulus < (1u64 << 32));
            let (primes_32, primes_64) = primes.split_at(mid);

            let plan_32 = primes_32
                .iter()
                .map(|&modulus| prime32::Plan::try_new(polynomial_size, modulus as u32))
                .collect::<Option<Box<[_]>>>()?;

            let plan_64 = primes_64
                .iter()
                .map(|&modulus| prime64::Plan::try_new(polynomial_size, modulus))
                .collect::<Option<Box<[_]>>>()?;

            let div_32 = plan_32
                .iter()
                .map(prime32::Plan::p_div)
                .collect::<Box<[_]>>();
            let div_64 = plan_64
                .iter()
                .map(prime64::Plan::p_div)
                .collect::<Box<[_]>>();

            let len = primes.len();

            let mut modular_inverses = alloc::vec![0u64; (len * (len - 1)) / 2].into_boxed_slice();
            let mut offset = 0;
            for (j, pj) in plan_32.iter().map(prime32::Plan::p_div).enumerate() {
                for (inv, &pi) in modular_inverses[offset..][..j]
                    .iter_mut()
                    .zip(&primes_32[..j])
                {
                    *inv = modular_inv_u32(pj, pi as u32) as u64;
                }
                offset += j;
            }

            let count_32 = plan_32.len();
            for (j, pj) in plan_64.iter().map(prime64::Plan::p_div).enumerate() {
                let j = j + count_32;

                for (inv, &pi) in modular_inverses[offset..][..j].iter_mut().zip(&primes[..j]) {
                    *inv = modular_inv_u64(pj, pi);
                }
                offset += j;
            }

            Some(Plan {
                polynomial_size,
                modulus,
                modular_inverses,
                plan_32,
                plan_64,
                div_32,
                div_64,
            })
        }

        try_new_impl(
            polynomial_size,
            modulus,
            &mut factors.as_ref().iter().copied().collect::<Box<[_]>>(),
        )
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.polynomial_size
    }

    /// Returns the modulus of the negacyclic NTT plan.
    #[inline]
    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    fn ntt_domain_len_u32(&self) -> usize {
        (self.polynomial_size / 2) * self.plan_32.len()
    }
    fn ntt_domain_len_u64(&self) -> usize {
        self.polynomial_size * self.plan_64.len()
    }

    pub fn ntt_domain_len(&self) -> usize {
        self.ntt_domain_len_u32() + self.ntt_domain_len_u64()
    }

    #[track_caller]
    pub fn fwd(&self, ntt: &mut [u64], standard: &[u64], mode: FwdMode) {
        assert_eq!(standard.len(), self.ntt_size());
        assert_eq!(ntt.len(), self.ntt_domain_len());

        let (ntt_32, ntt_64) = ntt.split_at_mut(self.ntt_domain_len_u32());
        let ntt_32: &mut [u32] = bytemuck::cast_slice_mut(ntt_32);

        // optimize common cases(?): u64x1, u32x1
        if self.plan_32.is_empty() && self.plan_64.len() == 1 {
            ntt_64.copy_from_slice(standard);
            self.plan_64[0].fwd(ntt_64);
            return;
        }
        if self.plan_32.len() == 1 && self.plan_64.is_empty() {
            for (ntt, &standard) in ntt_32.iter_mut().zip(standard) {
                *ntt = standard as u32;
            }
            self.plan_32[0].fwd(ntt_32);
            return;
        }

        if self.plan_32.len() == 2 && self.plan_64.is_empty() {
            let (ntt0, ntt1) = ntt_32.split_at_mut(self.ntt_size());
            let p0_div = self.plan_32[0].p_div();
            let p1_div = self.plan_32[1].p_div();
            let p0 = self.plan_32[0].modulus();
            let p1 = self.plan_32[1].modulus();
            let p = self.modulus();
            let p_u32 = p as u32;

            match mode {
                FwdMode::Bounded(bound) if bound < p0 as u64 && bound < p1 as u64 => {
                    for ((ntt0, ntt1), &standard) in
                        ntt0.iter_mut().zip(ntt1.iter_mut()).zip(standard)
                    {
                        let positive = standard < p / 2;
                        let standard = standard as u32;
                        let complement = p_u32.wrapping_sub(standard);
                        *ntt0 = if positive {
                            standard
                        } else {
                            p0.wrapping_sub(complement)
                        };
                        *ntt1 = if positive {
                            standard
                        } else {
                            p1.wrapping_sub(complement)
                        };
                    }
                }
                _ => {
                    for ((ntt0, ntt1), &standard) in
                        ntt0.iter_mut().zip(ntt1.iter_mut()).zip(standard)
                    {
                        *ntt0 = Div32::rem_u64(standard, p0_div);
                        *ntt1 = Div32::rem_u64(standard, p1_div);
                    }
                }
            }

            self.plan_32[0].fwd(ntt0);
            self.plan_32[1].fwd(ntt1);

            return;
        }

        for (ntt, plan) in ntt_32.chunks_exact_mut(self.ntt_size()).zip(&*self.plan_32) {
            let modulus = plan.p_div();

            for (ntt, &standard) in ntt.iter_mut().zip(standard) {
                *ntt = Div32::rem_u64(standard, modulus);
            }

            plan.fwd(ntt);
        }

        for (ntt, plan) in ntt_64.chunks_exact_mut(self.ntt_size()).zip(&*self.plan_64) {
            let modulus = plan.p_div();
            for (ntt, &standard) in ntt.iter_mut().zip(standard) {
                *ntt = Div64::rem(standard, modulus);
            }

            plan.fwd(ntt);
        }
    }

    #[track_caller]
    pub fn inv(&self, standard: &mut [u64], ntt: &mut [u64], mode: InvMode) {
        assert_eq!(standard.len(), self.ntt_size());
        assert_eq!(ntt.len(), self.ntt_domain_len());

        let (ntt_32, ntt_64) = ntt.split_at_mut(self.ntt_domain_len_u32());
        let ntt_32: &mut [u32] = bytemuck::cast_slice_mut(ntt_32);

        for (ntt, plan) in ntt_32.chunks_exact_mut(self.ntt_size()).zip(&*self.plan_32) {
            plan.inv(ntt);
        }
        for (ntt, plan) in ntt_64.chunks_exact_mut(self.ntt_size()).zip(&*self.plan_64) {
            plan.inv(ntt);
        }

        let ntt_32 = &*ntt_32;
        let ntt_64 = &*ntt_64;

        // optimize common cases(?): u64x1, u32x1, u32x2
        if self.plan_32.is_empty() && self.plan_64.is_empty() {
            match mode {
                InvMode::Replace => standard.fill(0),
                InvMode::Accumulate => {}
            }
            return;
        }

        if self.plan_32.is_empty() && self.plan_64.len() == 1 {
            match mode {
                InvMode::Replace => standard.copy_from_slice(ntt_64),
                InvMode::Accumulate => {
                    let p = self.plan_64[0].modulus();

                    for (standard, &ntt) in standard.iter_mut().zip(ntt_64) {
                        *standard = add_mod_u64(p, *standard, ntt);
                    }
                }
            }
            return;
        }
        if self.plan_32.len() == 1 && self.plan_64.is_empty() {
            match mode {
                InvMode::Replace => {
                    for (standard, &ntt) in standard.iter_mut().zip(ntt_32) {
                        *standard = ntt as u64;
                    }
                }
                InvMode::Accumulate => {
                    let p = self.plan_32[0].modulus();

                    for (standard, &ntt) in standard.iter_mut().zip(ntt_32) {
                        *standard = add_mod_u32(p, *standard as u32, ntt) as u64;
                    }
                }
            }
            return;
        }

        // implements the algorithms from "the art of computer programming (Donald E. Knuth)" 4.3.2
        // for finding solutions of the chinese remainder theorem
        if self.plan_32.len() == 2 && self.plan_64.is_empty() {
            let (ntt0, ntt1) = ntt_32.split_at(self.ntt_size());
            let p0 = self.plan_32[0].modulus();
            let p1 = self.plan_32[1].modulus();
            let p = self.modulus();
            let p1_div = self.plan_32[1].p_div();

            let inv = self.modular_inverses[0] as u32;

            if p1 < 1 << 31 {
                let inv_shoup = Div32::div_u64((inv as u64) << 32, p1_div) as u32;
                match mode {
                    InvMode::Replace => {
                        for (standard, &ntt0, &ntt1) in izip!(standard.iter_mut(), ntt0, ntt1) {
                            let u0 = ntt0;
                            let u1 = ntt1;

                            let v0 = u0;

                            let diff = sub_mod_u32(p1, u1, v0);
                            let v1 = shoup_mul_mod_u32(p1, diff, inv, inv_shoup);

                            *standard = v0 as u64 + (v1 as u64 * p0 as u64);
                        }
                    }
                    // we optimize this path in particular because it corresponds to a possibly hot
                    // loop in tfhe-rs (ntt pbs with modulus = product of two u32 primes < 2^31)
                    InvMode::Accumulate => {
                        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                        {
                            #[cfg(feature = "nightly")]
                            if let Some(simd) = pulp::x86::V4::try_new() {
                                struct Impl<'a> {
                                    simd: pulp::x86::V4,
                                    standard: &'a mut [u64],
                                    ntt0: &'a [u32],
                                    ntt1: &'a [u32],
                                    p: u64,
                                    p0: u32,
                                    p1: u32,
                                    inv: u32,
                                    inv_shoup: u32,
                                }

                                impl pulp::NullaryFnOnce for Impl<'_> {
                                    type Output = ();

                                    #[inline(always)]
                                    fn call(self) -> Self::Output {
                                        let Self {
                                            simd,
                                            standard,
                                            ntt0,
                                            ntt1,
                                            p,
                                            p0,
                                            p1,
                                            inv,
                                            inv_shoup,
                                        } = self;

                                        {
                                            let standard = pulp::as_arrays_mut::<8, _>(standard).0;
                                            let ntt0 = pulp::as_arrays::<8, _>(ntt0).0;
                                            let ntt1 = pulp::as_arrays::<8, _>(ntt1).0;

                                            let standard: &mut [pulp::u64x8] =
                                                bytemuck::cast_slice_mut(standard);
                                            let ntt0: &[pulp::u32x8] = bytemuck::cast_slice(ntt0);
                                            let ntt1: &[pulp::u32x8] = bytemuck::cast_slice(ntt1);

                                            let p1_u32 = simd.splat_u32x8(p1);
                                            let p1_u64 = simd.convert_u32x8_to_u64x8(p1_u32);
                                            let p0 =
                                                simd.convert_u32x8_to_u64x8(simd.splat_u32x8(p0));
                                            let p = simd.splat_u64x8(p);
                                            let inv =
                                                simd.convert_u32x8_to_u64x8(simd.splat_u32x8(inv));
                                            let inv_shoup = simd.convert_u32x8_to_u64x8(
                                                simd.splat_u32x8(inv_shoup),
                                            );

                                            for (standard, &ntt0, &ntt1) in
                                                izip!(standard.iter_mut(), ntt0, ntt1)
                                            {
                                                let u0 = ntt0;
                                                let u1 = ntt1;

                                                let v0 = u0;

                                                let diff = simd.wrapping_sub_u32x8(u1, v0);
                                                let diff = simd.min_u32x8(
                                                    diff,
                                                    simd.wrapping_add_u32x8(diff, p1_u32),
                                                );
                                                let diff = simd.convert_u32x8_to_u64x8(diff);

                                                let v1: pulp::u64x8 = {
                                                    // shoup mul mod
                                                    let a = diff;
                                                    let b = inv;
                                                    let b_shoup = inv_shoup;
                                                    let modulus = p1_u64;

                                                    let q =
                                                        pulp::cast(simd.avx512f._mm512_mul_epu32(
                                                            pulp::cast(a),
                                                            pulp::cast(b_shoup),
                                                        ));
                                                    let q = simd.shr_const_u64x8::<32>(q);

                                                    let ab =
                                                        pulp::cast(simd.avx512f._mm512_mul_epu32(
                                                            pulp::cast(a),
                                                            pulp::cast(b),
                                                        ));

                                                    let qmod =
                                                        pulp::cast(simd.avx512f._mm512_mul_epu32(
                                                            pulp::cast(q),
                                                            pulp::cast(modulus),
                                                        ));

                                                    let r = simd.wrapping_sub_u32x16(ab, qmod);
                                                    let r = simd.and_u32x16(
                                                        r,
                                                        pulp::u32x16(
                                                            !0, 0, !0, 0, !0, 0, !0, 0, !0, 0, !0,
                                                            0, !0, 0, !0, 0,
                                                        ),
                                                    );

                                                    let r = simd.min_u32x16(
                                                        r,
                                                        simd.wrapping_sub_u32x16(
                                                            r,
                                                            pulp::cast(modulus),
                                                        ),
                                                    );
                                                    pulp::cast(r)
                                                };

                                                let v0 = simd.convert_u32x8_to_u64x8(v0);
                                                let v = simd.wrapping_add_u64x8(
                                                    v0,
                                                    pulp::cast(simd.avx512f._mm512_mul_epu32(
                                                        pulp::cast(v1),
                                                        pulp::cast(p0),
                                                    )),
                                                );
                                                let sum = simd.wrapping_add_u64x8(*standard, v);
                                                let smaller_than_p = simd.cmp_lt_u64x8(sum, p);
                                                *standard = simd.select_u64x8(
                                                    smaller_than_p,
                                                    sum,
                                                    simd.wrapping_sub_u64x8(sum, p),
                                                );
                                            }
                                        }
                                    }
                                }

                                simd.vectorize(Impl {
                                    simd,
                                    standard,
                                    ntt0,
                                    ntt1,
                                    p,
                                    p0,
                                    p1,
                                    inv,
                                    inv_shoup,
                                });

                                return;
                            }

                            if let Some(simd) = pulp::x86::V3::try_new() {
                                struct Impl<'a> {
                                    simd: pulp::x86::V3,
                                    standard: &'a mut [u64],
                                    ntt0: &'a [u32],
                                    ntt1: &'a [u32],
                                    p: u64,
                                    p0: u32,
                                    p1: u32,
                                    inv: u32,
                                    inv_shoup: u32,
                                }

                                impl pulp::NullaryFnOnce for Impl<'_> {
                                    type Output = ();

                                    #[inline(always)]
                                    fn call(self) -> Self::Output {
                                        let Self {
                                            simd,
                                            standard,
                                            ntt0,
                                            ntt1,
                                            p,
                                            p0,
                                            p1,
                                            inv,
                                            inv_shoup,
                                        } = self;

                                        {
                                            let standard = pulp::as_arrays_mut::<4, _>(standard).0;
                                            let ntt0 = pulp::as_arrays::<4, _>(ntt0).0;
                                            let ntt1 = pulp::as_arrays::<4, _>(ntt1).0;

                                            let standard: &mut [pulp::u64x4] =
                                                bytemuck::cast_slice_mut(standard);
                                            let ntt0: &[pulp::u32x4] = bytemuck::cast_slice(ntt0);
                                            let ntt1: &[pulp::u32x4] = bytemuck::cast_slice(ntt1);

                                            let p1_u32 = simd.splat_u32x4(p1);
                                            let p1_u64 = simd.convert_u32x4_to_u64x4(p1_u32);
                                            let p0 =
                                                simd.convert_u32x4_to_u64x4(simd.splat_u32x4(p0));
                                            let p = simd.splat_u64x4(p);
                                            let inv =
                                                simd.convert_u32x4_to_u64x4(simd.splat_u32x4(inv));
                                            let inv_shoup = simd.convert_u32x4_to_u64x4(
                                                simd.splat_u32x4(inv_shoup),
                                            );

                                            for (standard, &ntt0, &ntt1) in
                                                izip!(standard.iter_mut(), ntt0, ntt1)
                                            {
                                                let u0 = ntt0;
                                                let u1 = ntt1;

                                                let v0 = u0;

                                                let diff = simd.wrapping_sub_u32x4(u1, v0);
                                                let diff = simd.min_u32x4(
                                                    diff,
                                                    simd.wrapping_add_u32x4(diff, p1_u32),
                                                );
                                                let diff = simd.convert_u32x4_to_u64x4(diff);

                                                let v1: pulp::u64x4 = {
                                                    // shoup mul mod
                                                    let a = diff;
                                                    let b = inv;
                                                    let b_shoup = inv_shoup;
                                                    let modulus = p1_u64;

                                                    let q = pulp::cast(simd.avx2._mm256_mul_epu32(
                                                        pulp::cast(a),
                                                        pulp::cast(b_shoup),
                                                    ));
                                                    let q = simd.shr_const_u64x4::<32>(q);

                                                    let ab =
                                                        pulp::cast(simd.avx2._mm256_mul_epu32(
                                                            pulp::cast(a),
                                                            pulp::cast(b),
                                                        ));

                                                    let qmod =
                                                        pulp::cast(simd.avx2._mm256_mul_epu32(
                                                            pulp::cast(q),
                                                            pulp::cast(modulus),
                                                        ));

                                                    let r = simd.wrapping_sub_u32x8(ab, qmod);
                                                    let r = simd.and_u32x8(
                                                        r,
                                                        pulp::u32x8(!0, 0, !0, 0, !0, 0, !0, 0),
                                                    );

                                                    let r = simd.min_u32x8(
                                                        r,
                                                        simd.wrapping_sub_u32x8(
                                                            r,
                                                            pulp::cast(modulus),
                                                        ),
                                                    );
                                                    pulp::cast(r)
                                                };

                                                let v0 = simd.convert_u32x4_to_u64x4(v0);
                                                let v = simd.wrapping_add_u64x4(
                                                    v0,
                                                    pulp::cast(simd.avx2._mm256_mul_epu32(
                                                        pulp::cast(v1),
                                                        pulp::cast(p0),
                                                    )),
                                                );
                                                let sum = simd.wrapping_add_u64x4(*standard, v);
                                                let smaller_than_p = simd.cmp_lt_u64x4(sum, p);
                                                *standard = simd.select_u64x4(
                                                    smaller_than_p,
                                                    sum,
                                                    simd.wrapping_sub_u64x4(sum, p),
                                                );
                                            }
                                        }
                                    }
                                }

                                simd.vectorize(Impl {
                                    simd,
                                    standard,
                                    ntt0,
                                    ntt1,
                                    p,
                                    p0,
                                    p1,
                                    inv,
                                    inv_shoup,
                                });

                                return;
                            }
                        }

                        for (standard, &ntt0, &ntt1) in izip!(standard.iter_mut(), ntt0, ntt1) {
                            let u0 = ntt0;
                            let u1 = ntt1;

                            let v0 = u0;

                            let diff = sub_mod_u32(p1, u1, v0);
                            let v1 = shoup_mul_mod_u32(p1, diff, inv, inv_shoup);

                            *standard = add_mod_u64_less_than_2_63(
                                p,
                                *standard,
                                v0 as u64 + (v1 as u64 * p0 as u64),
                            );
                        }
                    }
                }
            } else {
                match mode {
                    InvMode::Replace => {
                        for (standard, &ntt0, &ntt1) in izip!(standard.iter_mut(), ntt0, ntt1) {
                            let u0 = ntt0;
                            let u1 = ntt1;

                            let v0 = u0;

                            let diff = sub_mod_u32(p1, u1, v0);
                            let v1 = mul_mod_u32(p1_div, diff, inv);

                            *standard = v0 as u64 + (v1 as u64 * p0 as u64);
                        }
                    }
                    InvMode::Accumulate => {
                        for (standard, &ntt0, &ntt1) in izip!(standard.iter_mut(), ntt0, ntt1) {
                            let u0 = ntt0;
                            let u1 = ntt1;

                            let v0 = u0;

                            let diff = sub_mod_u32(p1, u1, v0);
                            let v1 = mul_mod_u32(p1_div, diff, inv);

                            *standard =
                                add_mod_u64(p, *standard, v0 as u64 + (v1 as u64 * p0 as u64));
                        }
                    }
                }
            }

            return;
        }

        let u_32 = &mut *alloc::vec![0u32; self.plan_32.len()];
        let v_32 = &mut *alloc::vec![0u32; self.plan_32.len()];
        let u_64 = &mut *alloc::vec![0u64; self.plan_64.len()];
        let v_64 = &mut *alloc::vec![0u64; self.plan_64.len()];

        let div_32 = &*self.div_32;
        let div_64 = &*self.div_64;

        let p = self.modulus();

        let count_32 = self.plan_32.len();

        let modular_inverses = &*self.modular_inverses;

        for (idx, standard) in standard.iter_mut().enumerate() {
            let ntt_32 = ntt_32.get(idx..).unwrap_or(&[]);
            let ntt_64 = ntt_64.get(idx..).unwrap_or(&[]);

            let ntt_32 = ntt_32.iter().step_by(self.ntt_size()).copied();
            let ntt_64 = ntt_64.iter().step_by(self.ntt_size()).copied();

            u_32.iter_mut()
                .zip(ntt_32)
                .for_each(|(dst, src)| *dst = src);
            u_64.iter_mut()
                .zip(ntt_64)
                .for_each(|(dst, src)| *dst = src);

            let u_32 = &*u_32;
            let u_64 = &*u_64;

            let mut offset = 0;

            for (j, (&uj, &div_j)) in u_32.iter().zip(div_32).enumerate() {
                let pj = div_j.divisor();
                let mut x = uj;
                {
                    let v = &v_32[..j];

                    for (&vj, &inv) in v.iter().zip(&modular_inverses[offset..][..j]) {
                        let diff = sub_mod_u32(pj, x, vj);
                        x = mul_mod_u32(div_j, diff, inv as u32);
                    }
                    offset += j;
                }
                v_32[j] = x;
            }

            for (j, (&uj, &div_j)) in u_64.iter().zip(div_64).enumerate() {
                let pj = div_j.divisor();
                let mut x = uj;
                {
                    let v = &*v_32;

                    for (&vj, &inv) in v.iter().zip(&modular_inverses[offset..][..count_32]) {
                        let diff = sub_mod_u64(pj, x, vj as u64);
                        x = mul_mod_u64(div_j, diff, inv);
                    }
                    offset += count_32;
                }
                {
                    let v = &v_64[..j];

                    for (&vj, &inv) in v.iter().zip(&modular_inverses[offset..][..j]) {
                        let diff = sub_mod_u64(pj, x, vj);
                        x = mul_mod_u64(div_j, diff, inv);
                    }
                    offset += j;
                }
                v_64[j] = x;
            }

            let mut acc = 0u64;
            for (&v, &p) in v_64.iter().zip(div_64).rev() {
                let p = p.divisor();
                acc *= p;
                acc += v;
            }
            for (&v, &p) in v_32.iter().zip(div_32).rev() {
                let p = p.divisor();
                acc *= p as u64;
                acc += v as u64;
            }

            match mode {
                InvMode::Replace => *standard = acc,
                InvMode::Accumulate => *standard = add_mod_u64(p, *standard, acc),
            }
        }
    }

    /// Computes the elementwise product of `lhs` and `rhs`, multiplied by the inverse of the
    /// polynomial modulo the NTT modulus, and stores the result in `lhs`.
    #[track_caller]
    pub fn mul_assign_normalize(&self, lhs: &mut [u64], rhs: &[u64]) {
        assert_eq!(lhs.len(), self.ntt_domain_len());
        assert_eq!(rhs.len(), self.ntt_domain_len());

        let (lhs_32, lhs_64) = lhs.split_at_mut(self.ntt_domain_len_u32());
        let (rhs_32, rhs_64) = rhs.split_at(self.ntt_domain_len_u32());

        let lhs_32: &mut [u32] = bytemuck::cast_slice_mut(lhs_32);
        let rhs_32: &[u32] = bytemuck::cast_slice(rhs_32);

        let size = self.ntt_size();

        for ((lhs, rhs), plan) in lhs_32
            .chunks_exact_mut(size)
            .zip(rhs_32.chunks_exact(size))
            .zip(&*self.plan_32)
        {
            plan.mul_assign_normalize(lhs, rhs);
        }

        for ((lhs, rhs), plan) in lhs_64
            .chunks_exact_mut(size)
            .zip(rhs_64.chunks_exact(size))
            .zip(&*self.plan_64)
        {
            plan.mul_assign_normalize(lhs, rhs);
        }
    }

    /// Multiplies the values by the inverse of the polynomial modulo the NTT modulus, and stores
    /// the result in `values`.
    #[track_caller]
    pub fn normalize(&self, values: &mut [u64]) {
        assert_eq!(values.len(), self.ntt_domain_len());

        let (values_32, values_64) = values.split_at_mut(self.ntt_domain_len_u32());
        let values_32: &mut [u32] = bytemuck::cast_slice_mut(values_32);

        let size = self.ntt_size();

        for (values, plan) in values_32.chunks_exact_mut(size).zip(&*self.plan_32) {
            plan.normalize(values);
        }
        for (values, plan) in values_64.chunks_exact_mut(size).zip(&*self.plan_64) {
            plan.normalize(values);
        }
    }

    /// Computes the elementwise product of `lhs` and `rhs` and accumulates the result to `acc`.
    #[track_caller]
    pub fn mul_accumulate(&self, acc: &mut [u64], lhs: &[u64], rhs: &[u64]) {
        assert_eq!(lhs.len(), self.ntt_domain_len());
        assert_eq!(rhs.len(), self.ntt_domain_len());

        let (acc_32, acc_64) = acc.split_at_mut(self.ntt_domain_len_u32());
        let (lhs_32, lhs_64) = lhs.split_at(self.ntt_domain_len_u32());
        let (rhs_32, rhs_64) = rhs.split_at(self.ntt_domain_len_u32());

        let acc_32: &mut [u32] = bytemuck::cast_slice_mut(acc_32);
        let lhs_32: &[u32] = bytemuck::cast_slice(lhs_32);
        let rhs_32: &[u32] = bytemuck::cast_slice(rhs_32);

        let size = self.ntt_size();

        for (((acc, lhs), rhs), plan) in acc_32
            .chunks_exact_mut(size)
            .zip(lhs_32.chunks_exact(size))
            .zip(rhs_32.chunks_exact(size))
            .zip(&*self.plan_32)
        {
            plan.mul_accumulate(acc, lhs, rhs);
        }

        for (((acc, lhs), rhs), plan) in acc_64
            .chunks_exact_mut(size)
            .zip(lhs_64.chunks_exact(size))
            .zip(rhs_64.chunks_exact(size))
            .zip(&*self.plan_64)
        {
            plan.mul_accumulate(acc, lhs, rhs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prime::largest_prime_in_arithmetic_progression64;

    extern crate alloc;

    #[test]
    fn test_product_u64x1() {
        let n = 256;

        let p = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, u64::MAX).unwrap();
        let plan = Plan::try_new(n, p, [p]).unwrap();

        let standard = &*(0..n)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Box<[_]>>();
        let ntt = &mut *alloc::vec![0u64; plan.ntt_domain_len()];
        let roundtrip = &mut *alloc::vec![0u64; n];

        let p_div = Div64::new(p);
        let mul = |a, b| mul_mod_u64(p_div, a, b);

        let n_inv_mod_p = modular_inv_u64(p_div, n as u64);
        plan.fwd(ntt, standard, FwdMode::Generic);
        plan.inv(roundtrip, ntt, InvMode::Replace);
        for x in roundtrip.iter_mut() {
            *x = mul(*x, n_inv_mod_p);
        }

        assert_eq!(roundtrip, standard);
    }

    #[test]
    fn test_product_u32x1() {
        let n = 256;

        let p =
            largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, u32::MAX as u64).unwrap();
        let plan = Plan::try_new(n, p, [p]).unwrap();

        let standard = &*(0..n)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Box<[_]>>();
        let ntt = &mut *alloc::vec![0u64; plan.ntt_domain_len()];
        let roundtrip = &mut *alloc::vec![0u64; n];

        let p_div = Div64::new(p);
        let mul = |a, b| mul_mod_u64(p_div, a, b);

        let n_inv_mod_p = modular_inv_u64(p_div, n as u64);
        plan.fwd(ntt, standard, FwdMode::Generic);
        plan.inv(roundtrip, ntt, InvMode::Replace);
        for x in roundtrip.iter_mut() {
            *x = mul(*x, n_inv_mod_p);
        }

        assert_eq!(roundtrip, standard);
    }

    #[test]
    fn test_product_u32x2() {
        let n = 256;

        let p0 =
            largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, u32::MAX as u64).unwrap();
        let p1 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, p0 - 1).unwrap();

        let p = p0 * p1;
        let plan = Plan::try_new(n, p, [p0, p1]).unwrap();

        let standard = &*(0..n)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Box<[_]>>();
        for inv_mode in [InvMode::Replace, InvMode::Accumulate] {
            let ntt = &mut *alloc::vec![0u64; plan.ntt_domain_len()];
            let roundtrip = &mut *alloc::vec![0u64; n];

            let p_div = Div64::new(p);
            let mul = |a, b| mul_mod_u64(p_div, a, b);

            let n_inv_mod_p = modular_inv_u64(p_div, n as u64);
            plan.fwd(ntt, standard, FwdMode::Generic);
            plan.inv(roundtrip, ntt, inv_mode);
            for x in roundtrip.iter_mut() {
                *x = mul(*x, n_inv_mod_p);
            }

            assert_eq!(roundtrip, standard);
        }
    }

    #[test]
    fn test_product_u30x2() {
        let n = 256;

        let p0 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, 1 << 30).unwrap();
        let p1 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, p0 - 1).unwrap();

        let p = p0 * p1;
        let plan = Plan::try_new(n, p, [p0, p1]).unwrap();

        let standard = &*(0..n)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Box<[_]>>();
        for inv_mode in [InvMode::Replace, InvMode::Accumulate] {
            let ntt = &mut *alloc::vec![0u64; plan.ntt_domain_len()];
            let roundtrip = &mut *alloc::vec![0u64; n];

            let p_div = Div64::new(p);
            let mul = |a, b| mul_mod_u64(p_div, a, b);

            let n_inv_mod_p = modular_inv_u64(p_div, n as u64);
            plan.fwd(ntt, standard, FwdMode::Generic);
            plan.inv(roundtrip, ntt, inv_mode);
            for x in roundtrip.iter_mut() {
                *x = mul(*x, n_inv_mod_p);
            }

            assert_eq!(roundtrip, standard);
        }
    }

    #[test]
    fn test_product_u32x4() {
        let n = 256;

        let p0 =
            largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, u16::MAX as u64).unwrap();
        let p1 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, p0 - 1).unwrap();
        let p2 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, p1 - 1).unwrap();
        let p3 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, p2 - 1).unwrap();

        let p = p0 * p1 * p2 * p3;
        let plan = Plan::try_new(n, p, [p0, p1, p2, p3]).unwrap();

        let standard = &*(0..n)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Box<[_]>>();
        let ntt = &mut *alloc::vec![0u64; plan.ntt_domain_len()];
        let roundtrip = &mut *alloc::vec![0u64; n];

        let p_div = Div64::new(p);
        let mul = |a, b| mul_mod_u64(p_div, a, b);

        let n_inv_mod_p = modular_inv_u64(p_div, n as u64);
        plan.fwd(ntt, standard, FwdMode::Generic);
        plan.inv(roundtrip, ntt, InvMode::Replace);
        for x in roundtrip.iter_mut() {
            *x = mul(*x, n_inv_mod_p);
        }

        assert_eq!(roundtrip, standard);
    }

    #[test]
    fn test_product_u32x2_u64x1() {
        let n = 256;

        let p0 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, 1u64 << 33).unwrap();
        let p1 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, 1u64 << 15).unwrap();
        let p2 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, p1 - 1).unwrap();

        let p = p0 * p1 * p2;
        let plan = Plan::try_new(n, p, [p0, p1, p2]).unwrap();

        let standard = &*(0..n)
            .map(|_| rand::random::<u64>() % p)
            .collect::<Box<[_]>>();
        let ntt = &mut *alloc::vec![0u64; plan.ntt_domain_len()];
        let roundtrip = &mut *alloc::vec![0u64; n];

        let p_div = Div64::new(p);
        let mul = |a, b| mul_mod_u64(p_div, a, b);

        let n_inv_mod_p = modular_inv_u64(p_div, n as u64);
        plan.fwd(ntt, standard, FwdMode::Generic);
        plan.inv(roundtrip, ntt, InvMode::Replace);
        for x in roundtrip.iter_mut() {
            *x = mul(*x, n_inv_mod_p);
        }

        assert_eq!(roundtrip, standard);
    }

    #[test]
    fn test_plan_failure_zero() {
        let n = 256;
        let p0 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, 1u64 << 33).unwrap();
        assert!(Plan::try_new(n, 0, [p0, 0]).is_none());
    }

    #[test]
    fn test_plan_failure_dup() {
        let n = 256;
        let p0 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, 1u64 << 33).unwrap();
        let p1 = largest_prime_in_arithmetic_progression64(2 * n as u64, 1, 0, 1u64 << 15).unwrap();
        assert!(Plan::try_new(n, p0 * p1 * p1, [p1, p0, p1]).is_none());
    }
}
