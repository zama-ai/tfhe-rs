pub(crate) use crate::native64::{mul_mod32, mul_mod64};
use aligned_vec::avec;

/// Negacyclic NTT plan for multiplying two 128bit polynomials.
#[derive(Clone, Debug)]
pub struct Plan32(
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
);

#[inline(always)]
fn reconstruct_32bit_0123456789_v2(
    mod_p0: u32,
    mod_p1: u32,
    mod_p2: u32,
    mod_p3: u32,
    mod_p4: u32,
    mod_p5: u32,
    mod_p6: u32,
    mod_p7: u32,
    mod_p8: u32,
    mod_p9: u32,
) -> u128 {
    use crate::primes32::*;

    let mod_p01 = {
        let v0 = mod_p0;
        let v1 = mul_mod32(P1, P0_INV_MOD_P1, 2 * P1 + mod_p1 - v0);
        v0 as u64 + (v1 as u64 * P0 as u64)
    };
    let mod_p23 = {
        let v2 = mod_p2;
        let v3 = mul_mod32(P3, P2_INV_MOD_P3, 2 * P3 + mod_p3 - v2);
        v2 as u64 + (v3 as u64 * P2 as u64)
    };
    let mod_p45 = {
        let v4 = mod_p4;
        let v5 = mul_mod32(P5, P4_INV_MOD_P5, 2 * P5 + mod_p5 - v4);
        v4 as u64 + (v5 as u64 * P4 as u64)
    };
    let mod_p67 = {
        let v6 = mod_p6;
        let v7 = mul_mod32(P7, P6_INV_MOD_P7, 2 * P7 + mod_p7 - v6);
        v6 as u64 + (v7 as u64 * P6 as u64)
    };
    let mod_p89 = {
        let v8 = mod_p8;
        let v9 = mul_mod32(P9, P8_INV_MOD_P9, 2 * P9 + mod_p9 - v8);
        v8 as u64 + (v9 as u64 * P8 as u64)
    };

    let v01 = mod_p01;
    let v23 = mul_mod64(
        P23.wrapping_neg(),
        2 * P23 + mod_p23 - v01,
        P01_INV_MOD_P23,
        P01_INV_MOD_P23_SHOUP,
    );
    let v45 = mul_mod64(
        P45.wrapping_neg(),
        2 * P45 + mod_p45 - (v01 + mul_mod64(P45.wrapping_neg(), v23, P01, P01_MOD_P45_SHOUP)),
        P0123_INV_MOD_P45,
        P0123_INV_MOD_P45_SHOUP,
    );
    let v67 = mul_mod64(
        P67.wrapping_neg(),
        2 * P67 + mod_p67
            - (v01
                + mul_mod64(
                    P67.wrapping_neg(),
                    v23 + mul_mod64(P67.wrapping_neg(), v45, P23, P23_MOD_P67_SHOUP),
                    P01,
                    P01_MOD_P67_SHOUP,
                )),
        P012345_INV_MOD_P67,
        P012345_INV_MOD_P67_SHOUP,
    );
    let v89 = mul_mod64(
        P89.wrapping_neg(),
        2 * P89 + mod_p89
            - (v01
                + mul_mod64(
                    P89.wrapping_neg(),
                    v23 + mul_mod64(
                        P89.wrapping_neg(),
                        v45 + mul_mod64(P89.wrapping_neg(), v67, P45, P45_MOD_P89_SHOUP),
                        P23,
                        P23_MOD_P89_SHOUP,
                    ),
                    P01,
                    P01_MOD_P89_SHOUP,
                )),
        P01234567_INV_MOD_P89,
        P01234567_INV_MOD_P89_SHOUP,
    );

    let sign = v89 > (P89 / 2);
    let pos = (v01 as u128)
        .wrapping_add(u128::wrapping_mul(v23 as u128, P01 as u128))
        .wrapping_add(u128::wrapping_mul(v45 as u128, P0123))
        .wrapping_add(u128::wrapping_mul(v67 as u128, P012345))
        .wrapping_add(u128::wrapping_mul(v89 as u128, P01234567));
    let neg = pos.wrapping_sub(P0123456789);

    if sign {
        neg
    } else {
        pos
    }
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
            Plan::try_new(n, P5)?,
            Plan::try_new(n, P6)?,
            Plan::try_new(n, P7)?,
            Plan::try_new(n, P8)?,
            Plan::try_new(n, P9)?,
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
    #[inline]
    pub fn ntt_5(&self) -> &crate::prime32::Plan {
        &self.5
    }
    #[inline]
    pub fn ntt_6(&self) -> &crate::prime32::Plan {
        &self.6
    }
    #[inline]
    pub fn ntt_7(&self) -> &crate::prime32::Plan {
        &self.7
    }
    #[inline]
    pub fn ntt_8(&self) -> &crate::prime32::Plan {
        &self.8
    }
    #[inline]
    pub fn ntt_9(&self) -> &crate::prime32::Plan {
        &self.9
    }

    pub fn fwd(
        &self,
        value: &[u128],
        mod_p0: &mut [u32],
        mod_p1: &mut [u32],
        mod_p2: &mut [u32],
        mod_p3: &mut [u32],
        mod_p4: &mut [u32],
        mod_p5: &mut [u32],
        mod_p6: &mut [u32],
        mod_p7: &mut [u32],
        mod_p8: &mut [u32],
        mod_p9: &mut [u32],
    ) {
        for (
            value,
            mod_p0,
            mod_p1,
            mod_p2,
            mod_p3,
            mod_p4,
            mod_p5,
            mod_p6,
            mod_p7,
            mod_p8,
            mod_p9,
        ) in crate::izip!(
            value,
            &mut *mod_p0,
            &mut *mod_p1,
            &mut *mod_p2,
            &mut *mod_p3,
            &mut *mod_p4,
            &mut *mod_p5,
            &mut *mod_p6,
            &mut *mod_p7,
            &mut *mod_p8,
            &mut *mod_p9,
        ) {
            *mod_p0 = (value % crate::primes32::P0 as u128) as u32;
            *mod_p1 = (value % crate::primes32::P1 as u128) as u32;
            *mod_p2 = (value % crate::primes32::P2 as u128) as u32;
            *mod_p3 = (value % crate::primes32::P3 as u128) as u32;
            *mod_p4 = (value % crate::primes32::P4 as u128) as u32;
            *mod_p5 = (value % crate::primes32::P5 as u128) as u32;
            *mod_p6 = (value % crate::primes32::P6 as u128) as u32;
            *mod_p7 = (value % crate::primes32::P7 as u128) as u32;
            *mod_p8 = (value % crate::primes32::P8 as u128) as u32;
            *mod_p9 = (value % crate::primes32::P9 as u128) as u32;
        }
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
        self.2.fwd(mod_p2);
        self.3.fwd(mod_p3);
        self.4.fwd(mod_p4);
        self.5.fwd(mod_p5);
        self.6.fwd(mod_p6);
        self.7.fwd(mod_p7);
        self.8.fwd(mod_p8);
        self.9.fwd(mod_p9);
    }

    pub fn inv(
        &self,
        value: &mut [u128],
        mod_p0: &mut [u32],
        mod_p1: &mut [u32],
        mod_p2: &mut [u32],
        mod_p3: &mut [u32],
        mod_p4: &mut [u32],
        mod_p5: &mut [u32],
        mod_p6: &mut [u32],
        mod_p7: &mut [u32],
        mod_p8: &mut [u32],
        mod_p9: &mut [u32],
    ) {
        self.0.inv(mod_p0);
        self.1.inv(mod_p1);
        self.2.inv(mod_p2);
        self.3.inv(mod_p3);
        self.4.inv(mod_p4);
        self.5.inv(mod_p5);
        self.6.inv(mod_p6);
        self.7.inv(mod_p7);
        self.8.inv(mod_p8);
        self.9.inv(mod_p9);

        for (
            value,
            &mod_p0,
            &mod_p1,
            &mod_p2,
            &mod_p3,
            &mod_p4,
            &mod_p5,
            &mod_p6,
            &mod_p7,
            &mod_p8,
            &mod_p9,
        ) in crate::izip!(
            value, &*mod_p0, &*mod_p1, &*mod_p2, &*mod_p3, &*mod_p4, &*mod_p5, &*mod_p6, &*mod_p7,
            &*mod_p8, &*mod_p9,
        ) {
            *value = reconstruct_32bit_0123456789_v2(
                mod_p0, mod_p1, mod_p2, mod_p3, mod_p4, mod_p5, mod_p6, mod_p7, mod_p8, mod_p9,
            );
        }
    }

    /// Computes the negacyclic polynomial product of `lhs` and `rhs`, and stores the result in
    /// `prod`.
    pub fn negacyclic_polymul(&self, prod: &mut [u128], lhs: &[u128], rhs: &[u128]) {
        let n = prod.len();
        assert_eq!(n, lhs.len());
        assert_eq!(n, rhs.len());

        let mut lhs0 = avec![0; n];
        let mut lhs1 = avec![0; n];
        let mut lhs2 = avec![0; n];
        let mut lhs3 = avec![0; n];
        let mut lhs4 = avec![0; n];
        let mut lhs5 = avec![0; n];
        let mut lhs6 = avec![0; n];
        let mut lhs7 = avec![0; n];
        let mut lhs8 = avec![0; n];
        let mut lhs9 = avec![0; n];

        let mut rhs0 = avec![0; n];
        let mut rhs1 = avec![0; n];
        let mut rhs2 = avec![0; n];
        let mut rhs3 = avec![0; n];
        let mut rhs4 = avec![0; n];
        let mut rhs5 = avec![0; n];
        let mut rhs6 = avec![0; n];
        let mut rhs7 = avec![0; n];
        let mut rhs8 = avec![0; n];
        let mut rhs9 = avec![0; n];

        self.fwd(
            lhs, &mut lhs0, &mut lhs1, &mut lhs2, &mut lhs3, &mut lhs4, &mut lhs5, &mut lhs6,
            &mut lhs7, &mut lhs8, &mut lhs9,
        );
        self.fwd(
            rhs, &mut rhs0, &mut rhs1, &mut rhs2, &mut rhs3, &mut rhs4, &mut rhs5, &mut rhs6,
            &mut rhs7, &mut rhs8, &mut rhs9,
        );

        self.0.mul_assign_normalize(&mut lhs0, &rhs0);
        self.1.mul_assign_normalize(&mut lhs1, &rhs1);
        self.2.mul_assign_normalize(&mut lhs2, &rhs2);
        self.3.mul_assign_normalize(&mut lhs3, &rhs3);
        self.4.mul_assign_normalize(&mut lhs4, &rhs4);
        self.5.mul_assign_normalize(&mut lhs5, &rhs5);
        self.6.mul_assign_normalize(&mut lhs6, &rhs6);
        self.7.mul_assign_normalize(&mut lhs7, &rhs7);
        self.8.mul_assign_normalize(&mut lhs8, &rhs8);
        self.9.mul_assign_normalize(&mut lhs9, &rhs9);

        self.inv(
            prod, &mut lhs0, &mut lhs1, &mut lhs2, &mut lhs3, &mut lhs4, &mut lhs5, &mut lhs6,
            &mut lhs7, &mut lhs8, &mut lhs9,
        );
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use rand::random;

    extern crate alloc;

    pub fn negacyclic_convolution(n: usize, lhs: &[u128], rhs: &[u128]) -> Vec<u128> {
        let mut full_convolution = vec![0u128; 2 * n];
        let mut negacyclic_convolution = vec![0u128; n];
        for i in 0..n {
            for j in 0..n {
                full_convolution[i + j] =
                    full_convolution[i + j].wrapping_add(lhs[i].wrapping_mul(rhs[j]));
            }
        }
        for i in 0..n {
            negacyclic_convolution[i] = full_convolution[i].wrapping_sub(full_convolution[i + n]);
        }
        negacyclic_convolution
    }

    pub fn random_lhs_rhs_with_negacyclic_convolution(
        n: usize,
    ) -> (Vec<u128>, Vec<u128>, Vec<u128>) {
        let mut lhs = vec![0u128; n];
        let mut rhs = vec![0u128; n];

        for x in &mut lhs {
            *x = random();
        }
        for x in &mut rhs {
            *x = random();
        }

        let lhs = lhs;
        let rhs = rhs;

        let negacyclic_convolution = negacyclic_convolution(n, &lhs, &rhs);
        (lhs, rhs, negacyclic_convolution)
    }

    #[test]
    fn reconstruct_32bit() {
        for n in [32, 64, 256, 1024, 2048] {
            let value = (0..n).map(|_| random::<u128>()).collect::<Vec<_>>();
            let mut value_roundtrip = vec![0; n];
            let mut mod_p0 = vec![0; n];
            let mut mod_p1 = vec![0; n];
            let mut mod_p2 = vec![0; n];
            let mut mod_p3 = vec![0; n];
            let mut mod_p4 = vec![0; n];
            let mut mod_p5 = vec![0; n];
            let mut mod_p6 = vec![0; n];
            let mut mod_p7 = vec![0; n];
            let mut mod_p8 = vec![0; n];
            let mut mod_p9 = vec![0; n];

            let plan = Plan32::try_new(n).unwrap();
            plan.fwd(
                &value,
                &mut mod_p0,
                &mut mod_p1,
                &mut mod_p2,
                &mut mod_p3,
                &mut mod_p4,
                &mut mod_p5,
                &mut mod_p6,
                &mut mod_p7,
                &mut mod_p8,
                &mut mod_p9,
            );
            plan.inv(
                &mut value_roundtrip,
                &mut mod_p0,
                &mut mod_p1,
                &mut mod_p2,
                &mut mod_p3,
                &mut mod_p4,
                &mut mod_p5,
                &mut mod_p6,
                &mut mod_p7,
                &mut mod_p8,
                &mut mod_p9,
            );
            for (&value, &value_roundtrip) in crate::izip!(&value, &value_roundtrip) {
                assert_eq!(value_roundtrip, value.wrapping_mul(n as u128));
            }

            let (lhs, rhs, negacyclic_convolution) = random_lhs_rhs_with_negacyclic_convolution(n);

            let mut prod = vec![0; n];
            plan.negacyclic_polymul(&mut prod, &lhs, &rhs);
            assert_eq!(prod, negacyclic_convolution);
        }
    }
}
