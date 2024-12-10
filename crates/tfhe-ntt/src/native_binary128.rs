pub(crate) use crate::native64::{mul_mod32, mul_mod64};
use aligned_vec::avec;

pub struct Plan32(
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
    crate::prime32::Plan,
);

#[inline(always)]
fn reconstruct_32bit_01234_v2(
    mod_p0: u32,
    mod_p1: u32,
    mod_p2: u32,
    mod_p3: u32,
    mod_p4: u32,
) -> u128 {
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

    const _0: u128 = P0 as u128;
    const _012: u128 = _0.wrapping_mul(P12 as u128);
    const _01234: u128 = _012.wrapping_mul(P34 as u128);

    let pos = (v0 as u128)
        .wrapping_add((v12 as u128).wrapping_mul(_0))
        .wrapping_add((v34 as u128).wrapping_mul(_012));
    let neg = pos.wrapping_sub(_01234);

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
        ))
    }

    /// Returns the polynomial size of the negacyclic NTT plan.
    #[inline]
    pub fn ntt_size(&self) -> usize {
        self.0.ntt_size()
    }

    pub fn fwd(
        &self,
        value: &[u128],
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
            &mut *mod_p4,
        ) {
            *mod_p0 = (value % crate::primes32::P0 as u128) as u32;
            *mod_p1 = (value % crate::primes32::P1 as u128) as u32;
            *mod_p2 = (value % crate::primes32::P2 as u128) as u32;
            *mod_p3 = (value % crate::primes32::P3 as u128) as u32;
            *mod_p4 = (value % crate::primes32::P4 as u128) as u32;
        }
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
        self.2.fwd(mod_p2);
        self.3.fwd(mod_p3);
        self.4.fwd(mod_p4);
    }

    pub fn fwd_binary(
        &self,
        value: &[u128],
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
            &mut *mod_p4,
        ) {
            *mod_p0 = *value as u32;
            *mod_p1 = *value as u32;
            *mod_p2 = *value as u32;
            *mod_p3 = *value as u32;
            *mod_p4 = *value as u32;
        }
        self.0.fwd(mod_p0);
        self.1.fwd(mod_p1);
        self.2.fwd(mod_p2);
        self.3.fwd(mod_p3);
        self.4.fwd(mod_p4);
    }

    pub fn inv(
        &self,
        value: &mut [u128],
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

        for (value, &mod_p0, &mod_p1, &mod_p2, &mod_p3, &mod_p4) in
            crate::izip!(value, &*mod_p0, &*mod_p1, &*mod_p2, &*mod_p3, &*mod_p4)
        {
            *value = reconstruct_32bit_01234_v2(mod_p0, mod_p1, mod_p2, mod_p3, mod_p4);
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

        let mut rhs0 = avec![0; n];
        let mut rhs1 = avec![0; n];
        let mut rhs2 = avec![0; n];
        let mut rhs3 = avec![0; n];
        let mut rhs4 = avec![0; n];

        self.fwd(lhs, &mut lhs0, &mut lhs1, &mut lhs2, &mut lhs3, &mut lhs4);
        self.fwd_binary(rhs, &mut rhs0, &mut rhs1, &mut rhs2, &mut rhs3, &mut rhs4);

        self.0.mul_assign_normalize(&mut lhs0, &rhs0);
        self.1.mul_assign_normalize(&mut lhs1, &rhs1);
        self.2.mul_assign_normalize(&mut lhs2, &rhs2);
        self.3.mul_assign_normalize(&mut lhs3, &rhs3);
        self.4.mul_assign_normalize(&mut lhs4, &rhs4);

        self.inv(prod, &mut lhs0, &mut lhs1, &mut lhs2, &mut lhs3, &mut lhs4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native128::tests::negacyclic_convolution;
    use alloc::{vec, vec::Vec};
    use rand::random;

    extern crate alloc;

    #[test]
    fn reconstruct_32bit() {
        for n in [32, 64, 256, 1024, 2048] {
            let plan = Plan32::try_new(n).unwrap();

            let lhs = (0..n).map(|_| random::<u128>()).collect::<Vec<_>>();
            let rhs = (0..n).map(|_| random::<u128>() % 2).collect::<Vec<_>>();
            let negacyclic_convolution = negacyclic_convolution(n, &lhs, &rhs);

            let mut prod = vec![0; n];
            plan.negacyclic_polymul(&mut prod, &lhs, &rhs);
            assert_eq!(prod, negacyclic_convolution);
        }
    }
}
