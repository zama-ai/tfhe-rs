//! This module contains convenience primitive to perform polynomial multiplications of inputs in
//! the usual $$Z/qZ\[X\] / X^N + 1$$ polynomial ring used in TFHE-rs, where q = 2^64 specifically,
//! in addition the right hand side polynomial **needs** to have binary coefficients.

use crate::core_crypto::commons::parameters::PolynomialSize;
use crate::core_crypto::commons::plan::GenericPlanMap;
use std::sync::{Arc, OnceLock};
use tfhe_ntt::native_binary64::Plan32;

#[derive(Clone, Debug)]
pub struct NttNativeBinary64 {
    plan: Arc<Plan32>,
}

impl NttNativeBinary64 {
    #[inline]
    pub fn as_view(&self) -> NttNativeBinary64View<'_> {
        NttNativeBinary64View { plan: &self.plan }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NttNativeBinary64View<'a> {
    plan: &'a Plan32,
}

impl NttNativeBinary64View<'_> {
    pub fn negacyclic_polymul(&self, prod: &mut [u64], lhs: &[u64], rhs: &[u64]) {
        self.plan.negacyclic_polymul(prod, lhs, rhs);
    }
}

type PlanMap = GenericPlanMap<PolynomialSize, Plan32>;

pub(crate) static PLANS: OnceLock<PlanMap> = OnceLock::new();

fn plans() -> &'static PlanMap {
    PLANS.get_or_init(GenericPlanMap::new)
}

impl NttNativeBinary64 {
    /// Real polynomial of size `size`.
    pub fn new(size: PolynomialSize) -> Self {
        let global_plans = plans();

        let plan = global_plans.get_or_init(size, |size| {
            Plan32::try_new(size.0).unwrap_or_else(|| {
                panic!(
                    "could not generate an NTT plan for the given size: {}",
                    size.0
                )
            })
        });

        Self { plan }
    }
}

#[cfg(all(feature = "avx512", any(target_arch = "x86", target_arch = "x86_64")))]
mod avx512 {
    use super::*;
    use tfhe_ntt::native_binary64::Plan52;

    #[derive(Clone, Debug)]
    pub struct NttNativeBinary64Avx512 {
        plan: Arc<Plan52>,
    }

    impl NttNativeBinary64Avx512 {
        #[inline]
        pub fn as_view(&self) -> NttNativeBinary64Avx512View<'_> {
            NttNativeBinary64Avx512View { plan: &self.plan }
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct NttNativeBinary64Avx512View<'a> {
        plan: &'a Plan52,
    }

    impl NttNativeBinary64Avx512View<'_> {
        pub fn negacyclic_polymul(&self, prod: &mut [u64], lhs: &[u64], rhs: &[u64]) {
            self.plan.negacyclic_polymul(prod, lhs, rhs);
        }
    }

    type Avx512PlanMap = GenericPlanMap<PolynomialSize, Plan52>;

    pub(crate) static AVX512_PLANS: OnceLock<Avx512PlanMap> = OnceLock::new();

    fn avx512_plans() -> &'static Avx512PlanMap {
        AVX512_PLANS.get_or_init(GenericPlanMap::new)
    }

    impl NttNativeBinary64Avx512 {
        /// Real polynomial of size `size`.
        pub fn try_new(size: PolynomialSize) -> Option<Self> {
            if !Plan52::is_available() {
                return None;
            }

            let global_plans = avx512_plans();

            let plan = global_plans.get_or_init(size, |size| {
                Plan52::try_new(size.0).unwrap_or_else(|| {
                    panic!(
                        "could not generate an NTT plan for the given size: {}",
                        size.0
                    )
                })
            });

            Some(Self { plan })
        }
    }
}

#[cfg(all(feature = "avx512", any(target_arch = "x86", target_arch = "x86_64")))]
pub use avx512::*;
