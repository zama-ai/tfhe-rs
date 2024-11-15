use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use tfhe_ntt::prime64::Plan;

#[derive(Clone, Debug)]
pub struct Ntt64 {
    plan: Arc<Plan>,
}

#[derive(Clone, Copy, Debug)]
pub struct Ntt64View<'a> {
    pub(crate) plan: &'a Plan,
}

impl Ntt64 {
    #[inline]
    pub fn as_view(&self) -> Ntt64View<'_> {
        Ntt64View { plan: &self.plan }
    }
}

type PlanMap = RwLock<HashMap<usize, Arc<OnceLock<Arc<Plan>>>>>;
pub(crate) static PLANS: OnceLock<PlanMap> = OnceLock::new();
fn plans() -> &'static PlanMap {
    PLANS.get_or_init(|| RwLock::new(HashMap::new()))
}

impl Ntt64 {
    /// Real polynomial of size `size`.
    pub fn new(modulus: CiphertextModulus<u64>, size: PolynomialSize) -> Self {
        let global_plans = plans();

        assert_eq!(modulus.kind(), CiphertextModulusKind::Other);

        let n = size.0;
        let modulus = modulus.get_custom_modulus() as u64;
        let get_plan = || {
            let plans = global_plans.read().unwrap();
            let plan = plans.get(&n).cloned();
            drop(plans);

            plan.map(|p| {
                p.get_or_init(|| {
                    Arc::new(Plan::try_new(n, modulus).unwrap_or_else(|| {
                        panic!("could not generate an NTT plan for the given modulus ({modulus})")
                    }))
                })
                .clone()
            })
        };

        // could not find a plan of the given size, we lock the map again and try to insert it
        let mut plans = global_plans.write().unwrap();
        if let Entry::Vacant(v) = plans.entry(n) {
            v.insert(Arc::new(OnceLock::new()));
        }

        drop(plans);

        Self {
            plan: get_plan().unwrap(),
        }
    }
}

impl Ntt64View<'_> {
    pub fn polynomial_size(self) -> PolynomialSize {
        PolynomialSize(self.plan.ntt_size())
    }

    pub fn custom_modulus(self) -> u64 {
        self.plan.modulus()
    }

    pub fn forward(self, ntt: PolynomialMutView<'_, u64>, standard: PolynomialView<'_, u64>) {
        let mut ntt = ntt;
        let ntt = ntt.as_mut();
        let standard = standard.as_ref();
        ntt.copy_from_slice(standard);
        self.plan.fwd(ntt);
    }

    pub fn forward_normalized(
        self,
        ntt: PolynomialMutView<'_, u64>,
        standard: PolynomialView<'_, u64>,
    ) {
        let mut ntt = ntt;
        let ntt = ntt.as_mut();
        let standard = standard.as_ref();
        ntt.copy_from_slice(standard);
        self.plan.fwd(ntt);
        self.plan.normalize(ntt);
    }

    pub fn add_backward(
        self,
        standard: PolynomialMutView<'_, u64>,
        ntt: PolynomialMutView<'_, u64>,
    ) {
        let mut ntt = ntt;
        let mut standard = standard;
        let ntt = ntt.as_mut();
        let standard = standard.as_mut();
        self.plan.inv(ntt);

        // autovectorize
        pulp::Arch::new().dispatch(
            #[inline(always)]
            || {
                for (out, inp) in izip!(standard, &*ntt) {
                    *out = u64::wrapping_add_custom_mod(*out, *inp, self.custom_modulus());
                }
            },
        )
    }
}
