use crate::core_crypto::commons::parameters::PolynomialSize;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::UnsignedInteger;
use aligned_vec::CACHELINE_ALIGN;
use concrete_ntt::native64::Plan32;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

#[derive(Clone)]
pub(crate) struct PlanWrapper(Plan32);
impl core::ops::Deref for PlanWrapper {
    type Target = Plan32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::fmt::Debug for PlanWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        "[?]".fmt(f)
    }
}

#[derive(Clone, Debug)]
pub struct CrtNtt64 {
    inner: Arc<PlanWrapper>,
}

/// View type for [`CrtNtt64`].
#[derive(Clone, Copy, Debug)]
pub struct CrtNtt64View<'a> {
    pub(crate) inner: &'a PlanWrapper,
}

type PlanMap = RwLock<HashMap<usize, Arc<OnceLock<Arc<PlanWrapper>>>>>;
pub(crate) static PLANS: OnceLock<PlanMap> = OnceLock::new();
fn plans() -> &'static PlanMap {
    PLANS.get_or_init(|| RwLock::new(HashMap::new()))
}

impl CrtNtt64 {
    /// Polynomial of size `size`.
    pub fn new(size: PolynomialSize) -> Self {
        let global_plans = plans();

        let n = size.0;
        let get_plan = || {
            let plans = global_plans.read().unwrap();
            let plan = plans.get(&n).cloned();
            drop(plans);

            plan.map(|p| {
                p.get_or_init(|| Arc::new(PlanWrapper(Plan32::try_new(n).unwrap())))
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
            inner: get_plan().unwrap(),
        }
    }

    pub fn as_view(&self) -> CrtNtt64View<'_> {
        CrtNtt64View { inner: &self.inner }
    }
}

pub trait CrtNtt<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize>: UnsignedInteger {
    type Plan;
    type PlanView<'a>: Copy;

    fn new_plan(size: PolynomialSize) -> Self::Plan;
    fn plan_as_view(plan: &Self::Plan) -> Self::PlanView<'_>;

    fn forward(plan: Self::PlanView<'_>, ntt: [&mut [CrtScalar]; N_COMPONENTS], standard: &[Self]);
    fn forward_normalized(
        plan: Self::PlanView<'_>,
        ntt: [&mut [CrtScalar]; N_COMPONENTS],
        standard: &[Self],
    );

    fn add_backward(
        plan: Self::PlanView<'_>,
        standard: &mut [Self],
        ntt: [&mut [CrtScalar]; N_COMPONENTS],
        stack: PodStack<'_>,
    );

    fn add_backward_scratch(polynomial_size: PolynomialSize) -> Result<StackReq, SizeOverflow>;

    fn mul_accumulate(
        plan: Self::PlanView<'_>,
        acc: [&mut [CrtScalar]; N_COMPONENTS],
        lhs: [&[CrtScalar]; N_COMPONENTS],
        rhs: [&[CrtScalar]; N_COMPONENTS],
    );
}

impl CrtNtt<u32, 5> for u64 {
    type Plan = CrtNtt64;
    type PlanView<'a> = CrtNtt64View<'a>;

    fn new_plan(size: PolynomialSize) -> Self::Plan {
        Self::Plan::new(size)
    }
    fn plan_as_view(plan: &Self::Plan) -> Self::PlanView<'_> {
        plan.as_view()
    }

    fn forward(
        plan: Self::PlanView<'_>,
        [ntt0, ntt1, ntt2, ntt3, ntt4]: [&mut [u32]; 5],
        standard: &[Self],
    ) {
        plan.inner.0.fwd(standard, ntt0, ntt1, ntt2, ntt3, ntt4);
    }

    fn forward_normalized(
        plan: Self::PlanView<'_>,
        [ntt0, ntt1, ntt2, ntt3, ntt4]: [&mut [u32]; 5],
        standard: &[Self],
    ) {
        plan.inner.0.fwd(standard, ntt0, ntt1, ntt2, ntt3, ntt4);
        plan.inner.0.ntt_0().normalize(ntt0);
        plan.inner.0.ntt_1().normalize(ntt1);
        plan.inner.0.ntt_2().normalize(ntt2);
        plan.inner.0.ntt_3().normalize(ntt3);
        plan.inner.0.ntt_4().normalize(ntt4);
    }

    fn add_backward(
        plan: Self::PlanView<'_>,
        standard: &mut [Self],
        [ntt0, ntt1, ntt2, ntt3, ntt4]: [&mut [u32]; 5],
        stack: PodStack<'_>,
    ) {
        let n = standard.len();
        let (mut tmp, _) = stack.make_aligned_raw::<u64>(n, CACHELINE_ALIGN);
        plan.inner.0.inv(&mut tmp, ntt0, ntt1, ntt2, ntt3, ntt4);

        // autovectorize
        pulp::Arch::new().dispatch(
            #[inline(always)]
            || {
                for (out, inp) in izip!(standard, &*tmp) {
                    *out = u64::wrapping_add(*out, *inp);
                }
            },
        )
    }

    fn add_backward_scratch(polynomial_size: PolynomialSize) -> Result<StackReq, SizeOverflow> {
        StackReq::try_new_aligned::<u64>(polynomial_size.0, CACHELINE_ALIGN)
    }

    fn mul_accumulate(
        plan: Self::PlanView<'_>,
        [acc0, acc1, acc2, acc3, acc4]: [&mut [u32]; 5],
        [lhs0, lhs1, lhs2, lhs3, lhs4]: [&[u32]; 5],
        [rhs0, rhs1, rhs2, rhs3, rhs4]: [&[u32]; 5],
    ) {
        plan.inner.ntt_0().mul_accumulate(acc0, lhs0, rhs0);
        plan.inner.ntt_1().mul_accumulate(acc1, lhs1, rhs1);
        plan.inner.ntt_2().mul_accumulate(acc2, lhs2, rhs2);
        plan.inner.ntt_3().mul_accumulate(acc3, lhs3, rhs3);
        plan.inner.ntt_4().mul_accumulate(acc4, lhs4, rhs4);
    }
}
