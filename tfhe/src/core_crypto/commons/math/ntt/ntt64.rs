use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::utils::izip_eq;
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

// Key is (polynomial size, modulus).
type PlanMap = RwLock<HashMap<(usize, u64), Arc<OnceLock<Arc<Plan>>>>>;
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
            let plan = plans.get(&(n, modulus)).cloned();
            drop(plans);

            plan.map(|p| {
                p.get_or_init(|| {
                    Arc::new(Plan::try_new(n, modulus).unwrap_or_else(|| {
                        panic!("could not generate an NTT plan for the given (size, modulus) ({n}, {modulus})")
                    }))
                })
                .clone()
            })
        };

        get_plan().map_or_else(
            || {
                // If we don't find a plan for the given polynomial size and modulus, we insert a
                // new OnceLock, drop the write lock on the map and then let
                // get_plan() initialize the OnceLock (without holding the write
                // lock on the map).
                let mut plans = global_plans.write().unwrap();
                if let Entry::Vacant(v) = plans.entry((n, modulus)) {
                    v.insert(Arc::new(OnceLock::new()));
                }
                drop(plans);

                Self {
                    plan: get_plan().unwrap(),
                }
            },
            |plan| Self { plan },
        )
    }
}

/// Below implementation block define common functions used while working on value already
/// on ntt prime modulus
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
                for (out, inp) in izip_eq!(standard, &*ntt) {
                    *out = u64::wrapping_add_custom_mod(*out, *inp, self.custom_modulus());
                }
            },
        )
    }
}

/// Below implementation block define functions used while working with power-of-two modulus values
impl Ntt64View<'_> {
    /// Check modswitch requirement
    ///
    /// Return power of two modulus width if modswitch is required
    /// #Notes
    /// Only modswitch from a power of two modulus is supported
    /// Power-of-two modulus value are always MSB aligned
    pub(crate) fn modswitch_requirement(self, from: CiphertextModulus<u64>) -> Option<u32> {
        let ntt_modulus = CiphertextModulus::new(self.plan.modulus() as u128);
        if from == ntt_modulus {
            None
        } else {
            assert!(
                from.is_compatible_with_native_modulus(),
                "Only support implicit modswitch from pow-of-two modulus to ntt_modulus"
            );
            if from.is_native_modulus() {
                Some(u64::BITS)
            } else {
                let pow2_modulus = from.get_custom_modulus();
                let pow2_width = pow2_modulus.ilog2();
                Some(pow2_width)
            }
        }
    }

    /// Handle modswitch between power-of-two modulus and Ntt prime modulus
    /// This function switches modulus for a slice of coefficients
    /// From: power_of_two domain (NB: value are aligned on MSB)
    /// To:   ntt domain  (i.e. prime modulus)
    /// Switching are done inplace
    pub(crate) fn modswitch_from_power_of_two_to_ntt_prime(
        self,
        input_modulus_width: u32,
        data: &mut [u64],
    ) {
        let mod_p_u128 = self.plan.modulus() as u128;
        for val in data.iter_mut() {
            let val_u128: u128 = (*val as u128) >> (u64::BITS - input_modulus_width);
            *val = (((val_u128 * mod_p_u128) + (1 << (input_modulus_width - 1)))
                >> input_modulus_width) as u64;
        }
    }

    /// Handle modswitch between Ntt prime modulus and power-of-two modulus
    /// This function switches modulus for a slice of coefficients
    /// From: ntt domain  (i.e. prime modulus)
    /// To:   power_of_two domain (NB: value are aligned on MSB)
    /// Switching are done inplace
    pub(crate) fn modswitch_from_ntt_prime_to_power_of_two(
        self,
        output_modulus_width: u32,
        data: &mut [u64],
    ) {
        let mod_p_u128 = self.plan.modulus() as u128;
        for val in data.iter_mut() {
            let val_u128: u128 = (*val).cast_into();
            *val = (((((val_u128) << output_modulus_width) | ((mod_p_u128) >> 1)) / mod_p_u128)
                as u64)
                << (u64::BITS - output_modulus_width);
        }
    }

    /// Applies a forward negacyclic NTT
    ///
    /// Entries coefficients are on power_of_two modulus
    pub fn forward_from_power_of_two_modulus(
        &self,
        input_modulus_width: u32,
        ntt: PolynomialMutView<'_, u64>,
        standard: PolynomialView<'_, u64>,
    ) {
        let mut ntt = ntt;
        let ntt = ntt.as_mut();
        let standard = standard.as_ref();
        ntt.copy_from_slice(standard);

        self.modswitch_from_power_of_two_to_ntt_prime(input_modulus_width, ntt);
        self.plan.fwd(ntt);
    }

    /// Applies a forward negacyclic NTT transform in place to the given buffer.
    ///
    /// Entries come from decomposer and thus are small signed extended value around 0.
    /// There are considered as on power_of_two modulus, however a full modswitch isn't needed.
    /// It's simply needed to correctly encoded the negative value regarding the ntt prime value
    pub fn forward_from_decomp(
        &self,
        ntt: PolynomialMutView<'_, u64>,
        decomp: PolynomialView<'_, u64>,
    ) {
        let mut ntt = ntt;
        let ntt = ntt.as_mut();
        let decomp = decomp.as_ref();
        ntt.copy_from_slice(decomp);

        for x in ntt.iter_mut() {
            *x = if (*x as i64) < 0 {
                // Correctly encode negative value in regard of the prime modulus
                x.wrapping_add(self.custom_modulus())
            } else {
                *x
            };
        }
        self.plan.fwd(ntt);
    }

    /// Applies a backward negacyclic NTT transform on ntt, moved obtained value on power-of-two
    /// modulus And sum them with standard polynomial
    pub fn add_backward_on_power_of_two_modulus(
        self,
        output_modulus_width: u32,
        standard: PolynomialMutView<'_, u64>,
        ntt: PolynomialMutView<'_, u64>,
    ) {
        let mut ntt = ntt;
        let mut standard = standard;
        let ntt = ntt.as_mut();
        let standard = standard.as_mut();
        self.plan.inv(ntt);
        self.modswitch_from_ntt_prime_to_power_of_two(output_modulus_width, ntt);

        // autovectorize
        pulp::Arch::new().dispatch(
            #[inline(always)]
            || {
                for (out, inp) in izip_eq!(standard, &*ntt) {
                    *out = u64::wrapping_add(*out, *inp);
                }
            },
        )
    }
}
