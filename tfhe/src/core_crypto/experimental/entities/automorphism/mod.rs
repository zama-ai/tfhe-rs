//! Galois automorphisms for the negacyclic polynomial ring `Z[X]/(X^N+1)`.
//!
//! The Galois group of `Z[X]/(X^N+1)` (where `N` is a power of 2) consists of the maps
//! `σ_a : X ↦ X^a` for each odd integer `a` coprime to `2N`. These automorphisms permute the
//! `N` coefficients of any polynomial, potentially negating some of them, because reducing
//! `X^(kN+n)` modulo `X^N+1` gives `(-1)^k · X^n`.
//!
//! This module provides:
//! - [`Automorphism`] — the pre-computed permutation and sign-change tables for a single σ_a.
//! - [`MonomialReducer`] — fast bit-mask reduction of `X^p` modulo `X^N+1`.
//! - [`Diff`] — a relative step between two automorphisms in a base-power decomposition, used
//!   during blind rotation to track how much still needs to be applied.
//! - [`AutomKey`] — an encryption of the automorphism as a GLWE key-switch key (see
//!   [`hom_aut_key`]).
//! - [`Travs`] — a sliding window of [`AutomKey`] (GLWE key-switch keys) covering automorphism
//!   powers `-base^0, base^1, -base^1, base^2, -base^2, …` (see [`travs`]).
//! - [`TravBsk`] — GGSWs for blind rotate which include a key switch. HomAut (Autom + GLWE KS) come
//!   before each external product. We pay the cost of a GLWE KS and an External product. These keys
//!   are single GGSWs which when used to do the External product also do the GLWE KS.

use crate::core_crypto::entities::{GlweCiphertext, GlweSecretKey, Polynomial};
use crate::core_crypto::experimental::algorithms::automorphism_based_decomposition::compute_power;
use crate::core_crypto::prelude::{
    CastFrom, Container, ContainerMut, ContiguousEntityContainer, ContiguousEntityContainerMut,
    PolynomialSize, UnsignedInteger,
};
use itertools::izip;
use serde::{Deserialize, Serialize};

pub use hom_aut_key::*;
pub use msed_for_automorphism::*;
pub use trav_bsk::*;
pub use travs::*;

pub mod hom_aut_key;
pub mod msed_for_automorphism;
pub mod trav_bsk;
pub mod travs;

/// A relative step between two automorphisms expressed in the base-power decomposition.
///
/// During blind rotation the accumulator must be moved from its current automorphism to a target
/// one. `Diff` tracks how much is left to apply: `power_diff` steps in the exponent ladder and
/// an optional sign flip. The actual automorphism exponent corresponding to a `Diff` is
/// `±base^power_diff mod 2N` (see [`Diff::power`]).
#[derive(Clone, Copy, Debug)]
pub struct Diff {
    pub power_diff: usize,
    pub sign_change: bool,
}

/// Returns the multiplicative inverse of `power` in `Z*_{2·polynomial_size}`.
///
/// `power` must be odd. The inverse `a⁻¹` satisfies `power · a⁻¹ ≡ 1 (mod 2N)`, where
/// `N = polynomial_size`. It is used to construct the inverse automorphism σ_{a⁻¹} = σ_a⁻¹.
pub fn invert_autom(power: usize, polynomial_size: usize) -> usize {
    assert!(power % 2 == 1);

    let mut result = 1;

    for _ in 0..polynomial_size {
        if (power * result) % (2 * polynomial_size) == 1 {
            return result;
        }
        result += 2;
    }

    panic!(
        "{power} has no multiplicative inverse mod {}: it must be odd and coprime to {}",
        2 * polynomial_size,
        2 * polynomial_size
    )
}

impl Diff {
    /// Subtracts `other_diff` from `self`, consuming its contribution.
    ///
    /// Used when one automorphism step has been applied: the remaining diff is reduced by that
    /// step. Panics if `other_diff` is larger than `self` or has a sign change that `self` does
    /// not.
    pub fn reduce_diff_by(&mut self, other_diff: Self) {
        assert!(self.power_diff >= other_diff.power_diff);

        assert!(!other_diff.sign_change || self.sign_change);

        self.power_diff -= other_diff.power_diff;
        self.sign_change ^= other_diff.sign_change;
    }

    /// Returns `true` when the diff is the identity (no exponent step, no sign change).
    pub fn is_identity(&self) -> bool {
        self.power_diff == 0 && !self.sign_change
    }

    /// Converts the diff into the concrete automorphism exponent `±base^power_diff mod m`.
    ///
    /// A sign change is encoded as negation modulo `m`: the returned value is `m - base^power_diff`
    /// when `sign_change` is `true`, and `base^power_diff` otherwise.
    pub fn power(&self, base: u64, m: usize) -> usize {
        let power = compute_power(base, self.power_diff as u64, m as u64) as usize;

        if self.sign_change {
            m - power
        } else {
            power
        }
    }
}

/// Reduces a monomial `X^p` modulo `X^N+1` using fast bitmask operations.
///
/// Because `X^N ≡ -1`, we have `X^(kN+n) = (-1)^k · X^n`. Given an arbitrary non-negative
/// exponent `p`, [`MonomialReducer::reduce_monomial`] extracts the reduced exponent `n = p mod N`
/// and whether a sign flip is required (when `floor(p/N)` is odd).
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct MonomialReducer {
    modular_mask: u64,
    log_poly_size_minus_1: u64,
    modular_sign_change_mask: u64,
}

impl MonomialReducer {
    /// Creates a reducer for the ring `Z[X]/(X^N+1)` with `N = polynomial_size`.
    pub fn new(polynomial_size: PolynomialSize) -> Self {
        let modular_mask = (polynomial_size.0 - 1) as u64;

        let log_poly_size_minus_1 = (polynomial_size.log2().0 - 1) as u64;

        let modular_sign_change_mask = polynomial_size.0 as u64;

        Self {
            modular_mask,
            log_poly_size_minus_1,
            modular_sign_change_mask,
        }
    }

    /// Reduces `X^power` modulo `X^N + 1` and returns the sign and reduced exponent.
    //
    // X^(kN+n) = (-1)^k * X^n modulo X^N+1
    pub fn reduce_monomial(&self, power: u64) -> ReducedMonomial {
        // = 0 if power does not change sign
        // = 2 if power does change sign
        let should_be_negated =
            (power & self.modular_sign_change_mask) >> self.log_poly_size_minus_1;

        // = 1 if power does not change sign
        // = -1 if power does change sign
        let sign = 1.wrapping_sub(should_be_negated) as i8;

        let reduced_power = power & self.modular_mask;

        ReducedMonomial {
            sign,
            reduced_power,
        }
    }
}

/// Output of [`MonomialReducer::reduce_monomial`]: the sign (`1` or `-1`) and the reduced
/// exponent in `[0, N)` after applying `X^N ≡ -1`.
pub struct ReducedMonomial {
    pub sign: i8,
    pub reduced_power: u64,
}

/// The Galois automorphism `σ_a : X ↦ X^a` on `Z[X]/(X^N+1)`, pre-computed as a coefficient
/// permutation together with a sign-change mask.
///
/// Applying σ_a to a polynomial `p(X)` yields `p(X^a)`. After reducing modulo `X^N+1` each
/// output coefficient is either `±p[j]` for some `j`.
/// We only use odd a to have invertible automorphisms.
///
/// [`Automorphism`] stores these mappings in two parallel arrays so that
/// [`apply_to_polynomial`](Automorphism::apply_to_polynomial) can be implemented with a single
/// scatter pass followed by a conditional negation pass.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Automorphism {
    Identity {
        polynomial_size: PolynomialSize,
    },
    Nontrivial {
        permutation: Vec<u16>,
        sign_change: Vec<bool>,
        polynomial_size: PolynomialSize,
    },
}

impl Automorphism {
    /// Builds the automorphism `σ_{base\_power}` for a ring of degree `polynomial_size`.
    ///
    /// `base_power` must be odd (all automorphisms of `Z[X]/(X^N+1)` have odd exponents).
    pub fn new(base_power: usize, polynomial_size: PolynomialSize) -> Self {
        if base_power == 1 {
            Self::Identity { polynomial_size }
        } else {
            let monomial_reducer = MonomialReducer::new(polynomial_size);

            let mut permutation = vec![0; polynomial_size.0];

            let mut sign_change = vec![false; polynomial_size.0];

            let mut power = 0;

            for source_index in 0..polynomial_size.0 {
                let ReducedMonomial {
                    sign,
                    reduced_power,
                } = monomial_reducer.reduce_monomial(power);

                permutation[reduced_power as usize] = source_index as u16;
                sign_change[reduced_power as usize] = sign == -1;

                power += base_power as u64;
            }

            Self::Nontrivial {
                permutation,
                sign_change,
                polynomial_size,
            }
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Identity { polynomial_size } => *polynomial_size,
            Self::Nontrivial {
                polynomial_size, ..
            } => *polynomial_size,
        }
    }

    /// Applies the automorphism to the input polynomial and store the result to the output
    ///
    /// ```rust
    /// use tfhe::core_crypto::experimental::entities::automorphism::Automorphism;
    /// use tfhe::core_crypto::prelude::{Polynomial, PolynomialSize, UnsignedInteger};
    ///
    /// let polynomial_size = PolynomialSize(8);
    ///
    /// let in_polynomial = Polynomial::from_container(vec![0_u64, 1, 2, 3, 4, 5, 6, 7]);
    /// let mut out_polynomial = Polynomial::from_container(vec![0_u64; 8]);
    ///
    /// let automorphism = Automorphism::new(3, polynomial_size);
    ///
    /// automorphism.apply_to_polynomial(&in_polynomial, &mut out_polynomial);
    ///
    /// let expected_result = [
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    /// ];
    /// assert_eq!(out_polynomial.as_ref(), expected_result.as_slice());
    /// ```
    pub fn apply_to_polynomial<Scalar, InCont, OutCont>(
        &self,
        input: &Polynomial<InCont>,
        output: &mut Polynomial<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        assert_eq!(input.polynomial_size(), self.polynomial_size());
        assert_eq!(output.polynomial_size(), self.polynomial_size());

        match self {
            Self::Identity { .. } => {
                output
                    .as_mut_view()
                    .into_container()
                    .copy_from_slice(input.as_view().into_container());
            }
            Self::Nontrivial {
                permutation,
                sign_change,
                ..
            } => {
                let input = input.as_ref();
                let output = output.as_mut();

                for (destination_index, source_index) in permutation.iter().enumerate() {
                    let value = unsafe { *input.get_unchecked(*source_index as usize) };

                    let ref_mut = unsafe { output.get_unchecked_mut(destination_index) };

                    *ref_mut = value;
                }

                for (destination_index, sign_change) in sign_change.iter().enumerate() {
                    let ref_mut = unsafe { output.get_unchecked_mut(destination_index) };

                    if *sign_change {
                        *ref_mut = ref_mut.wrapping_neg();
                    }
                }
            }
        }
    }

    /// Applies the automorphism to the input polynomial and store the result to the output
    ///
    /// ```rust
    /// use tfhe::core_crypto::experimental::entities::automorphism::Automorphism;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextModulus, GlweCiphertext, GlweSize, PolynomialSize, UnsignedInteger,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(8);
    /// let glwe_size = GlweSize(2);
    /// let ciphertetx_modulus = CiphertextModulus::new_native();
    ///
    /// let in_glwe = GlweCiphertext::from_container(
    ///     vec![0_u64, 1, 2, 3, 4, 5, 6, 7, 0_u64, 1, 2, 3, 4, 5, 6, 7],
    ///     polynomial_size,
    ///     ciphertetx_modulus,
    /// );
    /// let mut out_glwe =
    ///     GlweCiphertext::from_container(vec![0_u64; 16], polynomial_size, ciphertetx_modulus);
    ///
    /// let automorphism = Automorphism::new(3, polynomial_size);
    ///
    /// automorphism.apply_to_glwe_ciphertext(&in_glwe, &mut out_glwe);
    ///
    /// let expected_result = [
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    /// ];
    /// assert_eq!(out_glwe.as_ref(), expected_result.as_slice());
    /// ```
    pub fn apply_to_glwe_ciphertext<Scalar, InCont, OutCont>(
        &self,
        input: &GlweCiphertext<InCont>,
        output: &mut GlweCiphertext<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        for (i, mut j) in izip!(input.iter(), output.iter_mut()) {
            self.apply_to_polynomial(&i, &mut j);
        }
    }

    /// Applies the automorphism to a GLWE secret key.
    ///
    /// Each polynomial in the key is permuted independently, producing the key `σ_a(sk)`. This
    /// is used when building [`AutomKey`]: an [`AutomKey`] for `σ_a` is a key-switch from
    /// `σ_a(sk)` back to `sk`, so that after applying the automorphism to a ciphertext one can
    /// recover a ciphertext under the original key.
    pub fn apply_to_glwe_secret_key<Scalar, InCont, OutCont>(
        &self,
        input: &GlweSecretKey<InCont>,
        output: &mut GlweSecretKey<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        for (i, mut j) in izip!(
            input.as_polynomial_list().iter(),
            output.as_polynomial_list_mut().iter_mut()
        ) {
            self.apply_to_polynomial(&i, &mut j);
        }
    }
}

#[cfg(test)]
mod tests {
    use itertools::izip;

    use crate::core_crypto::experimental::entities::automorphism::{invert_autom, Automorphism};
    use crate::core_crypto::prelude::*;

    #[test]
    fn test_invert_autom() {
        // For several polynomial sizes and a range of odd exponents, verify that
        // power * invert_autom(power) ≡ 1 (mod 2N).
        for log_n in 2..=12_usize {
            let n = 1 << log_n;
            let m = 2 * n;
            for power in (1..m).step_by(2) {
                let inv = invert_autom(power, n);
                assert_eq!(
                    (power * inv) % m,
                    1,
                    "invert_autom({power}, {n}) = {inv} is not a multiplicative inverse mod {m}"
                );
            }
        }
    }

    #[test]
    fn glwe_automorphism_then_ks_to_initial_key() {
        let log_polynomial_size = 3;

        let polynomial_size = PolynomialSize(1 << log_polynomial_size);
        let glwe_size = GlweSize(2);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let decomp_base_log = DecompositionBaseLog(8);
        let decomp_level_count = DecompositionLevelCount(3);
        let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
            StandardDev(0.00000000000000029403601535432533),
            0.0,
        );

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        // Create the GlweSecretKey
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
            &mut secret_generator,
        );

        let plaintext_input = (0..polynomial_size.0 as u64)
            .map(|a| a << (64 - log_polynomial_size))
            .collect::<Vec<u64>>();

        let plaintext_list = PlaintextList::from_container(plaintext_input.clone());

        let mut in_glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut in_glwe,
            &plaintext_list,
            glwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut after_autom_glwe =
            GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

        for base_power in (1..polynomial_size.0).step_by(2) {
            let automorphism = Automorphism::new(base_power, polynomial_size);

            let mut autom_glwe_secret_key =
                GlweSecretKey::new_empty_key(0, glwe_size.to_glwe_dimension(), polynomial_size);

            automorphism.apply_to_glwe_secret_key(&glwe_secret_key, &mut autom_glwe_secret_key);

            automorphism.apply_to_glwe_ciphertext(&in_glwe, &mut after_autom_glwe);

            // Check autom(enc(sk, p)) = enc(autom(sk), autom(p))
            {
                let in_polynomial = Polynomial::from_container(plaintext_input.as_slice());

                let mut automorphism_on_input =
                    Polynomial::from_container(vec![0; polynomial_size.0]);

                automorphism.apply_to_polynomial(&in_polynomial, &mut automorphism_on_input);

                decrypt_compare_glwe(
                    log_polynomial_size,
                    &autom_glwe_secret_key,
                    &after_autom_glwe,
                    &automorphism_on_input,
                );
            }

            // Check ks(autom(sk)-> sk, autom(enc(sk, p)))
            //     = ks(autom(sk)-> sk, enc(autom(sk), autom(p))
            //     = enc(sk, autom(p))
            {
                let ksk = allocate_and_generate_new_glwe_keyswitch_key(
                    &autom_glwe_secret_key,
                    &glwe_secret_key,
                    decomp_base_log,
                    decomp_level_count,
                    glwe_noise_distribution,
                    ciphertext_modulus,
                    &mut encryption_generator,
                );

                let mut output_glwe =
                    GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

                keyswitch_glwe_ciphertext(&ksk, &after_autom_glwe, &mut output_glwe);

                let in_polynomial = Polynomial::from_container(plaintext_input.as_slice());

                let mut automorphism_on_input =
                    Polynomial::from_container(vec![0; polynomial_size.0]);

                automorphism.apply_to_polynomial(&in_polynomial, &mut automorphism_on_input);

                decrypt_compare_glwe(
                    log_polynomial_size,
                    &glwe_secret_key,
                    &output_glwe,
                    &automorphism_on_input,
                );
            }
        }
    }

    fn decrypt_compare_glwe(
        log_polynomial_size: usize,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        encrypted_glwe: &GlweCiphertext<Vec<u64>>,
        expected_polynomial: &Polynomial<Vec<u64>>,
    ) {
        let polynomial_size = PolynomialSize(1 << log_polynomial_size);

        let mut out_plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(glwe_secret_key, encrypted_glwe, &mut out_plaintext_list);
        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(log_polynomial_size),
            DecompositionLevelCount(1),
        );
        for (out_encoded, modified_input_encoded) in izip!(
            out_plaintext_list.as_ref().iter(),
            expected_polynomial.as_ref()
        ) {
            let out_encoded = decomposer.decode_plaintext(Plaintext(*out_encoded));

            let modified_input_decoded =
                decomposer.decode_plaintext(Plaintext(*modified_input_encoded));

            assert_eq!(out_encoded, modified_input_decoded);
        }
    }
}
