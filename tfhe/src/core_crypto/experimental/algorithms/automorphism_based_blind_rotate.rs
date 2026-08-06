use crate::core_crypto::experimental::algorithms::automorphism_based_decomposition::Decomposition;
use crate::core_crypto::experimental::entities::automorphism::*;
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_div;
use crate::core_crypto::prelude::*;

#[cfg(feature = "shortint")]
use crate::shortint::{CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus};

#[cfg(feature = "shortint")]
pub const AUTOM_PARAMS_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(918),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(45)),
    glwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(3)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(1),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: crate::shortint::prelude::ModulusSwitchType::Standard,
};

/// ```text
/// Performs automorphism-based blind rotation.
///
/// Let's define the homomorphic automorphism
/// HomAut_u(Enc_sk(input))
/// = GLWE_KS(Aut_u(sk) -> sk, Aut_u(Enc_sk(input)))
/// = GLWE_KS(Aut_u(sk) -> sk, Enc_{Aut_u(sk)}(Aut_u(input)))
/// = Enc_sk(Aut_u(input))
///
/// Based on https://eprint.iacr.org/2025/163
///
/// This is an alternative to the standard TFHE blind rotation.
/// Instead of computing one CMUX per LWE mask coefficient
/// `GGSW(si)⋅(X^ai ACC - ACC) + ACC = X^ai⋅si ACC`
/// The idea is to use algorithm uses external product
/// `HomAut_ai(HomAut_{1/ai}(ACC)⋅GGSW(X^si))) = X^ai⋅si ACC`
/// ai needs to be odd to be invertible.
///
/// This allows secret key elements to be integers instead of just 0 or 1.
/// But choosing bigger integers increases modulus switch noise.
///
/// This is described in Fig. 2.1 as (a) Basic method.
///
/// Some optimizations:
///
/// 1. We merge HomAut_{1/a{i+1}}∘HomAut_ai from separate steps into HomAut_{ai/a{i+1}}
///    Fig. 2.1 as (b) Telescoping method.
///
/// 2. We decompose each masks in a base ±base^n and sort them in decreasing exponent n.
/// 2.1. We can then remove HomAut_{ai/a{i+1}} when ai = a{i+1}
/// 2.2. In most cases, ai/a{i+1} = ±base^n with n small.
///      Most of the time, we only need small GLWE_KS(Aut_{±base^n}(sk) -> sk, _) keys,
///      n < window_size.
///      When there is a bigger jump, we can use multiple small keys jump.
///      This limits public key material.
///      Algorithm 3.1 (-base^n and +base^n mask treated separately) and
///      Algorithm 3.2 (-base^n and +base^n mask treated together)
///
/// 3. We merge KS and external products by making a key switching GGSW: GGSW(Aut_u(sk) -> sk, X^si)
///    This increase material size a lot to save the cost of some GLWE KS.
///    Algorithm 4.1
///
/// The algorithm 4.1 is implemented
/// If we chose bsk_window_size=1 to build `bsks`, it corresponds to algorithm 3.2
/// ```
#[allow(clippy::too_many_arguments)]
pub fn blind_rotate(
    msed: &MsedLweFromAutomorphism,
    bsks: &TravBsk,
    trav: &Travs,
    lut: GlweCiphertextMutView<'_, u64>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    automorphisms: &[Automorphism],
) {
    let mut accumulator = lut;

    assert_eq!(msed.masks.len(), bsks.len());

    let ciphertext_modulus = CiphertextModulus::new_native();

    let mut tmp_poly = Polynomial::from_container(vec![0; polynomial_size.0]);

    let monomial_degree = MonomialDegree(msed.body as usize);

    accumulator
        .as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
        });

    let mut temp_accumulator =
        GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

    let mut previous_base_exponent = 0;
    let mut previous_negative = false;

    // mu = N/2 = half the Galois group order; base exponents live in [0, mu)
    let mu = polynomial_size.0 / 2;

    for MaskElement {
        decomposition: Decomposition {
            base_exponent,
            negative,
        },
        sk_index,
        combine_with_next,
    } in msed.masks.iter().rev()
    {
        // Compute the diff from the previous base exponent to the current one.
        let mut diff = Diff {
            power_diff: (mu + previous_base_exponent as usize - *base_exponent as usize) % mu,
            sign_change: *negative != previous_negative,
        };

        loop {
            if let Some(ggsw) = bsks.get(*sk_index, diff, *combine_with_next) {
                // diff is within the TravBsk window: apply the target automorphism to the
                // accumulator, then multiply by the GGSW to fold in this secret key integer.
                let diff_index = 2 * diff.power_diff + if diff.sign_change { 1 } else { 0 };

                let automorphism = &automorphisms[diff_index];

                automorphism.apply_to_glwe_ciphertext(&accumulator, &mut temp_accumulator);

                accumulator.as_mut().fill(0);

                add_external_product_assign(&mut accumulator, ggsw, &temp_accumulator);

                break;
            }

            // diff exceeds the window: greedily apply the largest available Travs key to
            // bring the accumulator closer to the target automorphism.
            let (best_diff, autom) = trav.best_diff_reduction(&diff);

            diff.reduce_diff_by(best_diff);

            autom.apply(&mut accumulator, &mut temp_accumulator);
        }

        previous_negative = *negative;
        previous_base_exponent = *base_exponent;
    }

    // Return the accumulator to the identity automorphism after the last coefficient.
    let mut diff_with_identity = Diff {
        power_diff: previous_base_exponent as usize,
        sign_change: previous_negative,
    };

    while !diff_with_identity.is_identity() {
        let (best_diff, autom) = trav.best_diff_reduction(&diff_with_identity);
        diff_with_identity.reduce_diff_by(best_diff);

        autom.apply(&mut accumulator, &mut temp_accumulator);
    }
}
