//! Module containing primitives pertaining to the generation of
//! [`half-rotate LWE bootstrap keys`](`LweHalfRotateBootstrapKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Generate the two standard-domain sections of a "half-rotate" bootstrap key (see
/// [`Fourier128HalfRotateLweBootstrapKey`]).
///
/// The input LWE secret key is split at `input_lwe_dimension_start`: the first section encrypts
/// bits `0..input_lwe_dimension_start` with `(decomp_base_log_start, decomp_level_count_start)` and
/// the second section encrypts bits `input_lwe_dimension_start..` with
/// `(decomp_base_log_end, decomp_level_count_end)`. Both sections are encrypted under the same
/// output GLWE key, so concatenating them realises a full bootstrap key for `input_lwe_secret_key`.
///
/// The returned [`LweHalfRotateBootstrapKey`] is meant to be converted to the Fourier domain with
/// [`par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128`](super::par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128).
///
/// # Panics
///
/// Panics if `input_lwe_dimension_start` is larger than the input LWE dimension.
#[allow(clippy::too_many_arguments)]
pub fn par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    input_lwe_dimension_start: LweDimension,
    decomp_base_log_start: DecompositionBaseLog,
    decomp_level_count_start: DecompositionLevelCount,
    decomp_base_log_end: DecompositionBaseLog,
    decomp_level_count_end: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweHalfRotateBootstrapKeyOwned<OutputScalar>
where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let input_lwe_dimension = input_lwe_secret_key.lwe_dimension();
    assert!(
        input_lwe_dimension_start.0 <= input_lwe_dimension.0,
        "input_lwe_dimension_start ({}) must not exceed the input LWE dimension ({})",
        input_lwe_dimension_start.0,
        input_lwe_dimension.0
    );

    let sk = input_lwe_secret_key.as_ref();
    let sk_start = LweSecretKey::from_container(&sk[..input_lwe_dimension_start.0]);
    let sk_end = LweSecretKey::from_container(&sk[input_lwe_dimension_start.0..]);

    let bsk_start = par_allocate_and_generate_new_lwe_bootstrap_key(
        &sk_start,
        output_glwe_secret_key,
        decomp_base_log_start,
        decomp_level_count_start,
        noise_distribution,
        ciphertext_modulus,
        generator,
    );
    let bsk_end = par_allocate_and_generate_new_lwe_bootstrap_key(
        &sk_end,
        output_glwe_secret_key,
        decomp_base_log_end,
        decomp_level_count_end,
        noise_distribution,
        ciphertext_modulus,
        generator,
    );

    LweHalfRotateBootstrapKey::from_keys(bsk_start, bsk_end)
}
