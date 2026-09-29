//! Module containing primitives pertaining to the generation of combined
//! [`half-product + half-rotate LWE bootstrap keys`](`LweHalfProductHalfRotateBootstrapKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Generate the two standard-domain sections of a combined "half-product + half-rotate" bootstrap
/// key (see [`Fourier128HalfProductHalfRotateLweBootstrapKey`]).
///
/// The input LWE secret key is split at `input_lwe_dimension_start` as in
/// [`par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key`], and each section is a
/// half-product key with its own mask and body decomposition parameters.
///
/// # Panics
///
/// Panics if `input_lwe_dimension_start` is larger than the input LWE dimension.
#[allow(clippy::too_many_arguments)]
pub fn par_allocate_and_generate_new_half_product_half_rotate_lwe_bootstrap_key<
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
    decomp_base_log_mask_start: DecompositionBaseLog,
    decomp_level_count_mask_start: DecompositionLevelCount,
    decomp_base_log_body_start: DecompositionBaseLog,
    decomp_level_count_body_start: DecompositionLevelCount,
    decomp_base_log_mask_end: DecompositionBaseLog,
    decomp_level_count_mask_end: DecompositionLevelCount,
    decomp_base_log_body_end: DecompositionBaseLog,
    decomp_level_count_body_end: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweHalfProductHalfRotateBootstrapKeyOwned<OutputScalar>
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

    let bsk_start = par_allocate_and_generate_new_half_product_lwe_bootstrap_key(
        &sk_start,
        output_glwe_secret_key,
        decomp_base_log_mask_start,
        decomp_level_count_mask_start,
        decomp_base_log_body_start,
        decomp_level_count_body_start,
        noise_distribution,
        ciphertext_modulus,
        generator,
    );
    let bsk_end = par_allocate_and_generate_new_half_product_lwe_bootstrap_key(
        &sk_end,
        output_glwe_secret_key,
        decomp_base_log_mask_end,
        decomp_level_count_mask_end,
        decomp_base_log_body_end,
        decomp_level_count_body_end,
        noise_distribution,
        ciphertext_modulus,
        generator,
    );

    LweHalfProductHalfRotateBootstrapKey::from_keys(bsk_start, bsk_end)
}
