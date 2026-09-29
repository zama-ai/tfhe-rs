//! Module containing primitives pertaining to the generation of
//! [`half-product LWE bootstrap keys`](`LweHalfProductBootstrapKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Fill a [`half-product LWE bootstrap key`](`LweHalfProductBootstrapKey`) with an actual
/// bootstrapping key constructed from an input [`LWE secret key`](`LweSecretKey`) and an output
/// [`GLWE secret key`](`GlweSecretKey`).
pub fn par_generate_new_half_product_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweHalfProductBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    OutputCont: ContainerMut<Element = OutputScalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref().par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_constant_half_product_ggsw_ciphertext(
                output_glwe_secret_key,
                &mut ggsw,
                Cleartext(input_key_element.cast_into()),
                noise_distribution,
                &mut generator,
            );
        });
}

/// Allocate and generate a new [`half-product LWE bootstrap key`](`LweHalfProductBootstrapKey`).
///
/// The `k` mask GLev ciphertexts of every GGSW use `(decomp_base_log_mask,
/// decomp_level_count_mask)` while the body GLev uses `(decomp_base_log_body,
/// decomp_level_count_body)`. Convert the result to the Fourier domain with
/// [`par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128`](super::par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128).
#[allow(clippy::too_many_arguments)]
pub fn par_allocate_and_generate_new_half_product_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log_mask: DecompositionBaseLog,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_base_log_body: DecompositionBaseLog,
    decomp_level_count_body: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweHalfProductBootstrapKeyOwned<OutputScalar>
where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut bsk = LweHalfProductBootstrapKeyOwned::new(
        OutputScalar::ZERO,
        input_lwe_secret_key.lwe_dimension(),
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log_mask,
        decomp_level_count_mask,
        decomp_base_log_body,
        decomp_level_count_body,
        ciphertext_modulus,
    );

    par_generate_new_half_product_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
        generator,
    );

    bsk
}
