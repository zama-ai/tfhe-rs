//! Module containing primitives pertaining to [`half-product GGSW
//! ciphertext`](`HalfProductGgswCiphertext`) encryption.

use rayon::prelude::*;

use crate::core_crypto::algorithms::ggsw_encryption::{
    encrypt_constant_ggsw_level_matrix_row, ggsw_encryption_multiplicative_factor,
};
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Encrypt a plaintext in a [`half-product GGSW ciphertext`](`HalfProductGgswCiphertext`) in the
/// constant coefficient.
///
/// This is the half-product analog of
/// [`encrypt_constant_ggsw_ciphertext`](`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`):
/// the mask rows are encrypted with the mask decomposition parameters and the body rows with the
/// body ones.
pub fn encrypt_constant_half_product_ggsw_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut HalfProductGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    check_half_product_ggsw_encryption_shapes(glwe_secret_key, output);

    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into half-product GGSW rows");

    let glwe_size = output.glwe_size();
    let decomp_base_log_mask = output.decomposition_base_log_mask();
    let decomp_level_count_mask = output.decomposition_level_count_mask();
    let decomp_base_log_body = output.decomposition_base_log_body();
    let decomp_level_count_body = output.decomposition_level_count_body();
    let ciphertext_modulus = output.ciphertext_modulus();
    let last_row_index = glwe_size.to_glwe_dimension().0;

    for ((row_index, mut row_as_glwe), mut generator) in output
        .as_mut_glwe_list()
        .iter_mut()
        .enumerate()
        .zip(gen_iter)
    {
        let (decomp_level, decomp_base_log, level_matrix_row_index) = half_product_row_metadata(
            glwe_size,
            decomp_base_log_mask,
            decomp_level_count_mask,
            decomp_base_log_body,
            decomp_level_count_body,
            row_index,
        );
        let factor = ggsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            decomp_level,
            decomp_base_log,
            cleartext,
        );
        encrypt_constant_ggsw_level_matrix_row(
            glwe_secret_key,
            (level_matrix_row_index, last_row_index),
            factor,
            &mut row_as_glwe,
            noise_distribution,
            &mut generator,
        );
    }
}

/// Parallel variant of [`encrypt_constant_half_product_ggsw_ciphertext`].
pub fn par_encrypt_constant_half_product_ggsw_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut HalfProductGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    check_half_product_ggsw_encryption_shapes(glwe_secret_key, output);

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into half-product GGSW rows");

    let glwe_size = output.glwe_size();
    let decomp_base_log_mask = output.decomposition_base_log_mask();
    let decomp_level_count_mask = output.decomposition_level_count_mask();
    let decomp_base_log_body = output.decomposition_base_log_body();
    let decomp_level_count_body = output.decomposition_level_count_body();
    let ciphertext_modulus = output.ciphertext_modulus();
    let last_row_index = glwe_size.to_glwe_dimension().0;

    output
        .as_mut_glwe_list()
        .par_iter_mut()
        .enumerate()
        .zip(gen_iter)
        .for_each(|((row_index, mut row_as_glwe), mut generator)| {
            let (decomp_level, decomp_base_log, level_matrix_row_index) = half_product_row_metadata(
                glwe_size,
                decomp_base_log_mask,
                decomp_level_count_mask,
                decomp_base_log_body,
                decomp_level_count_body,
                row_index,
            );
            let factor = ggsw_encryption_multiplicative_factor(
                ciphertext_modulus,
                decomp_level,
                decomp_base_log,
                cleartext,
            );
            encrypt_constant_ggsw_level_matrix_row(
                glwe_secret_key,
                (level_matrix_row_index, last_row_index),
                factor,
                &mut row_as_glwe,
                noise_distribution,
                &mut generator,
            );
        });
}

/// Return the decomposition level and base log the `row_index`-th row of a
/// [`HalfProductGgswCiphertext`] is encrypted with, together with its index within the level matrix
/// it belongs to.
fn half_product_row_metadata(
    glwe_size: GlweSize,
    decomp_base_log_mask: DecompositionBaseLog,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_base_log_body: DecompositionBaseLog,
    decomp_level_count_body: DecompositionLevelCount,
    row_index: usize,
) -> (DecompositionLevel, DecompositionBaseLog, usize) {
    let mask_row_count =
        half_product_ggsw_ciphertext_mask_row_count(glwe_size, decomp_level_count_mask);
    let glwe_dimension = glwe_size.to_glwe_dimension().0;

    if row_index < mask_row_count {
        (
            DecompositionLevel(decomp_level_count_mask.0 - row_index / glwe_dimension),
            decomp_base_log_mask,
            row_index % glwe_dimension,
        )
    } else {
        let body_index = row_index - mask_row_count;
        (
            DecompositionLevel(decomp_level_count_body.0 - body_index),
            decomp_base_log_body,
            glwe_dimension,
        )
    }
}

fn check_half_product_ggsw_encryption_shapes<Scalar, KeyCont, OutputCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &HalfProductGgswCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    OutputCont: Container<Element = Scalar>,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
}
