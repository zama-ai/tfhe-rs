use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::entities::*;

/// Encrypt an input [`GLWE secret key`](`GlweSecretKey`) under an output [`GLWE secret
/// key`](`GlweSecretKey`) in a [`pseudo GGSW ciphertext`](`PseudoGgswCiphertext`).
///
/// # Example
///
/// See [`crate::core_crypto::experimental::algorithms::glwe_fast_keyswitch::glwe_fast_keyswitch`]
/// for usage.
pub fn encrypt_pseudo_ggsw_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_key_out: &GlweSecretKey<KeyCont>,
    glwe_secret_key_in: &GlweSecretKey<KeyCont>,
    output: &mut PseudoGgswCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == glwe_secret_key_out.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key_out.polynomial_size()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into pseudo ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    for (output_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
        // We scale the factor down from the native torus to whatever our torus is, the
        // encryption process will scale it back up
        let encoded = Scalar::ONE;
        let factor = encoded
            .wrapping_neg()
            .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)))
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = generator
            .try_fork_from_config(level_matrix.encryption_fork_config(Uniform, noise_distribution))
            .expect("Failed to split generator into glwe");

        for ((row_index, mut row_as_glwe), mut generator) in level_matrix
            .as_mut_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            encrypt_pseudo_ggsw_level_matrix_row(
                glwe_secret_key_out,
                glwe_secret_key_in,
                row_index,
                factor,
                &mut row_as_glwe,
                noise_distribution,
                &mut generator,
            );
        }
    }
}

fn encrypt_pseudo_ggsw_level_matrix_row<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    glwe_secret_key_to_encrypt: &GlweSecretKey<KeyCont>,
    row_index: usize,
    factor: Scalar,
    row_as_glwe: &mut GlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let sk_poly_list = glwe_secret_key_to_encrypt.as_polynomial_list();
    let sk_poly = sk_poly_list.get(row_index);

    // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
    let mut body = row_as_glwe.get_mut_body();
    body.as_mut().copy_from_slice(sk_poly.as_ref());

    slice_wrapping_scalar_mul_assign(body.as_mut(), factor);

    encrypt_glwe_ciphertext_assign(glwe_secret_key, row_as_glwe, noise_distribution, generator);
}
