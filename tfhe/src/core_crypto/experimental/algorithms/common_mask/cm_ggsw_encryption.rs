//! Module containing primitives pertaining to [`common mask GGSW ciphertext
//! encryption`](`CmGgswCiphertext#ggsw-encryption`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::{CiphertextModulus, CiphertextModulusKind};
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{
    DecompositionLevel, DecompositionTerm, DecompositionTermNonNative,
};
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::DecompositionBaseLog;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::*;
use crate::core_crypto::experimental::prelude::encrypt_cm_glwe_ciphertext_assign;
use crate::core_crypto::prelude::{Cleartext, GlweSecretKey};
use itertools::Itertools;
use rayon::prelude::*;

pub fn cm_ggsw_encryption_multiplicative_factor<Scalar: UnsignedInteger>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
    decomp_level: DecompositionLevel,
    decomp_base_log: DecompositionBaseLog,
    cleartext: Cleartext<Scalar>,
) -> Scalar {
    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Other => DecompositionTermNonNative::new(
            decomp_level,
            decomp_base_log,
            cleartext.0.wrapping_neg(),
            ciphertext_modulus,
        )
        .to_recomposition_summand(),
        CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
            let native_decomp_term =
                DecompositionTerm::new(decomp_level, decomp_base_log, cleartext.0.wrapping_neg())
                    .to_recomposition_summand();
            // We scale the factor down from the native torus to whatever our power of 2 torus is,
            // the encryption process will scale it back up
            native_decomp_term
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus())
        }
    }
}

pub fn encrypt_constant_cm_ggsw_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    output: &mut CmGgswCiphertext<OutputCont>,
    cleartexts: &[Cleartext<Scalar>],
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
        output.polynomial_size() == glwe_secret_keys[0].polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_keys[0].polynomial_size()
    );

    assert!(
        output.glwe_dimension() == glwe_secret_keys[0].glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_dimension(),
        glwe_secret_keys[0].glwe_dimension()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let ciphertext_modulus = output.ciphertext_modulus();

    for (level_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(level_index + 1);

        let factors = cleartexts
            .iter()
            .map(|cleartext| {
                ggsw_encryption_multiplicative_factor(
                    ciphertext_modulus,
                    decomp_level,
                    decomp_base_log,
                    *cleartext,
                )
            })
            .collect_vec();

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = generator
            .try_fork_from_config(level_matrix.encryption_fork_config(Uniform, noise_distribution))
            .expect("Failed to split generator into glwe");

        let last_row_index = level_matrix.glwe_dimension().0;

        for ((row_index, mut row_as_glwe), mut generator) in level_matrix
            .as_mut_cm_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            encrypt_constant_cm_ggsw_level_matrix_row(
                glwe_secret_keys,
                (row_index, last_row_index),
                &factors,
                &mut row_as_glwe,
                noise_distribution,
                &mut generator,
            );
        }
    }
}

pub fn par_encrypt_constant_cm_ggsw_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    output: &mut CmGgswCiphertext<OutputCont>,
    cleartexts: &[Cleartext<Scalar>],
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == glwe_secret_keys[0].polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_keys[0].polynomial_size()
    );

    assert!(
        output.glwe_dimension() == glwe_secret_keys[0].glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_dimension(),
        glwe_secret_keys[0].glwe_dimension()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let ciphertext_modulus = output.ciphertext_modulus();

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(level_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(level_index + 1);

            let factors = cleartexts
                .iter()
                .map(|cleartext| {
                    ggsw_encryption_multiplicative_factor(
                        ciphertext_modulus,
                        decomp_level,
                        decomp_base_log,
                        *cleartext,
                    )
                })
                .collect_vec();

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .par_try_fork_from_config(
                    level_matrix.encryption_fork_config(Uniform, noise_distribution),
                )
                .expect("Failed to split generator into glwe");

            let last_row_index = level_matrix.glwe_dimension().0;

            level_matrix
                .as_mut_cm_glwe_list()
                .par_iter_mut()
                .enumerate()
                .zip(gen_iter)
                .for_each(|((row_index, mut row_as_glwe), mut generator)| {
                    encrypt_constant_cm_ggsw_level_matrix_row(
                        glwe_secret_keys,
                        (row_index, last_row_index),
                        &factors,
                        &mut row_as_glwe,
                        noise_distribution,
                        &mut generator,
                    );
                });
        },
    );
}

fn encrypt_constant_cm_ggsw_level_matrix_row<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    (row_index, last_row_index): (usize, usize),
    factors: &[Scalar],
    row_as_glwe: &mut CmGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(matches!(
        row_as_glwe.ciphertext_modulus().kind(),
        CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo
    ));

    let mut bodies = row_as_glwe.get_mut_bodies();

    if row_index < last_row_index {
        // Mask row
        for ((glwe_secret_key, mut body), factor) in glwe_secret_keys
            .iter()
            .zip_eq(bodies.iter_mut())
            .zip_eq(factors.iter())
        {
            let sk_poly_list = glwe_secret_key.as_polynomial_list();
            let sk_poly = sk_poly_list.get(row_index);

            // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
            body.as_mut().copy_from_slice(sk_poly.as_ref());

            slice_wrapping_scalar_mul_assign(body.as_mut(), *factor)
        }
    } else {
        // Body rows

        bodies.as_mut().fill(Scalar::ZERO);

        let encoded = factors[row_index - last_row_index].wrapping_neg();

        let mut body = bodies.get_mut(row_index - last_row_index);

        // set the constant coefficient (X^0)
        body.as_mut()[0] = encoded;
    }
    encrypt_cm_glwe_ciphertext_assign(glwe_secret_keys, row_as_glwe, noise_distribution, generator);
}
