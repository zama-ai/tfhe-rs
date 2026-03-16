//! Module containing primitives pertaining to
//! [`CommonMask GGSW ciphertext encryption`](`CmGgswCiphertext`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::*;
use crate::core_crypto::experimental::prelude::encrypt_cm_glwe_ciphertext_assign;
use crate::core_crypto::prelude::{Cleartext, GlweSecretKey};
use itertools::Itertools;
use rayon::prelude::*;

pub fn encrypt_constant_cm_ggsw_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    output: &mut CmGgswCiphertext<OutputCont>,
    // TODO: Use a CleartextList
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
    for glwe_secret_key in glwe_secret_keys {
        assert!(
            output.polynomial_size() == glwe_secret_key.polynomial_size(),
            "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
            Got {:?} in output, and {:?} in secret key.",
            output.polynomial_size(),
            glwe_secret_key.polynomial_size()
        );

        assert!(
            output.glwe_dimension() == glwe_secret_key.glwe_dimension(),
            "Mismatch between GlweDimension of output ciphertexts and input secret key. \
            Got {:?} in output, and {:?} in secret key.",
            output.glwe_dimension(),
            glwe_secret_key.glwe_dimension()
        );
    }

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    for (level_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(decomp_level_count.0 - level_index);

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
    for glwe_secret_key in glwe_secret_keys {
        assert!(
            output.polynomial_size() == glwe_secret_key.polynomial_size(),
            "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
            Got {:?} in output, and {:?} in secret key.",
            output.polynomial_size(),
            glwe_secret_key.polynomial_size()
        );

        assert!(
            output.glwe_dimension() == glwe_secret_key.glwe_dimension(),
            "Mismatch between GlweDimension of output ciphertexts and input secret key. \
            Got {:?} in output, and {:?} in secret key.",
            output.glwe_dimension(),
            glwe_secret_key.glwe_dimension()
        );
    }

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(level_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(decomp_level_count.0 - level_index);

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
    (row_index, first_body_row_index): (usize, usize),
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

    row_as_glwe.get_mut_mask().as_mut().fill(Scalar::ZERO);

    let mut bodies = row_as_glwe.get_mut_bodies();

    if row_index < first_body_row_index {
        // Mask row

        // The Matrix must encode polynomail list
        // [factor1 * sk1[row_index], factor2 * sk2[row_index], ...]

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

        // The Matrix must encode polynomial list
        // [0, ..., -factor_i * X^0, ..., 0]
        // with i = body_row_index

        bodies.as_mut().fill(Scalar::ZERO);

        let body_row_index = row_index - first_body_row_index;

        let encoded = factors[body_row_index].wrapping_neg();

        let mut body = bodies.get_mut(body_row_index);

        // set the constant coefficient (X^0)
        body.as_mut()[0] = encoded;
    }
    encrypt_cm_glwe_ciphertext_assign(glwe_secret_keys, row_as_glwe, noise_distribution, generator);
}
