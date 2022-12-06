use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

pub fn encrypt_ggsw_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut GgswCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .fork_ggsw_to_ggsw_levels::<Scalar>(
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .expect("Failed to split generator into ggsw levels");

    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();

    for (level_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(level_index + 1);
        let factor = encoded
            .0
            .wrapping_neg()
            .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)));

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = generator
            .fork_ggsw_level_to_glwe::<Scalar>(output_glwe_size, output_polynomial_size)
            .expect("Failed to split generator into glwe");

        let last_row_index = level_matrix.glwe_size().0 - 1;
        let sk_poly_list = glwe_secret_key.as_polynomial_list();

        for ((row_index, mut row_as_glwe), mut generator) in level_matrix
            .as_mut_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            encrypt_ggsw_level_matrix_row(
                glwe_secret_key,
                (row_index, last_row_index),
                factor,
                &sk_poly_list,
                &mut row_as_glwe,
                noise_parameters,
                &mut generator,
            );
        }
    }
}

pub fn par_encrypt_ggsw_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut GgswCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .par_fork_ggsw_to_ggsw_levels::<Scalar>(
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .expect("Failed to split generator into ggsw levels");

    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(level_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(level_index + 1);
            let factor = encoded
                .0
                .wrapping_neg()
                .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)));

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .par_fork_ggsw_level_to_glwe::<Scalar>(output_glwe_size, output_polynomial_size)
                .expect("Failed to split generator into glwe");

            let last_row_index = level_matrix.glwe_size().0 - 1;
            let sk_poly_list = glwe_secret_key.as_polynomial_list();

            level_matrix
                .as_mut_glwe_list()
                .par_iter_mut()
                .enumerate()
                .zip(gen_iter)
                .for_each(|((row_index, mut row_as_glwe), mut generator)| {
                    encrypt_ggsw_level_matrix_row(
                        glwe_secret_key,
                        (row_index, last_row_index),
                        factor,
                        &sk_poly_list,
                        &mut row_as_glwe,
                        noise_parameters,
                        &mut generator,
                    );
                });
        },
    );
}

fn encrypt_ggsw_level_matrix_row<Scalar, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    sk_poly_list: &PolynomialList<InputCont>,
    row_as_glwe: &mut GlweCiphertext<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    if row_index < last_row_index {
        // Not the last row
        let sk_poly = sk_poly_list.get(row_index);

        // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
        let mut body = row_as_glwe.get_mut_body();
        body.as_mut().copy_from_slice(sk_poly.as_ref());

        update_slice_with_wrapping_scalar_mul(body.as_mut(), factor);

        encrypt_glwe_ciphertext_in_place(glwe_secret_key, row_as_glwe, noise_parameters, generator);
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();

        body.as_mut().fill(Scalar::ZERO);
        body.as_mut()[0] = factor.wrapping_neg();

        encrypt_glwe_ciphertext_in_place(glwe_secret_key, row_as_glwe, noise_parameters, generator);
    }
}
