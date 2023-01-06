use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Encrypt a plaintext in a [`GGSW ciphertext`](`GgswCiphertext`).
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let encoded_msg = 3u64 << 60;
/// let plaintext = Plaintext(encoded_msg);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
/// );
///
/// encrypt_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
/// ```
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
                &mut row_as_glwe,
                noise_parameters,
                &mut generator,
            );
        }
    }
}

/// Parallel variant of [`encrypt_ggsw_ciphertext`].
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// New tasks are created per level matrix and per row of each level matrix.
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let encoded_msg = 3u64 << 60;
/// let plaintext = Plaintext(encoded_msg);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
/// );
///
/// par_encrypt_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
/// ```
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
                        &mut row_as_glwe,
                        noise_parameters,
                        &mut generator,
                    );
                });
        },
    );
}

/// Convenience function to encrypt a row of a [`GgswLevelMatrix`] irrespective of the current row
/// being encrypted. Allows to share code between sequential ([`encrypt_ggsw_ciphertext`]) and
/// parallel ([`par_encrypt_ggsw_ciphertext`]) variants of the GGSW ciphertext encryption.
///
/// You probably don't want to use this function directly.
fn encrypt_ggsw_level_matrix_row<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    row_as_glwe: &mut GlweCiphertext<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    if row_index < last_row_index {
        // Not the last row
        let sk_poly_list = glwe_secret_key.as_polynomial_list();
        let sk_poly = sk_poly_list.get(row_index);

        // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
        let mut body = row_as_glwe.get_mut_body();
        body.as_mut().copy_from_slice(sk_poly.as_ref());

        slice_wrapping_scalar_mul_assign(body.as_mut(), factor);

        encrypt_glwe_ciphertext_assign(glwe_secret_key, row_as_glwe, noise_parameters, generator);
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();

        body.as_mut().fill(Scalar::ZERO);
        body.as_mut()[0] = factor.wrapping_neg();

        encrypt_glwe_ciphertext_assign(glwe_secret_key, row_as_glwe, noise_parameters, generator);
    }
}

pub fn encrypt_seeded_ggsw_ciphertext_with_existing_generator<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar> + std::fmt::Debug,
    Gen: ByteRandomGenerator,
{
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

    for (level_index, (mut level_matrix, mut loop_generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(level_index + 1);
        let factor = encoded
            .0
            .wrapping_neg()
            .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)));

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = loop_generator
            .fork_ggsw_level_to_glwe::<Scalar>(output_glwe_size, output_polynomial_size)
            .expect("Failed to split generator into glwe");

        let last_row_index = level_matrix.glwe_size().0 - 1;

        for ((row_index, mut row_as_glwe), mut loop_generator) in level_matrix
            .as_mut_seeded_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            encrypt_seeded_ggsw_level_matrix_row(
                glwe_secret_key,
                (row_index, last_row_index),
                factor,
                &mut row_as_glwe,
                noise_parameters,
                &mut loop_generator,
            );
        }
    }
}

/// Encrypt a plaintext in a [`seeded GGSW ciphertext`](`SeededGgswCiphertext`).
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let encoded_msg = 3u64 << 60;
/// let plaintext = Plaintext(encoded_msg);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = SeededGgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     seeder.seed().into(),
/// );
///
/// encrypt_seeded_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     seeder,
/// );
/// ```
pub fn encrypt_seeded_ggsw_ciphertext<Scalar, KeyCont, OutputCont, NoiseSeeder>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar> + std::fmt::Debug,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
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

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_seeded_ggsw_ciphertext_with_existing_generator(
        glwe_secret_key,
        output,
        encoded,
        noise_parameters,
        &mut generator,
    )
}

pub fn par_encrypt_seeded_ggsw_ciphertext_with_existing_generator<
    Scalar,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
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

            level_matrix
                .as_mut_seeded_glwe_list()
                .par_iter_mut()
                .enumerate()
                .zip(gen_iter)
                .for_each(|((row_index, mut row_as_glwe), mut generator)| {
                    encrypt_seeded_ggsw_level_matrix_row(
                        glwe_secret_key,
                        (row_index, last_row_index),
                        factor,
                        &mut row_as_glwe,
                        noise_parameters,
                        &mut generator,
                    );
                });
        },
    );
}

/// Parallel variant of [`encrypt_ggsw_ciphertext`].
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// New tasks are created per level matrix and per row of each level matrix.
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let encoded_msg = 3u64 << 60;
/// let plaintext = Plaintext(encoded_msg);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = SeededGgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     seeder.seed().into(),
/// );
///
/// par_encrypt_seeded_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     seeder,
/// );
/// ```
pub fn par_encrypt_seeded_ggsw_ciphertext<Scalar, KeyCont, OutputCont, NoiseSeeder>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter + Sync,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
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

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    par_encrypt_seeded_ggsw_ciphertext_with_existing_generator(
        glwe_secret_key,
        output,
        encoded,
        noise_parameters,
        &mut generator,
    );
}

/// Convenience function to encrypt a row of a [`GgswLevelMatrix`] irrespective of the current row
/// being encrypted. Allows to share code between sequential ([`encrypt_seeded_ggsw_ciphertext`])
/// and parallel ([`par_encrypt_seeded_ggsw_ciphertext`]) variants of the GGSW ciphertext
/// encryption.
///
/// You probably don't want to use this function directly.
fn encrypt_seeded_ggsw_level_matrix_row<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    row_as_glwe: &mut SeededGlweCiphertext<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    if row_index < last_row_index {
        // Not the last row
        let sk_poly_list = glwe_secret_key.as_polynomial_list();
        let sk_poly = sk_poly_list.get(row_index);

        // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
        let mut body = row_as_glwe.get_mut_body();
        body.as_mut().copy_from_slice(sk_poly.as_ref());

        slice_wrapping_scalar_mul_assign(body.as_mut(), factor);

        encrypt_seeded_glwe_ciphertext_assign_with_existing_generator(
            glwe_secret_key,
            row_as_glwe,
            noise_parameters,
            generator,
        );
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();

        body.as_mut().fill(Scalar::ZERO);
        body.as_mut()[0] = factor.wrapping_neg();

        encrypt_seeded_glwe_ciphertext_assign_with_existing_generator(
            glwe_secret_key,
            row_as_glwe,
            noise_parameters,
            generator,
        );
    }
}

#[cfg(test)]
mod test {
    use crate::core_crypto::commons::generators::{
        DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
    };
    use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
    use crate::core_crypto::commons::test_tools;
    use crate::core_crypto::prelude::*;
    use crate::seeders::new_seeder;

    fn test_parallel_and_seeded_ggsw_encryption_equivalence<Scalar>()
    where
        Scalar: UnsignedTorus + Sync + Send,
    {
        // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
        // computations
        // Define parameters for GgswCiphertext creation
        let glwe_size = GlweSize(2);
        let polynomial_size = PolynomialSize(1024);
        let decomp_base_log = DecompositionBaseLog(8);
        let decomp_level_count = DecompositionLevelCount(3);
        let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let main_seed = seeder.seed();
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        const NB_TESTS: usize = 10;

        for _ in 0..NB_TESTS {
            // Create the GlweSecretKey
            let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_size.to_glwe_dimension(),
                polynomial_size,
                &mut secret_generator,
            );

            // Create the plaintext
            let encoded_msg: Scalar =
                test_tools::random_uint_between(Scalar::ZERO..Scalar::TWO.shl(2));
            let plaintext = Plaintext(encoded_msg);

            let compression_seed: CompressionSeed = seeder.seed().into();

            let mut ser_ggsw = GgswCiphertext::new(
                Scalar::ZERO,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
            );

            let mut deterministic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);

            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    compression_seed.seed,
                    &mut deterministic_seeder,
                );

            encrypt_ggsw_ciphertext(
                &glwe_secret_key,
                &mut ser_ggsw,
                plaintext,
                glwe_modular_std_dev,
                &mut encryption_generator,
            );

            let mut par_ggsw = GgswCiphertext::new(
                Scalar::ZERO,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
            );

            let mut deterministic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);

            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    compression_seed.seed,
                    &mut deterministic_seeder,
                );

            par_encrypt_ggsw_ciphertext(
                &glwe_secret_key,
                &mut par_ggsw,
                plaintext,
                glwe_modular_std_dev,
                &mut encryption_generator,
            );

            assert_eq!(ser_ggsw, par_ggsw);

            // Create a new GgswCiphertext
            let mut ser_seeded_ggsw = SeededGgswCiphertext::new(
                Scalar::ZERO,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                compression_seed,
            );

            let mut deterministic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);

            encrypt_seeded_ggsw_ciphertext(
                &glwe_secret_key,
                &mut ser_seeded_ggsw,
                plaintext,
                glwe_modular_std_dev,
                &mut deterministic_seeder,
            );

            let mut par_seeded_ggsw = SeededGgswCiphertext::new(
                Scalar::ZERO,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                compression_seed,
            );

            let mut deterministic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);

            par_encrypt_seeded_ggsw_ciphertext(
                &glwe_secret_key,
                &mut par_seeded_ggsw,
                plaintext,
                glwe_modular_std_dev,
                &mut deterministic_seeder,
            );

            assert_eq!(ser_seeded_ggsw, par_seeded_ggsw);

            let decompressed_ggsw = par_seeded_ggsw.decompress_into_ggsw_ciphertext();

            assert_eq!(ser_ggsw, decompressed_ggsw);
        }
    }

    #[test]
    fn test_parallel_and_seeded_ggsw_encryption_equivalence_u32() {
        test_parallel_and_seeded_ggsw_encryption_equivalence::<u32>();
    }

    #[test]
    fn test_parallel_and_seeded_ggsw_encryption_equivalence_u64() {
        test_parallel_and_seeded_ggsw_encryption_equivalence::<u64>();
    }
}
