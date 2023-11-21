//! Module containing primitives pertaining to [`GGSW ciphertext
//! encryption`](`GgswCiphertext#ggsw-encryption`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;
use crate::core_crypto::commons::parameters::PlaintextCount;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Encrypt a plaintext in a [`GGSW ciphertext`](`GgswCiphertext`) in the constant coefficient.
///
/// See the [`GGSW ciphertext formal definition`](`GgswCiphertext#ggsw-encryption`) for the
/// definition of the encryption algorithm.
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
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
/// let plaintext = Plaintext(3u64);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_constant_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn encrypt_constant_ggsw_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
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
    let ciphertext_modulus = output.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    for (level_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(level_index + 1);
        // We scale the factor down from the native torus to whatever our torus is, the
        // encryption process will scale it back up
        let factor = encoded
            .0
            .wrapping_neg()
            .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)))
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());

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
            encrypt_constant_ggsw_level_matrix_row(
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

/// Parallel variant of [`encrypt_constant_ggsw_ciphertext`].
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// New tasks are created per level matrix and per row of each level matrix.
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
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
/// let plaintext = Plaintext(3u64);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// par_encrypt_constant_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn par_encrypt_constant_ggsw_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
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
    let ciphertext_modulus = output.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(level_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(level_index + 1);
            // We scale the factor down from the native torus to whatever our torus is, the
            // encryption process will scale it back up
            let factor = encoded
                .0
                .wrapping_neg()
                .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)))
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());

            // We iterate over the rows of the level matrix, the last row needs special
            // treatment
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
                    encrypt_constant_ggsw_level_matrix_row(
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
/// being encrypted. Allows to share code between sequential ([`encrypt_constant_ggsw_ciphertext`])
/// and parallel ([`par_encrypt_constant_ggsw_ciphertext`]) variants of the GGSW ciphertext
/// encryption.
///
/// You probably don't want to use this function directly.
fn encrypt_constant_ggsw_level_matrix_row<Scalar, KeyCont, OutputCont, Gen>(
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
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();

        body.as_mut().fill(Scalar::ZERO);
        body.as_mut()[0] = factor.wrapping_neg();
    }
    encrypt_glwe_ciphertext_assign(glwe_secret_key, row_as_glwe, noise_parameters, generator);
}

/// Convenience function to share the core logic of the seeded GGSW encryption between all
/// functions needing it.
///
/// Allows to efficiently encrypt lists of seeded GGSW.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator<
    Scalar,
    KeyCont,
    OutputCont,
    Gen,
>(
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
    let ciphertext_modulus = output.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    for (level_index, (mut level_matrix, mut loop_generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(level_index + 1);
        // We scale the factor down from the native torus to whatever our torus is, the
        // encryption process will scale it back up
        let factor = encoded
            .0
            .wrapping_neg()
            .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)))
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());

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
            encrypt_constant_seeded_ggsw_level_matrix_row(
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

/// Encrypt a plaintext in a [`seeded GGSW ciphertext`](`SeededGgswCiphertext`) in the constant
/// coefficient.
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
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
///     ciphertext_modulus,
/// );
///
/// encrypt_constant_seeded_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     seeder,
/// );
/// ```
pub fn encrypt_constant_seeded_ggsw_ciphertext<Scalar, KeyCont, OutputCont, NoiseSeeder>(
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

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator(
        glwe_secret_key,
        output,
        encoded,
        noise_parameters,
        &mut generator,
    );
}

/// Convenience function to share the core logic of the parallel seeded GGSW encryption between all
/// functions needing it.
///
/// Allows to efficiently encrypt lists of seeded GGSW.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator<
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
    let ciphertext_modulus = output.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(level_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(level_index + 1);
            // We scale the factor down from the native torus to whatever our torus is, the
            // encryption process will scale it back up
            let factor = encoded
                .0
                .wrapping_neg()
                .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)))
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());

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
                    encrypt_constant_seeded_ggsw_level_matrix_row(
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

/// Parallel variant of [`encrypt_constant_seeded_ggsw_ciphertext`].
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// New tasks are created per level matrix and per row of each level matrix.
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
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
///     ciphertext_modulus,
/// );
///
/// par_encrypt_constant_seeded_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     seeder,
/// );
/// ```
pub fn par_encrypt_constant_seeded_ggsw_ciphertext<Scalar, KeyCont, OutputCont, NoiseSeeder>(
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

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator(
        glwe_secret_key,
        output,
        encoded,
        noise_parameters,
        &mut generator,
    );
}

/// Convenience function to encrypt a row of a [`GgswLevelMatrix`] irrespective of the current row
/// being encrypted. Allows to share code between sequential
/// ([`encrypt_constant_seeded_ggsw_ciphertext`]) and parallel
/// ([`par_encrypt_constant_seeded_ggsw_ciphertext`]) variants of the GGSW ciphertext encryption.
///
/// You probably don't want to use this function directly.
fn encrypt_constant_seeded_ggsw_level_matrix_row<Scalar, KeyCont, OutputCont, Gen>(
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
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();

        body.as_mut().fill(Scalar::ZERO);
        body.as_mut()[0] = factor.wrapping_neg();
    }
    encrypt_seeded_glwe_ciphertext_assign_with_existing_generator(
        glwe_secret_key,
        row_as_glwe,
        noise_parameters,
        generator,
    );
}

/// Decrypt a [`GGSW ciphertext`](`GgswCiphertext`) only yielding the plaintext from the constant
/// term of the polynomial.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
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
/// let plaintext = Plaintext(3u64);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// par_encrypt_constant_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     plaintext,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn decrypt_constant_ggsw_ciphertext<Scalar, KeyCont, InputCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    ggsw_ciphertext: &GgswCiphertext<InputCont>,
) -> Plaintext<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        ggsw_ciphertext.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of input ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        ggsw_ciphertext.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        ggsw_ciphertext.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of input ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        ggsw_ciphertext.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    let level_matrix = ggsw_ciphertext.last().unwrap();
    let level_matrix_as_glwe_list = level_matrix.as_glwe_list();
    let last_row = level_matrix_as_glwe_list.last().unwrap();
    let decomp_level = ggsw_ciphertext.decomposition_level_count();

    let mut decrypted_plaintext_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(ggsw_ciphertext.polynomial_size().0),
    );

    decrypt_glwe_ciphertext(glwe_secret_key, &last_row, &mut decrypted_plaintext_list);

    let decomp_base_log = ggsw_ciphertext.decomposition_base_log();

    let decomposer = SignedDecomposer::new(decomp_base_log, decomp_level);

    let plaintext_ref = decrypted_plaintext_list.get(0);

    let ciphertext_modulus = ggsw_ciphertext.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // Glwe decryption maps to a smaller torus potentially, map back to the native torus
    let rounded = decomposer.closest_representable(
        (*plaintext_ref.0)
            .wrapping_mul(ciphertext_modulus.get_power_of_two_scaling_to_native_torus()),
    );
    let decoded =
        rounded.wrapping_div(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)));

    Plaintext(decoded)
}
