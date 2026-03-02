//! Module containing primitives pertaining to [`GGSW ciphertext
//! encryption`](`GgswCiphertext#ggsw-encryption`).

use crate::core_crypto::algorithms::misc::divide_round;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::{CiphertextModulus, CiphertextModulusKind};
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{
    DecompositionLevel, DecompositionTerm, DecompositionTermNonNative, SignedDecomposer,
};
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Distribution, Uniform};
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, PlaintextCount};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Compute the multiplicative factor for a GGSW encryption based on an input value and GGSW
/// encryption parameters.
pub fn ggsw_encryption_multiplicative_factor<Scalar: UnsignedInteger>(
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

/// Encrypt a plaintext in a [`GGSW ciphertext`](`GgswCiphertext`) in the constant coefficient.
///
/// See the [`GGSW ciphertext formal definition`](`GgswCiphertext#ggsw-encryption`) for the
/// definition of the encryption algorithm.
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the cleartext
/// let cleartext = Cleartext(3u64);
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
///     cleartext,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, cleartext);
/// ```
pub fn encrypt_constant_ggsw_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut GgswCiphertext<OutputCont>,
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
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    for (output_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
        let factor = ggsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            decomp_level,
            decomp_base_log,
            cleartext,
        );

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = generator
            .try_fork_from_config(level_matrix.encryption_fork_config(Uniform, noise_distribution))
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
                noise_distribution,
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the cleartext
/// let cleartext = Cleartext(3u64);
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
///     cleartext,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, cleartext);
/// ```
pub fn par_encrypt_constant_ggsw_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut GgswCiphertext<OutputCont>,
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
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(output_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
            let factor = ggsw_encryption_multiplicative_factor(
                ciphertext_modulus,
                decomp_level,
                decomp_base_log,
                cleartext,
            );

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .par_try_fork_from_config(
                    level_matrix.encryption_fork_config(Uniform, noise_distribution),
                )
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
                        noise_distribution,
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
fn encrypt_constant_ggsw_level_matrix_row<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
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
    if row_index < last_row_index {
        // Not the last row
        let sk_poly_list = glwe_secret_key.as_polynomial_list();
        let sk_poly = sk_poly_list.get(row_index);

        // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
        let mut body = row_as_glwe.get_mut_body();
        body.as_mut().copy_from_slice(sk_poly.as_ref());

        let ciphertext_modulus = body.ciphertext_modulus();

        match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => slice_wrapping_scalar_mul_assign_custom_mod(
                body.as_mut(),
                factor,
                ciphertext_modulus.get_custom_modulus().cast_into(),
            ),
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                slice_wrapping_scalar_mul_assign(body.as_mut(), factor)
            }
        }
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();
        let ciphertext_modulus = body.ciphertext_modulus();

        body.as_mut().fill(Scalar::ZERO);
        let encoded = match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => {
                factor.wrapping_neg_custom_mod(ciphertext_modulus.get_custom_modulus().cast_into())
            }
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                factor.wrapping_neg()
            }
        };
        body.as_mut()[0] = encoded;
    }
    encrypt_glwe_ciphertext_assign(glwe_secret_key, row_as_glwe, noise_distribution, generator);
}

/// Convenience function to share the core logic of the seeded GGSW encryption between all
/// functions needing it.
///
/// Allows to efficiently encrypt lists of seeded GGSW.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
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
    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    for (output_index, (mut level_matrix, mut loop_generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
        let factor = ggsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            decomp_level,
            decomp_base_log,
            cleartext,
        );

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = loop_generator
            .try_fork_from_config(level_matrix.encryption_fork_config(Uniform, noise_distribution))
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
                noise_distribution,
                &mut loop_generator,
            );
        }
    }
}

/// Encrypt a cleartext in a [`seeded GGSW ciphertext`](`SeededGgswCiphertext`) in the constant
/// coefficient.
///
/// See the [`formal definition`](`GgswCiphertext#ggsw-encryption`) for the definition of the
/// encryption algorithm.
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the cleartext
/// let cleartext = Cleartext(3u64);
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
///     cleartext,
///     glwe_noise_distribution,
///     seeder,
/// );
///
/// let ggsw = ggsw.decompress_into_ggsw_ciphertext();
///
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, cleartext);
/// ```
pub fn encrypt_constant_seeded_ggsw_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
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

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed(),
        noise_seeder,
    );

    encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator(
        glwe_secret_key,
        output,
        cleartext,
        noise_distribution,
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
pub fn par_encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
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
    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(output_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
            let factor = ggsw_encryption_multiplicative_factor(
                ciphertext_modulus,
                decomp_level,
                decomp_base_log,
                cleartext,
            );

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .par_try_fork_from_config(
                    level_matrix.encryption_fork_config(Uniform, noise_distribution),
                )
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
                        noise_distribution,
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the cleartext
/// let cleartext = Cleartext(3u64);
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
///     cleartext,
///     glwe_noise_distribution,
///     seeder,
/// );
/// ```
pub fn par_encrypt_constant_seeded_ggsw_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
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

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed(),
        noise_seeder,
    );

    par_encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator(
        glwe_secret_key,
        output,
        cleartext,
        noise_distribution,
        &mut generator,
    );
}

/// Convenience function to encrypt a row of a [`GgswLevelMatrix`] irrespective of the current row
/// being encrypted. Allows to share code between sequential
/// ([`encrypt_constant_seeded_ggsw_ciphertext`]) and parallel
/// ([`par_encrypt_constant_seeded_ggsw_ciphertext`]) variants of the GGSW ciphertext encryption.
///
/// You probably don't want to use this function directly.
fn encrypt_constant_seeded_ggsw_level_matrix_row<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    row_as_glwe: &mut SeededGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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

        let ciphertext_modulus = body.ciphertext_modulus();

        match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => slice_wrapping_scalar_mul_assign_custom_mod(
                body.as_mut(),
                factor,
                ciphertext_modulus.get_custom_modulus().cast_into(),
            ),
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                slice_wrapping_scalar_mul_assign(body.as_mut(), factor)
            }
        }
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();
        let ciphertext_modulus = body.ciphertext_modulus();

        body.as_mut().fill(Scalar::ZERO);
        let encoded = match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => {
                factor.wrapping_neg_custom_mod(ciphertext_modulus.get_custom_modulus().cast_into())
            }
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                factor.wrapping_neg()
            }
        };
        body.as_mut()[0] = encoded;
    }
    encrypt_seeded_glwe_ciphertext_assign_with_pre_seeded_generator(
        glwe_secret_key,
        row_as_glwe,
        noise_distribution,
        generator,
    );
}

/// Decrypt a [`GGSW ciphertext`](`GgswCiphertext`) only yielding the cleartext from the constant
/// term of the polynomial.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the cleartext
/// let cleartext = Cleartext(3u64);
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
///     cleartext,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, cleartext);
/// ```
pub fn decrypt_constant_ggsw_ciphertext<Scalar, KeyCont, InputCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    ggsw_ciphertext: &GgswCiphertext<InputCont>,
) -> Cleartext<Scalar>
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

    let level_matrix = ggsw_ciphertext.first().unwrap();
    let level_matrix_as_glwe_list = level_matrix.as_glwe_list();
    let last_row = level_matrix_as_glwe_list.last().unwrap();
    let decomp_level = ggsw_ciphertext.decomposition_level_count();

    let mut decrypted_plaintext_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(ggsw_ciphertext.polynomial_size().0),
    );

    decrypt_glwe_ciphertext(glwe_secret_key, &last_row, &mut decrypted_plaintext_list);

    let decomp_base_log = ggsw_ciphertext.decomposition_base_log();

    let cleartext_ref = decrypted_plaintext_list.get(0);

    let ciphertext_modulus = ggsw_ciphertext.ciphertext_modulus();

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Other => {
            let delta = DecompositionTermNonNative::new(
                DecompositionLevel(decomp_level.0),
                decomp_base_log,
                Scalar::ONE,
                ciphertext_modulus,
            )
            .to_recomposition_summand();

            let decoded = divide_round(*cleartext_ref.0, delta)
                .wrapping_rem(Scalar::ONE << (decomp_level.0 * decomp_base_log.0));

            Cleartext(decoded)
        }
        CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
            let decomposer = SignedDecomposer::new(decomp_base_log, decomp_level);

            // Glwe decryption maps to a smaller torus potentially, map back to the native torus
            let rounded = decomposer.closest_representable(
                (*cleartext_ref.0)
                    .wrapping_mul(ciphertext_modulus.get_power_of_two_scaling_to_native_torus()),
            );
            let decoded = rounded
                .wrapping_div(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)));

            Cleartext(decoded)
        }
    }
}
