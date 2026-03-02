//! Module containing primitives pertaining to [`LWE public key
//! generation`](`LwePublicKey#lwe-public-key`) and [`seeded LWE public key
//! generation`](`SeededLwePublicKey#lwe-public-key`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{CompressionSeed, Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Fill an [`LWE public key`](`LwePublicKey`) with an actual public key constructed from a private
/// [`LWE secret key`](`LweSecretKey`).
///
/// Consider using [`par_generate_lwe_public_key`] for better key generation times.
pub fn generate_lwe_public_key<Scalar, NoiseDistribution, InputKeyCont, OutputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut LwePublicKey<OutputKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_secret_key.lwe_dimension() == output.lwe_size().to_lwe_dimension(),
        "Mismatched LweDimension between input LweSecretKey {:?} and output LwePublicKey {:?}",
        lwe_secret_key.lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
    );

    let zeros = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(output.zero_encryption_count().0),
    );

    encrypt_lwe_ciphertext_list(
        lwe_secret_key,
        output,
        &zeros,
        noise_distribution,
        generator,
    );
}

/// Allocate a new [`LWE public key`](`LwePublicKey`) and fill it with an actual public key
/// constructed from a private [`LWE secret key`](`LweSecretKey`).
///
/// Consider using [`par_allocate_and_generate_new_lwe_public_key`] for better key generation times.
///
/// See [`encrypt_lwe_ciphertext_with_public_key`] for usage.
pub fn allocate_and_generate_new_lwe_public_key<Scalar, NoiseDistribution, InputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePublicKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut pk = LwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
        ciphertext_modulus,
    );

    generate_lwe_public_key(lwe_secret_key, &mut pk, noise_distribution, generator);

    pk
}

/// Parallel variant of [`generate_lwe_public_key`], it is recommended to use this function for
/// better key generation times as LWE public keys can be quite large.
pub fn par_generate_lwe_public_key<Scalar, NoiseDistribution, InputKeyCont, OutputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut LwePublicKey<OutputKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar> + Sync,
    OutputKeyCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        lwe_secret_key.lwe_dimension() == output.lwe_size().to_lwe_dimension(),
        "Mismatch LweDimension between lwe_secret_key {:?} and public key {:?}",
        lwe_secret_key.lwe_dimension(),
        output.lwe_size().to_lwe_dimension()
    );

    let zeros = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(output.zero_encryption_count().0),
    );

    par_encrypt_lwe_ciphertext_list(
        lwe_secret_key,
        output,
        &zeros,
        noise_distribution,
        generator,
    );
}

/// Parallel variant of [`allocate_and_generate_new_lwe_public_key`], it is recommended to use this
/// function for better key generation times as LWE public keys can be quite large.
pub fn par_allocate_and_generate_new_lwe_public_key<Scalar, NoiseDistribution, InputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePublicKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut pk = LwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
        ciphertext_modulus,
    );

    par_generate_lwe_public_key(lwe_secret_key, &mut pk, noise_distribution, generator);

    pk
}

/// Fill a [`seeded LWE public key`](`SeededLwePublicKey`) with an actual public key.
///
/// Consider using [`par_generate_seeded_lwe_public_key`] for better key generation times.
pub fn generate_seeded_lwe_public_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut SeededLwePublicKey<OutputKeyCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        lwe_secret_key.lwe_dimension() == output.lwe_size().to_lwe_dimension(),
        "Mismatched LweDimension between input LweSecretKey {:?} and output SeededLwePublicKey {:?}",
        lwe_secret_key.lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
    );

    let zeros = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(output.zero_encryption_count().0),
    );

    encrypt_seeded_lwe_ciphertext_list(
        lwe_secret_key,
        output,
        &zeros,
        noise_distribution,
        noise_seeder,
    );
}

/// Allocate a new [`seeded LWE public key`](`SeededLwePublicKey`) and fill it with an actual
/// seeded public key.
///
/// Consider using [`par_allocate_and_generate_new_seeded_lwe_public_key`] for better key
/// generation times.
///
/// See [`encrypt_lwe_ciphertext_with_seeded_public_key`] for usage.
pub fn allocate_and_generate_new_seeded_lwe_public_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    NoiseSeeder,
>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLwePublicKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut pk = SeededLwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
        CompressionSeed::from(noise_seeder.seed()),
        ciphertext_modulus,
    );

    generate_seeded_lwe_public_key(lwe_secret_key, &mut pk, noise_distribution, noise_seeder);

    pk
}

/// Parallel variant of [`par_generate_seeded_lwe_public_key`], it is recommended to use this
/// function for better key generation times as LWE public keys can be quite large.
pub fn par_generate_seeded_lwe_public_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut SeededLwePublicKey<OutputKeyCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar> + Sync,
    OutputKeyCont: ContainerMut<Element = Scalar> + Sync,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        lwe_secret_key.lwe_dimension() == output.lwe_size().to_lwe_dimension(),
        "Mismatch LweDimension between lwe_secret_key {:?} and public key {:?}",
        lwe_secret_key.lwe_dimension(),
        output.lwe_size().to_lwe_dimension()
    );

    let zeros = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(output.zero_encryption_count().0),
    );

    par_encrypt_seeded_lwe_ciphertext_list(
        lwe_secret_key,
        output,
        &zeros,
        noise_distribution,
        noise_seeder,
    );
}

/// Parallel variant of [`allocate_and_generate_new_seeded_lwe_public_key`], it is recommended to
/// use this function for better key generation times as LWE public keys can be quite large.
pub fn par_allocate_and_generate_new_seeded_lwe_public_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    NoiseSeeder,
>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLwePublicKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar> + Sync,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut pk = SeededLwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
        CompressionSeed::from(noise_seeder.seed()),
        ciphertext_modulus,
    );

    par_generate_seeded_lwe_public_key(lwe_secret_key, &mut pk, noise_distribution, noise_seeder);

    pk
}
