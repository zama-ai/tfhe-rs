use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn generate_seeded_lwe_public_key<Scalar, InputKeyCont, OutputKeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut SeededLwePublicKey<OutputKeyCont>,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus,
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
        noise_parameters,
        noise_seeder,
    );
}

pub fn allocate_and_generate_new_seeded_lwe_public_key<Scalar, InputKeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLwePublicKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut pk = SeededLwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
        CompressionSeed {
            seed: noise_seeder.seed(),
        },
    );

    generate_seeded_lwe_public_key(lwe_secret_key, &mut pk, noise_parameters, noise_seeder);

    pk
}

pub fn par_generate_seeded_lwe_public_key<Scalar, InputKeyCont, OutputKeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut SeededLwePublicKey<OutputKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus + Sync + Send,
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
        noise_parameters,
        noise_seeder,
    )
}

pub fn par_allocate_and_generate_new_seeded_lwe_public_key<Scalar, InputKeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_parameters: impl DispersionParameter + Sync,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLwePublicKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar> + Sync,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut pk = SeededLwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
        CompressionSeed {
            seed: noise_seeder.seed(),
        },
    );

    par_generate_seeded_lwe_public_key(lwe_secret_key, &mut pk, noise_parameters, noise_seeder);

    pk
}
