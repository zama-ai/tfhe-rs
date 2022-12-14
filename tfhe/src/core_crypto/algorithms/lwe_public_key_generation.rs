use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn generate_lwe_public_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut LwePublicKey<OutputKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
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

    encrypt_lwe_ciphertext_list(lwe_secret_key, output, &zeros, noise_parameters, generator)
}

pub fn allocate_and_generate_new_lwe_public_key<Scalar, InputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePublicKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut pk = LwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
    );

    generate_lwe_public_key(lwe_secret_key, &mut pk, noise_parameters, generator);

    pk
}

pub fn par_generate_lwe_public_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut LwePublicKey<OutputKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
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

    par_encrypt_lwe_ciphertext_list(lwe_secret_key, output, &zeros, noise_parameters, generator)
}

pub fn par_allocate_and_generate_new_lwe_public_key<Scalar, InputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePublicKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut pk = LwePublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        zero_encryption_count,
    );

    par_generate_lwe_public_key(lwe_secret_key, &mut pk, noise_parameters, generator);

    pk
}
