//! Module containing primitives pertaining to [`LWE compact public key
//! generation`](`LweCompactPublicKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::ActivatedRandomGenerator;
use slice_algorithms::*;

/// Fill an [`LWE compact public key`](`LweCompactPublicKey`) with an actual public key constructed
/// from a private [`LWE secret key`](`LweSecretKey`).
pub fn generate_lwe_compact_public_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut LweCompactPublicKey<OutputKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    assert!(
        lwe_secret_key.lwe_dimension() == output.lwe_dimension(),
        "Mismatched LweDimension between input LweSecretKey {:?} \
    and output LweCompactPublicKey {:?}",
        lwe_secret_key.lwe_dimension(),
        output.lwe_dimension()
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();
    generator.fill_slice_with_random_mask(mask.as_mut());

    slice_semi_reverse_negacyclic_convolution(
        body.as_mut(),
        mask.as_ref(),
        lwe_secret_key.as_ref(),
    );

    generator
        .unsigned_torus_slice_wrapping_add_random_noise_assign(body.as_mut(), noise_parameters);
}

/// Allocate a new [`LWE compact public key`](`LweCompactPublicKey`) and fill it with an actual
/// public key constructed from a private [`LWE secret key`](`LweSecretKey`).
///
/// See [`encrypt_lwe_ciphertext_with_compact_public_key`] for usage.
pub fn allocate_and_generate_new_lwe_compact_public_key<Scalar, InputKeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweCompactPublicKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut pk = LweCompactPublicKeyOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension(),
        ciphertext_modulus,
    );

    generate_lwe_compact_public_key(lwe_secret_key, &mut pk, noise_parameters, generator);

    pk
}

/// Fill a [`seeded LWE compact public key`](`LweCompactPublicKey`) with an actual public key
/// constructed from a private [`LWE secret key`](`LweSecretKey`).
pub fn generate_seeded_lwe_compact_public_key<Scalar, InputKeyCont, OutputKeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output: &mut SeededLweCompactPublicKey<OutputKeyCont>,
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
        output.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    assert!(
        lwe_secret_key.lwe_dimension() == output.lwe_dimension(),
        "Mismatched LweDimension between input LweSecretKey {:?} \
    and output LweCompactPublicKey {:?}",
        lwe_secret_key.lwe_dimension(),
        output.lwe_dimension()
    );

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    let mut tmp_mask = vec![Scalar::ZERO; output.lwe_dimension().0];
    generator.fill_slice_with_random_mask(tmp_mask.as_mut());

    let mut body = output.get_mut_body();

    slice_semi_reverse_negacyclic_convolution(
        body.as_mut(),
        tmp_mask.as_ref(),
        lwe_secret_key.as_ref(),
    );

    generator
        .unsigned_torus_slice_wrapping_add_random_noise_assign(body.as_mut(), noise_parameters);
}

/// Allocate a new [`seeded LWE compact public key`](`SeededLweCompactPublicKey`) and fill it with
/// an actual public key constructed from a private [`LWE secret key`](`LweSecretKey`).
pub fn allocate_and_generate_new_seeded_lwe_compact_public_key<Scalar, InputKeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweCompactPublicKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut pk = SeededLweCompactPublicKey::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension(),
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    generate_seeded_lwe_compact_public_key(lwe_secret_key, &mut pk, noise_parameters, noise_seeder);

    pk
}
