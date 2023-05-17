//! Module containing primitives pertaining to [`LWE shrinking keyswitch keys
//! generation`](`LweKeyswitchKey#key-switching-key`) and [`seeded LWE shrinking keyswitch keys
//! generation`](`SeededLweKeyswitchKey`).

//TODO: Seeded part not done

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn generate_lwe_shrinking_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, KSKeyCont, Gen>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweShrinkingKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar> + std::fmt::Debug,
    Gen: ByteRandomGenerator,
{
    let unshared_randomness_lwe_dimension = lwe_keyswitch_key.unshared_randomness_lwe_dimension();

    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
        to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );

    assert_eq!(
        input_lwe_sk.lwe_dimension().0,
        output_lwe_sk.lwe_dimension().0 + unshared_randomness_lwe_dimension.0
    );

    let shared_randomness_lwe_dimension = lwe_keyswitch_key.shared_randomness_lwe_dimension();

    let shrunk_input_lwe_secret_key =
        LweSecretKey::from_container(&input_lwe_sk.as_ref()[shared_randomness_lwe_dimension.0..]);
    generate_lwe_keyswitch_key(
        &shrunk_input_lwe_secret_key,
        output_lwe_sk,
        &mut lwe_keyswitch_key.as_mut_lwe_keyswitch_key(),
        noise_parameters,
        generator,
    )
}

/// Allocate a new [`LWE keyswitch key`](`LweKeyswitchKey`) and fill it with an actual keyswitching
/// key constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// See [`shrinking_keyswitch_lwe_ciphertext`] for usage.
#[allow(clippy::too_many_arguments)]
pub fn allocate_and_generate_new_lwe_shrinking_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    shared_randomness_coef_count: SharedLweSecretKeyCommonCoefCount,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweShrinkingKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweShrinkingKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
        shared_randomness_coef_count,
        ciphertext_modulus,
    );

    generate_lwe_shrinking_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_parameters,
        generator,
    );

    new_lwe_keyswitch_key
}
