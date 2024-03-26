//! Module containing primitives pertaining to [`LWE shrinking keyswitch keys
//! generation`](`crate::core_crypto::entities::LweKeyswitchKey#key-switching-key`).

use crate::core_crypto::algorithms::generate_lwe_keyswitch_key;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::LweSecretKey;
use crate::core_crypto::experimental::entities::{
    LweShrinkingKeyswitchKey, LweShrinkingKeyswitchKeyOwned,
};

pub fn generate_lwe_shrinking_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweShrinkingKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let shared_randomness = lwe_keyswitch_key.shared_randomness();

    let shrunk_input_lwe_secret_key =
        LweSecretKey::from_container(&input_lwe_sk.as_ref()[shared_randomness.0..]);
    generate_lwe_keyswitch_key(
        &shrunk_input_lwe_secret_key,
        output_lwe_sk,
        &mut lwe_keyswitch_key.as_mut_lwe_keyswitch_key(),
        noise_distribution,
        generator,
    )
}

/// Allocate a new [`shrinking LWE keyswitch key`](`LweShrinkingKeyswitchKey`) and fill it with an
/// actual keyswitching key constructed from an input and an output key [`LWE secret
/// key`](`LweSecretKey`).
///
/// See [`crate::core_crypto::experimental::algorithms::shrinking_keyswitch_lwe_ciphertext`] for
/// usage.
#[allow(clippy::too_many_arguments)]
pub fn allocate_and_generate_new_lwe_shrinking_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweShrinkingKeyswitchKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
        ciphertext_modulus,
    );

    generate_lwe_shrinking_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_distribution,
        generator,
    );

    new_lwe_keyswitch_key
}
