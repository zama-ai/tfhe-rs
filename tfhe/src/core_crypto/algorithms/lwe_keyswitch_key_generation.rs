use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn generate_lwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, KSKeyCont, Gen>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_levels_count();

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elmements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                .to_recomposition_summand();
        }

        encrypt_lwe_ciphertext_list(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_parameters,
            generator,
        );
    }
}

pub fn allocate_and_generate_new_lwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
    );

    generate_lwe_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_parameters,
        generator,
    );

    new_lwe_keyswitch_key
}
