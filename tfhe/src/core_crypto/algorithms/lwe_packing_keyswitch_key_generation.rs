use crate::core_crypto::algorithms::encrypt_glwe_ciphertext_list;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::{
    GlweSecretKey, LwePackingKeyswitchKey, LwePackingKeyswitchKeyOwned, LweSecretKey,
    PlaintextListOwned,
};

pub fn generate_lwe_packing_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, KSKeyCont, Gen>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    lwe_packing_keyswitch_key: &mut LwePackingKeyswitchKey<KSKeyCont>,
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
        lwe_packing_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LwePackingKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_packing_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_packing_keyswitch_key.output_key_glwe_dimension() == output_glwe_sk.glwe_dimension(),
        "The destination LwePackingKeyswitchKey output LweDimension is not equal \
    to the output GlweSecretKey GlweDimension. Destination: {:?}, output: {:?}",
        lwe_packing_keyswitch_key.output_key_glwe_dimension(),
        output_glwe_sk.glwe_dimension()
    );
    assert!(
        lwe_packing_keyswitch_key.output_key_polynomial_size() == output_glwe_sk.polynomial_size(),
        "The destination LwePackingKeyswitchKey output PolynomialSize is not equal \
        to the output GlweSecretKey PolynomialSize. Destination: {:?}, output: {:?}",
        lwe_packing_keyswitch_key.output_key_polynomial_size(),
        output_glwe_sk.polynomial_size()
    );

    let decomp_base_log = lwe_packing_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_packing_keyswitch_key.decomposition_level_count();
    let polynomial_size = lwe_packing_keyswitch_key.output_polynomial_size();
    let ciphertext_modulus = lwe_packing_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(decomp_level_count.0 * polynomial_size.0),
    );

    // Iterate over the input key elements and the destination lwe_packing_keyswitch_key memory
    for (input_key_element, mut packing_keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_packing_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, mut messages) in (1..=decomp_level_count.0)
            .rev()
            .map(DecompositionLevel)
            .zip(decomposition_plaintexts_buffer.chunks_exact_mut(polynomial_size.0))
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *messages.get_mut(0).0 =
                DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand()
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_glwe_ciphertext_list(
            output_glwe_sk,
            &mut packing_keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_parameters,
            generator,
        );
    }
}

pub fn allocate_and_generate_new_lwe_packing_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePackingKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_packing_keyswitch_key = LwePackingKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_glwe_sk.glwe_dimension(),
        output_glwe_sk.polynomial_size(),
        ciphertext_modulus,
    );

    generate_lwe_packing_keyswitch_key(
        input_lwe_sk,
        output_glwe_sk,
        &mut new_lwe_packing_keyswitch_key,
        noise_parameters,
        generator,
    );

    new_lwe_packing_keyswitch_key
}
