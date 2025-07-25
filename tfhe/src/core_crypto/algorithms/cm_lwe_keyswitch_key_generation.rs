//! Module containing primitives pertaining to [`LWE keyswitch keys
//! generation`](`CmLweKeyswitchKey#key-switching-key`) and [`seeded LWE keyswitch keys
//! generation`](`SeededLweKeyswitchKey`).

use itertools::Itertools;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn generate_cm_lwe_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_cm_lwe_sks: &[LweSecretKey<InputKeyCont>],
    output_cm_lwe_sks: &[LweSecretKey<OutputKeyCont>],
    cm_lwe_keyswitch_key: &mut CmLweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        cm_lwe_keyswitch_key.input_lwe_dimension() == input_cm_lwe_sks[0].lwe_dimension(),
        "The destination CmLweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        cm_lwe_keyswitch_key.input_lwe_dimension(),
        input_cm_lwe_sks[0].lwe_dimension()
    );
    assert!(
        cm_lwe_keyswitch_key.output_lwe_dimension() == output_cm_lwe_sks[0].lwe_dimension(),
        "The destination CmLweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        cm_lwe_keyswitch_key.output_lwe_dimension(),
        output_cm_lwe_sks[0].lwe_dimension()
    );

    let decomp_base_log = cm_lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = cm_lwe_keyswitch_key.decomposition_level_count();
    let cm_dimension = cm_lwe_keyswitch_key.cm_dimension();
    let ciphertext_modulus = cm_lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffers = (0..decomp_level_count.0)
        .map(|_| PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(cm_dimension.0)))
        .collect_vec();

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_bit_index, mut keyswitch_key_block) in
        cm_lwe_keyswitch_key.iter_mut().enumerate()
    {
        for (pt_index, input_cm_lwe_sk) in input_cm_lwe_sks.iter().enumerate() {
            // We fill the buffer with the powers of the key elements
            for (level, message) in (1..=decomp_level_count.0)
                .rev()
                .map(DecompositionLevel)
                .zip_eq(decomposition_plaintexts_buffers.iter_mut())
            {
                // Here  we take the decomposition term from the native torus, bring it to the torus
                // we are working with by dividing by the scaling factor and the
                // encryption will take care of mapping that back to the native
                // torus
                message.as_mut()[pt_index] = DecompositionTerm::new(
                    level,
                    decomp_base_log,
                    input_cm_lwe_sk.as_ref()[input_key_bit_index],
                )
                .to_recomposition_summand()
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
            }
        }

        encrypt_cm_lwe_ciphertext_list(
            output_cm_lwe_sks,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffers,
            noise_distribution,
            generator,
        );
    }
}

/// Allocate a new [`LWE keyswitch key`](`CmLweKeyswitchKey`) and fill it with an actual
/// keyswitching key constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// See [`cm_keyswitch_lwe_ciphertext`] for usage.
#[allow(clippy::too_many_arguments)]
pub fn allocate_and_generate_new_cm_lwe_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_cm_lwe_sks: &[LweSecretKey<InputKeyCont>],
    output_cm_lwe_sks: &[LweSecretKey<OutputKeyCont>],
    cm_dimension: CmDimension,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> CmLweKeyswitchKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_cm_lwe_keyswitch_key = CmLweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_cm_lwe_sks[0].lwe_dimension(),
        output_cm_lwe_sks[0].lwe_dimension(),
        cm_dimension,
        ciphertext_modulus,
    );

    generate_cm_lwe_keyswitch_key(
        input_cm_lwe_sks,
        output_cm_lwe_sks,
        &mut new_cm_lwe_keyswitch_key,
        noise_distribution,
        generator,
    );

    new_cm_lwe_keyswitch_key
}
