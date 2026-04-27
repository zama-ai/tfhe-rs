//! Module containing primitives pertaining to `CommonMask LWE ciphertext encryption and
//! decryption`.

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::prelude::*;
use itertools::Itertools;

pub fn fill_cm_lwe_mask_and_bodies_for_encryption<
    Scalar,
    NoiseDistribution,
    KeyCont,
    EncodedCont,
    OutputMaskCont,
    OutputBodyCont,
    Gen,
>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    output_mask: &mut LweMask<OutputMaskCont>,
    output_bodies: &mut LweBodyList<OutputBodyCont>,
    encoded: &PlaintextList<EncodedCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    EncodedCont: Container<Element = Scalar>,
    OutputMaskCont: ContainerMut<Element = Scalar>,
    OutputBodyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_bodies.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_bodies.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // generate a randomly uniform mask
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

    for ((sk, body), encoded) in lwe_secret_keys
        .iter()
        .zip_eq(output_bodies.iter_mut())
        .zip_eq(encoded.iter())
    {
        // generate an error from the given noise_distribution
        let noise = generator
            .random_noise_from_distribution_custom_mod(noise_distribution, ciphertext_modulus);
        // compute the multisum between the secret key and the mask
        let mask_key_dot_product = slice_wrapping_dot_product(output_mask.as_ref(), sk.as_ref());

        // Store sum(ai * si) + delta * m + e in the body
        *body.data = mask_key_dot_product
            .wrapping_add(*encoded.0)
            .wrapping_add(noise);
    }
}

pub fn encrypt_cm_lwe_ciphertext<Scalar, NoiseDistribution, KeyCont, EncodedCont, OutputCont, Gen>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    output: &mut CmLweCiphertext<OutputCont>,
    encoded: &PlaintextList<EncodedCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    EncodedCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let (mut mask, mut body) = output.get_mut_mask_and_bodies();

    fill_cm_lwe_mask_and_bodies_for_encryption(
        lwe_secret_keys,
        &mut mask,
        &mut body,
        encoded,
        noise_distribution,
        generator,
    );
}

pub fn decrypt_cm_lwe_ciphertext<Scalar, KeyCont, InputCont>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    cm_lwe_ciphertext: &CmLweCiphertext<InputCont>,
) -> Vec<Plaintext<Scalar>>
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    for lwe_secret_key in lwe_secret_keys {
        assert!(
            cm_lwe_ciphertext.lwe_dimension() == lwe_secret_key.lwe_dimension(),
            "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
            cm_lwe_ciphertext.lwe_dimension(),
            lwe_secret_key.lwe_dimension()
        );
    }

    let ciphertext_modulus = cm_lwe_ciphertext.ciphertext_modulus();

    assert!(ciphertext_modulus.is_native_modulus());

    let (mask, bodies) = cm_lwe_ciphertext.get_mask_and_bodies();

    bodies
        .iter()
        .zip_eq(lwe_secret_keys.iter())
        .map(|(body, lwe_secret_key)| {
            let mask_key_dot_product =
                slice_wrapping_dot_product(mask.as_ref(), lwe_secret_key.as_ref());

            Plaintext(body.data.wrapping_sub(mask_key_dot_product))
        })
        .collect_vec()
}

pub fn allocate_and_encrypt_new_cm_lwe_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    EncodedCont,
    Gen,
>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    encoded: &PlaintextList<EncodedCont>,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> CmLweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    EncodedCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ct = CmLweCiphertextOwned::new(
        Scalar::ZERO,
        lwe_secret_keys[0].lwe_dimension(),
        CmDimension(encoded.as_ref().len()),
        ciphertext_modulus,
    );

    encrypt_cm_lwe_ciphertext(
        lwe_secret_keys,
        &mut new_ct,
        encoded,
        noise_distribution,
        generator,
    );

    new_ct
}

pub fn encrypt_cm_lwe_ciphertext_list<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    output: &mut CmLweCiphertextList<OutputCont>,
    encoded: &[PlaintextList<InputCont>],
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    for (mut output, encoded) in output.iter_mut().zip_eq(encoded.iter()) {
        encrypt_cm_lwe_ciphertext(
            lwe_secret_keys,
            &mut output,
            encoded,
            noise_distribution,
            generator,
        );
    }
}
