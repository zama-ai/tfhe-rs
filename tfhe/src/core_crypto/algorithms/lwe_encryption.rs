use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::{Container, ContainerMut};
use crate::core_crypto::entities::encoded::Encoded;
use crate::core_crypto::entities::lwe_ciphertext::{LweCiphertext, LweCiphertextBase};
use crate::core_crypto::entities::lwe_secret_key::LweSecretKeyBase;
use crate::core_crypto::specification::dispersion::DispersionParameter;

pub fn encrypt_lwe_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKeyBase<KeyCont>,
    output: &mut LweCiphertextBase<OutputCont>,
    encoded: &Encoded<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let (mut mask, body) = output.get_mut_mask_and_body();

    generator.fill_slice_with_random_mask(mask.as_mut());

    // generate an error from the normal distribution described by std_dev
    *body.0 = generator.random_noise(noise_parameters);

    // compute the multisum between the secret key and the mask
    *body.0 = (*body.0).wrapping_add(wrapping_dot_product(mask.as_ref(), lwe_secret_key.as_ref()));

    *body.0 = (*body.0).wrapping_add(encoded.0);
}

pub fn allocate_and_encrypt_new_lwe_ciphertext<Scalar, KeyCont, Gen>(
    lwe_secret_key: &LweSecretKeyBase<KeyCont>,
    encoded: &Encoded<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweCiphertext<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ct = LweCiphertext::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size());

    encrypt_lwe_ciphertext(
        lwe_secret_key,
        &mut new_ct,
        encoded,
        noise_parameters,
        generator,
    );

    new_ct
}

pub fn decrypt_lwe_ciphertext<Scalar, KeyCont, InputCont>(
    lwe_secret_key: &LweSecretKeyBase<KeyCont>,
    lwe_ciphertext: &LweCiphertextBase<InputCont>,
) -> Encoded<Scalar>
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    let (mask, body) = lwe_ciphertext.get_mask_and_body();

    Encoded(
        body.0
            .wrapping_sub(wrapping_dot_product(mask.as_ref(), lwe_secret_key.as_ref())),
    )
}
