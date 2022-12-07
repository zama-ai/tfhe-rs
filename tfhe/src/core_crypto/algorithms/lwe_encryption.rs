//! Module containing functions related to LWE ciphertext encryption and decryption

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn encrypt_lwe_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let (mut mask, body) = output.get_mut_mask_and_body();

    generator.fill_slice_with_random_mask(mask.as_mut());

    // generate an error from the normal distribution described by std_dev
    *body.0 = generator.random_noise(noise_parameters);

    // compute the multisum between the secret key and the mask
    *body.0 = (*body.0).wrapping_add(slice_wrapping_dot_product(
        mask.as_ref(),
        lwe_secret_key.as_ref(),
    ));

    *body.0 = (*body.0).wrapping_add(encoded.0);
}

pub fn allocate_and_encrypt_new_lwe_ciphertext<Scalar, KeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ct =
        LweCiphertextOwned::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size());

    encrypt_lwe_ciphertext(
        lwe_secret_key,
        &mut new_ct,
        encoded,
        noise_parameters,
        generator,
    );

    new_ct
}

pub fn trivially_encrypt_lwe_ciphertext<Scalar, OutputCont>(
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
{
    output
        .as_mut()
        .iter_mut()
        .for_each(|elt| *elt = Scalar::ZERO);

    *output.get_mut_body().0 = encoded.0
}

pub fn allocate_and_trivially_encrypt_new_lwe_ciphertext<Scalar>(
    lwe_size: LweSize,
    encoded: Plaintext<Scalar>,
) -> LweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
{
    let mut new_ct = LweCiphertextOwned::new(Scalar::ZERO, lwe_size);

    *new_ct.get_mut_body().0 = encoded.0;

    new_ct
}

pub fn decrypt_lwe_ciphertext<Scalar, KeyCont, InputCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    lwe_ciphertext: &LweCiphertext<InputCont>,
) -> Plaintext<Scalar>
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        lwe_ciphertext.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        lwe_ciphertext.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let (mask, body) = lwe_ciphertext.get_mask_and_body();

    Plaintext(body.0.wrapping_sub(slice_wrapping_dot_product(
        mask.as_ref(),
        lwe_secret_key.as_ref(),
    )))
}

pub fn encrypt_lwe_ciphertext_list<Scalar, KeyCont, OutputCont, InputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output cipertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    for (encoded_plaintext_ref, mut ciphertext) in encoded.iter().zip(output.iter_mut()) {
        encrypt_lwe_ciphertext(
            lwe_secret_key,
            &mut ciphertext,
            encoded_plaintext_ref.into(),
            noise_parameters,
            generator,
        )
    }
}

use rayon::prelude::*;
pub fn par_encrypt_lwe_ciphertext_list<Scalar, KeyCont, OutputCont, InputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output cipertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .par_fork_lwe_list_to_lwe::<Scalar>(output.lwe_ciphertext_count(), output.lwe_size())
        .unwrap();

    encoded
        .par_iter()
        .zip(output.par_iter_mut())
        .zip(gen_iter)
        .for_each(|((encoded_plaintext_ref, mut ciphertext), mut generator)| {
            encrypt_lwe_ciphertext(
                lwe_secret_key,
                &mut ciphertext,
                encoded_plaintext_ref.into(),
                noise_parameters,
                &mut generator,
            )
        });
}

pub fn encrypt_lwe_ciphertext_with_public_key<Scalar, KeyCont, OutputCont, Gen>(
    lwe_public_key: &LwePublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_public_key.lwe_size().to_lwe_dimension(),
        "Mismatch between LweDimension of output cipertext and input public key. \
        Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_public_key.lwe_size().to_lwe_dimension()
    );

    output.as_mut().fill(Scalar::ZERO);

    let mut ct_choice = vec![Scalar::ZERO; lwe_public_key.zero_encryption_count().0];

    generator.fill_slice_with_random_uniform_binary(&mut ct_choice);

    // Add the public encryption of zeros to get the zero encryption
    for (&chosen, public_encryption_of_zero) in ct_choice.iter().zip(lwe_public_key.iter()) {
        if chosen == Scalar::ONE {
            lwe_ciphertext_addition_assign(output, &public_encryption_of_zero);
        }
    }

    // Add encoded plaintext
    let body = output.get_mut_body();
    *body.0 = (*body.0).wrapping_add(encoded.0);
}
