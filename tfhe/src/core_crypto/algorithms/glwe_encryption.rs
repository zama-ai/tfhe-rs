use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::dispersion::DispersionParameter;

pub fn encrypt_glwe_ciphertext_in_place<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    output: &mut GlweCiphertextBase<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();

    generator.fill_slice_with_random_mask(mask.as_mut());

    generator.update_slice_with_wrapping_add_random_noise(body.as_mut(), noise_parameters);

    update_polynomial_with_wrapping_add_multisum(
        &mut body.as_mut_polynomial(),
        &mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
}

pub fn decrypt_glwe_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    input_glwe_ciphertext: &GlweCiphertextBase<InputCont>,
    output_plaintext_list: &mut PlaintextListBase<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_plaintext_list.plaintext_count().0 == input_glwe_ciphertext.polynomial_size().0,
        "TODO Error message"
    );
    assert!(
        glwe_secret_key.glwe_dimension() == input_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        "TODO Error message"
    );
    assert!(
        glwe_secret_key.polynomial_size() == input_glwe_ciphertext.polynomial_size(),
        "TODO Error message"
    );

    let (mask, body) = input_glwe_ciphertext.get_mask_and_body();
    output_plaintext_list
        .as_mut()
        .copy_from_slice(body.as_ref());
    update_polynomial_with_wrapping_sub_multisum(
        &mut output_plaintext_list.as_mut_polynomial(),
        &mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
}

pub fn decrypt_glwe_ciphertext_list<Scalar, KeyCont, InputCont, OutputCont>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    input_glwe_ciphertext_list: &GlweCiphertextListBase<InputCont>,
    output_plaintext_list: &mut PlaintextListBase<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_plaintext_list.plaintext_count().0
            == input_glwe_ciphertext_list.polynomial_size().0
                * input_glwe_ciphertext_list.glwe_ciphertext_count().0,
        "TODO Error message"
    );
    assert!(
        glwe_secret_key.glwe_dimension()
            == input_glwe_ciphertext_list.glwe_size().to_glwe_dimension(),
        "TODO Error message"
    );
    assert!(
        glwe_secret_key.polynomial_size() == input_glwe_ciphertext_list.polynomial_size(),
        "TODO Error message"
    );

    for (ciphertext, mut output_sublist) in input_glwe_ciphertext_list
        .iter()
        .zip(output_plaintext_list.chunks_exact_mut(input_glwe_ciphertext_list.polynomial_size().0))
    {
        decrypt_glwe_ciphertext(glwe_secret_key, &ciphertext, &mut output_sublist);
    }
}
