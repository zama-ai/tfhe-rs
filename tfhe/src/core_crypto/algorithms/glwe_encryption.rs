use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::dispersion::DispersionParameter;
use crate::core_crypto::specification::parameters::*;

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

pub fn encrypt_glwe_ciphertext<Scalar, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    input_plaintext_list: &PlaintextListBase<InputCont>,
    output_glwe_ciphertext: &mut GlweCiphertextBase<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_glwe_ciphertext.polynomial_size().0 == input_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of output cipertext PlaintextCount of input. \
    Got {:?} in output, and {:?} in input.",
        output_glwe_ciphertext.polynomial_size(),
        input_plaintext_list.plaintext_count()
    );
    assert!(
        output_glwe_ciphertext.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let (mut mask, mut body) = output_glwe_ciphertext.get_mut_mask_and_body();

    generator.fill_slice_with_random_mask(mask.as_mut());

    generator.fill_slice_with_random_noise(body.as_mut(), noise_parameters);

    update_polynomial_with_wrapping_add(
        &mut body.as_mut_polynomial(),
        &input_plaintext_list.as_polynomial(),
    );

    update_polynomial_with_wrapping_add_multisum(
        &mut body.as_mut_polynomial(),
        &mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
}

pub fn encrypt_glwe_ciphertext_list<Scalar, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    input_plaintext_list: &PlaintextListBase<InputCont>,
    output_glwe_ciphertext_list: &mut GlweCiphertextListBase<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_glwe_ciphertext_list.polynomial_size().0
            * output_glwe_ciphertext_list.glwe_ciphertext_count().0
            == input_plaintext_list.plaintext_count().0,
        "TODO error message",
    );
    assert!(
        output_glwe_ciphertext_list.glwe_size().to_glwe_dimension()
            == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext_list.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext_list.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext_list.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let polynomial_size = output_glwe_ciphertext_list.polynomial_size();
    for (mut ciphertext, encoded) in output_glwe_ciphertext_list
        .iter_mut()
        .zip(input_plaintext_list.chunks_exact(polynomial_size.0))
    {
        encrypt_glwe_ciphertext(
            glwe_secret_key,
            &encoded,
            &mut ciphertext,
            noise_parameters,
            generator,
        );
    }
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

pub fn trivially_encrypt_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    output: &mut GlweCiphertextBase<OutputCont>,
    encoded: &PlaintextListBase<InputCont>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        output.polynomial_size().0 == encoded.plaintext_count().0,
        "TODO Error message"
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();

    mask.as_mut().fill(Scalar::ZERO);
    body.as_mut().copy_from_slice(encoded.as_ref());
}

pub fn allocate_and_trivially_encrypt_new_glwe_ciphertext<Scalar, InputCont>(
    glwe_size: GlweSize,
    encoded: &PlaintextListBase<InputCont>,
) -> GlweCiphertext<Scalar>
where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
{
    let polynomial_size = PolynomialSize(encoded.plaintext_count().0);

    let mut new_ct = GlweCiphertext::new(Scalar::ZERO, polynomial_size, glwe_size);

    let mut body = new_ct.get_mut_body();
    body.as_mut().copy_from_slice(encoded.as_ref());

    new_ct
}
