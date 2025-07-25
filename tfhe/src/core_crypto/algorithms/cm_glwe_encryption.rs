//! Module containing primitives pertaining to [`GLWE ciphertext
//! encryption`](`GlweCiphertext#glwe-encryption`).

use itertools::Itertools;

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::{
    slice_wrapping_scalar_div_assign, slice_wrapping_scalar_mul_assign,
};
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the GLWE assign encryption between all functions
/// needing it.
pub fn fill_cm_glwe_mask_and_bodies_for_encryption_assign<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    output_mask: &mut GlweMask<MaskCont>,
    output_bodies: &mut GlweBodyList<BodyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_bodies.ciphertext_modulus(),
        "Mismatched moduli between output_mask ({:?}) and output_body ({:?})",
        output_mask.ciphertext_modulus(),
        output_bodies.ciphertext_modulus()
    );

    let ciphertext_modulus = output_bodies.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    generator.unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
        output_bodies.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(output_bodies.as_mut(), torus_scaling);
    }

    for (glwe_secret_key, mut output_body) in
        glwe_secret_keys.iter().zip_eq(output_bodies.iter_mut())
    {
        polynomial_wrapping_add_multisum_assign(
            &mut output_body.as_mut_polynomial(),
            &output_mask.as_polynomial_list(),
            &glwe_secret_key.as_polynomial_list(),
        );
    }
}

/// Variant of [`encrypt_cm_glwe_ciphertext`] which assumes that the plaintexts to encrypt are
/// already loaded in the body of the output [`GLWE ciphertext`](`GlweCiphertext`), this is
/// sometimes useful to avoid allocating a [`PlaintextList`] in situ.
///
/// See this [`formal definition`](`GlweCiphertext#glwe-encryption`) for the definition
/// of the GLWE encryption algorithm.
pub fn encrypt_cm_glwe_ciphertext_assign<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    output: &mut CmGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_dimension() == glwe_secret_keys[0].glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_dimension(),
        glwe_secret_keys[0].glwe_dimension()
    );
    assert!(
        output.polynomial_size() == glwe_secret_keys[0].polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_keys[0].polynomial_size()
    );

    let (mut mask, mut bodies) = output.get_mut_mask_and_bodies();

    fill_cm_glwe_mask_and_bodies_for_encryption_assign(
        glwe_secret_keys,
        &mut mask,
        &mut bodies,
        noise_distribution,
        generator,
    );
}

/// Convenience function to share the core logic of the GLWE encryption between all functions
/// needing it.
pub fn fill_cm_glwe_mask_and_bodies_for_encryption<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    output_mask: &mut GlweMask<MaskCont>,
    output_bodies: &mut GlweBodyList<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_bodies.ciphertext_modulus()
    );

    let ciphertext_modulus = output_bodies.ciphertext_modulus();

    let polynomial_size = output_bodies.polynomial_size();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    generator.fill_slice_with_random_noise_from_distribution_custom_mod(
        output_bodies.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );

    for ((glwe_secret_key, mut output_body), encoded) in glwe_secret_keys
        .iter()
        .zip_eq(output_bodies.iter_mut())
        .zip_eq(encoded.chunks_exact(polynomial_size.0))
    {
        polynomial_wrapping_add_assign(
            &mut output_body.as_mut_polynomial(),
            &encoded.as_polynomial(),
        );

        if !ciphertext_modulus.is_native_modulus() {
            let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
            slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
            slice_wrapping_scalar_mul_assign(output_body.as_mut(), torus_scaling);
        }

        polynomial_wrapping_add_multisum_assign(
            &mut output_body.as_mut_polynomial(),
            &output_mask.as_polynomial_list(),
            &glwe_secret_key.as_polynomial_list(),
        );
    }
}

pub fn encrypt_cm_glwe_ciphertext<Scalar, NoiseDistribution, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    output_glwe_ciphertext: &mut CmGlweCiphertext<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_glwe_ciphertext.polynomial_size().0 * output_glwe_ciphertext.cm_dimension().0
            == input_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of output ciphertext PlaintextCount of input. \
    Got {:?} in output, and {:?} in input.",
        output_glwe_ciphertext.polynomial_size(),
        input_plaintext_list.plaintext_count()
    );
    assert!(
        output_glwe_ciphertext.glwe_dimension() == glwe_secret_keys[0].glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.glwe_dimension(),
        glwe_secret_keys[0].glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext.polynomial_size() == glwe_secret_keys[0].polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.polynomial_size(),
        glwe_secret_keys[0].polynomial_size()
    );

    let (mut mask, mut bodies) = output_glwe_ciphertext.get_mut_mask_and_bodies();

    fill_cm_glwe_mask_and_bodies_for_encryption(
        glwe_secret_keys,
        &mut mask,
        &mut bodies,
        input_plaintext_list,
        noise_distribution,
        generator,
    );
}

/// Decrypt a [`GLWE ciphertext`](`GlweCiphertext`) in a (scalar) plaintext list.
///
/// See [`encrypt_cm_glwe_ciphertext`] for usage.
///
/// # Formal Definition
///
/// See this [`formal definition`](`GlweCiphertext#glwe-decryption`) for the definition
/// of the GLWE decryption algorithm.
pub fn decrypt_cm_glwe_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    glwe_secret_keys: &[GlweSecretKey<KeyCont>],
    input_cm_glwe_ciphertext: &CmGlweCiphertext<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_plaintext_list.plaintext_count().0
            == input_cm_glwe_ciphertext.polynomial_size().0 * glwe_secret_keys.len(),
        "Mismatched output PlaintextCount {:?} and input PolynomialSize {:?}",
        output_plaintext_list.plaintext_count(),
        input_cm_glwe_ciphertext.polynomial_size()
    );
    assert!(
        glwe_secret_keys[0].glwe_dimension() == input_cm_glwe_ciphertext.glwe_dimension(),
        "Mismatched GlweDimension between glwe_secret_key {:?} and input_glwe_ciphertext {:?}",
        glwe_secret_keys[0].glwe_dimension(),
        input_cm_glwe_ciphertext.glwe_dimension()
    );
    assert!(
        glwe_secret_keys[0].polynomial_size() == input_cm_glwe_ciphertext.polynomial_size(),
        "Mismatched PolynomialSize between glwe_secret_key {:?} and input_glwe_ciphertext {:?}",
        glwe_secret_keys[0].polynomial_size(),
        input_cm_glwe_ciphertext.polynomial_size()
    );

    let polynomial_size = input_cm_glwe_ciphertext.polynomial_size();

    let ciphertext_modulus = input_cm_glwe_ciphertext.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let (mask, bodies) = input_cm_glwe_ciphertext.get_mask_and_bodies();

    for ((glwe_secret_key, body), mut output_plaintext_list) in glwe_secret_keys
        .iter()
        .zip_eq(bodies.iter())
        .zip_eq(output_plaintext_list.chunks_exact_mut(polynomial_size.0))
    {
        output_plaintext_list
            .as_mut()
            .copy_from_slice(body.as_ref());

        polynomial_wrapping_sub_multisum_assign(
            &mut output_plaintext_list.as_mut_polynomial(),
            &mask.as_polynomial_list(),
            &glwe_secret_key.as_polynomial_list(),
        );
    }

    if !ciphertext_modulus.is_native_modulus() {
        slice_wrapping_scalar_div_assign(
            output_plaintext_list.as_mut(),
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );
    }
}

pub fn trivially_encrypt_cm_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    output: &mut CmGlweCiphertext<OutputCont>,
    encoded: &PlaintextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        encoded.plaintext_count().0 == output.polynomial_size().0 * output.cm_dimension().0,
        "Mismatched input PlaintextCount {:?} and output PolynomialSize * CmDimension {:?}",
        encoded.plaintext_count(),
        output.polynomial_size().0 * output.cm_dimension().0
    );

    let (mut mask, mut body) = output.get_mut_mask_and_bodies();

    mask.as_mut().fill(Scalar::ZERO);
    body.as_mut().copy_from_slice(encoded.as_ref());

    let ciphertext_modulus = body.ciphertext_modulus();

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native | CiphertextModulusKind::Other => (),
        CiphertextModulusKind::NonNativePowerOfTwo => {
            slice_wrapping_scalar_mul_assign(
                body.as_mut(),
                ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            );
        }
    }
}

pub fn allocate_and_trivially_encrypt_new_cm_glwe_ciphertext<Scalar, InputCont>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    encoded: &PlaintextList<InputCont>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> CmGlweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
{
    let mut new_ct = CmGlweCiphertextOwned::new(
        Scalar::ZERO,
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        ciphertext_modulus,
    );

    let mut bodies = new_ct.get_mut_bodies();
    bodies.as_mut().copy_from_slice(encoded.as_ref());

    // Manage the non native power of 2 encoding
    if ciphertext_modulus.kind() == CiphertextModulusKind::NonNativePowerOfTwo {
        slice_wrapping_scalar_mul_assign(
            bodies.as_mut(),
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );
    }

    new_ct
}
