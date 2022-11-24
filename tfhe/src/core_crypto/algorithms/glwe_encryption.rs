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
