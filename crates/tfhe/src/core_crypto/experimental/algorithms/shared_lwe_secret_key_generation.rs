//! Module containing primitives pertaining to shared [`LweSecretKey`] generation.

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::commons::parameters::LweDimension;
use crate::core_crypto::commons::traits::{Container, ContainerMut};
use crate::core_crypto::entities::{LweSecretKey, LweSecretKeyOwned};

/// Fill an [`LWE secret key`](`LweSecretKey`) with coefficients from an already existing secret
/// key.
pub fn generate_fully_shared_binary_lwe_secret_key<Scalar, KeyCont, InputKeyCont>(
    lwe_secret_key_with_shared_coefficients: &mut LweSecretKey<KeyCont>,
    source_key_to_share_coefficients: &LweSecretKey<InputKeyCont>,
) where
    Scalar: Copy,
    KeyCont: ContainerMut<Element = Scalar>,
    InputKeyCont: Container<Element = Scalar>,
{
    let output_len = lwe_secret_key_with_shared_coefficients.as_ref().len();
    let input_len = source_key_to_share_coefficients.as_ref().len();

    assert!(
        output_len <= input_len,
        "Output lwe_secret_key_with_shared_coefficients (len {output_len})\
        has to be smaller than  source_key_to_share_coefficients (len {input_len})."
    );

    lwe_secret_key_with_shared_coefficients
        .as_mut()
        .copy_from_slice(&source_key_to_share_coefficients.as_ref()[..output_len]);
}

pub fn allocate_and_generate_fully_shared_binary_lwe_secret_key<Scalar, InputKeyCont>(
    source_key_to_share_coefficients: &LweSecretKey<InputKeyCont>,
    output_key_lwe_dimension: LweDimension,
) -> LweSecretKeyOwned<Scalar>
where
    Scalar: Numeric,
    InputKeyCont: Container<Element = Scalar>,
{
    let mut lwe_secret_key = LweSecretKey::new_empty_key(Scalar::ZERO, output_key_lwe_dimension);

    generate_fully_shared_binary_lwe_secret_key(
        &mut lwe_secret_key,
        source_key_to_share_coefficients,
    );

    lwe_secret_key
}
