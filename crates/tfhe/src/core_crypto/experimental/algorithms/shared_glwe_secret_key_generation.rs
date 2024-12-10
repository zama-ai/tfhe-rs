use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::prelude::*;

pub fn allocate_and_generate_new_shared_glwe_secret_key_from_glwe_secret_key<Scalar, InCont>(
    in_large_glwe_key: &GlweSecretKey<InCont>,
    glwe_dimension_out: GlweDimension,
    shared_randomness: GlweSecretKeySharedCoefCount,
    polynomial_size: PolynomialSize,
) -> GlweSecretKeyOwned<Scalar>
where
    Scalar: RandomGenerable<UniformBinary> + Numeric,
    InCont: Container<Element = Scalar>,
{
    let mut small_glwe_secret_key =
        GlweSecretKey::new_empty_key(Scalar::ZERO, glwe_dimension_out, polynomial_size);

    small_glwe_secret_key.as_mut()[0..shared_randomness.0]
        .copy_from_slice(&in_large_glwe_key.as_ref()[0..shared_randomness.0]);
    small_glwe_secret_key
}
