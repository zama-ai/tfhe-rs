//! Module containing primitives pertaining to the generation of
//! [`GLWE secret keys`](`GlweSecretKey`).

use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Fill a [`GLWE secret key`](`GlweSecretKey`) with a predefined number of uniformly random binary
/// coefficients which can be smaller than the input key element count.
pub fn generate_binary_partial_glwe_secret_key<Scalar, KeyCont, Gen>(
    glwe_secret_key: &mut GlweSecretKey<KeyCont>,
    partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: RandomGenerable<UniformBinary> + Numeric,
    KeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        partial_glwe_secret_key_fill.0 <= glwe_secret_key.as_ref().len(),
        "partial_glwe_secret_key_fill ({partial_glwe_secret_key_fill:?}) \
        must be smaller than the total glwe_secret_key length ({}).",
        glwe_secret_key.as_ref().len()
    );

    // Generate random coefficients to partially fill the key
    generator.fill_slice_with_random_uniform_binary(
        &mut glwe_secret_key.as_mut()[..partial_glwe_secret_key_fill.0],
    );
}

/// Allocate a new [`GLWE secret key`](`GlweSecretKey`) and fill it with uniformly random binary
/// coefficients.
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(8);
/// let partial_glwe_secret_key_fill = PartialGlweSecretKeyRandomCoefCount(5);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let mut glwe_secret_key: GlweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_partial_glwe_secret_key(
///         glwe_size.to_glwe_dimension(),
///         polynomial_size,
///         partial_glwe_secret_key_fill,
///         &mut secret_generator,
///     );
/// assert!(glwe_secret_key.as_ref()[partial_glwe_secret_key_fill.0..]
///     .iter()
///     .all(|x| *x == 0u64));
/// ```
pub fn allocate_and_generate_new_binary_partial_glwe_secret_key<Scalar, Gen>(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount,
    generator: &mut SecretRandomGenerator<Gen>,
) -> GlweSecretKeyOwned<Scalar>
where
    Scalar: RandomGenerable<UniformBinary> + Numeric,
    Gen: ByteRandomGenerator,
{
    let mut glwe_secret_key =
        GlweSecretKeyOwned::new_empty_key(Scalar::ZERO, glwe_dimension, polynomial_size);

    generate_binary_partial_glwe_secret_key(
        &mut glwe_secret_key,
        partial_glwe_secret_key_fill,
        generator,
    );

    glwe_secret_key
}
