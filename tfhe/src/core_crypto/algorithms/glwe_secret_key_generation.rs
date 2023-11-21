//! Module containing primitives pertaining to the generation of
//! [`GLWE secret keys`](`GlweSecretKey`).

use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Allocate a new [`GLWE secret key`](`GlweSecretKey`) and fill it with uniformly random binary
/// coefficients.
///
/// See [`encrypt_glwe_ciphertext`](`super::glwe_encryption::encrypt_glwe_ciphertext`)
/// for usage.
pub fn allocate_and_generate_new_binary_glwe_secret_key<Scalar, Gen>(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    generator: &mut SecretRandomGenerator<Gen>,
) -> GlweSecretKeyOwned<Scalar>
where
    Scalar: RandomGenerable<UniformBinary> + Numeric,
    Gen: ByteRandomGenerator,
{
    let mut glwe_secret_key =
        GlweSecretKeyOwned::new_empty_key(Scalar::ZERO, glwe_dimension, polynomial_size);

    generate_binary_glwe_secret_key(&mut glwe_secret_key, generator);

    glwe_secret_key
}

/// Fill a [`GLWE secret key`](`GlweSecretKey`) with uniformly random binary coefficients.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweSecretKey creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let mut glwe_secret_key =
///     GlweSecretKey::new_empty_key(0u64, glwe_size.to_glwe_dimension(), polynomial_size);
///
/// generate_binary_glwe_secret_key(&mut glwe_secret_key, &mut secret_generator);
///
/// // Check all coefficients are not zero as we just generated a new key
/// // Note probability of this assert failing is (1/2)^polynomial_size or ~5.6 * 10^-309 for a
/// // polynomial size of 1024.
/// assert!(glwe_secret_key.as_ref().iter().all(|&elt| elt == 0) == false);
/// ```
pub fn generate_binary_glwe_secret_key<Scalar, InCont, Gen>(
    glwe_secret_key: &mut GlweSecretKey<InCont>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: RandomGenerable<UniformBinary>,
    InCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    generator.fill_slice_with_random_uniform_binary(glwe_secret_key.as_mut());
}
