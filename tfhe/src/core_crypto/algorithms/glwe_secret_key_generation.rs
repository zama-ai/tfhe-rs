//! Module containing primitives pertaining to the generation of
//! [`GLWE secret keys`](`GlweSecretKey`).

use std::ops::RangeInclusive;

use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
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
/// ```rust
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
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// let mut glwe_secret_key =
///     GlweSecretKey::new_empty_key(0u64, glwe_size.to_glwe_dimension(), polynomial_size);
///
/// generate_binary_glwe_secret_key(&mut glwe_secret_key, &mut secret_generator);
///
/// // Check all coefficients are not zero as we just generated a new key
/// // Note probability of this assert failing is (1/2)^polynomial_size or ~5.6 * 10^-309 for a
/// // polynomial size of 1024.
/// assert!(!glwe_secret_key.as_ref().iter().all(|&elt| elt == 0));
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

/// Fill a [`GLWE secret key`](`GlweSecretKey`) with uniformly random binary coefficients.
///
/// The hamming weight of the secret key will be in: `(1-pmax)*len..=pmax*len`
/// where pmax is in ]0.5, 1.0]
///
/// # Panics
///
/// Panics if pmax <= 0.5 or pmax > 1.0
///
/// # Example
///
/// ```rust
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
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let pmax = 0.7;
///
/// let mut glwe_secret_key =
///     GlweSecretKey::new_empty_key(0u64, glwe_size.to_glwe_dimension(), polynomial_size);
///
/// generate_binary_glwe_secret_key_with_bounded_hamming_weight(
///     &mut glwe_secret_key,
///     &mut secret_generator,
///     pmax,
/// );
///
/// // Check all coefficients are not zero as we just generated a new key
/// assert!(!glwe_secret_key.as_ref().iter().all(|&elt| elt == 0));
/// ```
pub fn generate_binary_glwe_secret_key_with_bounded_hamming_weight<Scalar, InCont, Gen>(
    glwe_secret_key: &mut GlweSecretKey<InCont>,
    generator: &mut SecretRandomGenerator<Gen>,
    pmax: f64,
) where
    Scalar: UnsignedInteger + RandomGenerable<UniformBinary>,
    InCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        0.5 < pmax && pmax <= 1.0,
        "pmax parameter must be in ]0.5, 1.0]"
    );

    let bounds = RangeInclusive::new(
        ((1.0 - pmax) * glwe_secret_key.polynomial_size().0 as f64) as u128,
        (pmax * glwe_secret_key.polynomial_size().0 as f64) as u128,
    );

    for mut secret_poly in glwe_secret_key.as_mut_polynomial_list().iter_mut() {
        loop {
            generator.fill_slice_with_random_uniform_binary_bits(secret_poly.as_mut());
            let hamming_weight = secret_poly
                .as_ref()
                .iter()
                .copied()
                .map(|bit| -> u128 { bit.cast_into() })
                .sum::<u128>();

            if bounds.contains(&hamming_weight) {
                break;
            }
        }
    }
}
