//! Module containing primitives pertaining to the generation of
//! [`LWE secret keys`](`LweSecretKey`).

use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Allocate a new [`LWE secret key`](`LweSecretKey`) and fill it with uniformly random binary
/// coefficients.
///
/// See [`encrypt_lwe_ciphertext`](`super::lwe_encryption::encrypt_lwe_ciphertext`) for usage.
pub fn allocate_and_generate_new_binary_lwe_secret_key<Scalar, Gen>(
    lwe_dimension: LweDimension,
    generator: &mut SecretRandomGenerator<Gen>,
) -> LweSecretKeyOwned<Scalar>
where
    Scalar: RandomGenerable<UniformBinary> + Numeric,
    Gen: ByteRandomGenerator,
{
    let mut lwe_secret_key = LweSecretKeyOwned::new_empty_key(Scalar::ZERO, lwe_dimension);

    generate_binary_lwe_secret_key(&mut lwe_secret_key, generator);

    lwe_secret_key
}

/// Fill an [`LWE secret key`](`LweSecretKey`) with uniformly random binary coefficients.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let mut lwe_secret_key = LweSecretKey::new_empty_key(0u64, lwe_dimension);
///
/// generate_binary_lwe_secret_key(&mut lwe_secret_key, &mut secret_generator);
///
/// // Check all coefficients are not zero as we just generated a new key
/// // Note probability of this assert failing is (1/2)^lwe_dimension or ~4.3 * 10^-224 for an LWE
/// // dimension of 742.
/// assert!(lwe_secret_key.as_ref().iter().all(|&elt| elt == 0) == false);
/// ```
pub fn generate_binary_lwe_secret_key<Scalar, InCont, Gen>(
    lwe_secret_key: &mut LweSecretKey<InCont>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: RandomGenerable<UniformBinary>,
    InCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    generator.fill_slice_with_random_uniform_binary(lwe_secret_key.as_mut());
}
