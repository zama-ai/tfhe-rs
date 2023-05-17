//! Module containing primitives pertaining to the generation of
//! [`LWE secret keys`](`LweSecretKey`).

use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::generate_binary_lwe_secret_key;

/// Allocate a new [`LWE secret key`](`LweSecretKey`) and fill it with uniformly random binary
/// coefficients.
/// phi: the number of non-zero coefficients
/// See [`encrypt_lwe_ciphertext`](`super::lwe_encryption::encrypt_lwe_ciphertext`) for usage.
///
/// /// Fill an [`LWE secret key`](`LweSecretKey`) with uniformly random binary coefficients.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(20);
/// let phi = LweDimension(15);
///
/// // Create the PRNG20
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let mut lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_partial_secret_key(
///         lwe_dimension,
///         &mut secret_generator,
///         phi,
///     );
/// // Check all coefficients are not zero as we just generated a new key
/// // Note probability of this assert failing is (1/2)^lwe_dimension or ~4.3 * 10^-224 for an LWE
/// // dimension of 742.
/// assert!(lwe_secret_key.as_ref().iter().all(|&elt| elt == 0) == false);
/// ```
pub fn allocate_and_generate_new_binary_lwe_partial_secret_key<Scalar, Gen>(
    lwe_dimension: LweDimension,
    generator: &mut SecretRandomGenerator<Gen>,
    phi: LweDimension,
) -> LweSecretKeyOwned<Scalar>
where
    Scalar: RandomGenerable<UniformBinary> + Numeric,
    Gen: ByteRandomGenerator,
{
    let mut lwe_secret_key = LweSecretKeyOwned::new_empty_key(Scalar::ZERO, phi);
    generate_binary_lwe_secret_key(&mut lwe_secret_key, generator);
    let mut lwe_secret_key_out = LweSecretKeyOwned::new_empty_key(Scalar::ZERO, lwe_dimension);
    lwe_secret_key_out
        .as_mut()
        .iter_mut()
        .zip(lwe_secret_key.as_ref().iter())
        .for_each(|(dst, &src)| *dst = src);
    //println!("Input Key = {:?}", lwe_secret_key.into_container().to_vec());
    //println!("Ouput Key = {:?}", lwe_secret_key_out.clone().into_container().to_vec());

    lwe_secret_key_out
}
