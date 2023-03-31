//! Module containing primitives pertaining to [`GLWE relinearisation key
//! generation`](`GlweRelinearisationKey`).

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, PolynomialCount};

/// Fill a [`GLWE relinearisation key`](`GlweRelinearisationKey`)
/// with an actual key.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(3);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(7);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key: GlweSecretKey<Vec<u64>> = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// allocate_and_generate_glwe_relinearisation_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
/// ```
pub fn generate_glwe_relinearisation_key<Scalar, GlweKeyCont, RelinKeyCont, Gen>(
    glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    glwe_relinearisation_key: &mut GlweRelinearisationKey<RelinKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    GlweKeyCont: Container<Element = Scalar>,
    RelinKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        glwe_secret_key.glwe_dimension(),
        glwe_relinearisation_key.glwe_dimension()
    );
    assert_eq!(
        glwe_secret_key.polynomial_size(),
        glwe_relinearisation_key.polynomial_size()
    );

    // We retrieve decomposition arguments
    let glwe_dimension = glwe_relinearisation_key.glwe_dimension();
    let decomp_level_count = glwe_relinearisation_key.decomposition_level_count();
    let decomp_base_log = glwe_relinearisation_key.decomposition_base_log();
    let polynomial_size = glwe_relinearisation_key.polynomial_size();
    let ciphertext_modulus = glwe_relinearisation_key.ciphertext_modulus();

    // Construct the "glwe secret key" we want to keyswitch from, this is made up of the square
    // and cross terms appearing when squaring glwe_secret_key
    let mut input_sk_poly_list = PolynomialList::new(
        Scalar::ZERO,
        polynomial_size,
        PolynomialCount(glwe_dimension.0 * (glwe_dimension.0 + 1) / 2),
    );
    let mut input_sk_poly_list_iter = input_sk_poly_list.iter_mut();

    for i in 0..glwe_dimension.0 {
        for j in 0..i + 1 {
            let mut input_key_pol = input_sk_poly_list_iter.next().unwrap();
            polynomial_wrapping_sub_mul_assign(
                &mut input_key_pol,
                &glwe_secret_key.as_polynomial_list().get(i),
                &glwe_secret_key.as_polynomial_list().get(j),
            );
        }
    }

    let input_glwe_sk = GlweSecretKey::from_container(input_sk_poly_list.as_ref(), polynomial_size);

    let mut glwe_ks_key = GlweKeyswitchKey::from_container(
        glwe_relinearisation_key.as_mut(),
        decomp_base_log,
        decomp_level_count,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    generate_glwe_keyswitch_key(
        &input_glwe_sk,
        glwe_secret_key,
        &mut glwe_ks_key,
        noise_parameters,
        generator,
    );
}

pub fn allocate_and_generate_glwe_relinearisation_key<Scalar, KeyCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> GlweRelinearisationKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut glwe_relinearisation_key = GlweRelinearisationKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        glwe_secret_key.polynomial_size(),
        ciphertext_modulus,
    );
    generate_glwe_relinearisation_key(
        glwe_secret_key,
        &mut glwe_relinearisation_key,
        noise_parameters,
        generator,
    );

    glwe_relinearisation_key
}

/*
 * Parallel variant of [`generate_glwe_relinearisation_key`]. You may want to use this
 * variant for better key generation times.
 */
