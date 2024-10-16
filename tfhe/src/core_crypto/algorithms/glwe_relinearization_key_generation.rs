//! Module containing primitives pertaining to [`GLWE relinearization key
//! generation`](`GlweRelinearizationKey`).

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, PolynomialCount};

/// Fill a [`GLWE Relinearization key`](`GlweRelinearizationKey`)
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
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
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
/// let relin_key = allocate_and_generate_glwe_relinearization_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// assert!(!relin_key.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn generate_glwe_relinearization_key<
    Scalar,
    NoiseDistribution,
    GlweKeyCont,
    RelinKeyCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    glwe_relinearization_key: &mut GlweRelinearizationKey<RelinKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    GlweKeyCont: Container<Element = Scalar>,
    RelinKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        glwe_secret_key.glwe_dimension(),
        glwe_relinearization_key.glwe_dimension()
    );
    assert_eq!(
        glwe_secret_key.polynomial_size(),
        glwe_relinearization_key.polynomial_size()
    );

    // We retrieve decomposition arguments
    let glwe_dimension = glwe_relinearization_key.glwe_dimension();
    let decomp_level_count = glwe_relinearization_key.decomposition_level_count();
    let decomp_base_log = glwe_relinearization_key.decomposition_base_log();
    let polynomial_size = glwe_relinearization_key.polynomial_size();
    let ciphertext_modulus = glwe_relinearization_key.ciphertext_modulus();

    // Construct the "glwe secret key" we want to keyswitch from, this is made up of the square
    // and cross terms appearing when tensoring the glwe_secret_key with itself
    let mut input_sk_poly_list = PolynomialList::new(
        Scalar::ZERO,
        polynomial_size,
        PolynomialCount(glwe_dimension.0 * (glwe_dimension.0 + 1) / 2),
    );
    let mut input_sk_poly_list_iter = input_sk_poly_list.iter_mut();

    // We compute the polynomial multiplication in the same way,
    // regardless of the ciphertext modulus.
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
        glwe_relinearization_key.as_mut(),
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
        noise_distribution,
        generator,
    );
}

pub fn allocate_and_generate_glwe_relinearization_key<Scalar, NoiseDistribution, KeyCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> GlweRelinearizationKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut glwe_relinearization_key = GlweRelinearizationKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        glwe_secret_key.polynomial_size(),
        ciphertext_modulus,
    );
    generate_glwe_relinearization_key(
        glwe_secret_key,
        &mut glwe_relinearization_key,
        noise_distribution,
        generator,
    );

    glwe_relinearization_key
}
