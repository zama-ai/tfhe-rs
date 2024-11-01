//! Module containing primitives pertaining to [`LWE trace packing keyswitch key
//! generation`](`LweTracePackingKeyswitchKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use crate::core_crypto::commons::math::random::{
    Distribution, RandomGenerable, Uniform, UniformBinary,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::polynomial_algorithms::apply_automorphism_wrapping_add_assign;
use crate::core_crypto::prelude::CiphertextModulus;

/// Fill a [`GLWE secret key`](`GlweSecretKey`) with an actual key derived from an
/// [`LWE secret key`](`LweSecretKey`) for use in the [`LWE trace packing keyswitch key`]
/// (`LweTracePackingKeyswitchKey`)
pub fn generate_tpksk_output_glwe_secret_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &mut GlweSecretKey<OutputKeyCont>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: RandomGenerable<UniformBinary> + UnsignedInteger,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let lwe_dimension = input_lwe_secret_key.lwe_dimension();
    let glwe_dimension = output_glwe_secret_key.glwe_dimension();
    let glwe_poly_size = output_glwe_secret_key.polynomial_size();

    assert!(
        lwe_dimension.0 <= glwe_dimension.0 * glwe_poly_size.0,
        "Mismatched between input_lwe_secret_key dimension {:?} and number of coefficients of \
        output_glwe_secret_key {:?}.",
        lwe_dimension.0,
        glwe_dimension.0 * glwe_poly_size.0
    );

    let glwe_key_container = output_glwe_secret_key.as_mut();

    if lwe_dimension.0 < glwe_dimension.0 * glwe_poly_size.0 {
        let additional_key_bits = LweSecretKey::generate_new_binary(
            LweDimension(glwe_dimension.0 * glwe_poly_size.0 - lwe_dimension.0),
            generator,
        );
        let extended_lwe_key_iter = input_lwe_secret_key
            .as_ref()
            .iter()
            .chain(additional_key_bits.as_ref().iter());
        for (index, lwe_key_bit) in extended_lwe_key_iter.enumerate() {
            if index % glwe_poly_size.0 == 0 {
                glwe_key_container[index] = *lwe_key_bit;
            } else {
                let rem = index % glwe_poly_size.0;
                let quo = index / glwe_poly_size.0;
                let new_index = (quo + 1) * glwe_poly_size.0 - rem;
                if ciphertext_modulus.is_compatible_with_native_modulus() {
                    glwe_key_container[new_index] = lwe_key_bit.wrapping_neg();
                } else {
                    glwe_key_container[new_index] = lwe_key_bit.wrapping_neg_custom_mod(
                        ciphertext_modulus.get_custom_modulus().cast_into(),
                    );
                }
            }
        }
    } else {
        let extended_lwe_key_iter = input_lwe_secret_key.as_ref().iter();
        for (index, lwe_key_bit) in extended_lwe_key_iter.enumerate() {
            if index % glwe_poly_size.0 == 0 {
                glwe_key_container[index] = *lwe_key_bit;
            } else {
                let rem = index % glwe_poly_size.0;
                let quo = index / glwe_poly_size.0;
                let new_index = (quo + 1) * glwe_poly_size.0 - rem;
                if ciphertext_modulus.is_compatible_with_native_modulus() {
                    glwe_key_container[new_index] = lwe_key_bit.wrapping_neg();
                } else {
                    glwe_key_container[new_index] = lwe_key_bit.wrapping_neg_custom_mod(
                        ciphertext_modulus.get_custom_modulus().cast_into(),
                    );
                }
            }
        }
    }
}

/// Fill an [`LWE trace packing keyswitch key`](`LweTracePackingKeyswitchKey`)
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
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let lwe_dimension = LweDimension(900);
/// let noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
///
/// let mut seeder = new_seeder();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let mut glwe_secret_key =
///     GlweSecretKey::new_empty_key(0u64, glwe_size.to_glwe_dimension(), polynomial_size);
///
/// generate_tpksk_output_glwe_secret_key(
///     &lwe_secret_key,
///     &mut glwe_secret_key,
///     ciphertext_modulus,
///     &mut secret_generator,
/// );
///
/// let decomp_base_log = DecompositionBaseLog(2);
/// let decomp_level_count = DecompositionLevelCount(8);
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
///
/// let mut lwe_tpksk = LweTracePackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     lwe_dimension.to_lwe_size(),
///     glwe_size,
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_trace_packing_keyswitch_key(
///     &glwe_secret_key,
///     &mut lwe_tpksk,
///     noise_distribution,
///     &mut encryption_generator,
/// );
///
/// assert!(!lwe_tpksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn generate_lwe_trace_packing_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_glwe_secret_key: &GlweSecretKey<InputKeyCont>,
    lwe_tpksk: &mut LweTracePackingKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = lwe_tpksk.ciphertext_modulus();
    if ciphertext_modulus.is_compatible_with_native_modulus() {
        generate_lwe_trace_packing_keyswitch_key_native_mod_compatible(
            input_glwe_secret_key,
            lwe_tpksk,
            noise_distribution,
            generator,
        )
    } else {
        generate_lwe_trace_packing_keyswitch_key_other_mod(
            input_glwe_secret_key,
            lwe_tpksk,
            noise_distribution,
            generator,
        )
    }
}

pub fn generate_lwe_trace_packing_keyswitch_key_native_mod_compatible<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_glwe_secret_key: &GlweSecretKey<InputKeyCont>,
    lwe_tpksk: &mut LweTracePackingKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        input_glwe_secret_key.glwe_dimension(),
        lwe_tpksk.output_glwe_key_dimension()
    );
    assert_eq!(
        input_glwe_secret_key.polynomial_size(),
        lwe_tpksk.polynomial_size()
    );

    let ciphertext_modulus = lwe_tpksk.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // We retrieve decomposition arguments
    let glwe_dimension = lwe_tpksk.output_glwe_key_dimension();
    let decomp_level_count = lwe_tpksk.decomposition_level_count();
    let decomp_base_log = lwe_tpksk.decomposition_base_log();
    let polynomial_size = lwe_tpksk.polynomial_size();

    let automorphism_index_iter = 1..=polynomial_size.log2().0;

    //let gen_iter = generator
    //    .try_fork_from_config(lwe_tpksk.encryption_fork_config(Uniform, noise_distribution))
    //    .unwrap();

    // loop over the before key blocks
    //for ((auto_index, glwe_keyswitch_block), mut loop_generator) in automorphism_index_iter
    for (auto_index, glwe_keyswitch_block) in automorphism_index_iter
        .zip(lwe_tpksk.iter_mut())
        //.zip(gen_iter)
    {
        let mut auto_glwe_sk_poly_list = PolynomialList::new(
            Scalar::ZERO,
            input_glwe_secret_key.polynomial_size(),
            PolynomialCount(input_glwe_secret_key.glwe_dimension().0),
        );
        let input_key_poly_list = input_glwe_secret_key.as_polynomial_list();
        let input_key_poly_iter = input_key_poly_list.iter();
        let auto_key_poly_iter = auto_glwe_sk_poly_list.iter_mut();
        for (mut auto_key_poly, input_key_poly) in auto_key_poly_iter.zip(input_key_poly_iter) {
            apply_automorphism_wrapping_add_assign(
                &mut auto_key_poly,
                &input_key_poly,
                2_usize.pow(auto_index as u32) + 1,
            );
        }
        let mut glwe_ksk = GlweKeyswitchKey::from_container(
            glwe_keyswitch_block.into_container(),
            decomp_base_log,
            decomp_level_count,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );
        let auto_glwe_sk =
            GlweSecretKey::from_container(auto_glwe_sk_poly_list.into_container(), polynomial_size);
        generate_glwe_keyswitch_key(
            &auto_glwe_sk,
            input_glwe_secret_key,
            &mut glwe_ksk,
            noise_distribution,
            //&mut loop_generator,
            generator,
        );
    }
}

pub fn generate_lwe_trace_packing_keyswitch_key_other_mod<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_glwe_secret_key: &GlweSecretKey<InputKeyCont>,
    lwe_tpksk: &mut LweTracePackingKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        input_glwe_secret_key.glwe_dimension(),
        lwe_tpksk.output_glwe_key_dimension()
    );
    assert_eq!(
        input_glwe_secret_key.polynomial_size(),
        lwe_tpksk.polynomial_size()
    );

    let ciphertext_modulus = lwe_tpksk.ciphertext_modulus();
    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    // Convert the input glwe_ secret key to a polynomial list
    // modulo the native modulus while keeping the sign
    let mut native_glwe_secret_key_poly_list = PolynomialList::new(
        Scalar::ZERO,
        input_glwe_secret_key.polynomial_size(),
        PolynomialCount(input_glwe_secret_key.glwe_dimension().0),
    );
    // Need to go from custom to native modulus while preserving the sign
    let modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
    input_glwe_secret_key
        .as_ref()
        .iter()
        .zip(native_glwe_secret_key_poly_list.as_mut().iter_mut())
        .for_each(|(&src, dst)| {
            if src > modulus_as_scalar / Scalar::TWO {
                *dst = src.wrapping_sub(modulus_as_scalar)
            } else {
                *dst = src
            }
        });

    // We retrieve decomposition arguments
    let glwe_dimension = lwe_tpksk.output_glwe_key_dimension();
    let decomp_level_count = lwe_tpksk.decomposition_level_count();
    let decomp_base_log = lwe_tpksk.decomposition_base_log();
    let polynomial_size = lwe_tpksk.polynomial_size();

    let automorphism_index_iter = 1..=polynomial_size.log2().0;

    let gen_iter = generator
        .try_fork_from_config(lwe_tpksk.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    // loop over the before key blocks
    for ((auto_index, glwe_keyswitch_block), mut loop_generator) in automorphism_index_iter
        .zip(lwe_tpksk.iter_mut())
        .zip(gen_iter)
    {
        let mut auto_glwe_sk_poly_list = PolynomialList::new(
            Scalar::ZERO,
            input_glwe_secret_key.polynomial_size(),
            PolynomialCount(input_glwe_secret_key.glwe_dimension().0),
        );
        let native_key_poly_iter = native_glwe_secret_key_poly_list.iter();
        let auto_key_poly_iter = auto_glwe_sk_poly_list.iter_mut();
        for (mut auto_key_poly, native_key_poly) in auto_key_poly_iter.zip(native_key_poly_iter) {
            apply_automorphism_wrapping_add_assign(
                &mut auto_key_poly,
                &native_key_poly,
                2_usize.pow(auto_index as u32) + 1,
            );
        }

        let mut glwe_ksk = GlweKeyswitchKey::from_container(
            glwe_keyswitch_block.into_container(),
            decomp_base_log,
            decomp_level_count,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );
        let auto_glwe_sk =
            GlweSecretKey::from_container(auto_glwe_sk_poly_list.into_container(), polynomial_size);
        generate_glwe_keyswitch_key(
            &auto_glwe_sk,
            input_glwe_secret_key,
            &mut glwe_ksk,
            noise_distribution,
            &mut loop_generator,
        );
    }
}

/// Allocate a new [`LWE trace packing keyswitch key`](`LweTracePackingKeyswitchKey`) and fill it
/// with an actual trace packing keyswitching key constructed from an associated input [`GLWE secret
/// key`](`GlweSecretKey`).
///
/// See  [`generate_tpksk_output_glwe_secret_key`](`generate_tpksk_output_glwe_secret_key`)
/// for more details.
///
/// See [`trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext`](`super::trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext`)
/// for usage.
pub fn allocate_and_generate_new_lwe_trace_packing_keyswitch_key<
    Scalar,
    NoiseDistribution,
    KeyCont,
    Gen,
>(
    lwe_size: LweSize,
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweTracePackingKeyswitchKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_trace_packing_keyswitch_key = LweTracePackingKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        lwe_size,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        glwe_secret_key.polynomial_size(),
        ciphertext_modulus,
    );

    generate_lwe_trace_packing_keyswitch_key(
        glwe_secret_key,
        &mut new_lwe_trace_packing_keyswitch_key,
        noise_distribution,
        generator,
    );

    new_lwe_trace_packing_keyswitch_key
}
