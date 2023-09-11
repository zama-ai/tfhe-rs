//! Module containing primitives pertaining to the generation of
//! [`standard LWE multi_bit bootstrap keys`](`LweMultiBitBootstrapKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweBootstrapKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let grouping_factor = LweBskGroupingFactor(2);
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
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut bsk = LweMultiBitBootstrapKey::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     grouping_factor,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_multi_bit_bootstrap_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut bsk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();
///
/// for (mut ggsw_group, input_key_elements) in bsk.chunks_exact(ggsw_per_multi_bit_element.0).zip(
///     input_lwe_secret_key
///         .as_ref()
///         .chunks_exact(grouping_factor.0),
/// ) {
///     for (bit_inversion_idx, ggsw) in ggsw_group.iter().enumerate() {
///         let mut key_bits_plaintext = 1u64;
///         for (bit_idx, &key_bit) in input_key_elements.iter().enumerate() {
///             let bit_position = input_key_elements.len() - (bit_idx + 1);
///             let inversion_bit = (((bit_inversion_idx >> bit_position) & 1) ^ 1) as u64;
///             let key_bit = key_bit ^ inversion_bit;
///             key_bits_plaintext *= key_bit;
///         }
///
///         let decrypted_ggsw = decrypt_constant_ggsw_ciphertext(&output_glwe_secret_key, &ggsw);
///         assert_eq!(decrypted_ggsw.0, key_bits_plaintext)
///     }
/// }
/// ```
pub fn generate_lwe_multi_bit_bootstrap_key<Scalar, InputKeyCont, OutputKeyCont, OutputCont, Gen>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweMultiBitBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + CastFrom<usize>,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .fork_multi_bit_bsk_to_ggsw_group::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
            output.grouping_factor(),
        )
        .unwrap();

    let output_decomposition_level_count = output.decomposition_level_count();
    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let output_grouping_factor = output.grouping_factor();
    let ggsw_per_multi_bit_element = output_grouping_factor.ggsw_per_multi_bit_element();

    for ((mut ggsw_group, input_key_elements), mut loop_generator) in output
        .chunks_exact_mut(ggsw_per_multi_bit_element.0)
        .zip(
            input_lwe_secret_key
                .as_ref()
                .chunks_exact(output_grouping_factor.0),
        )
        .zip(gen_iter)
    {
        let gen_iter = loop_generator
            .fork_multi_bit_bsk_ggsw_group_to_ggsw::<Scalar>(
                output_decomposition_level_count,
                output_glwe_size,
                output_polynomial_size,
                output_grouping_factor,
            )
            .unwrap();
        for ((bit_inversion_idx, mut ggsw), mut inner_loop_generator) in
            ggsw_group.iter_mut().enumerate().zip(gen_iter)
        {
            // Use the index of the ggsw as a way to know which bit to invert
            let key_bits_plaintext = combine_key_bits(bit_inversion_idx, input_key_elements);

            encrypt_constant_ggsw_ciphertext(
                output_glwe_secret_key,
                &mut ggsw,
                Plaintext(key_bits_plaintext),
                noise_parameters,
                &mut inner_loop_generator,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn allocate_and_generate_new_lwe_multi_bit_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweMultiBitBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize>,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut bsk = LweMultiBitBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        grouping_factor,
        ciphertext_modulus,
    );

    generate_lwe_multi_bit_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        generator,
    );

    bsk
}

/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweBootstrapKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let grouping_factor = LweBskGroupingFactor(2);
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
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut bsk = LweMultiBitBootstrapKey::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     grouping_factor,
///     ciphertext_modulus,
/// );
///
/// par_generate_lwe_multi_bit_bootstrap_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut bsk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
///     input_lwe_dimension,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     grouping_factor,
/// );
///
/// par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut multi_bit_bsk);
///
/// let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();
///
/// for (mut ggsw_group, input_key_elements) in bsk.chunks_exact(ggsw_per_multi_bit_element.0).zip(
///     input_lwe_secret_key
///         .as_ref()
///         .chunks_exact(grouping_factor.0),
/// ) {
///     for (bit_inversion_idx, ggsw) in ggsw_group.iter().enumerate() {
///         let mut key_bits_plaintext = 1u64;
///         for (bit_idx, &key_bit) in input_key_elements.iter().enumerate() {
///             let bit_position = input_key_elements.len() - (bit_idx + 1);
///             let inversion_bit = (((bit_inversion_idx >> bit_position) & 1) ^ 1) as u64;
///             let key_bit = key_bit ^ inversion_bit;
///             key_bits_plaintext *= key_bit;
///         }
///         let decrypted_ggsw = decrypt_constant_ggsw_ciphertext(&output_glwe_secret_key, &ggsw);
///         assert_eq!(decrypted_ggsw.0, key_bits_plaintext)
///     }
/// }
/// ```
pub fn par_generate_lwe_multi_bit_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweMultiBitBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + CastFrom<usize> + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .par_fork_multi_bit_bsk_to_ggsw_group::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
            output.grouping_factor(),
        )
        .unwrap();

    let output_decomposition_level_count = output.decomposition_level_count();
    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let output_grouping_factor = output.grouping_factor();
    let ggsw_per_multi_bit_element = output_grouping_factor.ggsw_per_multi_bit_element();

    output
        .par_iter_mut()
        .chunks(ggsw_per_multi_bit_element.0)
        .zip(
            input_lwe_secret_key
                .as_ref()
                .par_chunks_exact(output_grouping_factor.0),
        )
        .zip(gen_iter)
        .for_each(
            |((mut ggsw_group, input_key_elements), mut loop_generator)| {
                let gen_iter = loop_generator
                    .par_fork_multi_bit_bsk_ggsw_group_to_ggsw::<Scalar>(
                        output_decomposition_level_count,
                        output_glwe_size,
                        output_polynomial_size,
                        output_grouping_factor,
                    )
                    .unwrap();
                ggsw_group
                    .par_iter_mut()
                    .enumerate()
                    .zip(gen_iter)
                    .for_each(|((bit_inversion_idx, ggsw), mut inner_loop_generator)| {
                        // Use the index of the ggsw as a way to know which bit to invert
                        let key_bits_plaintext =
                            combine_key_bits(bit_inversion_idx, input_key_elements);

                        par_encrypt_constant_ggsw_ciphertext(
                            output_glwe_secret_key,
                            ggsw,
                            Plaintext(key_bits_plaintext),
                            noise_parameters,
                            &mut inner_loop_generator,
                        );
                    });
            },
        );
}

fn combine_key_bits<Scalar>(bit_selector: usize, input_key_elements: &[Scalar]) -> Scalar
where
    Scalar: UnsignedInteger + CastFrom<usize>,
{
    // Use a bit_selector (in practice the ggsw index) as a way to know which bit to invert, the
    // counter goes from e.g. 0 to 4 or 00, 01, 10 and 11 in binary, we use those bits to know which
    // key bit to invert in our product, also we invert the bit once more to be sure that the first
    // term is the GGSW encrypting a constant polynomial (and not a monomial), allowing to copy it
    // in the multi_bit PBS routine and computing polynomial products on the rest of the terms.

    // We compute products, initialize the combined key bits to 1
    let mut key_bits_plaintext = Scalar::ONE;
    for (bit_idx, &key_bit) in input_key_elements.iter().enumerate() {
        // Get the position of the bit we will check in bit_selector
        let bit_position = input_key_elements.len() - (bit_idx + 1);
        // Get the bit, invert it to have the first combined GGSW correspond to
        // the constant polynomial, i.e. we generate
        // first GGSW((1 - s_{i-1}) * (1 - s_i)) up
        // to GGSW(s_{i-1} * s_{i})
        let inversion_bit: Scalar = Scalar::cast_from(((bit_selector >> bit_position) & 1) ^ 1);
        // Invert the key_bit depending on the computed inversion_bit
        let key_bit = key_bit ^ inversion_bit;
        // Multiply the accumulator by the key_bit we need to combine it with
        key_bits_plaintext = key_bits_plaintext.wrapping_mul(key_bit);
    }
    key_bits_plaintext
}

#[allow(clippy::too_many_arguments)]
pub fn par_allocate_and_generate_new_lwe_multi_bit_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    noise_parameters: impl DispersionParameter + Sync,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweMultiBitBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut bsk = LweMultiBitBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        grouping_factor,
        ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        generator,
    );

    bsk
}

/// Fill a [`seeded LWE bootstrap key`](`SeededLweMultiBitBootstrapKey`) with an actual seeded
/// bootstrapping key constructed from an input key [`LWE secret key`](`LweSecretKey`) and an output
/// key [`GLWE secret key`](`GlweSecretKey`)
///
/// Consider using [`par_generate_seeded_lwe_multi_bit_bootstrap_key`] for better key generation
/// times.
#[allow(clippy::too_many_arguments)]
pub fn generate_seeded_lwe_multi_bit_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweMultiBitBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus + CastFrom<usize>,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .fork_multi_bit_bsk_to_ggsw_group::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
            output.grouping_factor(),
        )
        .unwrap();

    let output_decomposition_level_count = output.decomposition_level_count();
    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let output_grouping_factor = output.grouping_factor();
    let ggsw_per_multi_bit_element = output_grouping_factor.ggsw_per_multi_bit_element();

    for ((mut ggsw_group, input_key_elements), mut loop_generator) in output
        .chunks_exact_mut(ggsw_per_multi_bit_element.0)
        .zip(
            input_lwe_secret_key
                .as_ref()
                .chunks_exact(output_grouping_factor.0),
        )
        .zip(gen_iter)
    {
        let gen_iter = loop_generator
            .fork_multi_bit_bsk_ggsw_group_to_ggsw::<Scalar>(
                output_decomposition_level_count,
                output_glwe_size,
                output_polynomial_size,
                output_grouping_factor,
            )
            .unwrap();
        for ((bit_inversion_idx, mut ggsw), mut inner_loop_generator) in
            ggsw_group.iter_mut().enumerate().zip(gen_iter)
        {
            // Use the index of the ggsw as a way to know which bit to invert
            let key_bits_plaintext = combine_key_bits(bit_inversion_idx, input_key_elements);

            encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator(
                output_glwe_secret_key,
                &mut ggsw,
                Plaintext(key_bits_plaintext),
                noise_parameters,
                &mut inner_loop_generator,
            );
        }
    }
}

/// Allocate a new [`seeded LWE bootstrap key`](`SeededLweMultiBitBootstrapKey`) and fill it with an
/// actual seeded bootstrapping key constructed from an input key [`LWE secret key`](`LweSecretKey`)
/// and an output key [`GLWE secret key`](`GlweSecretKey`)
///
/// Consider using [`par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key`] for better
/// key generation times.
#[allow(clippy::too_many_arguments)]
pub fn allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    grouping_factor: LweBskGroupingFactor,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweMultiBitBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize>,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut bsk = SeededLweMultiBitBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        grouping_factor,
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    generate_seeded_lwe_multi_bit_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        noise_seeder,
    );

    bsk
}

/// Parallel variant of [`generate_seeded_lwe_multi_bit_bootstrap_key`], it is recommended to use
/// this function for better key generation times as LWE bootstrapping keys can be quite large.
#[allow(clippy::too_many_arguments)]
pub fn par_generate_seeded_lwe_multi_bit_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweMultiBitBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus + CastFrom<usize> + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    let gen_iter = generator
        .par_fork_multi_bit_bsk_to_ggsw_group::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
            output.grouping_factor(),
        )
        .unwrap();

    let output_decomposition_level_count = output.decomposition_level_count();
    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let output_grouping_factor = output.grouping_factor();
    let ggsw_per_multi_bit_element = output_grouping_factor.ggsw_per_multi_bit_element();

    output
        .par_iter_mut()
        .chunks(ggsw_per_multi_bit_element.0)
        .zip(
            input_lwe_secret_key
                .as_ref()
                .par_chunks_exact(output_grouping_factor.0),
        )
        .zip(gen_iter)
        .for_each(
            |((mut ggsw_group, input_key_elements), mut loop_generator)| {
                let gen_iter = loop_generator
                    .par_fork_multi_bit_bsk_ggsw_group_to_ggsw::<Scalar>(
                        output_decomposition_level_count,
                        output_glwe_size,
                        output_polynomial_size,
                        output_grouping_factor,
                    )
                    .unwrap();
                ggsw_group
                    .par_iter_mut()
                    .enumerate()
                    .zip(gen_iter)
                    .for_each(|((bit_inversion_idx, ggsw), mut inner_loop_generator)| {
                        // Use the index of the ggsw as a way to know which bit to invert
                        let key_bits_plaintext =
                            combine_key_bits(bit_inversion_idx, input_key_elements);

                        par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator(
                            output_glwe_secret_key,
                            ggsw,
                            Plaintext(key_bits_plaintext),
                            noise_parameters,
                            &mut inner_loop_generator,
                        );
                    });
            },
        );
}

/// Parallel variant of [`allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key`], it is
/// recommended to use this function for better key generation times as LWE bootstrapping keys can
/// be quite large.
#[allow(clippy::too_many_arguments)]
pub fn par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter + Sync,
    grouping_factor: LweBskGroupingFactor,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweMultiBitBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut bsk = SeededLweMultiBitBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        grouping_factor,
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    par_generate_seeded_lwe_multi_bit_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        noise_seeder,
    );

    bsk
}
