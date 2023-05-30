//! Module containing primitives pertaining to [`GLWE keyswitch key generation`](`GlweKeyswitchKey`)

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Fill a [`GLWE keyswitch key`](`GlweKeyswitchKey`) with an actual keyswitching key constructed
/// from an input and an output key [`GLWE secret key`](`GlweSecretKey`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_glwe_dimension = GlweDimension(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_glwe_dimension = GlweDimension(1);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
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
/// let input_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     input_glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     output_glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut ksk = GlweKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_glwe_dimension,
///     output_glwe_dimension,
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_glwe_keyswitch_key(
///     &input_glwe_secret_key,
///     &output_glwe_secret_key,
///     &mut ksk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// assert!(ksk.as_ref().iter().all(|&x| x == 0) == false);
/// ```
pub fn generate_glwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, KSKeyCont, Gen>(
    input_glwe_sk: &GlweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    glwe_keyswitch_key: &mut GlweKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        glwe_keyswitch_key.input_key_glwe_dimension() == input_glwe_sk.glwe_dimension(),
        "The destination GlweKeyswitchKey input GlweDimension is not equal \
    to the input GlweSecretKey GlweDimension. Destination: {:?}, input: {:?}",
        glwe_keyswitch_key.input_key_glwe_dimension(),
        input_glwe_sk.glwe_dimension()
    );
    assert!(
        glwe_keyswitch_key.output_key_glwe_dimension() == output_glwe_sk.glwe_dimension(),
        "The destination GlweKeyswitchKey output GlweDimension is not equal \
    to the output GlweSecretKey GlweDimension. Destination: {:?}, output: {:?}",
        glwe_keyswitch_key.output_key_glwe_dimension(),
        input_glwe_sk.glwe_dimension()
    );
    assert!(
        glwe_keyswitch_key.polynomial_size() == input_glwe_sk.polynomial_size(),
        "The destination GlweKeyswitchKey input PolynomialSize is not equal \
     to the input GlweSecretKey PolynomialSize. Destination: {:?}, input: {:?}",
        glwe_keyswitch_key.polynomial_size(),
        input_glwe_sk.polynomial_size(),
    );
    assert!(
        glwe_keyswitch_key.polynomial_size() == output_glwe_sk.polynomial_size(),
        "The distination GlweKeyswitchKey output PolynomialSize is not equal \
    to the output GlweSecretKey PolynomialSize. Destination: {:?}, output: {:?}",
        glwe_keyswitch_key.polynomial_size(),
        output_glwe_sk.polynomial_size(),
    );

    let decomp_base_log = glwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = glwe_keyswitch_key.decomposition_level_count();
    /*
    // forking the generator and using loop_generator works to generate glwe keyswitch keys but
    // break lwe_trace_packing_keyswotch_key_generation
    let gen_iter = generator
        .fork_glweks_to_glweks_chunks::<Scalar>(
            decomp_level_count,
            input_glwe_sk.glwe_dimension(),
            output_glwe_sk.glwe_dimension().to_glwe_size(),
            input_glwe_sk.polynomial_size(),
        )
        .unwrap();
     */

    // Iterate over the input key elements and the destination glwe_keyswitch_key memory
    //for ((input_key_polynomial, mut keyswitch_key_block), mut _loop_generator) in input_glwe_sk
    for (input_key_polynomial, mut keyswitch_key_block) in input_glwe_sk
        .as_polynomial_list()
        .iter()
        .zip(glwe_keyswitch_key.iter_mut())
    //.zip(gen_iter)
    {
        // The plaintexts used to encrypt a key element will be stored in this buffer
        let mut decomposition_polynomials_buffer = PolynomialList::new(
            Scalar::ZERO,
            input_glwe_sk.polynomial_size(),
            PolynomialCount(decomp_level_count.0),
        );

        // We fill the buffer with the powers of the key elmements
        for (level, mut message_polynomial) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .zip(decomposition_polynomials_buffer.as_mut_view().iter_mut())
        {
            for (message, input_key_element) in message_polynomial
                .iter_mut()
                .zip(input_key_polynomial.iter())
            {
                *message = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand();
            }
        }

        let decomposition_plaintexts_buffer =
            PlaintextList::from_container(decomposition_polynomials_buffer.into_container());

        encrypt_glwe_ciphertext_list(
            output_glwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_parameters,
            //&mut loop_generator,
            generator,
        );
    }
}

/// Allocate a new [`GLWE keyswitch key`](`GlweKeyswitchKey`) and fill it with an actual
/// keyswitching key constructed from an input and an output key
/// [`GLWE secret key`](`GlweSecretKey`).
///
/// See [`keyswitch_glwe_ciphertext`] for usage.
pub fn allocate_and_generate_new_glwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    input_glwe_sk: &GlweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> GlweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_glwe_keyswitch_key = GlweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_glwe_sk.glwe_dimension(),
        output_glwe_sk.glwe_dimension(),
        output_glwe_sk.polynomial_size(),
        ciphertext_modulus,
    );

    generate_glwe_keyswitch_key(
        input_glwe_sk,
        output_glwe_sk,
        &mut new_glwe_keyswitch_key,
        noise_parameters,
        generator,
    );

    new_glwe_keyswitch_key
}
