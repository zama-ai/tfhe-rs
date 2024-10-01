//! Module containing primitives pertaining to the [`LWE programmable
//! bootstrap`](`crate::core_crypto::entities::LweBootstrapKey#programmable-bootstrapping`) using
//! 128 bits FFT for polynomial multiplication.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::bootstrap_scratch as bootstrap_scratch_f128;
use crate::core_crypto::fft_impl::fft128::math::fft::{Fft128, Fft128View};
use dyn_stack::{PodStack, SizeOverflow, StackReq};

/// Perform a programmable bootstrap given an input [`LWE ciphertext`](`LweCiphertext`), a
/// look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) in the fourier domain using f128 see [`fourier LWE bootstrap
/// key`](`Fourier128LweBootstrapKey`). The result is written in the provided
/// output [`LWE ciphertext`](`LweCiphertext`).
///
/// If you want to manage the computation memory manually you can use
/// [`programmable_bootstrap_f128_lwe_ciphertext_mem_optimized`].
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
/// let small_lwe_dimension = LweDimension(742);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let lwe_noise_distribution = Gaussian::from_dispersion_parameter(
///     StandardDev(0.000007069849454709433 * 0.000007069849454709433),
///     0.0,
/// );
/// let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
///     StandardDev(0.00000000000000029403601535432533 * 0.00000000000000029403601535432533),
///     0.0,
/// );
/// let pbs_base_log = DecompositionBaseLog(23);
/// let pbs_level = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Request the best seeder possible, starting with hardware entropy sources and falling back to
/// // /dev/random on Unix systems if enabled via cargo features
/// let mut boxed_seeder = new_seeder();
/// // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
/// let seeder = boxed_seeder.as_mut();
///
/// // Create a generator which uses a CSPRNG to generate secret keys
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
/// // noise
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
///
/// println!("Generating keys...");
///
/// // Generate an LweSecretKey with binary coefficients
/// let small_lwe_sk =
///     LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
///
/// // Generate a GlweSecretKey with binary coefficients
/// let glwe_sk =
///     GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
///
/// // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
/// let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
///
/// // Generate the seeded bootstrapping key to show how to handle entity decompression,
/// // we use the parallel variant for performance reason
/// let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
///     &small_lwe_sk,
///     &glwe_sk,
///     pbs_base_log,
///     pbs_level,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     seeder,
/// );
///
/// // We decompress the bootstrapping key
/// let std_bootstrapping_key: LweBootstrapKeyOwned<u128> =
///     std_bootstrapping_key.decompress_into_lwe_bootstrap_key();
///
/// // Create the empty bootstrapping key in the Fourier domain
/// let mut fourier_bsk = Fourier128LweBootstrapKey::new(
///     std_bootstrapping_key.input_lwe_dimension(),
///     std_bootstrapping_key.glwe_size(),
///     std_bootstrapping_key.polynomial_size(),
///     std_bootstrapping_key.decomposition_base_log(),
///     std_bootstrapping_key.decomposition_level_count(),
/// );
///
/// // Use the conversion function (a memory optimized version also exists but is more complicated
/// // to use) to convert the standard bootstrapping key to the Fourier domain
/// convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bootstrapping_key, &mut fourier_bsk);
/// // We don't need the standard bootstrapping key anymore
/// drop(std_bootstrapping_key);
///
/// // Our 4 bits message space
/// let message_modulus = 1u128 << 4;
///
/// // Our input message
/// let input_message = 3u128;
///
/// // Delta used to encode 4 bits of message + a bit of padding on u128
/// let delta = (1_u128 << 127) / message_modulus;
///
/// // Apply our encoding
/// let plaintext = Plaintext(input_message * delta);
///
/// // Allocate a new LweCiphertext and encrypt our plaintext
/// let lwe_ciphertext_in: LweCiphertextOwned<u128> = allocate_and_encrypt_new_lwe_ciphertext(
///     &small_lwe_sk,
///     plaintext,
///     lwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
/// // doing this operation in terms of performance as it's much more costly than a multiplication
/// // with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
/// // to evaluate arbitrary functions so depending on your use case it can be a better fit.
///
/// // Generate the accumulator for our multiplication by 2 using a simple closure
/// let accumulator: GlweCiphertextOwned<u128> = generate_programmable_bootstrap_glwe_lut(
///     polynomial_size,
///     glwe_dimension.to_glwe_size(),
///     message_modulus as usize,
///     ciphertext_modulus,
///     delta,
///     |x: u128| 2 * x,
/// );
///
/// // Allocate the LweCiphertext to store the result of the PBS
/// let mut pbs_multiplication_ct = LweCiphertext::new(
///     0u128,
///     big_lwe_sk.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
/// println!("Computing PBS...");
/// programmable_bootstrap_f128_lwe_ciphertext(
///     &lwe_ciphertext_in,
///     &mut pbs_multiplication_ct,
///     &accumulator,
///     &fourier_bsk,
/// );
///
/// // Decrypt the PBS multiplication result
/// let pbs_multiplication_plaintext: Plaintext<u128> =
///     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
///
/// // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
/// // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
/// // round the 5 MSB, 1 bit of padding plus our 4 bits of message
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// // Round and remove our encoding
/// let pbs_multiplication_result: u128 =
///     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;
///
/// println!("Checking result...");
/// assert_eq!(6, pbs_multiplication_result);
/// println!(
///     "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
/// );
/// ```
pub fn programmable_bootstrap_f128_lwe_ciphertext<Scalar, InputCont, OutputCont, AccCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &Fourier128LweBootstrapKey<KeyCont>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = f64>,
{
    assert_eq!(input.ciphertext_modulus(), output.ciphertext_modulus());
    assert_eq!(
        output.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );

    let mut buffers = ComputationBuffers::new();

    let fft = Fft128::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    programmable_bootstrap_f128_lwe_ciphertext_mem_optimized(
        input,
        output,
        accumulator,
        fourier_bsk,
        fft,
        stack,
    );
}

/// Memory optimized version of [`programmable_bootstrap_f128_lwe_ciphertext`], the caller must
/// provide a properly configured [`Fft128View`] object and a `PodStack` used as a memory buffer
/// having a capacity at least as large as the result of
/// [`programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement`].
pub fn programmable_bootstrap_f128_lwe_ciphertext_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &Fourier128LweBootstrapKey<KeyCont>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = f64>,
{
    fourier_bsk.bootstrap(output, input, accumulator, fft, stack);
}

/// Return the required memory for [`programmable_bootstrap_f128_lwe_ciphertext_mem_optimized`].
pub fn programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> Result<StackReq, SizeOverflow> {
    bootstrap_scratch_f128::<Scalar>(glwe_size, polynomial_size, fft)
}
