//! Module containing primitives pertaining to the [`LWE programmable
//! bootstrap`](`crate::core_crypto::entities::LweBootstrapKey#programmable-bootstrapping`) using 64
//! bits FFT for polynomial multiplication.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::{
    batch_bootstrap_scratch, blind_rotate_assign_scratch, bootstrap_scratch,
};
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign as impl_add_external_product_assign,
    add_external_product_assign_scratch as impl_add_external_product_assign_scratch, cmux,
    cmux_scratch,
};
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::core_crypto::prelude::ModulusSwitchedLweCiphertext;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

/// Perform a blind rotation given an input [`modulus switched LWE
/// ciphertext`](`ModulusSwitchedLweCiphertext`), modifying a look-up table passed as a [`GLWE
/// ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap key`](`LweBootstrapKey`) in the fourier
/// domain see [`fourier LWE bootstrap key`](`FourierLweBootstrapKey`).
///
/// If you want to manage the computation memory manually you can use
/// [`blind_rotate_assign_mem_optimized`].
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // This example recreates a PBS by combining a blind rotate and a sample extract.
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
/// let small_lwe_dimension = LweDimension(742);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let pbs_base_log = DecompositionBaseLog(23);
/// let pbs_level = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();
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
/// let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
///     std_bootstrapping_key.decompress_into_lwe_bootstrap_key();
///
/// // Create the empty bootstrapping key in the Fourier domain
/// let mut fourier_bsk = FourierLweBootstrapKey::new(
///     std_bootstrapping_key.input_lwe_dimension(),
///     std_bootstrapping_key.glwe_size(),
///     std_bootstrapping_key.polynomial_size(),
///     std_bootstrapping_key.decomposition_base_log(),
///     std_bootstrapping_key.decomposition_level_count(),
/// );
///
/// // Use the conversion function (a memory optimized version also exists but is more complicated
/// // to use) to convert the standard bootstrapping key to the Fourier domain
/// convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
/// // We don't need the standard bootstrapping key anymore
/// drop(std_bootstrapping_key);
///
/// // Our 4 bits message space
/// let message_modulus = 1u64 << 4;
///
/// // Our input message
/// let input_message = 3u64;
///
/// // Delta used to encode 4 bits of message + a bit of padding on u64
/// let delta = (1_u64 << 63) / message_modulus;
///
/// // Apply our encoding
/// let plaintext = Plaintext(input_message * delta);
///
/// // Allocate a new LweCiphertext and encrypt our plaintext
/// let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
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
/// let mut accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
///     polynomial_size,
///     glwe_dimension.to_glwe_size(),
///     message_modulus as usize,
///     ciphertext_modulus,
///     delta,
///     |x: u64| 2 * x,
/// );
///
/// // Allocate the LweCiphertext to store the result of the PBS
/// let mut pbs_multiplication_ct = LweCiphertext::new(
///     0u64,
///     big_lwe_sk.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// let lwe_ciphertext_in_msed = lwe_ciphertext_modulus_switch(lwe_ciphertext_in, log_modulus);
///
/// println!("Performing blind rotation...");
/// blind_rotate_assign(&lwe_ciphertext_in_msed, &mut accumulator, &fourier_bsk);
/// println!("Performing sample extraction...");
/// extract_lwe_sample_from_glwe_ciphertext(
///     &accumulator,
///     &mut pbs_multiplication_ct,
///     MonomialDegree(0),
/// );
///
/// // Decrypt the PBS multiplication result
/// let pbs_multiplication_plaintext: Plaintext<u64> =
///     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
///
/// // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
/// // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
/// // round the 5 MSB, 1 bit of padding plus our 4 bits of message
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// // Round and remove our encoding
/// let pbs_multiplication_result: u64 =
///     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;
///
/// println!("Checking result...");
/// assert_eq!(6, pbs_multiplication_result);
/// println!(
///     "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
/// );
/// ```
pub fn blind_rotate_assign<OutputScalar, OutputCont, KeyCont>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &mut GlweCiphertext<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
) where
    OutputScalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert!(
        lut.ciphertext_modulus().is_power_of_two(),
        "This operation requires the lut to have a power of two modulus."
    );

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();

    buffers.resize(
        blind_rotate_assign_mem_optimized_requirement::<OutputScalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    blind_rotate_assign_mem_optimized(msed_input, lut, fourier_bsk, fft, stack);
}

/// Memory optimized version of [`blind_rotate_assign`], the caller must provide
/// a properly configured [`FftView`] object and a `PodStack` used as a memory buffer having a
/// capacity at least as large as the result of [`blind_rotate_assign_mem_optimized_requirement`].
pub fn blind_rotate_assign_mem_optimized<OutputScalar, OutputCont, KeyCont>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &mut GlweCiphertext<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    OutputScalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert!(
        lut.ciphertext_modulus().is_power_of_two(),
        "This operation requires the lut to have a power of two modulus."
    );
    assert_eq!(
        msed_input.lwe_dimension(),
        fourier_bsk.input_lwe_dimension()
    );
    assert_eq!(lut.glwe_size(), fourier_bsk.glwe_size());
    assert_eq!(lut.polynomial_size(), fourier_bsk.polynomial_size());

    // Blind rotate assign manages the rounding to go back to the proper torus if the ciphertext
    // modulus is not the native one
    fourier_bsk
        .as_view()
        .blind_rotate_assign(lut.as_mut_view(), msed_input, fft, stack);
}

/// Return the required memory for [`blind_rotate_assign_mem_optimized`].
pub fn blind_rotate_assign_mem_optimized_requirement<OutputScalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_assign_scratch::<OutputScalar>(glwe_size, polynomial_size, fft)
}

/// Compute the external product of `ggsw` and `glwe`, and add the result to `out`.
///
/// Strictly speaking this function computes:
///
/// ```text
/// out <- out + glwe * ggsw
/// ```
///
/// If you want to manage the computation memory manually you can use
/// [`add_external_product_assign_mem_optimized`].
pub fn add_external_product_assign<Scalar, OutputGlweCont, InputGlweCont, GgswCont>(
    out: &mut GlweCiphertext<OutputGlweCont>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
    glwe: &GlweCiphertext<InputGlweCont>,
) where
    Scalar: UnsignedTorus,
    OutputGlweCont: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
    InputGlweCont: Container<Element = Scalar>,
{
    assert_eq!(out.ciphertext_modulus(), glwe.ciphertext_modulus());

    let fft = Fft::new(ggsw.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        add_external_product_assign_mem_optimized_requirement::<Scalar>(
            ggsw.glwe_size(),
            ggsw.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    add_external_product_assign_mem_optimized(out, ggsw, glwe, fft, buffers.stack());
}

/// Memory optimized version of [`add_external_product_assign`], the caller must provide a properly
/// configured [`FftView`] object and a `PodStack` used as a memory buffer having a capacity at
/// least as large as the result of [`add_external_product_assign_mem_optimized_requirement`].
///
/// Compute the external product of `ggsw` and `glwe`, and add the result to `out`.
///
/// Strictly speaking this function computes:
///
/// ```text
/// out <- out + glwe * ggsw
/// ```
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(2048);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the cleartext, here we will multiply by 3
/// let msg_ggsw = Cleartext(3u64);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_constant_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw,
///     msg_ggsw,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let ct_plaintext = Plaintext(3 << 60);
///
/// let ct_plaintexts = PlaintextList::new(ct_plaintext.0, PlaintextCount(polynomial_size.0));
///
/// let mut ct = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut ct,
///     &ct_plaintexts,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let fft = Fft::new(polynomial_size);
/// let fft = fft.as_view();
/// let mut buffers = ComputationBuffers::new();
///
/// let buffer_size_req = add_external_product_assign_mem_optimized_requirement::<u64>(
///     glwe_size,
///     polynomial_size,
///     fft,
/// )
/// .unwrap()
/// .unaligned_bytes_required();
///
/// let buffer_size_req = buffer_size_req.max(
///     convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
///         .unwrap()
///         .unaligned_bytes_required(),
/// );
///
/// buffers.resize(buffer_size_req);
///
/// let mut fourier_ggsw = FourierGgswCiphertext::new(
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
/// );
///
/// convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
///     &ggsw,
///     &mut fourier_ggsw,
///     fft,
///     buffers.stack(),
/// );
///
/// let mut ct_out = ct.clone();
///
/// add_external_product_assign_mem_optimized(
///     &mut ct_out,
///     &fourier_ggsw,
///     &ct,
///     fft,
///     buffers.stack(),
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, ct_plaintexts.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &ct_out, &mut output_plaintext_list);
///
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));
///
/// // As we cloned the input ciphertext for the output, the external product result is added to the
/// // originally contained value, hence why we expect ct_plaintext + ct_plaintext * msg_ggsw
/// assert!(output_plaintext_list
///     .iter()
///     .all(|x| *x.0 == ct_plaintext.0 + ct_plaintext.0 * msg_ggsw.0));
/// ```
pub fn add_external_product_assign_mem_optimized<Scalar, OutputGlweCont, InputGlweCont, GgswCont>(
    out: &mut GlweCiphertext<OutputGlweCont>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
    glwe: &GlweCiphertext<InputGlweCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    OutputGlweCont: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
    InputGlweCont: Container<Element = Scalar>,
{
    assert_eq!(out.ciphertext_modulus(), glwe.ciphertext_modulus());
    let ciphertext_modulus = out.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    impl_add_external_product_assign(
        out.as_mut_view(),
        ggsw.as_view(),
        glwe.as_view(),
        fft,
        stack,
    );

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        out.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

/// Return the required memory for [`add_external_product_assign_mem_optimized`].
pub fn add_external_product_assign_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    impl_add_external_product_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// Compute a cmux on the input `ct0` and `ct1` using `ggsw` as selector.
///
/// `ct0` and `ct1` are both modified by this operation, the result is stored in `ct0` at the end
/// of the computation.
///
/// Strictly speaking this function computes:
///
/// ```text
/// ct1 <- ct1 - ct0
/// ct0 <- ct1 * ggsw + ct0
/// ```
///
/// Therefore encrypting values other than 0 or 1 in the `ggsw` will yield a linear combination of
/// `ct0` and `ct1`
///
/// From a logical point of view (without considering the side effects of the implementation) the
/// cmux operation does the following assuming a binary (0 or 1) value encrypted in the input
/// `ggsw`:
///
/// ```text
/// def cmux(ct0, ct1, ggsw):
///     if ggsw == 1:
///         return ct1
///     else:
///         return ct0
/// ```
///
/// If you want to manage the computation memory manually you can use
/// [`cmux_assign_mem_optimized`].
pub fn cmux_assign<Scalar, Cont0, Cont1, GgswCont>(
    ct0: &mut GlweCiphertext<Cont0>,
    ct1: &mut GlweCiphertext<Cont1>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
) where
    Scalar: UnsignedTorus,
    Cont0: ContainerMut<Element = Scalar>,
    Cont1: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
{
    assert_eq!(ct0.ciphertext_modulus(), ct1.ciphertext_modulus());

    let fft = Fft::new(ggsw.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        cmux_assign_mem_optimized_requirement::<Scalar>(
            ggsw.glwe_size(),
            ggsw.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    cmux_assign_mem_optimized(ct0, ct1, ggsw, fft, buffers.stack());
}

/// Memory optimized version of [`cmux_assign`], the caller must provide a properly configured
/// [`FftView`] object and a `PodStack` used as a memory buffer having a capacity at least as large
/// as the result of [`cmux_assign_mem_optimized_requirement`].
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(2048);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg_ggsw_0 = Cleartext(0u64);
///
/// // Create a new GgswCiphertext
/// let mut ggsw_0 = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_constant_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw_0,
///     msg_ggsw_0,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// // Create the plaintext
/// let msg_ggsw_1 = Cleartext(1u64);
///
/// // Create a new GgswCiphertext
/// let mut ggsw_1 = GgswCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_constant_ggsw_ciphertext(
///     &glwe_secret_key,
///     &mut ggsw_1,
///     msg_ggsw_1,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let ct0_plaintext = Plaintext(1 << 60);
/// let ct1_plaintext = Plaintext(3 << 60);
///
/// let ct0_plaintexts = PlaintextList::new(ct0_plaintext.0, PlaintextCount(polynomial_size.0));
/// let ct1_plaintexts = PlaintextList::new(ct1_plaintext.0, PlaintextCount(polynomial_size.0));
///
/// let mut ct0 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
/// let mut ct1 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut ct0,
///     &ct0_plaintexts,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut ct1,
///     &ct1_plaintexts,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let fft = Fft::new(polynomial_size);
/// let fft = fft.as_view();
/// let mut buffers = ComputationBuffers::new();
///
/// let buffer_size_req =
///     cmux_assign_mem_optimized_requirement::<u64>(glwe_size, polynomial_size, fft)
///         .unwrap()
///         .unaligned_bytes_required();
///
/// let buffer_size_req = buffer_size_req.max(
///     convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
///         .unwrap()
///         .unaligned_bytes_required(),
/// );
///
/// buffers.resize(buffer_size_req);
///
/// let mut fourier_ggsw_0 = FourierGgswCiphertext::new(
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
/// );
/// let mut fourier_ggsw_1 = FourierGgswCiphertext::new(
///     glwe_size,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
/// );
///
/// convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
///     &ggsw_0,
///     &mut fourier_ggsw_0,
///     fft,
///     buffers.stack(),
/// );
///
/// convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
///     &ggsw_1,
///     &mut fourier_ggsw_1,
///     fft,
///     buffers.stack(),
/// );
///
/// let mut ct0_clone = ct0.clone();
/// let mut ct1_clone = ct1.clone();
///
/// cmux_assign_mem_optimized(
///     &mut ct0_clone,
///     &mut ct1_clone,
///     &fourier_ggsw_0,
///     fft,
///     buffers.stack(),
/// );
///
/// let mut output_plaintext_list_0 = PlaintextList::new(0u64, ct0_plaintexts.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &ct0_clone, &mut output_plaintext_list_0);
///
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list_0
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));
///
/// assert!(output_plaintext_list_0
///     .iter()
///     .all(|x| *x.0 == ct0_plaintext.0));
///
/// cmux_assign_mem_optimized(&mut ct0, &mut ct1, &fourier_ggsw_1, fft, buffers.stack());
///
/// let mut output_plaintext_list_1 = PlaintextList::new(0u64, ct1_plaintexts.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &ct0, &mut output_plaintext_list_1);
///
/// output_plaintext_list_1
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));
///
/// assert!(output_plaintext_list_1
///     .iter()
///     .all(|x| *x.0 == ct1_plaintext.0));
/// ```
pub fn cmux_assign_mem_optimized<Scalar, Cont0, Cont1, GgswCont>(
    ct0: &mut GlweCiphertext<Cont0>,
    ct1: &mut GlweCiphertext<Cont1>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    Cont0: ContainerMut<Element = Scalar>,
    Cont1: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
{
    assert_eq!(ct0.ciphertext_modulus(), ct1.ciphertext_modulus());
    let ciphertext_modulus = ct0.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    cmux(
        ct0.as_mut_view(),
        ct1.as_mut_view(),
        ggsw.as_view(),
        fft,
        stack,
    );

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

/// Return the required memory for [`cmux_assign_mem_optimized`].
pub fn cmux_assign_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    cmux_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// Perform a programmable bootstrap given an input [`LWE ciphertext`](`LweCiphertext`), a
/// look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) in the fourier domain see [`fourier LWE bootstrap
/// key`](`FourierLweBootstrapKey`). The result is written in the provided output
/// [`LWE ciphertext`](`LweCiphertext`).
///
/// If you want to manage the computation memory manually you can use
/// [`programmable_bootstrap_lwe_ciphertext_mem_optimized`].
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
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
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
/// let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
///     std_bootstrapping_key.decompress_into_lwe_bootstrap_key();
///
/// // Create the empty bootstrapping key in the Fourier domain
/// let mut fourier_bsk = FourierLweBootstrapKey::new(
///     std_bootstrapping_key.input_lwe_dimension(),
///     std_bootstrapping_key.glwe_size(),
///     std_bootstrapping_key.polynomial_size(),
///     std_bootstrapping_key.decomposition_base_log(),
///     std_bootstrapping_key.decomposition_level_count(),
/// );
///
/// // Use the conversion function (a memory optimized version also exists but is more complicated
/// // to use) to convert the standard bootstrapping key to the Fourier domain
/// convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
/// // We don't need the standard bootstrapping key anymore
/// drop(std_bootstrapping_key);
///
/// // Our 4 bits message space
/// let message_modulus = 1u64 << 4;
///
/// // Our input message
/// let input_message = 3u64;
///
/// // Delta used to encode 4 bits of message + a bit of padding on u64
/// let delta = (1_u64 << 63) / message_modulus;
///
/// // Apply our encoding
/// let plaintext = Plaintext(input_message * delta);
///
/// // Allocate a new LweCiphertext and encrypt our plaintext
/// let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
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
/// let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
///     polynomial_size,
///     glwe_dimension.to_glwe_size(),
///     message_modulus as usize,
///     ciphertext_modulus,
///     delta,
///     |x: u64| 2 * x,
/// );
///
/// // Allocate the LweCiphertext to store the result of the PBS
/// let mut pbs_multiplication_ct = LweCiphertext::new(
///     0u64,
///     big_lwe_sk.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
/// println!("Computing PBS...");
/// programmable_bootstrap_lwe_ciphertext(
///     &lwe_ciphertext_in,
///     &mut pbs_multiplication_ct,
///     &accumulator,
///     &fourier_bsk,
/// );
///
/// // Decrypt the PBS multiplication result
/// let pbs_multiplication_plaintext: Plaintext<u64> =
///     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
///
/// // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
/// // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
/// // round the 5 MSB, 1 bit of padding plus our 4 bits of message
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// // Round and remove our encoding
/// let pbs_multiplication_result: u64 =
///     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;
///
/// println!("Checking result...");
/// assert_eq!(6, pbs_multiplication_result);
/// println!(
///     "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
/// );
/// ```
pub fn programmable_bootstrap_lwe_ciphertext<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert!(
        input.ciphertext_modulus().is_power_of_two(),
        "This operation requires the input to have a power of two modulus."
    );
    assert_eq!(
        output.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<OutputScalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        input,
        output,
        accumulator,
        fourier_bsk,
        fft,
        stack,
    );
}

/// Memory optimized version of [`programmable_bootstrap_lwe_ciphertext`], the caller must provide
/// a properly configured [`FftView`] object and a `PodStack` used as a memory buffer having a
/// capacity at least as large as the result of
/// [`programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement`].
pub fn programmable_bootstrap_lwe_ciphertext_mem_optimized<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert_eq!(
        accumulator.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched moduli between accumulator ({:?}) and output ({:?})",
        accumulator.ciphertext_modulus(),
        output.ciphertext_modulus()
    );

    assert_eq!(
        fourier_bsk.input_lwe_dimension(),
        input.lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        FourierLweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        fourier_bsk.input_lwe_dimension(),
        input.lwe_size().to_lwe_dimension(),
    );
    assert_eq!(
        fourier_bsk.output_lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
        "Mismatched output LweDimension. \
        FourierLweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        fourier_bsk.output_lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
    );

    fourier_bsk.as_view().bootstrap(
        output.as_mut_view(),
        input.as_view(),
        accumulator.as_view(),
        fft,
        stack,
    );
}

/// Return the required memory for [`programmable_bootstrap_lwe_ciphertext_mem_optimized`].
pub fn programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement<OutputScalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    bootstrap_scratch::<OutputScalar>(glwe_size, polynomial_size, fft)
}

/// This function takes list as input and output and computes the programmable bootstrap for each
/// slot progressively loading the bootstrapping key only once. The caller must provide
/// a properly configured [`FftView`] object and a `PodStack` used as a memory buffer having a
/// capacity at least as large as the result of
/// [`batch_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement`].
pub fn batch_programmable_bootstrap_lwe_ciphertext_mem_optimized<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertextList<InputCont>,
    output: &mut LweCiphertextList<OutputCont>,
    accumulator: &GlweCiphertextList<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert_eq!(
        accumulator.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched moduli between accumulator ({:?}) and output ({:?})",
        accumulator.ciphertext_modulus(),
        output.ciphertext_modulus()
    );

    assert_eq!(
        fourier_bsk.input_lwe_dimension(),
        input.lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        FourierLweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        fourier_bsk.input_lwe_dimension(),
        input.lwe_size().to_lwe_dimension(),
    );
    assert_eq!(
        fourier_bsk.output_lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
        "Mismatched output LweDimension. \
        FourierLweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        fourier_bsk.output_lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
    );
    assert_eq!(
        input.lwe_ciphertext_count().0,
        output.lwe_ciphertext_count().0,
        "Mismatched list length. \
     input LweCiphertextList length: {:?}, output LweCiphertextList length {:?}.",
        input.lwe_ciphertext_count().0,
        output.lwe_ciphertext_count().0,
    );
    assert_eq!(
        input.lwe_ciphertext_count().0,
        accumulator.glwe_ciphertext_count().0,
        "Mismatched list length. \
     input LweCiphertextList length: {:?}, accumulator GlweCiphertextList length {:?}.",
        input.lwe_ciphertext_count().0,
        accumulator.glwe_ciphertext_count().0,
    );

    fourier_bsk.as_view().batch_bootstrap(
        output.as_mut_view(),
        input.as_view(),
        &accumulator.as_view(),
        fft,
        stack,
    );
}

/// Return the required memory for [`batch_programmable_bootstrap_lwe_ciphertext_mem_optimized`].
pub fn batch_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement<OutputScalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_count: CiphertextCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    batch_bootstrap_scratch::<OutputScalar>(glwe_size, polynomial_size, ciphertext_count, fft)
}

// ============== Noise measurement trait implementations ============== //
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::LweClassicFftBootstrap;

impl<
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
        KeyCont: Container<Element = c64>,
        InputCont: Container<Element = InputScalar>,
        OutputCont: ContainerMut<Element = OutputScalar>,
        AccCont: Container<Element = OutputScalar>,
    >
    LweClassicFftBootstrap<
        LweCiphertext<InputCont>,
        LweCiphertext<OutputCont>,
        GlweCiphertext<AccCont>,
    > for FourierLweBootstrapKey<KeyCont>
{
    type SideResources = ();

    fn lwe_classic_fft_pbs(
        &self,
        input: &LweCiphertext<InputCont>,
        output: &mut LweCiphertext<OutputCont>,
        accumulator: &GlweCiphertext<AccCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        programmable_bootstrap_lwe_ciphertext(input, output, accumulator, self);
    }
}
