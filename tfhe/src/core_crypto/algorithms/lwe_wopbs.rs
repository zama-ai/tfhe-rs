//! Module containing primitives pertaining to the Wopbs (WithOut padding PBS).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::crypto::wop_pbs::{
    circuit_bootstrap_boolean_vertical_packing, circuit_bootstrap_boolean_vertical_packing_scratch,
    extract_bits, extract_bits_scratch,
};
use crate::core_crypto::fft_impl::fft64::math::fft::FftView;
use concrete_fft::c64;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use rayon::prelude::*;

/// Allocate a new [`list of LWE private functional packing keyswitch
/// keys`](`LwePrivateFunctionalPackingKeyswitchKeyList`) and fill it with actual keys required to
/// perform a circuit bootstrap.
///
/// Consider using [`par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list`] for better
/// key generation times.
pub fn allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus,
    LweKeyCont: Container<Element = Scalar>,
    GlweKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        ciphertext_modulus.is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        ciphertext_modulus
    );

    let mut cbs_pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyListOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(
            output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        ),
        ciphertext_modulus,
    );

    generate_circuit_bootstrap_lwe_pfpksk_list(
        &mut cbs_pfpksk_list,
        input_lwe_secret_key,
        output_glwe_secret_key,
        noise_parameters,
        generator,
    );

    cbs_pfpksk_list
}

/// Fill a [`list of LWE private functional packing keyswitch
/// keys`](`LwePrivateFunctionalPackingKeyswitchKeyList`) with actual keys required to perform a
/// circuit bootstrap.
///
/// Consider using [`par_generate_circuit_bootstrap_lwe_pfpksk_list`] for better key generation
/// times.
pub fn generate_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    OutputCont,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    output_cbs_pfpksk_list: &mut LwePrivateFunctionalPackingKeyswitchKeyList<OutputCont>,
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    LweKeyCont: Container<Element = Scalar>,
    GlweKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_cbs_pfpksk_list.lwe_pfpksk_count().0
            == output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        "Current list has {} pfpksk, need to have {} \
        (output_glwe_key.glwe_dimension().to_glwe_size())",
        output_cbs_pfpksk_list.lwe_pfpksk_count().0,
        output_glwe_secret_key.glwe_dimension().to_glwe_size().0
    );

    assert!(
        output_cbs_pfpksk_list
            .ciphertext_modulus()
            .is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        output_cbs_pfpksk_list.ciphertext_modulus()
    );

    let decomp_level_count = output_cbs_pfpksk_list.decomposition_level_count();

    let gen_iter = generator
        .fork_cbs_pfpksk_to_pfpksk::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            output_cbs_pfpksk_list.lwe_pfpksk_count(),
        )
        .unwrap();

    let mut last_polynomial_as_list = PolynomialListOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.polynomial_size(),
        PolynomialCount(1),
    );
    // We apply the x -> -x function so instead of putting one in the first coeff of the
    // polynomial, we put Scalar::MAX == - Sclar::One so that we can use a single function in
    // the loop avoiding branching
    last_polynomial_as_list.get_mut(0)[0] = Scalar::MAX;

    for ((mut lwe_pfpksk, polynomial_to_encrypt), mut loop_generator) in output_cbs_pfpksk_list
        .iter_mut()
        .zip(
            output_glwe_secret_key
                .as_polynomial_list()
                .iter()
                .chain(last_polynomial_as_list.iter()),
        )
        .zip(gen_iter)
    {
        generate_lwe_private_functional_packing_keyswitch_key(
            input_lwe_secret_key,
            output_glwe_secret_key,
            &mut lwe_pfpksk,
            noise_parameters,
            &mut loop_generator,
            |x| Scalar::ZERO.wrapping_sub(x),
            &polynomial_to_encrypt,
        );
    }
}

/// Parallel variant of [`allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list`], it is
/// recommended to use this function for better key generation times as the generated keys can be
/// quite large.
///
/// See [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`] for usage.
pub fn par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter + Sync,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    LweKeyCont: Container<Element = Scalar> + Sync,
    GlweKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        ciphertext_modulus.is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        ciphertext_modulus
    );

    let mut cbs_pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyListOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(
            output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        ),
        ciphertext_modulus,
    );

    par_generate_circuit_bootstrap_lwe_pfpksk_list(
        &mut cbs_pfpksk_list,
        input_lwe_secret_key,
        output_glwe_secret_key,
        noise_parameters,
        generator,
    );

    cbs_pfpksk_list
}

/// Parallel variant of [`generate_circuit_bootstrap_lwe_pfpksk_list`], it is recommended to use
/// this function for better key generation times as the generated keys can be quite large.
pub fn par_generate_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    OutputCont,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    output_cbs_pfpksk_list: &mut LwePrivateFunctionalPackingKeyswitchKeyList<OutputCont>,
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    OutputCont: ContainerMut<Element = Scalar>,
    LweKeyCont: Container<Element = Scalar> + Sync,
    GlweKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output_cbs_pfpksk_list.lwe_pfpksk_count().0
            == output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        "Current list has {} pfpksk, need to have {} \
        (output_glwe_key.glwe_dimension().to_glwe_size())",
        output_cbs_pfpksk_list.lwe_pfpksk_count().0,
        output_glwe_secret_key.glwe_dimension().to_glwe_size().0
    );

    assert!(
        output_cbs_pfpksk_list
            .ciphertext_modulus()
            .is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        output_cbs_pfpksk_list.ciphertext_modulus()
    );

    let decomp_level_count = output_cbs_pfpksk_list.decomposition_level_count();

    let gen_iter = generator
        .par_fork_cbs_pfpksk_to_pfpksk::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            output_cbs_pfpksk_list.lwe_pfpksk_count(),
        )
        .unwrap();

    let mut last_polynomial_as_list = PolynomialListOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.polynomial_size(),
        PolynomialCount(1),
    );
    // We apply the x -> -x function so instead of putting one in the first coeff of the
    // polynomial, we put Scalar::MAX == - Sclar::One so that we can use a single function in
    // the loop avoiding branching
    last_polynomial_as_list.get_mut(0)[0] = Scalar::MAX;

    output_cbs_pfpksk_list
        .par_iter_mut()
        .zip(
            output_glwe_secret_key
                .as_polynomial_list()
                .par_iter()
                .chain(last_polynomial_as_list.par_iter()),
        )
        .zip(gen_iter)
        .for_each(
            |((mut lwe_pfpksk, polynomial_to_encrypt), mut loop_generator)| {
                par_generate_lwe_private_functional_packing_keyswitch_key(
                    input_lwe_secret_key,
                    output_glwe_secret_key,
                    &mut lwe_pfpksk,
                    noise_parameters,
                    &mut loop_generator,
                    |x| Scalar::ZERO.wrapping_sub(x),
                    &polynomial_to_encrypt,
                );
            },
        );
}

#[allow(clippy::too_many_arguments)]
/// Fill the `output` [`LWE ciphertext list`](`LweCiphertextList`) with the bit extraction of the
/// `input` [`LWE ciphertext`](`LweCiphertext`), extracting `number_of_bits_to_extract` bits
/// starting from the bit at index `delta_log` (0-indexed) included, and going towards the most
/// significant bits.
///
/// Output bits are ordered from the MSB to the LSB. Each one of them is output in a distinct [`LWE
/// ciphertext`](`LweCiphertext`), containing the encryption of the bit scaled by q/2 (i.e., the
/// most significant bit in the plaintext representation).
///
/// The caller must provide a properly configured [`FftView`] object and a `PodStack` used as a
/// memory buffer having a capacity at least as large as the result of
/// [`extract_bits_from_lwe_ciphertext_mem_optimized_requirement`].
///
/// See [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`] for usage.
///
/// # Formal Definition
///
/// This function takes as input an [`LWE ciphertext`](`LweCiphertext`)
/// $$\mathsf{ct\} = \mathsf{LWE}^n\_{\vec{s}}( \mathsf{m}) \subseteq \mathbb{Z}\_q^{(n+1)}$$
/// which encrypts some message `m`. We extract bits $m\_i$ of this message into individual LWE
/// ciphertexts. Each of these ciphertexts contains an encryption of $m\_i \cdot q/2$, i.e.
/// $$\mathsf{ct\_i} = \mathsf{LWE}^n\_{\vec{s}}( \mathsf{m\_i} \cdot q/2 )$$.
pub fn extract_bits_from_lwe_ciphertext_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    BskCont,
    KSKCont,
>(
    lwe_in: &LweCiphertext<InputCont>,
    lwe_list_out: &mut LweCiphertextList<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    ksk: &LweKeyswitchKey<KSKCont>,
    delta_log: DeltaLog,
    number_of_bits_to_extract: ExtractedBitsCount,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KSKCont: Container<Element = Scalar>,
{
    assert_eq!(
        lwe_list_out.ciphertext_modulus(),
        lwe_in.ciphertext_modulus()
    );
    assert_eq!(lwe_in.ciphertext_modulus(), ksk.ciphertext_modulus());
    assert!(
        ksk.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    extract_bits(
        lwe_list_out.as_mut_view(),
        lwe_in.as_view(),
        ksk.as_view(),
        fourier_bsk.as_view(),
        delta_log,
        number_of_bits_to_extract,
        fft,
        stack,
    )
}

/// Return the required memory for [`extract_bits_from_lwe_ciphertext_mem_optimized`].
pub fn extract_bits_from_lwe_ciphertext_mem_optimized_requirement<Scalar>(
    lwe_dimension: LweDimension,
    ksk_output_key_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    extract_bits_scratch::<Scalar>(
        lwe_dimension,
        ksk_output_key_lwe_dimension,
        glwe_size,
        polynomial_size,
        fft,
    )
}

#[allow(clippy::too_many_arguments)]
/// Perform a boolean circuit bootstrapping followed by a vertical packing to evaluate a look-up
/// table on an [`LWE ciphertext list`](`LweCiphertextList`). The term "boolean" refers to the fact
/// the input ciphertexts encrypt a single bit of message.
///
/// The provided "big" `luts` look-up table is expected to be divisible into the same number of
/// chunks of polynomials as there are ciphertexts in the `output` [`LWE Ciphertext
/// list`](`LweCiphertextList`). Each chunk of polynomials is used as a look-up table to evaluate
/// during the vertical packing operation to fill an output ciphertext.
///
/// Note that there should be enough polynomials provided in each chunk to perform the vertical
/// packing given the number of boolean input ciphertexts. The number of boolean input ciphertexts
/// is in fact a number of bits. For this example let's say we have 16 input ciphertexts
/// representing 16 bits and want to output 4 ciphertexts. The "big" `luts` will need to be
/// divisible into 4 chunks of equal size. If the polynomial size used is $1024 = 2^{10}$ then each
/// chunk must contain $2^6 = 64$ polynomials ($2^6 * 2^{10} = 2^{16}$) to match the amount of
/// values representable by the 16 input ciphertexts each encrypting a bit. The "big" `luts` then
/// has a layout looking as follows:
///
/// ```text
/// small lut for 1st output ciphertext|...|small lut for 4th output ciphertext
/// |[polynomial 1] ... [polynomial 64]|...|[polynomial 1] ... [polynomial 64]|
/// ```
///
/// The polynomials in the above representation are not necessarily the same, this is just for
/// illustration purposes.
///
/// It is also possible in the above example to have a single polynomial of size $2^{16} = 65 536$
/// for each chunk if the polynomial size is supported for computation. Chunks containing a single
/// polynomial of size $2^{10} = 1024$ would work for example for 10 input ciphertexts as that
/// polynomial size is supported for computations. The "big" `luts` layout would then look as
/// follows for that 10 bits example (still with 4 output ciphertexts):
///
/// ```text
/// small lut for 1st output ciphertext|...|small lut for 4th output ciphertext
/// |[          polynomial 1          ]|...|[          polynomial 1          ]|
/// ```
///
/// The caller must provide a properly configured [`FftView`] object and a `PodStack` used as a
/// memory buffer having a capacity at least as large as the result of
/// [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement`].
///
/// # Example
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_dimension = GlweDimension(1);
/// let lwe_dimension = LweDimension(481);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let var_small = Variance::from_variance(2f64.powf(-80.0));
/// let var_big = Variance::from_variance(2f64.powf(-70.0));
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
/// let lwe_small_sk =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
/// let lwe_big_sk = glwe_sk.clone().into_lwe_secret_key();
///
/// let bsk_level_count = DecompositionLevelCount(9);
/// let bsk_base_log = DecompositionBaseLog(4);
///
/// let std_bsk: LweBootstrapKeyOwned<u64> = par_allocate_and_generate_new_lwe_bootstrap_key(
///     &lwe_small_sk,
///     &glwe_sk,
///     bsk_base_log,
///     bsk_level_count,
///     var_small,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut fourier_bsk = FourierLweBootstrapKeyOwned::new(
///     std_bsk.input_lwe_dimension(),
///     std_bsk.glwe_size(),
///     std_bsk.polynomial_size(),
///     std_bsk.decomposition_base_log(),
///     std_bsk.decomposition_level_count(),
/// );
///
/// let ksk_level_count = DecompositionLevelCount(9);
/// let ksk_base_log = DecompositionBaseLog(1);
///
/// let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
///     &lwe_big_sk,
///     &lwe_small_sk,
///     ksk_base_log,
///     ksk_level_count,
///     var_big,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let pfpksk_level_count = DecompositionLevelCount(9);
/// let pfpksk_base_log = DecompositionBaseLog(4);
///
/// let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
///     &lwe_big_sk,
///     &glwe_sk,
///     pfpksk_base_log,
///     pfpksk_level_count,
///     var_small,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // We will have a message with 10 bits of information
/// let message_bits = 10;
/// let bits_to_extract = ExtractedBitsCount(message_bits);
///
/// // Note that this particular table will not trigger the cmux tree from the vertical packing,
/// // adapt the LUT generation to your usage.
/// //  Here we apply a single look-up table as we output a single ciphertext.
/// let number_of_luts_and_output_vp_ciphertexts = LweCiphertextCount(1);
///
/// let cbs_level_count = DecompositionLevelCount(4);
/// let cbs_base_log = DecompositionBaseLog(6);
///
/// let fft = Fft::new(polynomial_size);
/// let fft = fft.as_view();
/// let mut buffers = ComputationBuffers::new();
///
/// let buffer_size_req =
///     convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
///         .unwrap()
///         .unaligned_bytes_required();
/// let buffer_size_req = buffer_size_req.max(
///     extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
///         lwe_dimension,
///         ksk_big_to_small.output_key_lwe_dimension(),
///         glwe_dimension.to_glwe_size(),
///         polynomial_size,
///         fft,
///     )
///     .unwrap()
///     .unaligned_bytes_required(),
/// );
/// let buffer_size_req = buffer_size_req.max(
///     circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<
///         u64,
///     >(
///         LweCiphertextCount(bits_to_extract.0),
///         number_of_luts_and_output_vp_ciphertexts,
///         lwe_dimension.to_lwe_size(),
///         PolynomialCount(1),
///         fourier_bsk.output_lwe_dimension().to_lwe_size(),
///         fourier_bsk.glwe_size(),
///         polynomial_size,
///         cbs_level_count,
///         fft,
///     )
///     .unwrap()
///     .unaligned_bytes_required(),
/// );
///
/// // We resize our buffers once
/// buffers.resize(buffer_size_req);
///
/// convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
///     &std_bsk,
///     &mut fourier_bsk,
///     fft,
///     buffers.stack(),
/// );
///
/// // The value we encrypt is 42, we will extract the bits of this value and apply the
/// // circuit bootstrapping followed by the vertical packing on the extracted bits.
/// let cleartext = 42;
/// let delta_log_msg = DeltaLog(64 - message_bits);
///
/// let encoded_message = Plaintext(cleartext << delta_log_msg.0);
/// let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(
///     &lwe_big_sk,
///     encoded_message,
///     var_big,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Bit extraction output, use the zero_encrypt engine to allocate a ciphertext vector
/// let mut bit_extraction_output = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(bits_to_extract.0),
///     ciphertext_modulus,
/// );
///
/// extract_bits_from_lwe_ciphertext_mem_optimized(
///     &lwe_in,
///     &mut bit_extraction_output,
///     &fourier_bsk,
///     &ksk_big_to_small,
///     delta_log_msg,
///     bits_to_extract,
///     fft,
///     buffers.stack(),
/// );
///
/// // Though the delta log here is the same as the message delta log, in the general case they
/// // are different, so we create two DeltaLog parameters
/// let delta_log_lut = DeltaLog(64 - message_bits);
///
/// // Create a look-up table we want to apply during vertical packing, here just the identity
/// // with the proper encoding.
/// // Note that this particular table will not trigger the cmux tree from the vertical packing,
/// // adapt the LUT generation to your usage.
/// // Here we apply a single look-up table as we output a single ciphertext.
/// let lut_size = 1 << bits_to_extract.0;
/// let mut lut: Vec<u64> = Vec::with_capacity(lut_size);
///
/// for i in 0..lut_size {
///     lut.push((i as u64 % (1 << message_bits)) << delta_log_lut.0);
/// }
///
/// let lut_as_polynomial_list = PolynomialList::from_container(lut, polynomial_size);
///
/// let mut output_cbs_vp = LweCiphertextList::new(
///     0u64,
///     lwe_big_sk.lwe_dimension().to_lwe_size(),
///     number_of_luts_and_output_vp_ciphertexts,
///     ciphertext_modulus,
/// );
///
/// circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
///     &bit_extraction_output,
///     &mut output_cbs_vp,
///     &lut_as_polynomial_list,
///     &fourier_bsk,
///     &cbs_pfpksk,
///     cbs_base_log,
///     cbs_level_count,
///     fft,
///     buffers.stack(),
/// );
///
/// // We have a single output ct
/// let result_ct = output_cbs_vp.iter().next().unwrap();
///
/// let decomposer = SignedDecomposer::new(
///     DecompositionBaseLog(bits_to_extract.0),
///     DecompositionLevelCount(1),
/// );
///
/// // decrypt result
/// let decrypted_message = decrypt_lwe_ciphertext(&lwe_big_sk, &result_ct);
/// let decoded_message = decomposer.closest_representable(decrypted_message.0) >> delta_log_lut.0;
///
/// // print information if the result is wrong
/// assert_eq!(
///     decoded_message, cleartext,
///     "decoded_message ({decoded_message:?}) != cleartext ({cleartext:?})\n\
/// decrypted_message: {decrypted_message:?}, decoded_message: {decoded_message:?}",
/// );
/// ```
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    LutCont,
    BskCont,
    PFPKSKCont,
>(
    lwe_list_in: &LweCiphertextList<InputCont>,
    lwe_list_out: &mut LweCiphertextList<OutputCont>,
    big_lut_as_polynomial_list: &PolynomialList<LutCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    pfpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<PFPKSKCont>,
    base_log_cbs: DecompositionBaseLog,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    LutCont: Container<Element = Scalar>,
    BskCont: Container<Element = c64>,
    PFPKSKCont: Container<Element = Scalar>,
{
    assert_eq!(
        lwe_list_out.ciphertext_modulus(),
        lwe_list_in.ciphertext_modulus()
    );
    assert_eq!(
        lwe_list_in.ciphertext_modulus(),
        pfpksk_list.ciphertext_modulus()
    );
    assert!(
        pfpksk_list.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    circuit_bootstrap_boolean_vertical_packing(
        big_lut_as_polynomial_list.as_view(),
        fourier_bsk.as_view(),
        lwe_list_out.as_mut_view(),
        lwe_list_in.as_view(),
        pfpksk_list.as_view(),
        level_cbs,
        base_log_cbs,
        fft,
        stack,
    )
}

#[allow(clippy::too_many_arguments)]
/// Return the required memory for
/// [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`].
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement<
    Scalar,
>(
    lwe_list_in_count: LweCiphertextCount,
    lwe_list_out_count: LweCiphertextCount,
    lwe_in_size: LweSize,
    big_lut_polynomial_count: PolynomialCount,
    bsk_output_lwe_size: LweSize,
    glwe_size: GlweSize,
    fpksk_output_polynomial_size: PolynomialSize,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    circuit_bootstrap_boolean_vertical_packing_scratch::<Scalar>(
        lwe_list_in_count,
        lwe_list_out_count,
        lwe_in_size,
        big_lut_polynomial_count,
        bsk_output_lwe_size,
        glwe_size,
        fpksk_output_polynomial_size,
        level_cbs,
        fft,
    )
}
