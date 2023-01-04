//! Module containing primitives pertaining to the Wopbs (WithOut padding PBS).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::crypto::wop_pbs::{
    circuit_bootstrap_boolean_vertical_packing, circuit_bootstrap_boolean_vertical_packing_scratch,
    extract_bits, extract_bits_scratch,
};
use crate::core_crypto::fft_impl::math::fft::FftView;
use concrete_fft::c64;
use dyn_stack::{DynStack, SizeOverflow, StackReq};
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
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus,
    LweKeyCont: Container<Element = Scalar>,
    GlweKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
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
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    LweKeyCont: Container<Element = Scalar> + Sync,
    GlweKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
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
/// The caller must provide a properly configured [`FftView`] object and a `DynStack` used as a
/// memory buffer having a capacity at least as large as the result of
/// [`extract_bits_from_lwe_ciphertext_mem_optimized_requirement`].
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
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KSKCont: Container<Element = Scalar>,
{
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
/// The caller must provide a properly configured [`FftView`] object and a `DynStack` used as a
/// memory buffer having a capacity at least as large as the result of
/// [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement`].
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
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    LutCont: Container<Element = Scalar>,
    BskCont: Container<Element = c64>,
    PFPKSKCont: Container<Element = Scalar>,
{
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
