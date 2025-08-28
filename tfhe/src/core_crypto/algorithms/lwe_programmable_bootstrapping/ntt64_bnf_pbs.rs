//! Module containing primitives pertaining to the [`LWE programmable
//! bootstrap`](`crate::core_crypto::entities::LweBootstrapKey#programmable-bootstrapping`) using 64
//! bits NTT for polynomial multiplication.

use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::ntt::ntt64::{Ntt64, Ntt64View};
use crate::core_crypto::commons::parameters::{GlweSize, MonomialDegree, PolynomialSize};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{lwe_ciphertext_modulus_switch, ModulusSwitchedLweCiphertext};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, SizeOverflow, StackReq};

/// Perform a blind rotation given an input [`LWE ciphertext`](`LweCiphertext`), modifying a look-up
/// table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) in the NTT domain see [`NTT LWE bootstrap
/// key`](`NttLweBootstrapKey`).
///
/// If you want to manage the computation memory manually you can use
/// [`blind_rotate_ntt64_bnf_assign_mem_optimized`].
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
/// let ntt_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
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
/// // Generate the bootstrapping key to show, we use the parallel variant for performance reason
/// let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
///     &small_lwe_sk,
///     &glwe_sk,
///     pbs_base_log,
///     pbs_level,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Create the empty bootstrapping key in the Fourier domain
/// let mut ntt_bsk = NttLweBootstrapKey::new(
///     0u64,
///     std_bootstrapping_key.input_lwe_dimension(),
///     std_bootstrapping_key.glwe_size(),
///     std_bootstrapping_key.polynomial_size(),
///     std_bootstrapping_key.decomposition_base_log(),
///     std_bootstrapping_key.decomposition_level_count(),
///     ntt_modulus,
/// );
///
/// // Use the conversion function (a memory optimized version also exists but is more complicated
/// // to use) to convert the standard bootstrapping key to the Fourier domain.
/// convert_standard_lwe_bootstrap_key_to_ntt64(
///     &std_bootstrapping_key,
///     &mut ntt_bsk,
///     NttLweBootstrapKeyOption::Raw,
/// );
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
/// blind_rotate_ntt64_bnf_assign(&lwe_ciphertext_in_msed, &mut accumulator, &ntt_bsk);
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
/// // Round and remove our encoding
/// let pbs_multiplication_result: u64 = divide_round(pbs_multiplication_plaintext.0, delta);
///
/// println!("Checking result...");
/// assert_eq!(6, pbs_multiplication_result);
/// println!(
///     "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
/// );
/// ```
pub fn blind_rotate_ntt64_bnf_assign<OutputCont, KeyCont>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &mut GlweCiphertext<OutputCont>,
    bsk: &NttLweBootstrapKey<KeyCont>,
) where
    OutputCont: ContainerMut<Element = u64>,
    KeyCont: Container<Element = u64>,
{
    let mut buffers = ComputationBuffers::new();

    let ntt = Ntt64::new(bsk.ciphertext_modulus(), bsk.polynomial_size());
    let ntt = ntt.as_view();

    buffers.resize(
        blind_rotate_ntt64_bnf_assign_mem_optimized_requirement(
            bsk.glwe_size(),
            bsk.polynomial_size(),
            ntt,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    blind_rotate_ntt64_bnf_assign_mem_optimized(msed_input, lut, bsk, ntt, stack);
}

/// Memory optimized version of [`blind_rotate_ntt64_bnf_assign`], the caller must provide
/// a properly configured [`Ntt64View`] object and a `PodStack` used as a memory buffer having a
/// capacity at least as large as the result of
/// [`blind_rotate_ntt64_bnf_assign_mem_optimized_requirement`].
///
/// # Panics
/// This will panic if the input mask len does not match the size of the bsk
pub fn blind_rotate_ntt64_bnf_assign_mem_optimized<OutputCont, KeyCont>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &mut GlweCiphertext<OutputCont>,
    bsk: &NttLweBootstrapKey<KeyCont>,
    ntt: Ntt64View<'_>,
    stack: &mut PodStack,
) where
    OutputCont: ContainerMut<Element = u64>,
    KeyCont: Container<Element = u64>,
{
    fn implementation(
        bsk: NttLweBootstrapKeyView<'_, u64>,
        lut: GlweCiphertextMutView<'_, u64>,
        msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
        ntt: Ntt64View<'_>,
        stack: &mut PodStack,
    ) {
        use crate::core_crypto::prelude::polynomial_algorithms::{
            polynomial_wrapping_monic_monomial_div_assign,
            polynomial_wrapping_monic_monomial_mul_assign,
        };

        let msed_lwe_mask = msed_lwe.mask();
        let msed_lwe_body = msed_lwe.body();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;

        for (lwe_mask_element, bootstrap_key_ggsw) in izip_eq!(msed_lwe_mask, bsk.into_ggsw_iter())
        {
            if lwe_mask_element != 0 {
                // We copy ct_0 to ct_1
                let (ct1, stack) =
                    stack.collect_aligned(CACHELINE_ALIGN, ct0.as_ref().iter().copied());
                let mut ct1 =
                    GlweCiphertextMutView::from_container(ct1, lut_poly_size, ciphertext_modulus);

                // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                for mut poly in ct1.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign(
                        &mut poly,
                        MonomialDegree(lwe_mask_element),
                    );
                }

                // ct1 is re-created each loop it can be moved, ct0 is already a view, but
                // as_mut_view is required to keep borrow rules consistent
                cmux_ntt64_bnf_assign(ct0.as_mut_view(), ct1, bootstrap_key_ggsw, ntt, stack);
            }
        }

        // Finally apply rotation by -b

        ct0.as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_div_assign(
                    &mut poly,
                    MonomialDegree(msed_lwe_body),
                )
            });
    }

    implementation(bsk.as_view(), lut.as_mut_view(), msed_input, ntt, stack);
}

/// Perform a programmable bootstrap given an input [`LWE ciphertext`](`LweCiphertext`), a
/// look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) in the NTT domain see [`NTT LWE bootstrap
/// key`](`NttLweBootstrapKey`). The result is written in the provided output
/// [`LWE ciphertext`](`LweCiphertext`).
///
/// If you want to manage the computation memory manually you can use
/// [`programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized`].
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
/// let ntt_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
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
/// // Generate the bootstrapping key, we use the parallel variant for performance reason
/// let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
///     &small_lwe_sk,
///     &glwe_sk,
///     pbs_base_log,
///     pbs_level,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Create the empty bootstrapping key in the Fourier domain
/// let mut ntt_bsk = NttLweBootstrapKey::new(
///     0u64,
///     std_bootstrapping_key.input_lwe_dimension(),
///     std_bootstrapping_key.glwe_size(),
///     std_bootstrapping_key.polynomial_size(),
///     std_bootstrapping_key.decomposition_base_log(),
///     std_bootstrapping_key.decomposition_level_count(),
///     ntt_modulus,
/// );
///
/// // Use the conversion function (a memory optimized version also exists but is more complicated
/// // to use) to convert the standard bootstrapping key to the Fourier domain.
/// convert_standard_lwe_bootstrap_key_to_ntt64(
///     &std_bootstrapping_key,
///     &mut ntt_bsk,
///     NttLweBootstrapKeyOption::Raw,
/// );
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
/// programmable_bootstrap_ntt64_bnf_lwe_ciphertext(
///     &lwe_ciphertext_in,
///     &mut pbs_multiplication_ct,
///     &accumulator,
///     &ntt_bsk,
/// );
///
/// // Decrypt the PBS multiplication result
/// let pbs_multiplication_plaintext: Plaintext<u64> =
///     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
///
/// // Round and remove our encoding
/// let pbs_multiplication_result: u64 = divide_round(pbs_multiplication_plaintext.0, delta);
///
/// println!("Checking result...");
/// assert_eq!(6, pbs_multiplication_result);
/// println!(
///     "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
/// );
/// ```
pub fn programmable_bootstrap_ntt64_bnf_lwe_ciphertext<InputCont, OutputCont, AccCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    bsk: &NttLweBootstrapKey<KeyCont>,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
    AccCont: Container<Element = u64>,
    KeyCont: Container<Element = u64>,
{
    assert_eq!(
        output.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );
    let mut buffers = ComputationBuffers::new();

    let ntt = Ntt64::new(bsk.ciphertext_modulus(), bsk.polynomial_size());
    let ntt = ntt.as_view();

    buffers.resize(
        programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized_requirement(
            bsk.glwe_size(),
            bsk.polynomial_size(),
            ntt,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized(
        input,
        output,
        accumulator,
        bsk,
        ntt,
        stack,
    );
}

pub fn programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized<
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    bsk: &NttLweBootstrapKey<KeyCont>,
    ntt: Ntt64View<'_>,
    stack: &mut PodStack,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
    AccCont: Container<Element = u64>,
    KeyCont: Container<Element = u64>,
{
    fn implementation(
        bsk: NttLweBootstrapKeyView<'_, u64>,
        mut lwe_out: LweCiphertextMutView<'_, u64>,
        lwe_in: LweCiphertextView<'_, u64>,
        accumulator: GlweCiphertextView<'_, u64>,
        ntt: Ntt64View<'_>,
        stack: &mut PodStack,
    ) {
        debug_assert_eq!(
            lwe_out.ciphertext_modulus(),
            accumulator.ciphertext_modulus()
        );

        let (local_accumulator_data, stack) =
            stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = GlweCiphertextMutView::from_container(
            local_accumulator_data,
            accumulator.polynomial_size(),
            accumulator.ciphertext_modulus(),
        );

        let log_modulus = accumulator
            .polynomial_size()
            .to_blind_rotation_input_modulus_log();

        let lwe_in_msed = lwe_ciphertext_modulus_switch(lwe_in, log_modulus);

        blind_rotate_ntt64_bnf_assign_mem_optimized(
            &lwe_in_msed,
            &mut local_accumulator,
            &bsk,
            ntt,
            stack,
        );

        extract_lwe_sample_from_glwe_ciphertext(
            &local_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }

    implementation(
        bsk.as_view(),
        output.as_mut_view(),
        input.as_view(),
        accumulator.as_view(),
        ntt,
        stack,
    )
}

/// Perform the external product of `ggsw` and `glwe`, and adds the result to `out`.
#[cfg_attr(feature = "__profiling", inline(never))]
pub(crate) fn add_external_product_ntt64_bnf_assign<InputGlweCont>(
    out: GlweCiphertextMutView<'_, u64>,
    ggsw: NttGgswCiphertextView<'_, u64>,
    glwe: &GlweCiphertext<InputGlweCont>,
    ntt: Ntt64View<'_>,
    stack: &mut PodStack,
) where
    InputGlweCont: Container<Element = u64>,
{
    fn implementation<InputGlweCont>(
        mut out: GlweCiphertextMutView<'_, u64>,
        ggsw: NttGgswCiphertextView<'_, u64>,
        glwe: &GlweCiphertext<InputGlweCont>,
        ntt: Ntt64View<'_>,
        stack: &mut PodStack,
    ) where
        InputGlweCont: Container<Element = u64>,
    {
        // Check that modswitch is really needed around cmux
        use crate::core_crypto::fft_impl::fft64::crypto::ggsw::collect_next_term;
        use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
        use crate::core_crypto::prelude::SignedDecomposer;
        let power_of_two_modulus_width =
            ntt.modswitch_requirement(glwe.ciphertext_modulus()).expect(
                "Back and Forth modswitch implementation only work with power-of-two user modulus",
            );

        // we check that the polynomial sizes match
        debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
        // we check that the glwe sizes match
        debug_assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), out.glwe_size());

        let align = CACHELINE_ALIGN;
        let poly_size = ggsw.polynomial_size().0;

        // we round the input mask and body
        let decomposer = SignedDecomposer::<u64>::new(
            ggsw.decomposition_base_log(),
            ggsw.decomposition_level_count(),
        );

        let (output_fft_buffer, substack0) =
            stack.make_aligned_raw::<u64>(poly_size * ggsw.glwe_size().0, align);
        // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
        // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
        // it has been fully initialized for the first time.
        let mut is_output_uninit = true;

        {
            // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER
            // DOMAIN In this section, we perform the external product in the ntt
            // domain, and accumulate the result in the output_fft_buffer variable.
            let (mut decomposition, substack1) = TensorSignedDecompositionLendingIter::new(
                glwe.as_ref()
                    .iter()
                    .map(|s| decomposer.init_decomposer_state(*s)),
                decomposer.base_log(),
                decomposer.level_count(),
                substack0,
            );

            // We loop through the levels
            ggsw.into_levels().for_each(|ggsw_decomp_matrix| {
                // We retrieve the decomposition of this level.
                let (glwe_level, glwe_decomp_term, substack2) =
                    collect_next_term(&mut decomposition, substack1, align);
                let glwe_decomp_term = GlweCiphertextView::from_container(
                    &*glwe_decomp_term,
                    ggsw.polynomial_size(),
                    out.ciphertext_modulus(),
                );
                debug_assert_eq!(ggsw_decomp_matrix.decomposition_level(), glwe_level);

                // For each level we have to add the result of the vector-matrix product between the
                // decomposition of the glwe, and the ggsw level matrix to the output. To do so, we
                // iteratively add to the output, the product between every line of the matrix, and
                // the corresponding (scalar) polynomial in the glwe decomposition:
                //
                //                ggsw_mat                        ggsw_mat
                //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
                //  | - - - | x | - - - - |         | - - - | x | - - - - | <
                //    ^         | - - - - |             ^       | - - - - |
                //
                //        t = 1                           t = 2                     ...

                izip_eq!(
                    ggsw_decomp_matrix.into_rows(),
                    glwe_decomp_term.as_polynomial_list().iter()
                )
                .for_each(|(ggsw_row, glwe_poly)| {
                    let mut ntt_poly = PolynomialMutView::from_container(
                        substack2.make_aligned_raw::<u64>(poly_size, align).0,
                    );
                    // We perform the forward ntt transform for the glwe polynomial
                    ntt.forward_from_decomp(ntt_poly.as_mut_view(), glwe_poly.as_view());

                    // Now we loop through the polynomials of the output, and add the
                    // corresponding product of polynomials.
                    update_with_fmadd_ntt64_bnf(
                        output_fft_buffer,
                        ggsw_row.as_ref(),
                        ntt_poly.as_ref(),
                        is_output_uninit,
                        poly_size,
                        ntt,
                    );

                    // we initialized `output_fft_buffer, so we can set this to false
                    is_output_uninit = false;
                });
            });
        }

        // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
        // In this section, we bring the result from the ntt domain, back to the standard
        // domain, and add it to the output.
        //
        // We iterate over the polynomials in the output.
        if !is_output_uninit {
            izip_eq!(
                out.as_mut_polynomial_list().iter_mut(),
                output_fft_buffer
                    .into_chunks(poly_size)
                    .map(PolynomialMutView::from_container),
            )
            .for_each(|(out, mut ntt_poly)| {
                // NB: Bnf implementation apply normalization on each bwd path
                ntt.plan.normalize(ntt_poly.as_mut());
                ntt.add_backward_on_power_of_two_modulus(power_of_two_modulus_width, out, ntt_poly);
            });
        }
    }

    implementation(out, ggsw, glwe, ntt, stack);
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
///
/// # Panics
/// This will panic if ct0 and ct1 are not of the same size
pub(crate) fn cmux_ntt64_bnf_assign(
    ct0: GlweCiphertextMutView<'_, u64>,
    ct1: GlweCiphertextMutView<'_, u64>,
    ggsw: NttGgswCiphertextView<'_, u64>,
    ntt: Ntt64View<'_>,
    stack: &mut PodStack,
) {
    fn implementation(
        ct0: GlweCiphertextMutView<'_, u64>,
        mut ct1: GlweCiphertextMutView<'_, u64>,
        ggsw: NttGgswCiphertextView<'_, u64>,
        ntt: Ntt64View<'_>,
        stack: &mut PodStack,
    ) {
        izip_eq!(ct1.as_mut(), ct0.as_ref(),).for_each(|(c1, c0)| {
            *c1 = c1.wrapping_sub(*c0);
        });
        add_external_product_ntt64_bnf_assign(ct0, ggsw, &ct1, ntt, stack);
    }

    implementation(ct0, ct1, ggsw, ntt, stack);
}

#[cfg_attr(feature = "__profiling", inline(never))]
pub(crate) fn update_with_fmadd_ntt64_bnf(
    output_fft_buffer: &mut [u64],
    lhs_polynomial_list: &[u64],
    ntt_poly: &[u64],
    is_output_uninit: bool,
    poly_size: usize,
    ntt: Ntt64View<'_>,
) {
    if is_output_uninit {
        output_fft_buffer.fill(0);
    }

    izip_eq!(
        output_fft_buffer.into_chunks(poly_size),
        lhs_polynomial_list.into_chunks(poly_size)
    )
    .for_each(|(output_ntt, ggsw_poly)| {
        ntt.plan.mul_accumulate(output_ntt, ggsw_poly, ntt_poly);
    });
}

/// Return the required memory for [`add_external_product_ntt64_bnf_assign`].
pub(crate) fn ntt64_bnf_add_external_product_assign_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, align)?;
    let decomp_sign_scratch =
        StackReq::try_new_aligned::<u8>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch = StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch_single = StackReq::try_new_aligned::<u64>(polynomial_size.0, align)?;
    let _ = &ntt;

    let substack2 = ntt_scratch_single;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = substack1
        .try_and(standard_scratch)?
        .try_and(decomp_sign_scratch)?;
    substack0.try_and(ntt_scratch)
}

/// Return the required memory for [`cmux_ntt64_bnf_assign`].
pub(crate) fn ntt64_bnf_cmux_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    ntt64_bnf_add_external_product_assign_scratch(glwe_size, polynomial_size, ntt)
}

/// Return the required memory for [`blind_rotate_ntt64_bnf_assign_mem_optimized`].
pub fn blind_rotate_ntt64_bnf_assign_mem_optimized_requirement(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?
        .try_and(ntt64_bnf_cmux_scratch(glwe_size, polynomial_size, ntt)?)
}

/// Return the required memory for
/// [`programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized`].
pub fn programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized_requirement(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_ntt64_bnf_assign_mem_optimized_requirement(glwe_size, polynomial_size, ntt)?
        .try_and(StackReq::try_new_aligned::<u64>(
            glwe_size.0 * polynomial_size.0,
            CACHELINE_ALIGN,
        )?)
}
