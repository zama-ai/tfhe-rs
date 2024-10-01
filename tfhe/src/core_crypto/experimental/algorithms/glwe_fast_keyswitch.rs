//! Module containing primitives pertaining to the FFT-based GLWE keyswitch.

use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::entities::fourier_pseudo_ggsw_ciphertext::{
    PseudoFourierGgswCiphertext, PseudoFourierGgswCiphertextView,
};
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{collect_next_term, update_with_fmadd};
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::fft_impl::fft64::math::fft::FftView;
use crate::core_crypto::fft_impl::fft64::math::polynomial::{
    FourierPolynomialMutView, FourierPolynomialView,
};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

/// The caller must provide a properly configured [`FftView`] object and a `PodStack` used as a
/// memory buffer having a capacity at least as large as the result of
/// [`glwe_fast_keyswitch_requirement`].
///
/// Compute the external product of `pseudo_ggsw` and `glwe`, and add the result to `out`.
///
/// Strictly speaking this function computes:
///
/// ```text
/// out <- out + glwe * pseudo_ggsw
/// ```
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::experimental::prelude::*;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size_out = GlweSize(2);
/// let glwe_size_in = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(2);
/// let glwe_noise_distribution =
///     DynamicDistribution::new_gaussian_from_std_dev(StandardDev(8.881784197001252e-16));
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
/// let glwe_secret_key_out = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size_out.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the GlweSecretKey
/// let glwe_secret_key_in = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size_in.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create a new GgswCiphertext
/// let mut pseudo_ggsw = PseudoGgswCiphertext::new(
///     0u64,
///     glwe_size_in,
///     glwe_size_out,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_pseudo_ggsw_ciphertext(
///     &glwe_secret_key_out,
///     &glwe_secret_key_in,
///     &mut pseudo_ggsw,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let ct_plaintext = Plaintext(3 << 60);
///
/// let mut ct_plaintexts = PlaintextList::new(ct_plaintext.0, PlaintextCount(polynomial_size.0));
/// let mut ct = GlweCiphertext::new(0u64, glwe_size_in, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key_in,
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
/// let buffer_size_req =
///     glwe_fast_keyswitch_requirement::<u64>(glwe_size_out, polynomial_size, fft)
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
/// let mut fourier_ggsw = PseudoFourierGgswCiphertext::new(
///     glwe_size_in,
///     glwe_size_out,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
/// );
///
/// convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized(
///     &pseudo_ggsw,
///     &mut fourier_ggsw,
///     fft,
///     buffers.stack(),
/// );
///
/// let mut ct_out = GlweCiphertext::new(0u64, glwe_size_out, polynomial_size, ciphertext_modulus);
///
/// glwe_fast_keyswitch(&mut ct_out, &fourier_ggsw, &ct, fft, buffers.stack());
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, ct_plaintexts.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key_out, &ct_out, &mut output_plaintext_list);
///
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));
///
/// assert_eq!(output_plaintext_list.as_ref(), ct_plaintexts.as_ref());
/// ```
pub fn glwe_fast_keyswitch<Scalar, OutputGlweCont, InputGlweCont, GgswCont>(
    out: &mut GlweCiphertext<OutputGlweCont>,
    pseudo_ggsw: &PseudoFourierGgswCiphertext<GgswCont>,
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

    out.as_mut().fill(Scalar::ZERO);

    /// Perform the external product of `ggsw` and `glwe`, and adds the result to `out`.
    #[cfg_attr(feature = "__profiling", inline(never))]
    pub fn impl_glwe_fast_keyswitch<Scalar, InputGlweCont>(
        mut out: GlweCiphertextMutView<'_, Scalar>,
        ggsw: PseudoFourierGgswCiphertextView<'_>,
        glwe: &GlweCiphertext<InputGlweCont>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) where
        Scalar: UnsignedTorus,
        InputGlweCont: Container<Element = Scalar>,
    {
        // we check that the polynomial sizes match
        debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
        // we check that the glwe sizes match
        debug_assert_eq!(ggsw.glwe_size_out(), out.glwe_size());

        let align = CACHELINE_ALIGN;
        let fourier_poly_size = ggsw.polynomial_size().to_fourier_polynomial_size().0;

        // we round the input mask and body
        let decomposer = SignedDecomposer::<Scalar>::new(
            ggsw.decomposition_base_log(),
            ggsw.decomposition_level_count(),
        );
        let (output_fft_buffer, substack0) =
            stack.make_aligned_raw::<c64>(fourier_poly_size * ggsw.glwe_size_out().0, align);
        // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
        // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
        // it has been fully initialized for the first time.
        let mut is_output_uninit = true;

        {
            // ------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
            // In this section, we perform the external product in the fourier
            // domain, and accumulate the result in the output_fft_buffer variable.
            let (mut decomposition, substack1) = TensorSignedDecompositionLendingIter::new(
                glwe.as_ref()
                    .iter()
                    .map(|s| decomposer.init_decomposer_state(*s)),
                DecompositionBaseLog(decomposer.base_log),
                DecompositionLevelCount(decomposer.level_count),
                substack0,
            );

            // We loop through the levels (we reverse to match the order of the decomposition
            // iterator.)
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

                izip!(
                    ggsw_decomp_matrix.into_rows(),
                    glwe_decomp_term.get_mask().as_polynomial_list().iter()
                )
                .for_each(|(ggsw_row, glwe_poly)| {
                    let (fourier, substack3) =
                        substack2.make_aligned_raw::<c64>(fourier_poly_size, align);

                    // We perform the forward fft transform for the glwe polynomial
                    let fourier = fft
                        .forward_as_integer(
                            FourierPolynomialMutView { data: fourier },
                            glwe_poly,
                            substack3,
                        )
                        .data;

                    // Now we loop through the polynomials of the output, and add the
                    // corresponding product of polynomials.
                    update_with_fmadd(
                        output_fft_buffer,
                        ggsw_row.data(),
                        fourier,
                        is_output_uninit,
                        fourier_poly_size,
                    );

                    // we initialized `output_fft_buffer, so we can set this to false
                    is_output_uninit = false;
                });
            });
        }

        // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
        // In this section, we bring the result from the fourier domain, back to the standard
        // domain, and add it to the output.
        //
        // We iterate over the polynomials in the output.
        if !is_output_uninit {
            izip!(
                out.as_mut_polynomial_list().iter_mut(),
                output_fft_buffer
                    .into_chunks(fourier_poly_size)
                    .map(|slice| FourierPolynomialView { data: slice }),
            )
            .for_each(|(out, fourier)| {
                fft.add_backward_as_torus(out, fourier, substack0);
            });
        }

        for (dst, src) in out
            .get_mut_body()
            .as_mut()
            .iter_mut()
            .zip(glwe.get_body().as_ref().iter())
        {
            *dst = dst.wrapping_add(*src);
        }
    }

    impl_glwe_fast_keyswitch(out.as_mut_view(), pseudo_ggsw.as_view(), glwe, fft, stack);

    let ciphertext_modulus = out.ciphertext_modulus();
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

/// Return the required memory for [`glwe_fast_keyswitch`].
pub fn glwe_fast_keyswitch_requirement<Scalar>(
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<Scalar>(glwe_size_out.0 * polynomial_size.0, align)?;
    let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;
    let fourier_scratch =
        StackReq::try_new_aligned::<c64>(glwe_size_out.0 * fourier_polynomial_size, align)?;
    let fourier_scratch_single = StackReq::try_new_aligned::<c64>(fourier_polynomial_size, align)?;

    let substack3 = fft.forward_scratch()?;
    let substack2 = substack3.try_and(fourier_scratch_single)?;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = StackReq::try_any_of([
        substack1.try_and(standard_scratch)?,
        fft.backward_scratch()?,
    ])?;
    substack0.try_and(fourier_scratch)
}
