use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, SizeOverflow, StackReq};

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::collect_next_term;
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::prelude::polynomial_algorithms::*;
use crate::core_crypto::prelude::{
    extract_lwe_sample_from_glwe_ciphertext, lwe_ciphertext_modulus_switch, ComputationBuffers,
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, ModulusSwitchedLweCiphertext,
    MonomialDegree, PolynomialSize, SignedDecomposer,
};

pub fn programmable_bootstrap_karatsuba_lwe_ciphertext_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        // local accumulator
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
        // blind rotation
        blind_rotate_karatsuba_assign_scratch::<Scalar>(glwe_size, polynomial_size)?,
    ])
}

/// Return the required memory for [`blind_rotate_karatsuba_assign`].
pub fn blind_rotate_karatsuba_assign_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_any_of([
        // tmp_poly allocation
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?,
        StackReq::try_all_of([
            // ct1 allocation
            StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
            // external product
            karatsuba_add_external_product_assign_scratch::<Scalar>(glwe_size, polynomial_size)?,
        ])?,
    ])
}

/// Return the required memory for [`karatsuba_add_external_product_assign`].
pub fn karatsuba_add_external_product_assign_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        // Output buffer
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
        // decomposition
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
        // decomposition term
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    ])
}

/// Perform a programmable bootstrap given an input [`LWE ciphertext`](`LweCiphertext`), a
/// look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) using the karatsuba polynomial multiplication. The result is written in
/// the provided output [`LWE ciphertext`](`LweCiphertext`).
///
/// If you want to manage the computation memory manually you can use
/// [`programmable_bootstrap_karatsuba_lwe_ciphertext_mem_optimized`].
///
/// # Warning
/// For a more efficient implementation of the programmable bootstrap, see
/// [`programmable_bootstrap_lwe_ciphertext`](super::programmable_bootstrap_lwe_ciphertext)
pub fn programmable_bootstrap_karatsuba_lwe_ciphertext<InputCont, OutputCont, AccCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    bsk: &LweBootstrapKey<KeyCont>,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
    AccCont: Container<Element = u64>,
    KeyCont: Container<Element = u64>,
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

    buffers.resize(
        programmable_bootstrap_karatsuba_lwe_ciphertext_mem_optimized_requirement::<u64>(
            bsk.glwe_size(),
            bsk.polynomial_size(),
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    programmable_bootstrap_karatsuba_lwe_ciphertext_mem_optimized(
        input,
        output,
        accumulator,
        bsk,
        buffers.stack(),
    );
}

/// Perform a programmable bootstrap given an input [`LWE ciphertext`](`LweCiphertext`), a
/// look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) using the karatsuba polynomial multiplication. The result is written in
/// the provided output [`LWE ciphertext`](`LweCiphertext`).
///
/// # Warning
/// For a more efficient implementation of the programmable bootstrap, see
/// [`programmable_bootstrap_lwe_ciphertext_mem_optimized`](super::programmable_bootstrap_lwe_ciphertext_mem_optimized)
pub fn programmable_bootstrap_karatsuba_lwe_ciphertext_mem_optimized<
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    bsk: &LweBootstrapKey<KeyCont>,
    stack: &mut PodStack,
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
    assert_eq!(accumulator.ciphertext_modulus(), bsk.ciphertext_modulus());

    let (local_accumulator_data, stack) =
        stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
    let mut local_accumulator = GlweCiphertextMutView::from_container(
        &mut *local_accumulator_data,
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );

    let log_modulus = accumulator
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();

    let msed = lwe_ciphertext_modulus_switch(input.as_view(), log_modulus);

    blind_rotate_karatsuba_assign_mem_optimized(&msed, &mut local_accumulator, bsk, stack);

    extract_lwe_sample_from_glwe_ciphertext(&local_accumulator, output, MonomialDegree(0));
}

/// Perform a blind rotation given an input [`modulus switched LWE
/// ciphertext`](`ModulusSwitchedLweCiphertext`), modifying a look-up table passed as a [`GLWE
/// ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap key`](`LweBootstrapKey`) using the
/// karatsuba polynomial multiplication.
///
/// If you want to manage the computation memory manually you can use
/// [`blind_rotate_karatsuba_assign_mem_optimized`].
///
/// # Warning
/// For a more efficient implementation of the blind rotation, see
/// [`blind_rotate_assign`](super::blind_rotate_assign)
pub fn blind_rotate_karatsuba_assign<OutputScalar, OutputCont, KeyCont>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &mut GlweCiphertext<OutputCont>,
    bsk: &LweBootstrapKey<KeyCont>,
) where
    OutputScalar: UnsignedTorus + CastInto<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = OutputScalar>,
    GlweCiphertext<OutputCont>: PartialEq<GlweCiphertext<OutputCont>>,
{
    let mut buffers = ComputationBuffers::new();

    buffers.resize(
        blind_rotate_karatsuba_assign_scratch::<u64>(bsk.glwe_size(), bsk.polynomial_size())
            .unwrap()
            .unaligned_bytes_required(),
    );

    blind_rotate_karatsuba_assign_mem_optimized(msed_input, lut, bsk, buffers.stack())
}

/// Perform a blind rotation given an input [`modulus switched LWE
/// ciphertext`](`ModulusSwitchedLweCiphertext`), modifying a look-up table passed as a [`GLWE
/// ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap key`](`LweBootstrapKey`) using the
/// karatsuba polynomial multiplication.
///
/// # Warning
/// For a more efficient implementation of the blind rotation, see
/// [`blind_rotate_assign`](super::blind_rotate_assign)
pub fn blind_rotate_karatsuba_assign_mem_optimized<OutputScalar, OutputCont, KeyCont>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &mut GlweCiphertext<OutputCont>,
    bsk: &LweBootstrapKey<KeyCont>,
    stack: &mut PodStack,
) where
    OutputScalar: UnsignedTorus + CastInto<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = OutputScalar>,
    GlweCiphertext<OutputCont>: PartialEq<GlweCiphertext<OutputCont>>,
{
    assert!(lut.ciphertext_modulus().is_power_of_two());

    assert_eq!(
        bsk.input_lwe_dimension(),
        msed_input.lwe_dimension(),
        "Mismatched input LweDimension. \
        LweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        bsk.input_lwe_dimension(),
        msed_input.lwe_dimension(),
    );
    assert_eq!(
        bsk.glwe_size(),
        lut.glwe_size(),
        "Mismatched output LweDimension. \
        LweBootstrapKey input GlweDimension: {:?}, lut GlweDimension {:?}.",
        bsk.glwe_size(),
        lut.glwe_size(),
    );
    assert_eq!(lut.polynomial_size(), bsk.polynomial_size());

    let msed_lwe_mask = msed_input.mask();

    let msed_lwe_body = msed_input.body();

    let monomial_degree = MonomialDegree(msed_lwe_body.cast_into());

    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    lut.as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            let (tmp_poly, _) = stack.make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

            let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
        });

    // We initialize the ct_0 used for the successive cmuxes
    let ct0 = lut;
    let (ct1, stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
    let mut ct1 =
        GlweCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

    for (lwe_mask_element, bootstrap_key_ggsw) in izip_eq!(msed_lwe_mask, bsk.iter()) {
        if lwe_mask_element != 0 {
            let monomial_degree = MonomialDegree(lwe_mask_element);

            // we effectively inline the body of cmux here, merging the initial subtraction
            // operation with the monic polynomial multiplication, then performing the
            // external product manually

            // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
            // ct_1 <- (ct_0 * X^a_i) - ct_0
            for (mut ct1_poly, ct0_poly) in izip_eq!(
                ct1.as_mut_polynomial_list().iter_mut(),
                ct0.as_polynomial_list().iter(),
            ) {
                polynomial_wrapping_monic_monomial_mul_and_subtract(
                    &mut ct1_poly,
                    &ct0_poly,
                    monomial_degree,
                );
            }

            // second step of cmux:
            // ct_0 <- ct_0 + ct1s_i
            // with ct_0 + ct1s_i = ct_0 + ((ct_0 * X^a_i) - ct_0)s_i
            //                    = ct_0          if s_i= 0
            //                      ct_0 * X^a_i  otherwise
            //                    = ct_0 * X^(a_i * s_i)
            //
            // as_mut_view is required to keep borrow rules consistent
            karatsuba_add_external_product_assign(
                ct0.as_mut_view(),
                bootstrap_key_ggsw,
                ct1.as_view(),
                stack,
            );
        }
    }

    if !ciphertext_modulus.is_native_modulus() {
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

/// Perform the external product of `ggsw` and `glwe`, and adds the result to `out`.
#[cfg_attr(feature = "__profiling", inline(never))]
pub fn karatsuba_add_external_product_assign<Scalar>(
    mut out: GlweCiphertextMutView<'_, Scalar>,
    ggsw: GgswCiphertextView<Scalar>,
    glwe: GlweCiphertextView<Scalar>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
{
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
    debug_assert_eq!(ggsw.glwe_size(), out.glwe_size());

    let align = CACHELINE_ALIGN;
    let poly_size = ggsw.polynomial_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposer::<Scalar>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
    );

    let (output_buffer, substack0) =
        stack.make_aligned_raw::<Scalar>(poly_size * ggsw.glwe_size().0, align);
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_buffer = &mut *output_buffer;
    let mut is_output_uninit = true;

    let (mut decomposition, substack1) = TensorSignedDecompositionLendingIter::new(
        glwe.as_ref()
            .iter()
            .map(|s| decomposer.init_decomposer_state(*s)),
        DecompositionBaseLog(decomposer.base_log),
        DecompositionLevelCount(decomposer.level_count),
        substack0,
    );

    // We loop through the levels (we reverse to match the order of the decomposition iterator.)
    for ggsw_decomp_matrix in ggsw.iter() {
        // We retrieve the decomposition of this level.
        let (_glwe_level, glwe_decomp_term, _substack2) =
            collect_next_term(&mut decomposition, substack1, align);
        let glwe_decomp_term = GlweCiphertextView::from_container(
            &*glwe_decomp_term,
            ggsw.polynomial_size(),
            out.ciphertext_modulus(),
        );

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

        for (ggsw_row, glwe_poly) in izip_eq!(
            ggsw_decomp_matrix.as_glwe_list().iter(),
            glwe_decomp_term.as_polynomial_list().iter()
        ) {
            let row_as_poly_list = ggsw_row.as_polynomial_list();
            if is_output_uninit {
                for (mut output_poly, row_poly) in output_buffer
                    .chunks_exact_mut(poly_size)
                    .map(Polynomial::from_container)
                    .zip(row_as_poly_list.iter())
                {
                    polynomial_wrapping_mul(&mut output_poly, &row_poly, &glwe_poly);
                }
            } else {
                for (mut output_poly, row_poly) in output_buffer
                    .chunks_exact_mut(poly_size)
                    .map(Polynomial::from_container)
                    .zip(row_as_poly_list.iter())
                {
                    polynomial_wrapping_add_mul_assign(&mut output_poly, &row_poly, &glwe_poly);
                }
            }

            is_output_uninit = false;
        }
    }

    // We iterate over the polynomials in the output.
    if !is_output_uninit {
        izip_eq!(
            out.as_mut_polynomial_list().iter_mut(),
            output_buffer
                .into_chunks(poly_size)
                .map(Polynomial::from_container),
        )
        .for_each(|(mut out, res)| polynomial_wrapping_add_assign(&mut out, &res));
    }
}
