use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, MonomialDegree, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    ContiguousEntityContainer, ContiguousEntityContainerMut,
};
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::fft_impl::fft64::math::fft::FftView;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, StackReq};
use itertools::{izip, Itertools};

pub fn cm_blind_rotate_requirement<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    StackReq::any_of(&[
        // tmp_poly allocation
        StackReq::new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN),
        StackReq::all_of(&[
            // ct1 allocation
            StackReq::new_aligned::<Scalar>(
                cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size),
                CACHELINE_ALIGN,
            ),
            // external product
            cm_add_external_product_assign_requirement::<Scalar>(
                glwe_dimension,
                cm_dimension,
                polynomial_size,
                fft,
            ),
        ]),
    ])
}

pub fn cm_bootstrap_requirement<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    cm_blind_rotate_requirement::<Scalar>(glwe_dimension, cm_dimension, polynomial_size, fft).and(
        StackReq::new_aligned::<Scalar>(
            cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size),
            CACHELINE_ALIGN,
        ),
    )
}

pub fn cm_blind_rotate_assign_requirement<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    StackReq::all_of(&[
        StackReq::new_aligned::<Scalar>(
            cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size),
            CACHELINE_ALIGN,
        ),
        cm_cmux_requirement::<Scalar>(glwe_dimension, cm_dimension, polynomial_size, fft),
    ])
}

// CastInto required for PBS modulus switch which returns a usize
pub fn cm_blind_rotate_assign<InputScalar, OutputScalar>(
    cm_bsk: FourierCmLweBootstrapKeyView<'_>,
    mut luts: CmGlweCiphertextMutView<'_, OutputScalar>,
    lwe: CmLweCiphertextView<'_, InputScalar>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
{
    let mask = lwe.get_mask();
    let bodies = lwe.get_bodies();

    let lut_poly_size = luts.polynomial_size();
    let ciphertext_modulus = luts.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let log_modulus = lut_poly_size.to_blind_rotation_input_modulus_log();

    luts.get_mut_bodies()
        .as_mut_polynomial_list()
        .iter_mut()
        .zip_eq(bodies.iter())
        .for_each(|(mut poly, body)| {
            let monomial_degree =
                MonomialDegree(modulus_switch((*body.data).cast_into(), log_modulus));

            let (tmp_poly, _) = stack.make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

            let mut tmp_poly = Polynomial::from_container(tmp_poly);
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
        });

    // We initialize the ct_0 used for the successive cmuxes
    let mut ct0 = luts;
    let (ct1, stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
    let mut ct1 = CmGlweCiphertextMutView::from_container(
        ct1,
        cm_bsk.glwe_dimension(),
        cm_bsk.cm_dimension(),
        lut_poly_size,
        ciphertext_modulus,
    );

    for (lwe_mask_element, bootstrap_key_ggsw) in
        izip!(mask.as_ref().iter(), cm_bsk.into_cm_ggsw_iter())
    {
        if *lwe_mask_element != InputScalar::ZERO {
            let monomial_degree =
                MonomialDegree(modulus_switch((*lwe_mask_element).cast_into(), log_modulus));

            // we effectively inline the body of cmux here, merging the initial subtraction
            // operation with the monic polynomial multiplication, then performing the external
            // product manually

            // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
            // ct_1 <- (ct_0 * X^{a_hat}) - ct_0
            for (mut ct1_poly, ct0_poly) in izip!(
                ct1.as_mut_polynomial_list().iter_mut(),
                ct0.as_polynomial_list().iter(),
            ) {
                polynomial_wrapping_monic_monomial_mul_and_subtract(
                    &mut ct1_poly,
                    &ct0_poly,
                    monomial_degree,
                );
            }

            // as_mut_view is required to keep borrow rules consistent
            // second step of cmux
            cm_add_external_product_assign(
                ct0.as_mut_view(),
                bootstrap_key_ggsw,
                ct1.as_view(),
                fft,
                stack,
            );
        }
    }

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

pub fn cm_bootstrap<InputScalar, OutputScalar>(
    cm_bsk: FourierCmLweBootstrapKeyView<'_>,
    mut lwe_out: CmLweCiphertextMutView<'_, OutputScalar>,
    lwe_in: CmLweCiphertextView<'_, InputScalar>,
    accumulator: CmGlweCiphertextView<'_, OutputScalar>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
{
    assert!(lwe_in.ciphertext_modulus().is_power_of_two());
    assert!(lwe_out.ciphertext_modulus().is_power_of_two());
    assert_eq!(
        lwe_out.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );

    let (local_accumulator_data, stack) =
        stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
    let mut local_accumulator = CmGlweCiphertextMutView::from_container(
        local_accumulator_data,
        accumulator.glwe_dimension(),
        accumulator.cm_dimension(),
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );

    cm_blind_rotate_assign(
        cm_bsk,
        local_accumulator.as_mut_view(),
        lwe_in.as_view(),
        fft,
        stack,
    );

    extract_lwe_sample_from_cm_glwe_ciphertext(&local_accumulator, &mut lwe_out, MonomialDegree(0));
}
