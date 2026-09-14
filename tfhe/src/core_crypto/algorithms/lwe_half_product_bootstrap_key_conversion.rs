//! Module containing primitives pertaining to the conversion of
//! [`half-product LWE bootstrap keys`](`LweHalfProductBootstrapKey`) to the Fourier domain.

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::math::fft::Fft128;
use rayon::prelude::*;

/// Convert a standard-domain [`LweHalfProductBootstrapKey`] to a Fourier-domain
/// [`Fourier128HalfProductLweBootstrapKey`].
///
/// Both domains share the same row order, so this is a flat polynomial-wise transform.
pub fn par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128<
    Scalar,
    InputCont,
    OutputCont,
>(
    input_bsk: &LweHalfProductBootstrapKey<InputCont>,
    output_bsk: &mut Fourier128HalfProductLweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus + Sync,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = f64>,
{
    assert_eq!(
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
        "Mismatched PolynomialSize between input_bsk {:?} and output_bsk {:?}",
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
    );

    assert_eq!(
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
        "Mismatched GlweSize"
    );

    assert_eq!(
        input_bsk.decomposition_base_log_mask(),
        output_bsk.decomposition_base_log_mask(),
        "Mismatched mask DecompositionBaseLog"
    );

    assert_eq!(
        input_bsk.decomposition_level_count_mask(),
        output_bsk.decomposition_level_count_mask(),
        "Mismatched mask DecompositionLevelCount"
    );

    assert_eq!(
        input_bsk.decomposition_base_log_body(),
        output_bsk.decomposition_base_log_body(),
        "Mismatched body DecompositionBaseLog"
    );

    assert_eq!(
        input_bsk.decomposition_level_count_body(),
        output_bsk.decomposition_level_count_body(),
        "Mismatched body DecompositionLevelCount"
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    let fft = Fft128::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    let fourier_poly_size = output_bsk.polynomial_size().to_fourier_polynomial_size();

    let (data_re0, data_re1, data_im0, data_im1) = output_bsk.as_mut_view().data();

    data_re0
        .par_chunks_exact_mut(fourier_poly_size.0)
        .zip(
            data_re1.par_chunks_exact_mut(fourier_poly_size.0).zip(
                data_im0
                    .par_chunks_exact_mut(fourier_poly_size.0)
                    .zip(data_im1.par_chunks_exact_mut(fourier_poly_size.0)),
            ),
        )
        .zip(
            PolynomialListView::from_container(input_bsk.as_ref(), input_bsk.polynomial_size())
                .par_iter(),
        )
        .for_each(
            |((fourier_re0, (fourier_re1, (fourier_im0, fourier_im1))), coef_poly)| {
                fft.forward_as_torus(
                    fourier_re0,
                    fourier_re1,
                    fourier_im0,
                    fourier_im1,
                    coef_poly.as_ref(),
                );
            },
        );
}

/// Allocating counterpart of
/// [`par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128`].
pub fn par_allocate_and_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128<
    Scalar,
    Cont,
>(
    input_bsk: &LweHalfProductBootstrapKey<Cont>,
) -> Fourier128HalfProductLweBootstrapKeyOwned
where
    Scalar: UnsignedTorus + Sync,
    Cont: Container<Element = Scalar> + Sync,
{
    let mut output_bsk = Fourier128HalfProductLweBootstrapKey::new(
        input_bsk.input_lwe_dimension(),
        input_bsk.glwe_size(),
        input_bsk.polynomial_size(),
        input_bsk.decomposition_base_log_mask(),
        input_bsk.decomposition_level_count_mask(),
        input_bsk.decomposition_base_log_body(),
        input_bsk.decomposition_level_count_body(),
    );

    par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128::<Scalar, _, _>(
        input_bsk,
        &mut output_bsk,
    );

    output_bsk
}
