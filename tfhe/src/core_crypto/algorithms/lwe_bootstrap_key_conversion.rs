//! Module containing primitives pertaining to the conversion of
//! [`standard LWE bootstrap keys`](`LweBootstrapKey`) to various representations/numerical domains
//! like the Fourier domain.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::ntt::ntt64::Ntt64;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::math::fft::Fft128;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::fill_with_forward_fourier_scratch;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use rayon::prelude::*;
use tfhe_fft::c64;

/// Convert an [`LWE bootstrap key`](`LweBootstrapKey`) with standard coefficients to the Fourier
/// domain.
///
/// See [`programmable_bootstrap_lwe_ciphertext`](`crate::core_crypto::algorithms::programmable_bootstrap_lwe_ciphertext`) for usage.
pub fn convert_standard_lwe_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut FourierLweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(input_bsk, output_bsk, fft, stack);
}

/// Memory optimized version of [`convert_standard_lwe_bootstrap_key_to_fourier`].
pub fn convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut FourierLweBootstrapKey<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
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
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    output_bsk
        .as_mut_view()
        .fill_with_forward_fourier(input_bsk.as_view(), fft, stack);
}

pub fn par_convert_standard_lwe_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut FourierLweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
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
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    let fft = Fft::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    output_bsk
        .as_mut_view()
        .par_fill_with_forward_fourier(input_bsk.as_view(), fft);
}

/// Return the required memory for [`convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized`].
pub fn convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    fill_with_forward_fourier_scratch(fft)
}

/// Convert an [`LWE bootstrap key`](`LweBootstrapKey`) with standard coefficients to the Fourier
/// domain.
///
/// See [`programmable_bootstrap_f128_lwe_ciphertext`](`crate::core_crypto::algorithms::programmable_bootstrap_f128_lwe_ciphertext`) for usage.
pub fn convert_standard_lwe_bootstrap_key_to_fourier_128<Scalar, InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut Fourier128LweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
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
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    let fft = Fft128::new(output_bsk.polynomial_size());
    let fft = fft.as_view();

    output_bsk.fill_with_forward_fourier(input_bsk, fft);
}

pub fn par_convert_standard_lwe_bootstrap_key_to_fourier_128<Scalar, InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut Fourier128LweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
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
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
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
        .zip(input_bsk.as_polynomial_list().par_iter())
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

/// Convert an [`LWE bootstrap key`](`LweBootstrapKey`) with standard coefficients to the NTT
/// domain using a 64 bits NTT.
///
/// See [`programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized`](`crate::core_crypto::algorithms::programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized`) for usage.
pub fn convert_standard_lwe_bootstrap_key_to_ntt64<InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut NttLweBootstrapKey<OutputCont>,
    option: NttLweBootstrapKeyOption,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
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
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    let ntt = Ntt64::new(output_bsk.ciphertext_modulus(), input_bsk.polynomial_size());
    let ntt = ntt.as_view();

    // Extract modswitch_requirement
    let modswitch_requirement = ntt.modswitch_requirement(input_bsk.ciphertext_modulus());

    // Allocate a buffer for bitshift and modswitch
    for (input_poly, mut output_poly) in input_bsk
        .as_polynomial_list()
        .iter()
        .zip(output_bsk.as_mut_polynomial_list().iter_mut())
    {
        if let Some(input_modulus_width) = modswitch_requirement {
            ntt.forward_from_power_of_two_modulus(
                input_modulus_width,
                output_poly.as_mut_view(),
                input_poly,
            );
        } else {
            ntt.forward(output_poly.as_mut_view(), input_poly);
        }
        if matches!(option, NttLweBootstrapKeyOption::Normalize) {
            ntt.plan.normalize(output_poly.as_mut());
        }
    }
}

pub fn par_convert_standard_lwe_bootstrap_key_to_ntt64<InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut NttLweBootstrapKey<OutputCont>,
    option: NttLweBootstrapKeyOption,
) where
    InputCont: Container<Element = u64> + std::marker::Sync,
    OutputCont: ContainerMut<Element = u64>,
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
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    let ntt = Ntt64::new(output_bsk.ciphertext_modulus(), input_bsk.polynomial_size());
    let ntt = ntt.as_view();

    // Extract modswitch_requirement
    let modswitch_requirement = ntt.modswitch_requirement(input_bsk.ciphertext_modulus());

    let num_threads = rayon::current_num_threads();
    let input_as_polynomial_list = input_bsk.as_polynomial_list();
    let mut output_as_polynomial_list = output_bsk.as_mut_polynomial_list();
    let chunk_size = input_as_polynomial_list
        .polynomial_count()
        .0
        .div_ceil(num_threads);

    input_as_polynomial_list
        .par_chunks(chunk_size)
        .zip(output_as_polynomial_list.par_chunks_mut(chunk_size))
        .for_each(|(input_poly_chunk, mut output_poly_chunk)| {
            for (input_poly, mut output_poly) in
                input_poly_chunk.iter().zip(output_poly_chunk.iter_mut())
            {
                if let Some(input_modulus_width) = modswitch_requirement {
                    ntt.forward_from_power_of_two_modulus(
                        input_modulus_width,
                        output_poly.as_mut_view(),
                        input_poly,
                    );
                } else {
                    ntt.forward(output_poly.as_mut_view(), input_poly);
                }
                if matches!(option, NttLweBootstrapKeyOption::Normalize) {
                    ntt.plan.normalize(output_poly.as_mut());
                }
            }
        });
}
