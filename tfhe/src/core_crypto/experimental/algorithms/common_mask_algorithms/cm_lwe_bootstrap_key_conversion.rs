//! Module containing primitives pertaining to the conversion of
//! [`common mask LWE bootstrap keys`](`CmLweBootstrapKey`) to various representations/numerical
//! domains like the Fourier domain.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use dyn_stack::{PodStack, StackReq};
use tfhe_fft::c64;

pub fn convert_standard_cm_lwe_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    input_bsk: &CmLweBootstrapKey<InputCont>,
    output_bsk: &mut FourierCmLweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        convert_standard_cm_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
            .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    convert_standard_cm_lwe_bootstrap_key_to_fourier_mem_optimized(
        input_bsk, output_bsk, fft, stack,
    );
}

pub fn convert_standard_cm_lwe_bootstrap_key_to_fourier_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
>(
    input_bsk: &CmLweBootstrapKey<InputCont>,
    output_bsk: &mut FourierCmLweBootstrapKey<OutputCont>,
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
        input_bsk.glwe_dimension(),
        output_bsk.glwe_dimension(),
        "Mismatched GlweSize"
    );

    assert_eq!(
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
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

pub fn par_convert_standard_cm_lwe_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    input_bsk: &CmLweBootstrapKey<InputCont>,
    output_bsk: &mut FourierCmLweBootstrapKey<OutputCont>,
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
        input_bsk.glwe_dimension(),
        output_bsk.glwe_dimension(),
        "Mismatched GlweSize"
    );

    assert_eq!(
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
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

pub fn convert_standard_cm_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> StackReq {
    fft.forward_scratch()
}
