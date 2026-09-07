//! Module containing primitives pertaining to the conversion of
//! [`standard GGSW ciphertexts`](`GgswCiphertext`) to various representations/numerical domains
//! like the Fourier domain.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::ntt::ntt64::Ntt64View;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::fill_with_forward_fourier_scratch;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use dyn_stack::{PodStack, StackReq};
use tfhe_fft::c64;

/// Convert a [`GGSW ciphertext`](`GgswCiphertext`) with standard coefficients to the Fourier
/// domain.
///
/// If you want to manage the computation memory manually you can use
/// [`convert_standard_ggsw_ciphertext_to_fourier_mem_optimized`].
pub fn convert_standard_ggsw_ciphertext_to_fourier<Scalar, InputCont, OutputCont>(
    input_ggsw: &GgswCiphertext<InputCont>,
    output_ggsw: &mut FourierGgswCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let fft = Fft::new(output_ggsw.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
            .unaligned_bytes_required(),
    );

    convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
        input_ggsw,
        output_ggsw,
        fft,
        buffers.stack(),
    );
}

/// Memory optimized version of [`convert_standard_ggsw_ciphertext_to_fourier`].
///
/// See [`cmux_assign_mem_optimized`](`crate::core_crypto::algorithms::cmux_assign_mem_optimized`)
/// for usage.
pub fn convert_standard_ggsw_ciphertext_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    input_ggsw: &GgswCiphertext<InputCont>,
    output_ggsw: &mut FourierGgswCiphertext<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    output_ggsw
        .as_mut_view()
        .fill_with_forward_fourier(input_ggsw.as_view(), fft, stack);
}

/// Return the required memory for [`convert_standard_ggsw_ciphertext_to_fourier_mem_optimized`].
pub fn convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> StackReq {
    fill_with_forward_fourier_scratch(fft)
}

/// Convert a [`GGSW ciphertext`](`GgswCiphertext`) with standard coefficients to the NTT domain
/// using a 64 bits NTT.
///
/// If the [`CiphertextModulus`](`crate::core_crypto::commons::parameters::CiphertextModulus`) of
/// the input ciphertext is a power of two, its coefficients are first switched to the (prime)
/// modulus of the NTT, otherwise the input modulus is required to be the NTT modulus.
///
/// The `option` indicates whether the NTT normalization is embedded in the output or not, see
/// [`NttLweBootstrapKeyOption`].
pub fn convert_standard_ggsw_ciphertext_to_ntt64<InputCont, OutputCont>(
    input_ggsw: &GgswCiphertext<InputCont>,
    output_ggsw: &mut NttGgswCiphertext<OutputCont>,
    ntt: Ntt64View<'_>,
    option: NttLweBootstrapKeyOption,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
{
    assert_eq!(
        input_ggsw.polynomial_size(),
        output_ggsw.polynomial_size(),
        "Mismatched PolynomialSize between input_ggsw {:?} and output_ggsw {:?}",
        input_ggsw.polynomial_size(),
        output_ggsw.polynomial_size(),
    );

    assert_eq!(
        input_ggsw.polynomial_size(),
        ntt.polynomial_size(),
        "Mismatched PolynomialSize between input_ggsw {:?} and ntt {:?}",
        input_ggsw.polynomial_size(),
        ntt.polynomial_size(),
    );

    assert_eq!(
        input_ggsw.glwe_size(),
        output_ggsw.glwe_size(),
        "Mismatched GlweSize between input_ggsw {:?} and output_ggsw {:?}",
        input_ggsw.glwe_size(),
        output_ggsw.glwe_size(),
    );

    assert_eq!(
        input_ggsw.decomposition_base_log(),
        output_ggsw.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_ggsw {:?} and output_ggsw {:?}",
        input_ggsw.decomposition_base_log(),
        output_ggsw.decomposition_base_log(),
    );

    assert_eq!(
        input_ggsw.decomposition_level_count(),
        output_ggsw.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_ggsw {:?} and output_ggsw {:?}",
        input_ggsw.decomposition_level_count(),
        output_ggsw.decomposition_level_count(),
    );

    let polynomial_size = input_ggsw.polynomial_size();

    // Extract modswitch_requirement
    let modswitch_requirement = ntt.modswitch_requirement(input_ggsw.ciphertext_modulus());

    for (input_poly, mut output_poly) in izip_eq!(
        input_ggsw.as_polynomial_list().iter(),
        output_ggsw
            .as_mut()
            .chunks_exact_mut(polynomial_size.0)
            .map(PolynomialMutView::from_container)
    ) {
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
