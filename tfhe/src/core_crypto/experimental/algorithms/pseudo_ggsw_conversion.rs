//! Module containing primitives pertaining to the conversion of
//! [`standard pseudo GGSW ciphertexts`](`PseudoGgswCiphertext`) to various
//! representations/numerical domains like the Fourier domain.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::fourier_pseudo_ggsw_ciphertext::{
    fill_with_forward_fourier_scratch, PseudoFourierGgswCiphertext,
};
use crate::core_crypto::experimental::entities::pseudo_ggsw_ciphertext::PseudoGgswCiphertext;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

/// Convert a [`pseudo GGSW ciphertext`](`PseudoGgswCiphertext`) with standard coefficients to the
/// Fourier domain.
///
/// If you want to manage the computation memory manually you can use
/// [`convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized`].
pub fn convert_standard_pseudo_ggsw_ciphertext_to_fourier<Scalar, InputCont, OutputCont>(
    input_ggsw: &PseudoGgswCiphertext<InputCont>,
    output_ggsw: &mut PseudoFourierGgswCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let fft = Fft::new(output_ggsw.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );

    convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized(
        input_ggsw,
        output_ggsw,
        fft,
        buffers.stack(),
    );
}

/// Memory optimized version of [`convert_standard_pseudo_ggsw_ciphertext_to_fourier`].
pub fn convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
>(
    input_ggsw: &PseudoGgswCiphertext<InputCont>,
    output_ggsw: &mut PseudoFourierGgswCiphertext<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    output_ggsw
        .as_mut_view()
        .fill_with_forward_fourier(input_ggsw, fft, stack);
}

/// Return the required memory for
/// [`convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized`].
pub fn convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    fill_with_forward_fourier_scratch(fft)
}
