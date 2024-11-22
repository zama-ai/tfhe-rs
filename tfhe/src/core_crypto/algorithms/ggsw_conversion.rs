//! Module containing primitives pertaining to the conversion of
//! [`standard GGSW ciphertexts`](`GgswCiphertext`) to various representations/numerical domains
//! like the Fourier domain.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::fill_with_forward_fourier_scratch;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
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
            .unwrap()
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
) -> Result<StackReq, SizeOverflow> {
    fill_with_forward_fourier_scratch(fft)
}
