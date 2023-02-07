//! Module containing primitives pertaining to the conversion of
//! [`standard LWE bootstrap keys`](`LweBootstrapKey`) to various representations/numerical domains
//! like the Fourier domain.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::{
    fill_with_forward_fourier_scratch, FourierLweBootstrapKey,
};
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use concrete_fft::c64;
use dyn_stack::{PodStack, SizeOverflow, StackReq};

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

    output_bsk
        .as_mut_view()
        .fill_with_forward_fourier(input_bsk.as_view(), fft, stack);
}

/// Memory optimized version of [`convert_standard_lwe_bootstrap_key_to_fourier`].
pub fn convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized<Scalar, InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut FourierLweBootstrapKey<OutputCont>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    output_bsk
        .as_mut_view()
        .fill_with_forward_fourier(input_bsk.as_view(), fft, stack);
}

/// Return the required memory for [`convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized`].
pub fn convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    fill_with_forward_fourier_scratch(fft)
}
