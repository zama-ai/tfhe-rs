use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::crypto::ggsw::fill_with_forward_fourier_scratch;
use crate::core_crypto::fft_impl::math::fft::{Fft, FftView};
use concrete_fft::c64;
use dyn_stack::{DynStack, SizeOverflow, StackReq};

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
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_scratch(fft)
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
    stack: DynStack<'_>,
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
pub fn convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_scratch(
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    fill_with_forward_fourier_scratch(fft)
}
