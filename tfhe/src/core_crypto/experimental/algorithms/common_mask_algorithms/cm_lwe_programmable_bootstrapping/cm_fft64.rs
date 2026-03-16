//! Module containing primitives pertaining to the `CommonMask LWE programmable
//! bootstrap` using 64 bits FFT for polynomial multiplication.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::*;
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use dyn_stack::PodStack;
use tfhe_fft::c64;

pub fn programmable_bootstrap_cm_lwe_ciphertext<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &CmLweCiphertext<InputCont>,
    output: &mut CmLweCiphertext<OutputCont>,
    accumulator: &CmGlweCiphertext<AccCont>,
    fourier_bsk: &FourierCmLweBootstrapKey<KeyCont>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
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

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        cm_bootstrap_requirement::<OutputScalar>(
            fourier_bsk.glwe_dimension(),
            fourier_bsk.cm_dimension(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    cm_programmable_bootstrap_lwe_ciphertext_mem_optimized(
        input,
        output,
        accumulator,
        fourier_bsk,
        fft,
        stack,
    );
}

pub fn cm_programmable_bootstrap_lwe_ciphertext_mem_optimized<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &CmLweCiphertext<InputCont>,
    output: &mut CmLweCiphertext<OutputCont>,
    accumulator: &CmGlweCiphertext<AccCont>,
    fourier_bsk: &FourierCmLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert_eq!(
        accumulator.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched moduli between accumulator ({:?}) and output ({:?})",
        accumulator.ciphertext_modulus(),
        output.ciphertext_modulus()
    );

    assert_eq!(
        fourier_bsk.input_lwe_dimension(),
        input.lwe_dimension(),
        "Mismatched input LweDimension. \
        FourierLweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        fourier_bsk.input_lwe_dimension(),
        input.lwe_dimension(),
    );
    assert_eq!(
        fourier_bsk.output_lwe_dimension(),
        output.lwe_dimension(),
        "Mismatched output LweDimension. \
        FourierLweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        fourier_bsk.output_lwe_dimension(),
        output.lwe_dimension(),
    );

    cm_bootstrap(
        fourier_bsk.as_view(),
        output.as_mut_view(),
        input.as_view(),
        accumulator.as_view(),
        fft,
        stack,
    );
}
