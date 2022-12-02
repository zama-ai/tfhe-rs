use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::{bootstrap_scratch, FourierLweBootstrapKey};
use crate::core_crypto::fft_impl::math::fft::FftView;
use crate::core_crypto::specification::parameters::*;
use concrete_fft::c64;
use dyn_stack::{DynStack, SizeOverflow, StackReq};

pub fn programmable_bootstrap_lwe_ciphertext<Scalar, InputCont, OutputCont, AccCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64>,
{
    fourier_bsk.as_view().bootstrap(
        output.as_mut(),
        input.as_ref(),
        accumulator.as_view(),
        fft,
        stack,
    );
}

/// Returns the required memory for [`programmable_bootstrap_lwe_ciphertext`].
pub fn programmable_bootstrap_lwe_ciphertext_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    bootstrap_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}
