//! Module containing primitives pertaining to the [`LWE programmable
//! bootstrap`](`LweBootstrapKey#programmable-bootstrapping`).

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::{bootstrap_scratch, FourierLweBootstrapKey};
use crate::core_crypto::fft_impl::crypto::wop_pbs::blind_rotate_assign_scratch;
use crate::core_crypto::fft_impl::math::fft::{Fft, FftView};
use concrete_fft::c64;
use dyn_stack::{DynStack, SizeOverflow, StackReq};

/// Perform a blind rotation given an input [`LWE ciphertext`](`LweCiphertext`), modifying a look-up
/// table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) in the fourier domain.
///
/// If you want to manage the computation memory manually you can use
/// [`blind_rotate_assign_mem_optimized`].
pub fn blind_rotate_assign<Scalar, InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    lut: &mut GlweCiphertext<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    KeyCont: Container<Element = c64>,
{
    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        blind_rotate_assign_mem_optimized_requirement::<Scalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    blind_rotate_assign_mem_optimized(input, lut, fourier_bsk, fft, stack);
}

/// Memory optimized version of [`blind_rotate_assign`], the caller must provide
/// a properly configured [`FftView`] object and a `DynStack` used as a memory buffer having a
/// capacity at least as large as the result of [`blind_rotate_assign_mem_optimized_requirement`].
pub fn blind_rotate_assign_mem_optimized<Scalar, InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    lut: &mut GlweCiphertext<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    KeyCont: Container<Element = c64>,
{
    fourier_bsk
        .as_view()
        .blind_rotate_assign(lut.as_mut_view(), input.as_ref(), fft, stack);
}

/// Return the required memory for [`blind_rotate_assign_mem_optimized`].
pub fn blind_rotate_assign_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// Perform a programmable bootsrap given an input [`LWE ciphertext`](`LweCiphertext`), a
/// look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweBootstrapKey`) in the fourier domain. The result is written in the provided output
/// [`LWE ciphertext`](`LweCiphertext`).
///
/// If you want to manage the computation memory manually you can use
/// [`programmable_bootstrap_lwe_ciphertext_mem_optimized`].
pub fn programmable_bootstrap_lwe_ciphertext<Scalar, InputCont, OutputCont, AccCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64>,
{
    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        input,
        output,
        accumulator,
        fourier_bsk,
        fft,
        stack,
    )
}

/// Memory optimized version of [`programmable_bootstrap_lwe_ciphertext`], the caller must provide
/// a properly configured [`FftView`] object and a `DynStack` used as a memory buffer having a
/// capacity at least as large as the result of
/// [`programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement`].
pub fn programmable_bootstrap_lwe_ciphertext_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
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

/// Return the required memory for [`programmable_bootstrap_lwe_ciphertext_mem_optimized`].
pub fn programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    bootstrap_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}
