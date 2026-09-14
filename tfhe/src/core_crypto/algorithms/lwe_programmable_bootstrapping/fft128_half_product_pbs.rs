//! Module containing primitives pertaining to the "half-product" [`LWE programmable
//! bootstrap`](`crate::core_crypto::entities::LweBootstrapKey#programmable-bootstrapping`) using
//! 128 bits FFT for polynomial multiplication.
//!
//! The half-product variant gives the body GLev of every GGSW its own, lighter decomposition
//! parameters. See [`Fourier128HalfProductLweBootstrapKey`].

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_product::half_product_bootstrap_scratch;
use crate::core_crypto::fft_impl::fft128::math::fft::{Fft128, Fft128View};
use crate::core_crypto::prelude::ModulusSwitchedLweCiphertext;
use dyn_stack::{PodStack, StackReq};

/// Perform a "half-product" programmable bootstrap using a 128 bits FFT, given an input [`LWE
/// ciphertext`](`LweCiphertext`), a look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`)
/// and a [`Fourier128HalfProductLweBootstrapKey`]. The result is written in the provided output
/// [`LWE ciphertext`](`LweCiphertext`).
///
/// This is the half-product analog of
/// [`programmable_bootstrap_f128_lwe_ciphertext`](super::programmable_bootstrap_f128_lwe_ciphertext).
///
/// If you want to manage the computation memory manually you can use
/// [`half_product_programmable_bootstrap_f128_lwe_ciphertext_mem_optimized`].
pub fn half_product_programmable_bootstrap_f128_lwe_ciphertext<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &Fourier128HalfProductLweBootstrapKey<KeyCont>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = f64>,
{
    assert_eq!(
        output.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );

    let mut buffers = ComputationBuffers::new();

    let fft = Fft128::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        half_product_programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement::<
            OutputScalar,
        >(fourier_bsk.glwe_size(), fourier_bsk.polynomial_size(), fft)
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    half_product_programmable_bootstrap_f128_lwe_ciphertext_mem_optimized(
        input,
        output,
        accumulator,
        fourier_bsk,
        fft,
        stack,
    );
}

/// Memory optimized version of
/// [`half_product_programmable_bootstrap_f128_lwe_ciphertext`], the caller must provide a properly
/// configured [`Fft128View`] object and a `PodStack` used as a memory buffer having a capacity at
/// least as large as the result of
/// [`half_product_programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement`].
pub fn half_product_programmable_bootstrap_f128_lwe_ciphertext_mem_optimized<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &Fourier128HalfProductLweBootstrapKey<KeyCont>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = f64>,
{
    fourier_bsk.bootstrap(output, input, accumulator, fft, stack);
}

/// Return the required memory for
/// [`half_product_programmable_bootstrap_f128_lwe_ciphertext_mem_optimized`].
pub fn half_product_programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    half_product_bootstrap_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// Perform a "half-product" blind rotation using a 128 bits FFT, given an input [`modulus switched
/// LWE ciphertext`](`ModulusSwitchedLweCiphertext`), a look-up table passed as a [`GLWE
/// ciphertext`](`GlweCiphertext`) and a [`Fourier128HalfProductLweBootstrapKey`]. The result is
/// written in the provided output [`LWE ciphertext`](`LweCiphertext`).
pub fn half_product_blind_rotate_f128_lwe_ciphertext_mem_optimized<
    OutputScalar,
    OutputCont,
    AccCont,
    KeyCont,
>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &Fourier128HalfProductLweBootstrapKey<KeyCont>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) where
    OutputScalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = OutputScalar>,
    AccCont: Container<Element = OutputScalar>,
    KeyCont: Container<Element = f64>,
{
    fourier_bsk.blind_rotate(output, msed_input, accumulator, fft, stack);
}

/// Return the required memory for
/// [`half_product_blind_rotate_f128_lwe_ciphertext_mem_optimized`].
pub fn half_product_blind_rotate_f128_lwe_ciphertext_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    half_product_bootstrap_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}
