//! Module containing primitives pertaining to the [`LWE programmable
//! bootstrap`](`crate::core_crypto::entities::LweBootstrapKey#programmable-bootstrapping`) using 64
//! bits FFT for polynomial multiplication.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::*;
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign as impl_add_external_product_assign,
    add_external_product_assign_scratch as impl_add_external_product_assign_scratch, cmux,
    cmux_scratch,
};
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use crate::core_crypto::prelude::{FourierGgswCiphertext, GlweCiphertext};
use dyn_stack::{PodStack, StackReq};
use tfhe_fft::c64;

pub fn cm_blind_rotate_assign<InputScalar, OutputScalar, InputCont, OutputCont, KeyCont>(
    input: &CmLweCiphertext<InputCont>,
    lut: &mut CmGlweCiphertext<OutputCont>,
    fourier_bsk: &FourierCmLweBootstrapKey<KeyCont>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert!(
        input.ciphertext_modulus().is_power_of_two(),
        "This operation requires the input to have a power of two modulus."
    );
    assert!(
        lut.ciphertext_modulus().is_power_of_two(),
        "This operation requires the lut to have a power of two modulus."
    );

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        cm_blind_rotate_assign_mem_optimized_requirement::<OutputScalar>(
            fourier_bsk.glwe_dimension(),
            fourier_bsk.cm_dimension(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    cm_blind_rotate_assign_mem_optimized(input, lut, fourier_bsk, fft, stack);
}

pub fn cm_blind_rotate_assign_mem_optimized<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    KeyCont,
>(
    input: &CmLweCiphertext<InputCont>,
    lut: &mut CmGlweCiphertext<OutputCont>,
    fourier_bsk: &FourierCmLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
{
    assert!(
        input.ciphertext_modulus().is_power_of_two(),
        "This operation requires the input to have a power of two modulus."
    );
    assert!(
        lut.ciphertext_modulus().is_power_of_two(),
        "This operation requires the lut to have a power of two modulus."
    );
    assert_eq!(input.lwe_dimension(), fourier_bsk.input_lwe_dimension());
    assert_eq!(lut.glwe_dimension(), fourier_bsk.glwe_dimension());
    assert_eq!(lut.polynomial_size(), fourier_bsk.polynomial_size());

    // Blind rotate assign manages the rounding to go back to the proper torus if the ciphertext
    // modulus is not the native one

    cm_blind_rotate_assign_raw(
        fourier_bsk.as_view(),
        lut.as_mut_view(),
        input.as_view(),
        fft,
        stack,
    );
}

pub fn cm_blind_rotate_assign_mem_optimized_requirement<OutputScalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    cm_blind_rotate_assign_scratch::<OutputScalar>(
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        fft,
    )
}

pub fn cm_add_external_product_assign<Scalar, OutputGlweCont, InputGlweCont, GgswCont>(
    out: &mut GlweCiphertext<OutputGlweCont>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
    glwe: &GlweCiphertext<InputGlweCont>,
) where
    Scalar: UnsignedTorus,
    OutputGlweCont: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
    InputGlweCont: Container<Element = Scalar>,
{
    assert_eq!(out.ciphertext_modulus(), glwe.ciphertext_modulus());

    let fft = Fft::new(ggsw.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        cm_add_external_product_assign_mem_optimized_requirement::<Scalar>(
            ggsw.glwe_size(),
            ggsw.polynomial_size(),
            fft,
        )
        .unaligned_bytes_required(),
    );

    cm_add_external_product_assign_mem_optimized(out, ggsw, glwe, fft, buffers.stack());
}

pub fn cm_add_external_product_assign_mem_optimized<
    Scalar,
    OutputGlweCont,
    InputGlweCont,
    GgswCont,
>(
    out: &mut GlweCiphertext<OutputGlweCont>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
    glwe: &GlweCiphertext<InputGlweCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    OutputGlweCont: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
    InputGlweCont: Container<Element = Scalar>,
{
    assert_eq!(out.ciphertext_modulus(), glwe.ciphertext_modulus());
    let ciphertext_modulus = out.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    impl_add_external_product_assign(
        out.as_mut_view(),
        ggsw.as_view(),
        glwe.as_view(),
        fft,
        stack,
    );

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        out.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

pub fn cm_add_external_product_assign_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    impl_add_external_product_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

pub fn cm_cmux_assign<Scalar, Cont0, Cont1, GgswCont>(
    ct0: &mut GlweCiphertext<Cont0>,
    ct1: &mut GlweCiphertext<Cont1>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
) where
    Scalar: UnsignedTorus,
    Cont0: ContainerMut<Element = Scalar>,
    Cont1: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
{
    assert_eq!(ct0.ciphertext_modulus(), ct1.ciphertext_modulus());

    let fft = Fft::new(ggsw.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        cm_cmux_assign_mem_optimized_requirement::<Scalar>(
            ggsw.glwe_size(),
            ggsw.polynomial_size(),
            fft,
        )
        .unaligned_bytes_required(),
    );

    cm_cmux_assign_mem_optimized(ct0, ct1, ggsw, fft, buffers.stack());
}

pub fn cm_cmux_assign_mem_optimized<Scalar, Cont0, Cont1, GgswCont>(
    ct0: &mut GlweCiphertext<Cont0>,
    ct1: &mut GlweCiphertext<Cont1>,
    ggsw: &FourierGgswCiphertext<GgswCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    Cont0: ContainerMut<Element = Scalar>,
    Cont1: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
{
    assert_eq!(ct0.ciphertext_modulus(), ct1.ciphertext_modulus());
    let ciphertext_modulus = ct0.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    cmux(
        ct0.as_mut_view(),
        ct1.as_mut_view(),
        ggsw.as_view(),
        fft,
        stack,
    );

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

pub fn cm_cmux_assign_mem_optimized_requirement<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    cmux_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

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
        cm_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<OutputScalar>(
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

pub fn cm_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement<OutputScalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    cm_bootstrap_scratch::<OutputScalar>(glwe_dimension, cm_dimension, polynomial_size, fft)
}
