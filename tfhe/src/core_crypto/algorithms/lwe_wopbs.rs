use crate::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::crypto::wop_pbs::{
    circuit_bootstrap_boolean_vertical_packing, circuit_bootstrap_boolean_vertical_packing_scratch,
    extract_bits, extract_bits_scratch,
};
use crate::core_crypto::fft_impl::math::fft::FftView;
use crate::core_crypto::specification::parameters::*;
use concrete_fft::c64;
use dyn_stack::{DynStack, SizeOverflow, StackReq};

#[allow(clippy::too_many_arguments)]
pub fn extract_bits_from_lwe_ciphertext<Scalar, InputCont, OutputCont, BskCont, KSKCont>(
    lwe_in: &LweCiphertextBase<InputCont>,
    lwe_list_out: &mut LweCiphertextListBase<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    ksk: &LweKeyswitchKeyBase<KSKCont>,
    delta_log: DeltaLog,
    number_of_bits_to_extract: ExtractedBitsCount,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KSKCont: Container<Element = Scalar>,
{
    extract_bits(
        lwe_list_out.as_mut_view(),
        lwe_in.as_view(),
        ksk.as_view(),
        fourier_bsk.as_view(),
        delta_log,
        number_of_bits_to_extract,
        fft,
        stack,
    )
}

pub fn extract_bits_from_lwe_ciphertext_scratch<Scalar>(
    lwe_dimension: LweDimension,
    ksk_output_key_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    extract_bits_scratch::<Scalar>(
        lwe_dimension,
        ksk_output_key_lwe_dimension,
        glwe_size,
        polynomial_size,
        fft,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list<
    Scalar,
    InputCont,
    OutputCont,
    LutCont,
    BskCont,
    PFPKSKCont,
>(
    lwe_list_in: &LweCiphertextListBase<InputCont>,
    lwe_list_out: &mut LweCiphertextListBase<OutputCont>,
    big_lut_as_polynomial_list: &PolynomialListBase<LutCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    fpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<PFPKSKCont>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    LutCont: Container<Element = Scalar>,
    BskCont: Container<Element = c64>,
    PFPKSKCont: crate::core_crypto::commons::math::tensor::Container<Element = Scalar>,
{
    circuit_bootstrap_boolean_vertical_packing(
        big_lut_as_polynomial_list.as_view(),
        fourier_bsk.as_view(),
        lwe_list_out.as_mut_view(),
        lwe_list_in.as_view(),
        fpksk_list.as_view(),
        level_cbs,
        base_log_cbs,
        fft,
        stack,
    )
}

// TODO big_lut_polynomial_count looks wrong
#[allow(clippy::too_many_arguments)]
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_scracth<Scalar>(
    lwe_list_in_count: LweCiphertextCount,
    lwe_list_out_count: LweCiphertextCount,
    lwe_in_size: LweSize,
    big_lut_polynomial_count: PolynomialCount,
    bsk_output_lwe_size: LweSize,
    fpksk_output_polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    circuit_bootstrap_boolean_vertical_packing_scratch::<Scalar>(
        lwe_list_in_count,
        lwe_list_out_count,
        lwe_in_size,
        big_lut_polynomial_count,
        bsk_output_lwe_size,
        fpksk_output_polynomial_size,
        glwe_size,
        level_cbs,
        fft,
    )
}
