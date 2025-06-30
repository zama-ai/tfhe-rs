use crate::core_crypto::prelude::{
    centered_binary_ms_body_correction_to_add, CastInto, CiphertextModulusLog, Container,
    LazyStandardModulusSwitchedLweCiphertext, LweCiphertext, UnsignedInteger,
};
use tfhe_hpu_backend::prelude::HpuParameters;

/// This function change information position in value
/// Move information bits from MSB to LSB
pub fn msb2lsb<Scalar: UnsignedInteger>(params: &HpuParameters, data: Scalar) -> Scalar {
    let ct_width = params.ntt_params.ct_width as usize;
    let storage_width = Scalar::BITS;
    data >> (storage_width - ct_width)
}

/// This function change information position in value
/// Move information bits from LSB to MSB
pub fn lsb2msb<Scalar: UnsignedInteger>(params: &HpuParameters, data: Scalar) -> Scalar {
    let ct_width = params.ntt_params.ct_width as usize;
    let storage_width = Scalar::BITS;
    data << (storage_width - ct_width)
}

/// This function change information position in container
/// Move information bits from MSB to LSB
pub fn msb2lsb_align<Scalar: UnsignedInteger>(params: &HpuParameters, data: &mut [Scalar]) {
    let ct_width = params.ntt_params.ct_width as usize;
    let storage_width = Scalar::BITS;
    for val in data.iter_mut() {
        *val >>= storage_width - ct_width;
    }
}
/// This function change information position in container
/// Move information bits from LSB to MSB
pub fn lsb2msb_align<Scalar: UnsignedInteger>(params: &HpuParameters, data: &mut [Scalar]) {
    let ct_width = params.ntt_params.ct_width as usize;
    let storage_width = Scalar::BITS;
    for val in data.iter_mut() {
        *val <<= storage_width - ct_width;
    }
}

// Temporary implementation without half case correction which is not currently implemented
// Once implemented revert back to CPU implem
pub fn hpu_lwe_ciphertext_centered_binary_modulus_switch<Scalar, SwitchedScalar, Cont>(
    lwe_in: LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
) -> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, Cont>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
{
    assert!(log_modulus.0 <= Scalar::BITS);
    assert!(log_modulus.0 <= SwitchedScalar::BITS);

    let body_correction_to_add =
        // false here disables the half case correction
        centered_binary_ms_body_correction_to_add(&lwe_in, log_modulus, false);

    LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(
        lwe_in,
        body_correction_to_add,
        log_modulus,
    )
}
