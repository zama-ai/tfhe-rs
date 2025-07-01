use crate::core_crypto::prelude::UnsignedInteger;
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
