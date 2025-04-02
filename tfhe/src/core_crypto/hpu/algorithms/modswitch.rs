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
#[allow(unused)]
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
#[allow(unused)]
pub fn lsb2msb_align<Scalar: UnsignedInteger>(params: &HpuParameters, data: &mut [Scalar]) {
    let ct_width = params.ntt_params.ct_width as usize;
    let storage_width = Scalar::BITS;
    for val in data.iter_mut() {
        *val <<= storage_width - ct_width;
    }
}

/// This function switches modulus for a slice of coefficients
/// From: user domain (i.e. pow2 modulus)
/// To:   ntt domain  ( i.e. prime modulus)
/// Switching are done inplace
pub fn user2ntt_modswitch<Scalar: UnsignedInteger>(params: &HpuParameters, data: &mut [Scalar]) {
    let user_width = params.ntt_params.ct_width as usize;
    let mod_p_u128 = u64::from(&params.ntt_params.prime_modulus) as u128;
    for val in data.iter_mut() {
        let val_u128: u128 = val.cast_into();
        *val = Scalar::cast_from(((val_u128 * mod_p_u128) + (1 << (user_width - 1))) >> user_width);
    }
}

/// This function switches modulus for a slice of coefficients
/// From:   ntt domain  ( i.e. prime modulus)
/// To: user domain (i.e. pow2 modulus)
/// Switching are done inplace
pub fn ntt2user_modswitch<Scalar: UnsignedInteger>(params: &HpuParameters, data: &mut [Scalar]) {
    let user_width = params.ntt_params.ct_width as usize;
    let mod_p_u128 = u64::from(&params.ntt_params.prime_modulus) as u128;
    for val in data.iter_mut() {
        let val_u128: u128 = val.cast_into();
        *val = Scalar::cast_from((((val_u128) << user_width) | ((mod_p_u128) >> 1)) / mod_p_u128);
    }
}
