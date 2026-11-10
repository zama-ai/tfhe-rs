//! CRS for the NIST submission proven lists.
//!
//! The NIST compact list expansion does not do any PBS, so no opportunity for sanitization.
//! The CRS thus has to be stricter by ensuring blocks encrypts values at most `message_modulus - 1`

use crate::core_crypto::prelude::LweCiphertextCount;
use crate::shortint::parameters::CompactPublicKeyEncryptionParameters;
use crate::zk::{
    new_compact_pke_crs_conformance_params_with_msbs_zero_padding_bit_count, CompactPkeCrs,
    CompactPkeCrsConformanceParams, ZkMSBZeroPaddingBitCount,
};
use crate::Config;

/// Number of most significant bits of each plaintext that the proofs of a NIST list guarantee to
/// be 0: the padding bit and the carry bits.
fn msbs_zero_padding_bit_count(
    params: &CompactPublicKeyEncryptionParameters,
) -> crate::Result<ZkMSBZeroPaddingBitCount> {
    let carry_modulus = params.carry_modulus.0;
    if !carry_modulus.is_power_of_two() {
        return Err(crate::error!(
            "NIST submission requires a power of two carry modulus, got {carry_modulus}"
        ));
    }

    Ok(ZkMSBZeroPaddingBitCount(
        1 + u64::from(carry_modulus.ilog2()),
    ))
}

/// Number of blocks a single proof must be able to prove to hold `max_bit_size` bits, as NIST
/// lists are not packed.
fn max_num_message(
    params: &CompactPublicKeyEncryptionParameters,
    max_bit_size: usize,
) -> crate::Result<LweCiphertextCount> {
    let message_modulus = params.message_modulus.0;
    if message_modulus < 2 || !message_modulus.is_power_of_two() {
        return Err(crate::error!(
            "NIST submission requires a power of two message modulus of at least 2, got \
            {message_modulus}"
        ));
    }

    let message_bit_capacity = message_modulus.ilog2() as usize;
    Ok(LweCiphertextCount(
        max_bit_size.div_ceil(message_bit_capacity),
    ))
}

/// Create the CRS for NIST proven lists from a `Config` object.
///
/// `max_bit_size` is the maximum number of bits that can be proven by a single proof, e.g. 64 for
/// a single FheUint64 or 8 x FheUint8 values.
///
/// Its proofs guarantee that the padding bit and the carry bits of each block are 0, which the
/// NIST expansion relies on.
pub fn new_compact_pke_crs(config: Config, max_bit_size: usize) -> crate::Result<CompactPkeCrs> {
    let params = config.public_key_encryption_parameters()?;

    CompactPkeCrs::from_shortint_params_and_msbs_zero_padding_bit_count(
        params,
        max_num_message(&params, max_bit_size)?,
        msbs_zero_padding_bit_count(&params)?,
    )
}

/// Conformance parameters of a CRS created with [`new_compact_pke_crs`] with the same arguments
pub fn new_compact_pke_crs_conformance_params(
    config: Config,
    max_bit_size: usize,
) -> crate::Result<CompactPkeCrsConformanceParams> {
    let params = config.public_key_encryption_parameters()?;

    new_compact_pke_crs_conformance_params_with_msbs_zero_padding_bit_count(
        params,
        max_num_message(&params, max_bit_size)?,
        msbs_zero_padding_bit_count(&params)?,
    )
}
