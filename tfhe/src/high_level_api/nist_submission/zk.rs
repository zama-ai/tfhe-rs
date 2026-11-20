//! CRS for the NIST submission proven lists.
//!
//! The NIST compact list expansion does not do any PBS, so no opportunity for sanitization.
//! The CRS thus has to be stricter by ensuring blocks encrypts values at most `message_modulus - 1`

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::LweCiphertextCount;
use crate::named::Named;
use crate::shortint::parameters::CompactPublicKeyEncryptionParameters;
use crate::zk::{
    new_compact_pke_crs_conformance_params_with_msbs_zero_padding_bit_count,
    ZkMSBZeroPaddingBitCount,
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
    max_bit_size: u32,
) -> crate::Result<LweCiphertextCount> {
    let message_modulus = params.message_modulus.0;
    if message_modulus < 2 || !message_modulus.is_power_of_two() {
        return Err(crate::error!(
            "NIST submission requires a power of two message modulus of at least 2, got \
            {message_modulus}"
        ));
    }

    let message_bit_capacity = message_modulus.ilog2();
    Ok(LweCiphertextCount(
        max_bit_size.div_ceil(message_bit_capacity) as usize,
    ))
}

/// CRS of the NIST proven lists
///
/// Proofs made with this CRS guarantee that the padding bit and the carry bits of each block are 0,
/// which the NIST expansion relies on.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(transparent)]
pub struct CompactPkeCrs(crate::zk::CompactPkeCrs);

impl Named for CompactPkeCrs {
    const NAME: &'static str = "high_level_api::nist_submission::CompactPkeCrs";
}

impl CompactPkeCrs {
    /// Create the CRS for NIST proven lists from a `Config` object.
    ///
    /// `max_bit_size` is the maximum number of bits that can be proven by a single proof, e.g. 64
    /// for a single FheUint64 or 8 x FheUint8 values.
    pub fn from_config(config: Config, max_bit_size: u32) -> crate::Result<Self> {
        let params = config.public_key_encryption_parameters()?;

        crate::zk::CompactPkeCrs::from_shortint_params_and_msbs_zero_padding_bit_count(
            params,
            max_num_message(&params, max_bit_size)?,
            msbs_zero_padding_bit_count(&params)?,
        )
        .map(Self)
    }

    pub(super) fn inner(&self) -> &crate::zk::CompactPkeCrs {
        &self.0
    }
}

/// Conformance parameters of a NIST [`CompactPkeCrs`]
pub struct CompactPkeCrsConformanceParams(crate::zk::CompactPkeCrsConformanceParams);

impl CompactPkeCrsConformanceParams {
    /// Conformance parameters of a CRS created with [`CompactPkeCrs::from_config`] with the same
    /// arguments
    pub fn new(config: Config, max_bit_size: u32) -> crate::Result<Self> {
        let params = config.public_key_encryption_parameters()?;

        new_compact_pke_crs_conformance_params_with_msbs_zero_padding_bit_count(
            params,
            max_num_message(&params, max_bit_size)?,
            msbs_zero_padding_bit_count(&params)?,
        )
        .map(Self)
    }
}

impl ParameterSetConformant for CompactPkeCrs {
    type ParameterSet = CompactPkeCrsConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.0.is_conformant(&parameter_set.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::high_level_api::nist_submission::parameters::NIST_META_PARAMS_2_2;
    use crate::safe_serialization::{
        safe_deserialize, safe_deserialize_conformant, safe_serialize,
    };

    const SIZE_LIMIT: u64 = 1 << 30;

    #[test]
    fn test_nist_crs_conformance() {
        let config = Config::from(NIST_META_PARAMS_2_2);
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();
        let conformance_params = CompactPkeCrsConformanceParams::new(config, 32).unwrap();

        assert!(crs.is_conformant(&conformance_params));

        // The regular CRS only proves the padding bit
        let regular_crs = crate::zk::CompactPkeCrs::from_config(config, 32).unwrap();
        assert!(!CompactPkeCrs(regular_crs).is_conformant(&conformance_params));
    }

    #[test]
    fn test_nist_crs_serialization() {
        let config = Config::from(NIST_META_PARAMS_2_2);
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();
        let conformance_params = CompactPkeCrsConformanceParams::new(config, 32).unwrap();

        let mut serialized = Vec::new();
        safe_serialize(&crs, &mut serialized, SIZE_LIMIT).unwrap();
        let deserialized: CompactPkeCrs =
            safe_deserialize_conformant(serialized.as_slice(), SIZE_LIMIT, &conformance_params)
                .unwrap();
        assert!(deserialized.is_conformant(&conformance_params));

        // The NIST CRS is serialized as the regular one under another name
        let mut serialized_regular = Vec::new();
        safe_serialize(crs.inner(), &mut serialized_regular, SIZE_LIMIT).unwrap();
        assert_eq!(
            serialized.len() - CompactPkeCrs::NAME.len(),
            serialized_regular.len() - crate::zk::CompactPkeCrs::NAME.len()
        );

        // A regular CRS cannot be loaded as a NIST one
        let regular_crs = crate::zk::CompactPkeCrs::from_config(config, 32).unwrap();
        let mut serialized_regular = Vec::new();
        safe_serialize(&regular_crs, &mut serialized_regular, SIZE_LIMIT).unwrap();
        assert!(
            safe_deserialize::<CompactPkeCrs>(serialized_regular.as_slice(), SIZE_LIMIT).is_err()
        );
    }
}
