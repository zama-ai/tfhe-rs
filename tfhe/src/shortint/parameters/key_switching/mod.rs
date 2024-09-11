pub mod p_fail_2_minus_64;

use crate::shortint::backward_compatibility::parameters::key_switching::ShortintKeySwitchingParametersVersions;
use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, EncryptionKeyChoice,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// A set of cryptographic parameters for homomorphic Shortint key switching.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(ShortintKeySwitchingParametersVersions)]
pub struct ShortintKeySwitchingParameters {
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub destination_key: EncryptionKeyChoice,
}

impl ShortintKeySwitchingParameters {
    /// Constructs a new set of parameters for shortint key switching.
    ///
    /// # Warning
    ///
    /// Failing to fix the parameters properly would yield incorrect and insecure computation.
    /// Unless you are a cryptographer who really knows the impact of each of those parameters, you
    /// __must__ stick with the provided parameters (if any), which both offer correct results with
    /// 128 bits of security.
    pub fn new(
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        destination_key: EncryptionKeyChoice,
    ) -> Self {
        Self {
            ks_base_log,
            ks_level,
            destination_key,
        }
    }
}
