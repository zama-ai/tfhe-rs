use crate::shortint::parameters::{DecompositionBaseLog, DecompositionLevelCount};

use serde::{Deserialize, Serialize};

/// A set of cryptographic parameters for homomorphic Shortint key switching.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ShortintKeySwitchingParameters {
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
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
    ) -> ShortintKeySwitchingParameters {
        ShortintKeySwitchingParameters {
            ks_level,
            ks_base_log,
        }
    }
}

pub const PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(15),
        ks_base_log: DecompositionBaseLog(1),
    };
