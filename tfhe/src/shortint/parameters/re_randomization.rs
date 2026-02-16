use crate::shortint::backward_compatibility::parameters::re_randomization::ReRandomizationParametersVersions;

use crate::shortint::parameters::ShortintKeySwitchingParameters;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(ReRandomizationParametersVersions)]
pub enum ReRandomizationParameters {
    /// Case where the rerandomization is performed with a dedicated set of
    /// [`CompactPublicKeyEncryptionParameters`](`crate::shortint::parameters::CompactPublicKeyEncryptionParameters`)
    /// and key and corresponding [`ShortintKeySwitchingParameters`]. The keyswitch is assumed to
    /// target the large encryption key of the compute parameters used (KS_PBS case).
    LegacyDedicatedCPKWithKeySwitch {
        rerand_ksk_params: ShortintKeySwitchingParameters,
    },
    /// Case where the rerandomization is performed using derived
    /// [`CompactPublicKeyEncryptionParameters`](`crate::shortint::parameters::CompactPublicKeyEncryptionParameters`)
    /// from pre-existing compute parameters. This case does not require key switching parameters
    /// as it is assumed the required public key re-uses a secret key from the compute parameters.
    DerivedCPKWithoutKeySwitch,
}

impl From<ShortintKeySwitchingParameters> for ReRandomizationParameters {
    fn from(value: ShortintKeySwitchingParameters) -> Self {
        Self::LegacyDedicatedCPKWithKeySwitch {
            rerand_ksk_params: value,
        }
    }
}
