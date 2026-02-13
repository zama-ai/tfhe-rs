use crate::shortint::backward_compatibility::parameters::re_randomization::ReRandomizationParametersVersions;
use crate::shortint::parameters::ShortintKeySwitchingParameters;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(ReRandomizationParametersVersions)]
pub enum ReRandomizationParameters {
    /// [`CompactPublicKeyEncryptionParameters`](`crate::shortint::parameters::CompactPublicKeyEncryptionParameters`)
    /// can be anything as long as the [`ShortintKeySwitchingParameters`] parameters allow to go to
    /// the compute parameters under the correct key. In the KS_PBS case (which is the only one
    /// we support for simplicity) it means going to ciphertexts encrypted under the large key.
    DedicatedCompactPublicKeyWithKeySwitch {
        re_rand_ksk_params: ShortintKeySwitchingParameters,
    },
    /// [`CompactPublicKeyEncryptionParameters`](`crate::shortint::parameters::CompactPublicKeyEncryptionParameters`)
    /// will be derived from the available compute parameters and the corresponding secret key
    /// should correspond to the encryption key of the compute parameters. To make things
    /// simpler the parameters are restricted to the KS_PBS case (encryption under the large
    /// key).
    DerivedCompactPublicKeyWithoutKeySwitch,
}
