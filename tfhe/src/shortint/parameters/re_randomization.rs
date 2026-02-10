use crate::shortint::parameters::{
    CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters,
};

#[derive(Clone, Copy)]
pub enum ReRandomizationParameters {
    /// CompactPublicKey parameters can be anything as long as the keyswitching parameters allow to
    /// go to the compute parameters under the correct key. In the KS_PBS case (which is the only
    /// one we support for simplicity) it means going to ciphertexts encrypted under the large key.
    DedicatedCompactPublicKeyWithKeySwitch {
        dedicated_cpk_params: CompactPublicKeyEncryptionParameters,
        re_rand_ksk_params: ShortintKeySwitchingParameters,
    },
    /// CompactPublicKey parameters will be derived from the compute parameters and the
    /// corresponding secret key should correspond to the encryption key of the compute parameters.
    /// To make things simpler the parameters are restricted to the KS_PBS case (encryption under
    /// the large key).
    DerivedCompactPublicKeyWithoutKeySwitch,
}
