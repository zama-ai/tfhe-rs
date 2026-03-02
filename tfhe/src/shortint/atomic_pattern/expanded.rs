use crate::core_crypto::prelude::{CiphertextModulus, LweKeyswitchKeyOwned, PBSOrder};

use crate::shortint::server_key::expanded::ShortintExpandedBootstrappingKey;

#[derive(PartialEq)]
pub struct ExpandedStandardAtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintExpandedBootstrappingKey<u64, u64>,
    pub pbs_order: PBSOrder,
}

#[derive(PartialEq)]
pub struct ExpandedKS32AtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u32>,
    pub bootstrapping_key: ShortintExpandedBootstrappingKey<u64, u32>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

#[derive(PartialEq)]
pub enum ExpandedAtomicPatternServerKey {
    Standard(ExpandedStandardAtomicPatternServerKey),
    KeySwitch32(ExpandedKS32AtomicPatternServerKey),
}
