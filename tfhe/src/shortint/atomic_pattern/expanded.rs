use crate::core_crypto::prelude::{CiphertextModulus, LweKeyswitchKeyOwned, PBSOrder};

use crate::shortint::server_key::expanded::ShortintExpandedBootstrappingKey;

pub struct ExpandedStandardAtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintExpandedBootstrappingKey<u64, u64>,
    pub pbs_order: PBSOrder,
}

pub struct ExpandedKS32AtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u32>,
    pub bootstrapping_key: ShortintExpandedBootstrappingKey<u64, u32>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

pub enum ExpandedAtomicPatternServerKey {
    Standard(ExpandedStandardAtomicPatternServerKey),
    KeySwitch32(ExpandedKS32AtomicPatternServerKey),
}
