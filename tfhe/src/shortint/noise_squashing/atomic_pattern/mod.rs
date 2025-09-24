use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use ks32::KS32AtomicPatternNoiseSquashingKey;
use standard::StandardAtomicPatternNoiseSquashingKey;

use crate::core_crypto::prelude::CiphertextModulus as CoreCiphertextModulus;
use crate::shortint::backward_compatibility::noise_squashing::AtomicPatternNoiseSquashingKeyVersions;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::server_key::ServerKeyView;
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus};

use super::NoiseSquashingPrivateKey;

pub mod compressed;
pub mod ks32;
pub mod standard;

pub trait NoiseSquashingAtomicPattern {
    fn squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: ServerKeyView,
        output_message_modulus: MessageModulus,
        output_carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> crate::Result<SquashedNoiseCiphertext>;
}

/// The noise squashing key materials for all the supported Atomic Patterns
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(AtomicPatternNoiseSquashingKeyVersions)]
pub enum AtomicPatternNoiseSquashingKey {
    Standard(StandardAtomicPatternNoiseSquashingKey),
    KeySwitch32(KS32AtomicPatternNoiseSquashingKey),
}

impl AtomicPatternNoiseSquashingKey {
    pub fn new(
        cks: &AtomicPatternClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        match cks {
            AtomicPatternClientKey::Standard(std_cks) => Self::Standard(
                StandardAtomicPatternNoiseSquashingKey::new(std_cks, noise_squashing_private_key),
            ),
            AtomicPatternClientKey::KeySwitch32(ks32_cks) => Self::KeySwitch32(
                KS32AtomicPatternNoiseSquashingKey::new(ks32_cks, noise_squashing_private_key),
            ),
        }
    }
}

impl NoiseSquashingAtomicPattern for AtomicPatternNoiseSquashingKey {
    fn squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: ServerKeyView,
        output_message_modulus: MessageModulus,
        output_carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> crate::Result<SquashedNoiseCiphertext> {
        match self {
            Self::Standard(std_nsk) => std_nsk.squash_ciphertext_noise(
                ciphertext,
                src_server_key,
                output_message_modulus,
                output_carry_modulus,
                output_ciphertext_modulus,
            ),
            Self::KeySwitch32(ks32_nsk) => ks32_nsk.squash_ciphertext_noise(
                ciphertext,
                src_server_key,
                output_message_modulus,
                output_carry_modulus,
                output_ciphertext_modulus,
            ),
        }
    }
}
