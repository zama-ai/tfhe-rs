use crate::shortint::backward_compatibility::noise_squashing::CompressedAtomicPatternNoiseSquashingKeyVersions;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::noise_squashing::NoiseSquashingPrivateKey;
use ks32::CompressedKS32AtomicPatternNoiseSquashingKey;
use standard::CompressedStandardAtomicPatternNoiseSquashingKey;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use super::AtomicPatternNoiseSquashingKey;

pub mod ks32;
pub mod standard;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedAtomicPatternNoiseSquashingKeyVersions)]
pub enum CompressedAtomicPatternNoiseSquashingKey {
    Standard(CompressedStandardAtomicPatternNoiseSquashingKey),
    KeySwitch32(CompressedKS32AtomicPatternNoiseSquashingKey),
}

impl CompressedAtomicPatternNoiseSquashingKey {
    pub fn new(
        cks: &AtomicPatternClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        match cks {
            AtomicPatternClientKey::Standard(std_cks) => {
                Self::Standard(CompressedStandardAtomicPatternNoiseSquashingKey::new(
                    std_cks,
                    noise_squashing_private_key,
                ))
            }
            AtomicPatternClientKey::KeySwitch32(ks32_cks) => {
                Self::KeySwitch32(CompressedKS32AtomicPatternNoiseSquashingKey::new(
                    ks32_cks,
                    noise_squashing_private_key,
                ))
            }
        }
    }

    pub fn decompress(&self) -> AtomicPatternNoiseSquashingKey {
        match self {
            Self::Standard(std_compressed) => {
                AtomicPatternNoiseSquashingKey::Standard(std_compressed.decompress())
            }
            Self::KeySwitch32(ks32_compressed) => {
                AtomicPatternNoiseSquashingKey::KeySwitch32(ks32_compressed.decompress())
            }
        }
    }
}
