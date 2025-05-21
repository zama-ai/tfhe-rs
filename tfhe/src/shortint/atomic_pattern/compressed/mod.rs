pub mod ks32;
pub mod standard;
pub use ks32::*;
pub use standard::*;

use super::AtomicPatternServerKey;
use crate::conformance::ParameterSetConformant;
use crate::shortint::backward_compatibility::atomic_pattern::CompressedAtomicPatternServerKeyVersions;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{AtomicPatternParameters, CiphertextModulus, LweDimension};

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// The server key materials for all the supported Atomic Patterns
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedAtomicPatternServerKeyVersions)]
#[allow(clippy::large_enum_variant)] // The most common variant should be `Standard` so we optimize for it
pub enum CompressedAtomicPatternServerKey {
    Standard(CompressedStandardAtomicPatternServerKey),
    KeySwitch32(CompressedKS32AtomicPatternServerKey),
}

impl CompressedAtomicPatternServerKey {
    pub fn new(cks: &ClientKey, engine: &mut ShortintEngine) -> Self {
        match &cks.atomic_pattern {
            AtomicPatternClientKey::Standard(ap_cks) => Self::Standard(
                CompressedStandardAtomicPatternServerKey::new(ap_cks, engine),
            ),
            AtomicPatternClientKey::KeySwitch32(ap_cks) => {
                Self::KeySwitch32(CompressedKS32AtomicPatternServerKey::new(ap_cks, engine))
            }
        }
    }

    pub fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Standard(compressed_standard_atomic_pattern_server_key) => {
                compressed_standard_atomic_pattern_server_key.ciphertext_lwe_dimension()
            }
            Self::KeySwitch32(compressed_ks32_atomic_pattern_server_key) => {
                compressed_ks32_atomic_pattern_server_key.ciphertext_lwe_dimension()
            }
        }
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Standard(compressed_standard_atomic_pattern_server_key) => {
                compressed_standard_atomic_pattern_server_key
                    .bootstrapping_key()
                    .ciphertext_modulus()
            }
            Self::KeySwitch32(compressed_ks32_atomic_pattern_server_key) => {
                compressed_ks32_atomic_pattern_server_key
                    .bootstrapping_key()
                    .ciphertext_modulus()
            }
        }
    }

    pub fn decompress(&self) -> AtomicPatternServerKey {
        match self {
            Self::Standard(compressed_standard_atomic_pattern_server_key) => {
                AtomicPatternServerKey::Standard(
                    compressed_standard_atomic_pattern_server_key.decompress(),
                )
            }
            Self::KeySwitch32(compressed_ks32_atomic_pattern_server_key) => {
                AtomicPatternServerKey::KeySwitch32(
                    compressed_ks32_atomic_pattern_server_key.decompress(),
                )
            }
        }
    }
}

impl ParameterSetConformant for CompressedAtomicPatternServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (Self::Standard(ap), AtomicPatternParameters::Standard(params)) => {
                ap.is_conformant(params)
            }
            (Self::KeySwitch32(ap), AtomicPatternParameters::KeySwitch32(params)) => {
                ap.is_conformant(params)
            }
            _ => false,
        }
    }
}
