use crate::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey as ImplLweSeededKeyswitchKey;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
use crate::core_crypto::specification::entities::markers::LweSeededKeyswitchKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweSeededKeyswitchKeyEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a seeded LWE keyswitch key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededKeyswitchKey32(pub(crate) ImplLweSeededKeyswitchKey<Vec<u32>>);
impl AbstractEntity for LweSeededKeyswitchKey32 {
    type Kind = LweSeededKeyswitchKeyKind;
}
impl LweSeededKeyswitchKeyEntity for LweSeededKeyswitchKey32 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.output_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededKeyswitchKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a seeded LWE keyswitch key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededKeyswitchKey64(pub(crate) ImplLweSeededKeyswitchKey<Vec<u64>>);
impl AbstractEntity for LweSeededKeyswitchKey64 {
    type Kind = LweSeededKeyswitchKeyKind;
}
impl LweSeededKeyswitchKeyEntity for LweSeededKeyswitchKey64 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.output_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededKeyswitchKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
