use crate::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey as ImplLwePackingKeyswitchKey;
use crate::core_crypto::prelude::markers::LwePackingKeyswitchKeyKind;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
    LwePackingKeyswitchKeyEntity,
};
use crate::core_crypto::specification::entities::AbstractEntity;
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a packing keyswitch key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwePackingKeyswitchKey32(pub(crate) ImplLwePackingKeyswitchKey<Vec<u32>>);
impl AbstractEntity for LwePackingKeyswitchKey32 {
    type Kind = LwePackingKeyswitchKeyKind;
}
impl LwePackingKeyswitchKeyEntity for LwePackingKeyswitchKey32 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::core_crypto::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LwePackingKeyswitchKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a packing keyswitch key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwePackingKeyswitchKey64(pub(crate) ImplLwePackingKeyswitchKey<Vec<u64>>);
impl AbstractEntity for LwePackingKeyswitchKey64 {
    type Kind = LwePackingKeyswitchKeyKind;
}
impl LwePackingKeyswitchKeyEntity for LwePackingKeyswitchKey64 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_key_dimension()
    }

    fn output_glwe_dimension(&self) -> GlweDimension {
        self.0.output_glwe_key_dimension()
    }

    fn output_polynomial_size(&self) -> crate::core_crypto::prelude::PolynomialSize {
        self.0.output_polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LwePackingKeyswitchKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
