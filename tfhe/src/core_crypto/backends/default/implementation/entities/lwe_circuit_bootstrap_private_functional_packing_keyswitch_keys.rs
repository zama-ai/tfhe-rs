use crate::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList as ImplLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::core_crypto::prelude::markers::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    GlweDimension, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, LweDimension,
};
use crate::core_crypto::specification::entities::AbstractEntity;
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of private functional packing keyswitch keys used for a
/// circuit bootsrap with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
    pub(crate) ImplLwePrivateFunctionalPackingKeyswitchKeyList<Vec<u32>>,
);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity
    for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32
{
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

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of private functional packing keyswitch keys used for a
/// circuit bootsrap with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
    pub ImplLwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,
);
impl AbstractEntity for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
    type Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity
    for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64
{
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

    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        self.0.fpksk_count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
