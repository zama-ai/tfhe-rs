use crate::core_crypto::commons::crypto::lwe::LweKeyswitchKey as ImplLweKeyswitchKey;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
use crate::core_crypto::specification::entities::markers::LweKeyswitchKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweKeyswitchKeyEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an LWE keyswitch key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweKeyswitchKey32(pub(crate) ImplLweKeyswitchKey<Vec<u32>>);
impl AbstractEntity for LweKeyswitchKey32 {
    type Kind = LweKeyswitchKeyKind;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKey32 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweKeyswitchKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE keyswitch key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweKeyswitchKey64(pub(crate) ImplLweKeyswitchKey<Vec<u64>>);
impl AbstractEntity for LweKeyswitchKey64 {
    type Kind = LweKeyswitchKeyKind;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKey64 {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweKeyswitchKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE keyswitch key with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweKeyswitchKeyMutView32<'a>(pub(crate) ImplLweKeyswitchKey<&'a mut [u32]>);
impl AbstractEntity for LweKeyswitchKeyMutView32<'_> {
    type Kind = LweKeyswitchKeyKind;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKeyMutView32<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

/// A structure representing an LWE keyswitch key with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweKeyswitchKeyMutView64<'a>(pub(crate) ImplLweKeyswitchKey<&'a mut [u64]>);
impl AbstractEntity for LweKeyswitchKeyMutView64<'_> {
    type Kind = LweKeyswitchKeyKind;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKeyMutView64<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

/// A structure representing an LWE keyswitch key with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweKeyswitchKeyView32<'a>(pub(crate) ImplLweKeyswitchKey<&'a [u32]>);
impl AbstractEntity for LweKeyswitchKeyView32<'_> {
    type Kind = LweKeyswitchKeyKind;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKeyView32<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

/// A structure representing an LWE keyswitch key with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweKeyswitchKeyView64<'a>(pub(crate) ImplLweKeyswitchKey<&'a [u64]>);
impl AbstractEntity for LweKeyswitchKeyView64<'_> {
    type Kind = LweKeyswitchKeyKind;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKeyView64<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}
