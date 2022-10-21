use crate::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey as ImplStandardBootstrapKey;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::markers::LweBootstrapKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweBootstrapKeyEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an LWE bootstrap key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweBootstrapKey32(pub(crate) ImplStandardBootstrapKey<Vec<u32>>);
impl AbstractEntity for LweBootstrapKey32 {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for LweBootstrapKey32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweBootstrapKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE bootstrap key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweBootstrapKey64(pub(crate) ImplStandardBootstrapKey<Vec<u64>>);
impl AbstractEntity for LweBootstrapKey64 {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for LweBootstrapKey64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweBootstrapKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE bootstrap key with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweBootstrapKeyMutView32<'a>(pub(crate) ImplStandardBootstrapKey<&'a mut [u32]>);
impl AbstractEntity for LweBootstrapKeyMutView32<'_> {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for LweBootstrapKeyMutView32<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

/// A structure representing an LWE bootstrap key with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweBootstrapKeyMutView64<'a>(pub(crate) ImplStandardBootstrapKey<&'a mut [u64]>);
impl AbstractEntity for LweBootstrapKeyMutView64<'_> {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for LweBootstrapKeyMutView64<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

/// A structure representing an LWE bootstrap key with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweBootstrapKeyView32<'a>(pub(crate) ImplStandardBootstrapKey<&'a [u32]>);
impl AbstractEntity for LweBootstrapKeyView32<'_> {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for LweBootstrapKeyView32<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

/// A structure representing an LWE bootstrap key with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweBootstrapKeyView64<'a>(pub(crate) ImplStandardBootstrapKey<&'a [u64]>);
impl AbstractEntity for LweBootstrapKeyView64<'_> {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for LweBootstrapKeyView64<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}
