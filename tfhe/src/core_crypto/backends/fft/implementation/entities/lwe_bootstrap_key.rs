use super::super::super::private::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::specification::entities::markers::LweBootstrapKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweBootstrapKeyEntity};
use aligned_vec::ABox;
use concrete_fft::c64;
#[cfg(feature = "backend_fft_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an LWE bootstrap key with 32 bits of precision, in the Fourier domain.
#[derive(Debug, Clone, PartialEq)]
pub struct FftFourierLweBootstrapKey32(pub(crate) FourierLweBootstrapKey<ABox<[c64]>>);

/// A structure representing an LWE bootstrap key with 64 bits of precision, in the Fourier domain.
#[derive(Debug, Clone, PartialEq)]
pub struct FftFourierLweBootstrapKey64(pub(crate) FourierLweBootstrapKey<ABox<[c64]>>);

impl AbstractEntity for FftFourierLweBootstrapKey32 {
    type Kind = LweBootstrapKeyKind;
}
impl AbstractEntity for FftFourierLweBootstrapKey64 {
    type Kind = LweBootstrapKeyKind;
}

impl LweBootstrapKeyEntity for FftFourierLweBootstrapKey32 {
    fn glwe_dimension(&self) -> crate::core_crypto::prelude::GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> crate::core_crypto::prelude::PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> crate::core_crypto::prelude::LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> crate::core_crypto::prelude::DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn decomposition_level_count(
        &self,
    ) -> crate::core_crypto::prelude::DecompositionLevelCount {
        self.0.decomposition_level_count()
    }
}
impl LweBootstrapKeyEntity for FftFourierLweBootstrapKey64 {
    fn glwe_dimension(&self) -> crate::core_crypto::prelude::GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> crate::core_crypto::prelude::PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> crate::core_crypto::prelude::LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> crate::core_crypto::prelude::DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn decomposition_level_count(
        &self,
    ) -> crate::core_crypto::prelude::DecompositionLevelCount {
        self.0.decomposition_level_count()
    }
}

#[cfg(feature = "backend_fft_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftFourierLweBootstrapKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}
#[cfg(feature = "backend_fft_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftFourierLweBootstrapKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
