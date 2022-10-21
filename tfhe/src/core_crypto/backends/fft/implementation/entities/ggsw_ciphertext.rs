use super::super::super::private::crypto::ggsw::FourierGgswCiphertext;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::markers::GgswCiphertextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, GgswCiphertextEntity};
use aligned_vec::ABox;
use concrete_fft::c64;
#[cfg(feature = "backend_fft_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a GGSW ciphertext with 32 bits of precision in the Fourier domain.
#[derive(Debug, Clone, PartialEq)]
pub struct FftFourierGgswCiphertext32(pub(crate) FourierGgswCiphertext<ABox<[c64]>>);

/// A structure representing a GGSW ciphertext with 64 bits of precision in the Fourier domain.
#[derive(Debug, Clone, PartialEq)]
pub struct FftFourierGgswCiphertext64(pub(crate) FourierGgswCiphertext<ABox<[c64]>>);

impl AbstractEntity for FftFourierGgswCiphertext32 {
    type Kind = GgswCiphertextKind;
}
impl AbstractEntity for FftFourierGgswCiphertext64 {
    type Kind = GgswCiphertextKind;
}

impl GgswCiphertextEntity for FftFourierGgswCiphertext32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

impl GgswCiphertextEntity for FftFourierGgswCiphertext64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_fft_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftFourierGgswCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

#[cfg(feature = "backend_fft_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftFourierGgswCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
