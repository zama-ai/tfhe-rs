use std::fmt::Debug;

use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};

use crate::core_crypto::backends::cuda::private::crypto::ggsw::ciphertext::CudaGgswCiphertext;
use crate::core_crypto::specification::entities::markers::GgswCiphertextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, GgswCiphertextEntity};

/// A structure representing a vector of GGSW ciphertexts with 32 bits of precision on the GPU.
/// It is used as input to the Cuda WopPBS.
#[derive(Debug)]
pub struct CudaGgswCiphertext32(pub(crate) CudaGgswCiphertext<u32>);

impl AbstractEntity for CudaGgswCiphertext32 {
    type Kind = GgswCiphertextKind;
}

impl GgswCiphertextEntity for CudaGgswCiphertext32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log
    }
}

/// A structure representing a vector of GGSW ciphertexts with 64 bits of precision on the GPU.
/// It is used as input to the Cuda WopPBS.
#[derive(Debug)]
pub struct CudaGgswCiphertext64(pub(crate) CudaGgswCiphertext<u64>);

impl AbstractEntity for CudaGgswCiphertext64 {
    type Kind = GgswCiphertextKind;
}

impl GgswCiphertextEntity for CudaGgswCiphertext64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log
    }
}
