use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};

use crate::core_crypto::backends::cuda::private::crypto::bootstrap::CudaBootstrapKey;
use crate::core_crypto::specification::entities::markers::LweBootstrapKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweBootstrapKeyEntity};

/// A structure representing a Fourier bootstrap key for 32 bits precision ciphertexts on the GPU.
#[derive(Debug)]
pub struct CudaFourierLweBootstrapKey32(pub(crate) CudaBootstrapKey<u32>);

impl AbstractEntity for CudaFourierLweBootstrapKey32 {
    type Kind = LweBootstrapKeyKind;
}

impl LweBootstrapKeyEntity for CudaFourierLweBootstrapKey32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomp_base_log
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomp_level
    }
}

/// A structure representing a Fourier bootstrap key for 64 bits precision ciphertexts on the GPU.
#[derive(Debug)]
pub struct CudaFourierLweBootstrapKey64(pub(crate) CudaBootstrapKey<u64>);

impl AbstractEntity for CudaFourierLweBootstrapKey64 {
    type Kind = LweBootstrapKeyKind;
}

impl LweBootstrapKeyEntity for CudaFourierLweBootstrapKey64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomp_base_log
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomp_level
    }
}
