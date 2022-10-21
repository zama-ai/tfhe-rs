use std::fmt::Debug;

use crate::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};

use crate::core_crypto::backends::cuda::private::crypto::glwe::list::CudaGlweList;
use crate::core_crypto::specification::entities::markers::GlweCiphertextVectorKind;
use crate::core_crypto::specification::entities::{
    AbstractEntity, GlweCiphertextVectorEntity,
};

/// A structure representing a vector of GLWE ciphertexts with 32 bits of precision on the GPU.
/// It is used as input to the Cuda bootstrap for the array of lookup tables.
#[derive(Debug)]
pub struct CudaGlweCiphertextVector32(pub(crate) CudaGlweList<u32>);

impl AbstractEntity for CudaGlweCiphertextVector32 {
    type Kind = GlweCiphertextVectorKind;
}

impl GlweCiphertextVectorEntity for CudaGlweCiphertextVector32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        self.0.glwe_ciphertext_count
    }
}

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision on the GPU.
/// It is used as input to the Cuda bootstrap for the array of lookup tables.
#[derive(Debug)]
pub struct CudaGlweCiphertextVector64(pub(crate) CudaGlweList<u64>);

impl AbstractEntity for CudaGlweCiphertextVector64 {
    type Kind = GlweCiphertextVectorKind;
}

impl GlweCiphertextVectorEntity for CudaGlweCiphertextVector64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        self.0.glwe_ciphertext_count
    }
}
