use std::fmt::Debug;

use crate::core_crypto::prelude::{LweCiphertextCount, LweDimension};

use crate::core_crypto::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::core_crypto::specification::entities::markers::LweCiphertextVectorKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweCiphertextVectorEntity};

/// A structure representing a vector of LWE ciphertexts with 32 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertextVector32(pub(crate) CudaLweList<u32>);

impl AbstractEntity for CudaLweCiphertextVector32 {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for CudaLweCiphertextVector32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count
    }
}

/// A structure representing a vector of LWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertextVector64(pub(crate) CudaLweList<u64>);

impl AbstractEntity for CudaLweCiphertextVector64 {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for CudaLweCiphertextVector64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count
    }
}
