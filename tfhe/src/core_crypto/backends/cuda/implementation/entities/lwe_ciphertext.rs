use std::fmt::Debug;

use crate::core_crypto::prelude::LweDimension;

use crate::core_crypto::backends::cuda::private::crypto::lwe::ciphertext::CudaLweCiphertext;
use crate::core_crypto::specification::entities::markers::LweCiphertextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweCiphertextEntity};

/// A structure representing a vector of LWE ciphertexts with 32 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertext32(pub(crate) CudaLweCiphertext<u32>);

impl AbstractEntity for CudaLweCiphertext32 {
    type Kind = LweCiphertextKind;
}

impl LweCiphertextEntity for CudaLweCiphertext32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }
}

/// A structure representing a vector of LWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertext64(pub(crate) CudaLweCiphertext<u64>);

impl AbstractEntity for CudaLweCiphertext64 {
    type Kind = LweCiphertextKind;
}

impl LweCiphertextEntity for CudaLweCiphertext64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }
}
