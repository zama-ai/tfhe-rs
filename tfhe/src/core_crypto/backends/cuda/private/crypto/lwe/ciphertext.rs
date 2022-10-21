use crate::core_crypto::backends::cuda::private::vec::CudaVec;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::prelude::LweDimension;

/// An LWE ciphertext on the GPU 0.
///
/// There is no multi GPU support at this stage since the user cannot
/// specify on which GPU to convert the data.

// Fields with `d_` are data in the GPU
#[derive(Debug)]
pub(crate) struct CudaLweCiphertext<T: UnsignedInteger> {
    // Pointers to GPU data: one cuda vec on GPU 0
    pub(crate) d_vec: CudaVec<T>,
    // Lwe dimension
    pub(crate) lwe_dimension: LweDimension,
}
