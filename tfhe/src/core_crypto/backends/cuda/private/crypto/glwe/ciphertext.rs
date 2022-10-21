use crate::core_crypto::backends::cuda::private::vec::CudaVec;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::prelude::{GlweDimension, PolynomialSize};

/// One GLWE ciphertext on GPU 0.
///
/// There is no multi GPU support at this stage since the user cannot
/// specify on which GPU to convert the data.
// Fields with `d_` are data in the GPU
#[derive(Debug)]
pub(crate) struct CudaGlweCiphertext<T: UnsignedInteger> {
    // Pointer to GPU data: one cuda vec on GPU 0
    pub(crate) d_vec: CudaVec<T>,
    // Glwe dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Polynomial size
    pub(crate) polynomial_size: PolynomialSize,
}
