//! Keyswitch key with Cuda.
use crate::core_crypto::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::core_crypto::backends::cuda::private::vec::CudaVec;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};

#[derive(Debug)]
pub(crate) struct CudaLweKeyswitchKey<T: UnsignedInteger> {
    // Pointers to GPU data: one cuda vec per GPU
    pub(crate) d_vecs: Vec<CudaVec<T>>,
    // Input LWE dimension
    pub(crate) input_lwe_dimension: LweDimension,
    // Output LWE dimension
    pub(crate) output_lwe_dimension: LweDimension,
    // Number of decomposition levels
    pub(crate) decomp_level: DecompositionLevelCount,
    // Value of the base log for the decomposition
    pub(crate) decomp_base_log: DecompositionBaseLog,
}

unsafe impl<T> Send for CudaLweKeyswitchKey<T> where T: Send + UnsignedInteger {}
unsafe impl<T> Sync for CudaLweKeyswitchKey<T> where T: Sync + UnsignedInteger {}
