//! Bootstrap key with Cuda.
use crate::core_crypto::backends::cuda::engines::SharedMemoryAmount;
use crate::core_crypto::backends::cuda::private::crypto::glwe::list::CudaGlweList;
use crate::core_crypto::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::core_crypto::backends::cuda::private::device::{CudaStream, GpuIndex, NumberOfGpus};
use crate::core_crypto::backends::cuda::private::vec::CudaVec;
use crate::core_crypto::backends::cuda::private::{
    compute_number_of_samples_on_gpu, number_of_active_gpus,
};
use crate::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
use crate::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::prelude::{
    CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
    LweCiphertextIndex, LweDimension, PolynomialSize,
};
use std::marker::PhantomData;

#[derive(Debug)]
pub(crate) struct CudaBootstrapKey<T: UnsignedInteger> {
    // Pointers to GPU data: one cuda vec per GPU
    pub(crate) d_vecs: Vec<CudaVec<f64>>,
    // Input LWE dimension
    pub(crate) input_lwe_dimension: LweDimension,
    // Size of polynomials in the key
    pub(crate) polynomial_size: PolynomialSize,
    // GLWE dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Number of decomposition levels
    pub(crate) decomp_level: DecompositionLevelCount,
    // Value of the base log for the decomposition
    pub(crate) decomp_base_log: DecompositionBaseLog,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

unsafe impl<T> Send for CudaBootstrapKey<T> where T: Send + UnsignedInteger {}
unsafe impl<T> Sync for CudaBootstrapKey<T> where T: Sync + UnsignedInteger {}

pub(crate) unsafe fn convert_lwe_bootstrap_key_from_cpu_to_gpu<T: UnsignedInteger, Cont>(
    streams: &[CudaStream],
    input: &StandardBootstrapKey<Cont>,
    number_of_gpus: NumberOfGpus,
) -> Vec<CudaVec<f64>>
where
    Cont: AsRefSlice<Element = T>,
{
    // Copy the entire input vector over all GPUs
    let mut vecs = Vec::with_capacity(number_of_gpus.0);
    // TODO
    //   Check if it would be better to have GPU 0 compute the BSK and copy it back to the
    //   CPU, then copy the BSK to the other GPUs. The order of instructions varies depending on
    //   the Cuda warp scheduling, which we cannot assume is deterministic, so we'll end up with
    //   slightly different BSKs on the GPUs. It is unclear how significantly this affects the
    //   noise after the bootstrap.
    let total_polynomials =
        input.key_size().0 * input.glwe_size().0 * input.glwe_size().0 * input.level_count().0;
    let alloc_size = total_polynomials * input.polynomial_size().0;
    for stream in streams.iter() {
        let mut d_vec = stream.malloc::<f64>(alloc_size as u32);
        let input_slice = input.as_tensor().as_slice();
        stream.initialize_twiddles(input.polynomial_size());
        stream.convert_lwe_bootstrap_key::<T>(
            &mut d_vec,
            input_slice,
            input.key_size(),
            input.glwe_size().to_glwe_dimension(),
            input.level_count(),
            input.polynomial_size(),
        );
        vecs.push(d_vec);
    }
    vecs
}
