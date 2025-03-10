use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::prelude::{LweCiphertextCount, LweDimension, UnsignedInteger};

use tfhe_cuda_backend::bindings::*;

pub unsafe fn lwe_expand_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_compact_array_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: LweCiphertextCount,
    max_ciphertext_per_bin: u32,
) {
    cuda_lwe_expand_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_compact_array_in.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples.0 as u32,
        max_ciphertext_per_bin,
    );
}