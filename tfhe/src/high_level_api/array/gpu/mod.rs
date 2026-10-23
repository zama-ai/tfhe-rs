pub(crate) mod booleans;
pub(crate) mod integers;

use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::details::MaybeCloned;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
#[cfg(test)]
pub use booleans::GpuFheBoolArrayBackend;
pub use booleans::{GpuFheBoolArray, GpuFheBoolSlice, GpuFheBoolSliceMut};
pub use integers::{
    GpuFheIntArray, GpuFheIntSlice, GpuFheIntSliceMut, GpuFheUintArray, GpuFheUintSlice,
    GpuFheUintSliceMut,
};

/// Returns the element if it is on the GPU where `streams` allocate ciphertexts,
/// otherwise (e.g. the server key was changed for one on another GPU) returns a copy of it
/// on that GPU
fn on_gpu<'a, T>(elem: &'a T, streams: &CudaStreams) -> MaybeCloned<'a, T>
where
    T: CudaIntegerRadixCiphertext,
{
    if streams.is_on_first_gpu(elem.gpu_indexes()) {
        MaybeCloned::Borrowed(elem)
    } else {
        MaybeCloned::Cloned(elem.duplicate(streams))
    }
}
