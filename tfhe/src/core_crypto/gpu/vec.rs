use crate::core_crypto::gpu::{CudaDevice, CudaPtr, CudaStream};
use crate::core_crypto::prelude::Numeric;
use std::ffi::c_void;
use std::marker::PhantomData;

/// A contiguous array type stored in the gpu memory.
///
/// Note:
/// -----
///
/// Such a structure:
/// + can be created via the `CudaStream::malloc` function
/// + can not be copied or cloned but can be (mutably) borrowed
/// + frees the gpu memory on drop.
///
/// Put differently, it owns a region of the gpu memory at a given time. For this reason, regarding
/// memory, it is pretty close to a `Vec`. That being said, it only present a very very limited api.
#[derive(Debug)]
pub struct CudaVec<T: Numeric> {
    ptr: CudaPtr,
    len: usize,
    device: CudaDevice,
    _phantom: PhantomData<T>,
}

impl<T: Numeric> CudaVec<T> {
    /// # Safety
    ///
    /// - `ptr` __must__ be a valid device pointer to an array of `len` elements of type `T`
    pub unsafe fn new(ptr: CudaPtr, len: usize, device: CudaDevice) -> Self {
        Self {
            ptr,
            len,
            device,
            _phantom: PhantomData,
        }
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn from_async(h_data: &Vec<T>, stream: &CudaStream) -> Self {
        let mut d_data = stream.malloc_async(h_data.len() as u32);
        stream.copy_to_gpu_async(&mut d_data, h_data.as_slice());
        d_data
    }

    pub(crate) fn as_mut_c_ptr(&mut self) -> *mut c_void {
        self.ptr.as_mut_c_ptr()
    }

    pub(crate) fn as_c_ptr(&self) -> *const c_void {
        self.ptr.as_c_ptr()
    }

    pub fn gpu_index(&self) -> u32 {
        self.device.gpu_index()
    }

    /// Returns the number of elements in the vector, also referred to as its ‘length’.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the CudaVec contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// SAFETY
//
// Behind the void* that is in the CudaPtr, the data is a contiguous
// chunk of T on the GPU, so as long as T is Send/Sync CudaVec is.
//
// clippy complains that we impl Send on CudaVec while CudaPtr is non Send.
// This is ok for us, as CudaPtr is meant to be a wrapper type that serves
// as distinguishing ptr that points to cuda memory from pointers pointing to
// CPU memory.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<T> Send for CudaVec<T> where T: Send + Numeric {}
unsafe impl<T> Sync for CudaVec<T> where T: Sync + Numeric {}
