use crate::core_crypto::commons::numeric::Numeric;
use concrete_cuda::cuda_bind::cuda_drop;
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
    pub(super) ptr: *mut c_void,
    pub(super) idx: u32,
    pub(super) len: usize,
    pub(super) _phantom: PhantomData<T>,
}

impl<T: Numeric> CudaVec<T> {
    /// Returns a raw pointer to the vector’s buffer.
    pub fn as_c_ptr(&self) -> *const c_void {
        self.ptr as *const c_void
    }

    /// Returns an unsafe mutable pointer to the vector’s buffer.
    pub fn as_mut_c_ptr(&mut self) -> *mut c_void {
        self.ptr
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

impl<T: Numeric> Drop for CudaVec<T> {
    fn drop(&mut self) {
        unsafe { cuda_drop(self.ptr, self.idx) };
    }
}
