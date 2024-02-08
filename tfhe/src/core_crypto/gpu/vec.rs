use crate::core_crypto::gpu::{CudaDevice, CudaPtr, CudaStream};
use crate::core_crypto::prelude::Numeric;
use std::collections::Bound::{Excluded, Included, Unbounded};
use std::ffi::c_void;
use std::marker::PhantomData;
use tfhe_cuda_backend::cuda_bind::{
    cuda_malloc_async, cuda_memcpy_async_gpu_to_gpu, cuda_memcpy_async_to_cpu,
    cuda_memcpy_async_to_gpu, cuda_memset_async,
};

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
    pub fn new(len: usize, stream: &CudaStream) -> Self {
        let vec = unsafe { Self::new_async(len, stream) };
        stream.synchronize();
        vec
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished
    pub unsafe fn new_async(len: usize, stream: &CudaStream) -> Self {
        let size = len as u64 * std::mem::size_of::<T>() as u64;
        let ptr = CudaPtr {
            ptr: cuda_malloc_async(size, stream.as_c_ptr()),
            device: stream.device,
        };
        cuda_memset_async(ptr.ptr, 0u64, size, stream.as_c_ptr());

        Self {
            ptr,
            len,
            device: stream.device,
            _phantom: PhantomData,
        }
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn from_cpu_async(src: &[T], stream: &CudaStream) -> Self {
        let mut res = Self::new_async(src.len(), stream);
        // We have to check that h_data is not empty, because cuda_memset with size 0 is invalid
        if !src.is_empty() {
            res.copy_from_cpu_async(src, stream);
        }
        res
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn memset_async(&mut self, value: T, stream: &CudaStream)
    where
        T: Into<u64>,
    {
        let size = self.len() * std::mem::size_of::<T>();
        // We check that self is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memset_async(
                self.as_mut_c_ptr(),
                value.into(),
                size as u64,
                stream.as_c_ptr(),
            );
        }
    }

    /// Copies data from slice into `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_from_cpu_async(&mut self, src: &[T], stream: &CudaStream)
    where
        T: Numeric,
    {
        assert!(self.len() >= src.len());
        let size = std::mem::size_of_val(src);

        // We have to check that src is not empty, because Rust slice with size 0 results in an
        // invalid pointer being passed to copy_to_gpu_async
        if size > 0 {
            cuda_memcpy_async_to_gpu(
                self.as_mut_c_ptr(),
                src.as_ptr().cast(),
                size as u64,
                stream.as_c_ptr(),
            );
        }
    }

    /// Copies data between two `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_from_gpu_async(&mut self, src: &Self, stream: &CudaStream)
    where
        T: Numeric,
    {
        assert!(self.len() >= src.len());
        let size = src.len() * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_gpu_to_gpu(
                self.as_mut_c_ptr(),
                src.as_c_ptr(),
                size as u64,
                stream.as_c_ptr(),
            );
        }
    }

    /// Copies data between two `CudaVec`, selecting a range of `src` as target
    ///
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_src_range_gpu_to_gpu_async<R>(
        &mut self,
        range: R,
        src: &Self,
        stream: &CudaStream,
    ) where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = src.range_bounds_to_start_end(range).into_inner();
        // size is > 0 thanks to this check
        if end < start {
            return;
        }
        assert!(end < src.len());
        assert!(end - start < self.len());

        let src_ptr = src.as_c_ptr().add(start * std::mem::size_of::<T>());
        let size = (end - start + 1) * std::mem::size_of::<T>();
        cuda_memcpy_async_gpu_to_gpu(self.as_mut_c_ptr(), src_ptr, size as u64, stream.as_c_ptr());
    }

    /// Copies data between two `CudaVec`, selecting a range of `self` as target
    ///
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_self_range_gpu_to_gpu_async<R>(
        &mut self,
        range: R,
        src: &Self,
        stream: &CudaStream,
    ) where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = self.range_bounds_to_start_end(range).into_inner();
        // size is > 0 thanks to this check
        if end < start {
            return;
        }
        assert!(end < self.len());
        assert!(end - start < src.len());

        let dest_ptr = self.as_mut_c_ptr().add(start * std::mem::size_of::<T>());
        let size = (end - start + 1) * std::mem::size_of::<T>();
        cuda_memcpy_async_gpu_to_gpu(dest_ptr, src.as_c_ptr(), size as u64, stream.as_c_ptr());
    }

    /// Copies data from `CudaVec` into slice
    ///
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn copy_to_cpu_async(&self, dest: &mut [T], stream: &CudaStream)
    where
        T: Numeric,
    {
        assert!(dest.len() >= self.len());
        let size = self.len() * std::mem::size_of::<T>();

        // We have to check that self is not empty, because Rust slice with size 0 results in an
        // invalid pointer being passed to copy_to_cpu_async
        if size > 0 {
            cuda_memcpy_async_to_cpu(
                dest.as_mut_ptr().cast(),
                self.as_c_ptr(),
                size as u64,
                stream.as_c_ptr(),
            );
        }
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

    pub(crate) fn range_bounds_to_start_end<R>(&self, range: R) -> std::ops::RangeInclusive<usize>
    where
        R: std::ops::RangeBounds<usize>,
    {
        let start = match range.start_bound() {
            Unbounded => 0usize,
            Included(start) => *start,
            Excluded(start) => *start + 1,
        };

        let end = match range.end_bound() {
            Unbounded => self.len().saturating_sub(1),
            Included(end) => *end,
            Excluded(end) => end.saturating_sub(1),
        };

        start..=end
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
