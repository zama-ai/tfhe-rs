use crate::core_crypto::gpu::slice::{CudaSlice, CudaSliceMut};
use crate::core_crypto::gpu::{synchronize_device, CudaStreams};
use crate::core_crypto::prelude::Numeric;
use std::collections::Bound::{Excluded, Included, Unbounded};
use std::ffi::c_void;
use std::marker::PhantomData;
use tfhe_cuda_backend::cuda_bind::{
    cuda_drop, cuda_malloc, cuda_malloc_async, cuda_memcpy_async_gpu_to_gpu,
    cuda_memcpy_async_to_cpu, cuda_memcpy_async_to_gpu, cuda_memcpy_gpu_to_gpu, cuda_memset_async,
    cuda_synchronize_device,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuIndex(pub u32);

/// A contiguous array type stored in the gpu memory.
///
/// Note:
/// -----
///
/// Such a structure:
/// + can be created via the `CudaStreams::malloc` function
/// + can not be copied or cloned but can be (mutably) borrowed
/// + frees the gpu memory on drop.
///
/// Put differently, it owns a region of the gpu memory at a given time. For this reason, regarding
/// memory, it is pretty close to a `Vec`. That being said, it only present a very very limited api.
#[derive(Debug)]
pub struct CudaVec<T: Numeric> {
    pub ptr: Vec<*mut c_void>,
    pub len: usize,
    pub gpu_indexes: Vec<GpuIndex>,
    _phantom: PhantomData<T>,
}

impl<T: Numeric> Clone for CudaVec<T> {
    fn clone(&self) -> Self {
        let size = self.len as u64 * std::mem::size_of::<T>() as u64;
        let mut cloned_vec = Vec::with_capacity(self.ptr.len());
        for (index, &gpu_index) in self.gpu_indexes.iter().enumerate() {
            unsafe {
                cuda_synchronize_device(gpu_index.0);
                let ptr = cuda_malloc(size, gpu_index.0);
                cuda_memcpy_gpu_to_gpu(ptr, self.ptr[index], size, gpu_index.0);
                cloned_vec.push(ptr);
            }
        }
        Self {
            ptr: cloned_vec,
            len: self.len,
            gpu_indexes: self.gpu_indexes.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<T: Numeric> CudaVec<T> {
    /// This creates a `CudaVec` that holds memory of `len` elements
    /// on the GPU with index `gpu_index`
    pub fn new(len: usize, streams: &CudaStreams, stream_index: u32) -> Self {
        let vec = unsafe { Self::new_async(len, streams, stream_index) };
        streams.synchronize();
        vec
    }
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished
    pub unsafe fn new_async(len: usize, streams: &CudaStreams, stream_index: u32) -> Self {
        let size = len as u64 * std::mem::size_of::<T>() as u64;
        let ptr = cuda_malloc_async(
            size,
            streams.ptr[stream_index as usize],
            streams.gpu_indexes[stream_index as usize].0,
        );
        cuda_memset_async(
            ptr,
            0u64,
            size,
            streams.ptr[stream_index as usize],
            streams.gpu_indexes[stream_index as usize].0,
        );

        Self {
            ptr: vec![ptr; 1],
            len,
            gpu_indexes: vec![streams.gpu_indexes[stream_index as usize]; 1],
            _phantom: PhantomData,
        }
    }

    /// This creates a `CudaVec` that holds memory of
    /// `len` elements on as many GPUs as there are `CudaStreams`
    pub fn new_multi_gpu(len: usize, streams: &CudaStreams) -> Self {
        let size = len as u64 * std::mem::size_of::<T>() as u64;
        let mut ptrs = Vec::with_capacity(streams.len());
        for (index, &stream) in streams.ptr.iter().enumerate() {
            let ptr = unsafe { cuda_malloc_async(size, stream, index as u32) };
            unsafe {
                cuda_memset_async(
                    ptr,
                    0u64,
                    size,
                    streams.ptr[index],
                    streams.gpu_indexes[index].0,
                );
            }
            streams.synchronize_one(index as u32);
            ptrs.push(ptr);
        }

        Self {
            ptr: ptrs,
            len,
            gpu_indexes: streams.gpu_indexes.clone(),
            _phantom: PhantomData,
        }
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn from_cpu_async(src: &[T], streams: &CudaStreams, stream_index: u32) -> Self {
        let mut res = Self::new(src.len(), streams, stream_index);
        // We have to check that h_data is not empty, because cuda_memset with size 0 is invalid
        if !src.is_empty() {
            res.copy_from_cpu_async(src, streams, stream_index);
        }
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn from_cpu_multi_gpu_async(src: &[T], streams: &CudaStreams) -> Self {
        let mut res = Self::new_multi_gpu(src.len(), streams);
        // We have to check that h_data is not empty, because cuda_memset with size 0 is invalid
        if !src.is_empty() {
            res.copy_from_cpu_multi_gpu_async(src, streams);
        }
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn memset_async(&mut self, value: T, streams: &CudaStreams, stream_index: u32)
    where
        T: Into<u64>,
    {
        let size = self.len() * std::mem::size_of::<T>();
        // We check that self is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memset_async(
                self.as_mut_c_ptr(stream_index),
                value.into(),
                size as u64,
                streams.ptr[stream_index as usize],
                streams.gpu_indexes[stream_index as usize].0,
            );
        }
    }

    /// Copies data from slice into `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required
    pub unsafe fn copy_from_cpu_async(
        &mut self,
        src: &[T],
        streams: &CudaStreams,
        stream_index: u32,
    ) where
        T: Numeric,
    {
        assert!(self.len() >= src.len());
        let size = std::mem::size_of_val(src);

        // We have to check that src is not empty, because Rust slice with size 0 results in an
        // invalid pointer being passed to copy_to_gpu_async
        if size > 0 {
            cuda_memcpy_async_to_gpu(
                self.as_mut_c_ptr(stream_index),
                src.as_ptr().cast(),
                size as u64,
                streams.ptr[stream_index as usize],
                streams.gpu_indexes[stream_index as usize].0,
            );
        }
    }

    /// Copies data from slice into `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required
    pub unsafe fn copy_from_cpu_multi_gpu_async(&mut self, src: &[T], streams: &CudaStreams)
    where
        T: Numeric,
    {
        for (gpu_index, &stream) in streams.ptr.iter().enumerate() {
            assert!(self.len() >= src.len());
            let size = std::mem::size_of_val(src);

            // We have to check that src is not empty, because Rust slice with size 0 results in an
            // invalid pointer being passed to copy_to_gpu_async
            if size > 0 {
                cuda_memcpy_async_to_gpu(
                    self.get_mut_c_ptr(gpu_index as u32),
                    src.as_ptr().cast(),
                    size as u64,
                    stream,
                    streams.gpu_indexes[gpu_index].0,
                );
            }
        }
    }

    /// Copies data between two `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required
    pub unsafe fn copy_from_gpu_async(
        &mut self,
        src: &Self,
        streams: &CudaStreams,
        stream_index: u32,
    ) where
        T: Numeric,
    {
        assert!(self.len() >= src.len());
        let size = src.len() * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_gpu_to_gpu(
                self.as_mut_c_ptr(stream_index),
                src.as_c_ptr(stream_index),
                size as u64,
                streams.ptr[stream_index as usize],
                streams.gpu_indexes[stream_index as usize].0,
            );
        }
    }

    /// Copies data between two `CudaVec`, selecting a range of `src` as target
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required
    pub unsafe fn copy_src_range_gpu_to_gpu_async<R>(
        &mut self,
        range: R,
        src: &Self,
        streams: &CudaStreams,
        stream_index: u32,
    ) where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(src.len(), range).into_inner();
        // size is > 0 thanks to this check
        if end < start {
            return;
        }
        assert!(end < src.len());
        assert!(end - start < self.len());

        let src_ptr = src
            .as_c_ptr(stream_index)
            .add(start * std::mem::size_of::<T>());
        let size = (end - start + 1) * std::mem::size_of::<T>();
        cuda_memcpy_async_gpu_to_gpu(
            self.as_mut_c_ptr(stream_index),
            src_ptr,
            size as u64,
            streams.ptr[stream_index as usize],
            streams.gpu_indexes[stream_index as usize].0,
        );
    }

    /// Copies data between two `CudaVec`, selecting a range of `self` as target
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required
    pub unsafe fn copy_self_range_gpu_to_gpu_async<R>(
        &mut self,
        range: R,
        src: &Self,
        streams: &CudaStreams,
        stream_index: u32,
    ) where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(), range).into_inner();
        // size is > 0 thanks to this check
        if end < start {
            return;
        }
        assert!(end < self.len());
        assert!(end - start < src.len());

        let dest_ptr = self
            .as_mut_c_ptr(stream_index)
            .add(start * std::mem::size_of::<T>());
        let size = (end - start + 1) * std::mem::size_of::<T>();
        cuda_memcpy_async_gpu_to_gpu(
            dest_ptr,
            src.as_c_ptr(stream_index),
            size as u64,
            streams.ptr[stream_index as usize],
            streams.gpu_indexes[stream_index as usize].0,
        );
    }

    /// Copies data from `CudaVec` into slice on a specific GPU
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called as soon as synchronization is required
    pub unsafe fn copy_to_cpu_async(&self, dest: &mut [T], streams: &CudaStreams, stream_index: u32)
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
                self.as_c_ptr(stream_index),
                size as u64,
                streams.ptr[stream_index as usize],
                streams.gpu_indexes[stream_index as usize].0,
            );
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn as_mut_c_ptr(&mut self, index: u32) -> *mut c_void {
        self.ptr[index as usize]
    }

    pub(crate) fn get_mut_c_ptr(&self, index: u32) -> *mut c_void {
        self.ptr[index as usize]
    }

    pub(crate) fn as_c_ptr(&self, index: u32) -> *const c_void {
        self.ptr[index as usize].cast_const()
    }

    pub(crate) fn as_slice<R>(&self, range: R, index: usize) -> Option<CudaSlice<T>>
    where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(), range).into_inner();

        // Check the range is compatible with the vec
        if end <= start || end > self.len - 1 {
            None
        } else {
            // Shift ptr
            let shifted_ptr: *mut c_void =
                self.ptr[index].wrapping_byte_add(start * std::mem::size_of::<T>());

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe { CudaSlice::new(shifted_ptr, new_len, self.gpu_indexes[index]) })
        }
    }

    // clippy complains as we only manipulate pointers, but we want to keep rust semantics
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn as_mut_slice<R>(&mut self, range: R, index: usize) -> Option<CudaSliceMut<T>>
    where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(), range).into_inner();

        // Check the range is compatible with the vec
        if end <= start || end > self.len - 1 {
            None
        } else {
            // Shift ptr
            let shifted_ptr: *mut c_void =
                self.ptr[index].wrapping_byte_add(start * std::mem::size_of::<T>());

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe { CudaSliceMut::new(shifted_ptr, new_len, self.gpu_indexes[index]) })
        }
    }

    /// Returns the GPU index at index
    pub fn gpu_index(&self, index: u32) -> GpuIndex {
        self.gpu_indexes[index as usize]
    }

    /// Returns the number of elements in the vector, also referred to as its ‘length’,
    /// on every GPU
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the CudaVec contains no elements on every GPU.
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

impl<T: Numeric> Drop for CudaVec<T> {
    /// Free memory for pointer `ptr` synchronously
    fn drop(&mut self) {
        for (ptr, gpu_index) in self
            .ptr
            .iter()
            .copied()
            .zip(self.gpu_indexes.iter().copied())
        {
            // Synchronizes the device to be sure no stream is still using this pointer
            synchronize_device(gpu_index.0);
            unsafe { cuda_drop(ptr, gpu_index.0) };
        }
    }
}

pub(crate) fn range_bounds_to_start_end<R>(len: usize, range: R) -> std::ops::RangeInclusive<usize>
where
    R: std::ops::RangeBounds<usize>,
{
    let start = match range.start_bound() {
        Unbounded => 0usize,
        Included(start) => *start,
        Excluded(start) => *start + 1,
    };

    let end = match range.end_bound() {
        Unbounded => len.saturating_sub(1),
        Included(end) => *end,
        Excluded(end) => end.saturating_sub(1),
    };

    start..=end
}
