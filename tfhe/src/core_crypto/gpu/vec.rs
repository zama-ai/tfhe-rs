use crate::core_crypto::gpu::slice::{CudaSlice, CudaSliceMut};
use crate::core_crypto::gpu::{synchronize_device, CudaStreams};
use crate::core_crypto::prelude::Numeric;
use std::collections::Bound::{Excluded, Included, Unbounded};
use std::ffi::c_void;
use std::marker::PhantomData;
use tfhe_cuda_backend::cuda_bind::{
    cuda_drop, cuda_malloc_async, cuda_memcpy_async_gpu_to_gpu, cuda_memcpy_async_to_cpu,
    cuda_memcpy_async_to_gpu, cuda_memset_async,
};

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
    pub lengths: Vec<usize>,
    pub gpu_indexes: Vec<u32>,
    _phantom: PhantomData<T>,
}

impl<T: Numeric> CudaVec<T> {
    pub fn new(len: usize, streams: &CudaStreams, gpu_index: u32) -> Self {
        let vec = unsafe { Self::new_async(len, streams, gpu_index) };
        streams.synchronize();
        vec
    }
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished
    pub unsafe fn new_async(len: usize, streams: &CudaStreams, gpu_index: u32) -> Self {
        let size = len as u64 * std::mem::size_of::<T>() as u64;
        let ptr = cuda_malloc_async(
            size,
            streams.ptr[gpu_index as usize],
            streams.gpu_indexes[gpu_index as usize],
        );
        cuda_memset_async(
            ptr,
            0u64,
            size,
            streams.ptr[gpu_index as usize],
            streams.gpu_indexes[gpu_index as usize],
        );

        Self {
            ptr: vec![ptr; 1],
            lengths: vec![len; 1],
            gpu_indexes: vec![streams.gpu_indexes[gpu_index as usize]; 1],
            _phantom: PhantomData,
        }
    }

    pub fn new_multi_gpu(len: usize, streams: &CudaStreams) -> Self {
        let size = len as u64 * std::mem::size_of::<T>() as u64;
        let mut ptrs = Vec::with_capacity(streams.len());
        for &gpu_index in streams.gpu_indexes.iter() {
            let ptr = unsafe {
                cuda_malloc_async(
                    size,
                    streams.ptr[gpu_index as usize],
                    streams.gpu_indexes[gpu_index as usize],
                )
            };
            unsafe {
                cuda_memset_async(
                    ptr,
                    0u64,
                    size,
                    streams.ptr[gpu_index as usize],
                    streams.gpu_indexes[gpu_index as usize],
                );
            }
            streams.synchronize_one(gpu_index);
            ptrs.push(ptr);
        }

        Self {
            ptr: ptrs,
            lengths: vec![len; streams.len()],
            gpu_indexes: streams.gpu_indexes.clone(),
            _phantom: PhantomData,
        }
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn from_cpu_async(src: &[T], streams: &CudaStreams, gpu_index: u32) -> Self {
        let mut res = Self::new(src.len(), streams, gpu_index);
        // We have to check that h_data is not empty, because cuda_memset with size 0 is invalid
        if !src.is_empty() {
            res.copy_from_cpu_async(src, streams, gpu_index);
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
    pub unsafe fn memset_async(&mut self, value: T, streams: &CudaStreams, gpu_index: u32)
    where
        T: Into<u64>,
    {
        let size = self.len(gpu_index) * std::mem::size_of::<T>();
        // We check that self is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memset_async(
                self.as_mut_c_ptr(gpu_index),
                value.into(),
                size as u64,
                streams.ptr[gpu_index as usize],
                streams.gpu_indexes[gpu_index as usize],
            );
        }
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn memset_multi_gpu_async(&mut self, value: T, streams: &CudaStreams)
    where
        T: Into<u64>,
    {
        for &gpu_index in self.gpu_indexes.clone().iter() {
            let size = self.len(gpu_index) * std::mem::size_of::<T>();
            // We check that self is not empty to avoid invalid pointers
            if size > 0 {
                cuda_memset_async(
                    self.as_mut_c_ptr(gpu_index),
                    value.into(),
                    size as u64,
                    streams.ptr[gpu_index as usize],
                    streams.gpu_indexes[gpu_index as usize],
                );
            }
        }
    }

    /// Copies data from slice into `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_from_cpu_async(&mut self, src: &[T], streams: &CudaStreams, gpu_index: u32)
    where
        T: Numeric,
    {
        assert!(self.len(gpu_index) >= src.len());
        let size = std::mem::size_of_val(src);

        // We have to check that src is not empty, because Rust slice with size 0 results in an
        // invalid pointer being passed to copy_to_gpu_async
        if size > 0 {
            cuda_memcpy_async_to_gpu(
                self.as_mut_c_ptr(gpu_index),
                src.as_ptr().cast(),
                size as u64,
                streams.ptr[gpu_index as usize],
                streams.gpu_indexes[gpu_index as usize],
            );
        }
    }

    /// Copies data from slice into `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_from_cpu_multi_gpu_async(&mut self, src: &[T], streams: &CudaStreams)
    where
        T: Numeric,
    {
        for &gpu_index in self.gpu_indexes.clone().iter() {
            assert!(self.len(gpu_index) >= src.len());
            let size = std::mem::size_of_val(src);

            // We have to check that src is not empty, because Rust slice with size 0 results in an
            // invalid pointer being passed to copy_to_gpu_async
            if size > 0 {
                cuda_memcpy_async_to_gpu(
                    self.as_mut_c_ptr(gpu_index),
                    src.as_ptr().cast(),
                    size as u64,
                    streams.ptr[gpu_index as usize],
                    streams.gpu_indexes[gpu_index as usize],
                );
            }
        }
    }

    /// Copies data between two `CudaVec`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_from_gpu_async(&mut self, src: &Self, streams: &CudaStreams, gpu_index: u32)
    where
        T: Numeric,
    {
        assert!(self.len(gpu_index) >= src.len(gpu_index));
        let size = src.len(gpu_index) * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_gpu_to_gpu(
                self.as_mut_c_ptr(gpu_index),
                src.as_c_ptr(gpu_index),
                size as u64,
                streams.ptr[gpu_index as usize],
                streams.gpu_indexes[gpu_index as usize],
            );
        }
    }

    /// Copies data between two `CudaVec`, selecting a range of `src` as target
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_src_range_gpu_to_gpu_async<R>(
        &mut self,
        range: R,
        src: &Self,
        streams: &CudaStreams,
        gpu_index: u32,
    ) where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(src.len(gpu_index), range).into_inner();
        // size is > 0 thanks to this check
        if end < start {
            return;
        }
        assert!(end < src.len(gpu_index));
        assert!(end - start < self.len(gpu_index));

        let src_ptr = src
            .as_c_ptr(gpu_index)
            .add(start * std::mem::size_of::<T>());
        let size = (end - start + 1) * std::mem::size_of::<T>();
        cuda_memcpy_async_gpu_to_gpu(
            self.as_mut_c_ptr(gpu_index),
            src_ptr,
            size as u64,
            streams.ptr[gpu_index as usize],
            streams.gpu_indexes[gpu_index as usize],
        );
    }

    /// Copies data between two `CudaVec`, selecting a range of `self` as target
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required
    pub unsafe fn copy_self_range_gpu_to_gpu_async<R>(
        &mut self,
        range: R,
        src: &Self,
        streams: &CudaStreams,
        gpu_index: u32,
    ) where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(gpu_index), range).into_inner();
        // size is > 0 thanks to this check
        if end < start {
            return;
        }
        assert!(end < self.len(gpu_index));
        assert!(end - start < src.len(gpu_index));

        let dest_ptr = self
            .as_mut_c_ptr(gpu_index)
            .add(start * std::mem::size_of::<T>());
        let size = (end - start + 1) * std::mem::size_of::<T>();
        cuda_memcpy_async_gpu_to_gpu(
            dest_ptr,
            src.as_c_ptr(gpu_index),
            size as u64,
            streams.ptr[gpu_index as usize],
            streams.gpu_indexes[gpu_index as usize],
        );
    }

    /// Copies data from `CudaVec` into slice on a specific GPU
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn copy_to_cpu_async(&self, dest: &mut [T], streams: &CudaStreams, gpu_index: u32)
    where
        T: Numeric,
    {
        assert!(dest.len() >= self.len(gpu_index));
        let size = self.len(gpu_index) * std::mem::size_of::<T>();

        // We have to check that self is not empty, because Rust slice with size 0 results in an
        // invalid pointer being passed to copy_to_cpu_async
        if size > 0 {
            cuda_memcpy_async_to_cpu(
                dest.as_mut_ptr().cast(),
                self.as_c_ptr(gpu_index),
                size as u64,
                streams.ptr[gpu_index as usize],
                streams.gpu_indexes[gpu_index as usize],
            );
        }
    }

    pub(crate) fn as_mut_c_ptr(&mut self, gpu_index: u32) -> *mut c_void {
        self.ptr[gpu_index as usize]
    }

    pub(crate) fn as_c_ptr(&self, gpu_index: u32) -> *const c_void {
        self.ptr[gpu_index as usize].cast_const()
    }

    pub(crate) fn as_slice<R>(&self, range: R, gpu_index: u32) -> Option<CudaSlice<T>>
    where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(gpu_index), range).into_inner();

        // Check the range is compatible with the vec
        if end <= start || end > self.lengths[gpu_index as usize] - 1 {
            None
        } else {
            // Shift ptr
            let shifted_ptr: *mut c_void = unsafe {
                self.ptr[gpu_index as usize]
                    .cast::<u8>()
                    .add(start * std::mem::size_of::<T>())
                    .cast()
            };

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe { CudaSlice::new(shifted_ptr, new_len, gpu_index) })
        }
    }

    pub(crate) fn as_mut_slice<R>(&mut self, range: R, gpu_index: u32) -> Option<CudaSliceMut<T>>
    where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(gpu_index), range).into_inner();

        // Check the range is compatible with the vec
        if end <= start || end > self.lengths[gpu_index as usize] - 1 {
            None
        } else {
            // Shift ptr
            let shifted_ptr: *mut c_void = unsafe {
                self.ptr[gpu_index as usize]
                    .cast::<u8>()
                    .add(start * std::mem::size_of::<T>())
                    .cast()
            };

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe { CudaSliceMut::new(shifted_ptr, new_len, gpu_index) })
        }
    }

    /// Returns the GPU index at index
    pub fn gpu_index(&self, index: u32) -> u32 {
        self.gpu_indexes[index as usize]
    }

    /// Returns the number of elements in the vector, also referred to as its ‘length’, on the GPU
    /// gpu_index.
    pub fn len(&self, gpu_index: u32) -> usize {
        self.lengths[gpu_index as usize]
    }

    /// Returns `true` if the CudaVec contains no elements on GPU gpu_index.
    pub fn is_empty(&self, gpu_index: u32) -> bool {
        self.lengths[gpu_index as usize] == 0
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
        for &gpu_index in self.gpu_indexes.clone().iter() {
            // Synchronizes the device to be sure no stream is still using this pointer
            synchronize_device(gpu_index);
            unsafe { cuda_drop(self.as_mut_c_ptr(gpu_index), gpu_index) };
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
