use crate::core_crypto::gpu::vec::range_bounds_to_start_end;
use crate::core_crypto::gpu::{CudaPtr, CudaPtrMut, CudaStreams};
use crate::core_crypto::prelude::Numeric;
use std::ffi::c_void;
use std::marker::PhantomData;
use tfhe_cuda_backend::cuda_bind::{cuda_memcpy_async_gpu_to_gpu, cuda_memcpy_async_to_cpu};

#[derive(Debug, Copy, Clone)]
pub struct CudaSlice<'a, T: Numeric> {
    ptr: CudaPtr,
    _len: usize,
    gpu_index: u32,
    _phantom_1: PhantomData<T>,
    _phantom_2: PhantomData<&'a ()>,
}

#[derive(Debug)]
pub struct CudaSliceMut<'a, T: Numeric> {
    ptr: CudaPtrMut,
    len: usize,
    gpu_index: u32,
    _phantom_1: PhantomData<T>,
    _phantom_2: PhantomData<&'a mut ()>,
}

impl<'a, T> CudaSlice<'a, T>
where
    T: Numeric,
{
    /// # Safety
    ///
    /// The ptr must be valid for reads for len * std::mem::size_of::<T> bytes on
    /// the cuda side.
    pub(crate) unsafe fn new(ptr: *const c_void, len: usize, gpu_index: u32) -> Self {
        Self {
            ptr: CudaPtr(ptr),
            _len: len,
            gpu_index,
            _phantom_1: PhantomData,
            _phantom_2: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_c_ptr(&self) -> *const c_void {
        self.ptr.0
    }
    pub(crate) fn gpu_index(&self) -> u32 {
        self.gpu_index
    }
}

impl<'a, T> CudaSliceMut<'a, T>
where
    T: Numeric,
{
    /// # Safety
    ///
    /// The ptr must be valid for reads and writes for len * std::mem::size_of::<T> bytes on
    /// the cuda side.
    pub(crate) unsafe fn new(ptr: *mut c_void, len: usize, gpu_index: u32) -> Self {
        Self {
            ptr: CudaPtrMut(ptr),
            len,
            gpu_index,
            _phantom_1: PhantomData,
            _phantom_2: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_mut_c_ptr(&mut self) -> *mut c_void {
        self.ptr.0
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_c_ptr(&self) -> *const c_void {
        self.ptr.0.cast_const()
    }

    /// Copies data between two `CudaSlice`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required.
    pub unsafe fn copy_from_gpu_async(&mut self, src: &Self, streams: &CudaStreams)
    where
        T: Numeric,
    {
        assert_eq!(self.len(), src.len());
        assert_eq!(self.gpu_index, streams.gpu_indexes[0]);
        assert_eq!(src.gpu_index, streams.gpu_indexes[0]);
        let size = src.len() * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_gpu_to_gpu(
                self.as_mut_c_ptr(),
                src.as_c_ptr(),
                size as u64,
                streams.ptr[0],
                streams.gpu_indexes[0],
            );
        }
    }

    #[allow(dead_code)]
    /// Copies data of a `CudaSlice` to the CPU
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required.
    pub unsafe fn copy_to_cpu_async(&self, dest: &mut [T], streams: &CudaStreams)
    where
        T: Numeric,
    {
        assert_eq!(self.len(), dest.len());
        assert_eq!(self.gpu_index, streams.gpu_indexes[0]);
        let size = self.len() * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_to_cpu(
                dest.as_mut_ptr().cast::<c_void>(),
                self.as_c_ptr(),
                size as u64,
                streams.ptr[0],
                streams.gpu_indexes[0],
            );
        }
    }

    /// Returns the number of elements in the vector, also referred to as its ‘length’.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the CudaSliceMut is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn get_mut<R>(&mut self, range: R) -> Option<CudaSliceMut<T>>
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
            let shifted_ptr: *mut c_void = unsafe {
                self.ptr
                    .0
                    .cast::<u8>()
                    .add(start * std::mem::size_of::<T>())
                    .cast()
            };

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe { CudaSliceMut::new(shifted_ptr, new_len, self.gpu_index) })
        }
    }

    pub(crate) fn split_at_mut(
        &mut self,
        mid: usize,
    ) -> (Option<CudaSliceMut<T>>, Option<CudaSliceMut<T>>)
    where
        T: Numeric,
    {
        // Check the index is compatible with the vec
        if mid > self.len - 1 {
            (None, None)
        } else if mid == 0 {
            (
                None,
                Some(unsafe { CudaSliceMut::new(self.ptr.0, self.len, self.gpu_index) }),
            )
        } else if mid == self.len - 1 {
            (
                Some(unsafe { CudaSliceMut::new(self.ptr.0, self.len, self.gpu_index) }),
                None,
            )
        } else {
            let new_len_1 = mid;
            let new_len_2 = self.len - mid;
            // Shift ptr
            let shifted_ptr: *mut c_void = unsafe {
                self.ptr
                    .0
                    .cast::<u8>()
                    .add(mid * std::mem::size_of::<T>())
                    .cast()
            };

            // Create the slice
            (
                Some(unsafe { CudaSliceMut::new(self.ptr.0, new_len_1, self.gpu_index) }),
                Some(unsafe { CudaSliceMut::new(shifted_ptr, new_len_2, self.gpu_index) }),
            )
        }
    }
    pub(crate) fn gpu_index(&self) -> u32 {
        self.gpu_index
    }
}
