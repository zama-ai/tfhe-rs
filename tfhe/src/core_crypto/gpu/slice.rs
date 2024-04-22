use crate::core_crypto::gpu::vec::range_bounds_to_start_end;
use crate::core_crypto::gpu::{CudaPtr, CudaStream};
use crate::core_crypto::prelude::Numeric;
use std::ffi::c_void;
use std::marker::PhantomData;
use tfhe_cuda_backend::cuda_bind::{cuda_memcpy_async_gpu_to_gpu, cuda_memcpy_async_to_cpu};

#[derive(Debug, Copy, Clone)]
pub struct CudaSlice<'a, T: Numeric> {
    ptr: CudaPtr,
    _len: usize,
    _phantom_1: PhantomData<T>,
    _phantom_2: PhantomData<&'a ()>,
}

#[derive(Debug)]
pub struct CudaSliceMut<'a, T: Numeric> {
    ptr: CudaPtr,
    len: usize,
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
    pub(crate) unsafe fn new(ptr: CudaPtr, len: usize) -> Self {
        Self {
            ptr,
            _len: len,
            _phantom_1: PhantomData,
            _phantom_2: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_c_ptr(&self) -> *const c_void {
        self.ptr.as_c_ptr()
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
    pub(crate) unsafe fn new(ptr: CudaPtr, len: usize) -> Self {
        Self {
            ptr,
            len,
            _phantom_1: PhantomData,
            _phantom_2: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_mut_c_ptr(&mut self) -> *mut c_void {
        self.ptr.as_mut_c_ptr()
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_c_ptr(&self) -> *const c_void {
        self.ptr.as_c_ptr()
    }

    /// Copies data between two `CudaSlice`
    ///
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required.
    pub unsafe fn copy_from_gpu_async(&mut self, src: &Self, stream: &CudaStream)
    where
        T: Numeric,
    {
        assert_eq!(self.len(), src.len());
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

    #[allow(dead_code)]
    /// Copies data of a `CudaSlice` to the CPU
    ///
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after the copy
    /// as soon as synchronization is required.
    pub unsafe fn copy_to_cpu_async(&self, dest: &mut [T], stream: &CudaStream)
    where
        T: Numeric,
    {
        assert_eq!(self.len(), dest.len());
        let size = self.len() * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_to_cpu(
                dest.as_mut_ptr().cast::<c_void>(),
                self.as_c_ptr(),
                size as u64,
                stream.as_c_ptr(),
            );
        }
    }

    /// Returns the number of elements in the vector, also referred to as its ‘length’.
    pub fn len(&self) -> usize {
        self.len
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
                    .as_mut_c_ptr()
                    .cast::<u8>()
                    .add(start * std::mem::size_of::<T>())
                    .cast()
            };
            let new_cuda_ptr = CudaPtr {
                ptr: shifted_ptr,
                device: self.ptr.device,
            };

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe { CudaSliceMut::new(new_cuda_ptr, new_len) })
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
            (None, Some(unsafe { CudaSliceMut::new(self.ptr, self.len) }))
        } else if mid == self.len - 1 {
            (Some(unsafe { CudaSliceMut::new(self.ptr, self.len) }), None)
        } else {
            let new_len_1 = mid;
            let new_len_2 = self.len - mid;
            // Shift ptr
            let shifted_ptr: *mut c_void = unsafe {
                self.ptr
                    .as_mut_c_ptr()
                    .cast::<u8>()
                    .add(mid * std::mem::size_of::<T>())
                    .cast()
            };
            let new_cuda_ptr = CudaPtr {
                ptr: shifted_ptr,
                device: self.ptr.device,
            };

            // Create the slice
            (
                Some(unsafe { CudaSliceMut::new(self.ptr, new_len_1) }),
                Some(unsafe { CudaSliceMut::new(new_cuda_ptr, new_len_2) }),
            )
        }
    }
}
