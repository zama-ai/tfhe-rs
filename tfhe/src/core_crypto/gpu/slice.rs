use crate::core_crypto::gpu::vec::range_bounds_to_start_end;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::Numeric;
use std::ffi::c_void;
use std::marker::PhantomData;
use tfhe_cuda_backend::cuda_bind::{cuda_memcpy_async_gpu_to_gpu, cuda_memcpy_async_to_cpu};

#[derive(Debug, Clone)]
pub struct CudaSlice<'a, T: Numeric> {
    ptrs: Vec<*const c_void>,
    _lengths: Vec<usize>,
    gpu_indexes: Vec<u32>,
    _phantom_1: PhantomData<T>,
    _phantom_2: PhantomData<&'a ()>,
}

#[derive(Debug)]
pub struct CudaSliceMut<'a, T: Numeric> {
    ptrs: Vec<*mut c_void>,
    lengths: Vec<usize>,
    gpu_indexes: Vec<u32>,
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
            ptrs: vec![ptr; 1],
            _lengths: vec![len; 1],
            gpu_indexes: vec![gpu_index; 1],
            _phantom_1: PhantomData,
            _phantom_2: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_c_ptr(&self, gpu_index: u32) -> *const c_void {
        self.ptrs[gpu_index as usize]
    }
    pub(crate) fn gpu_index(&self, index: u32) -> u32 {
        self.gpu_indexes[index as usize]
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
            ptrs: vec![ptr; 1],
            lengths: vec![len; 1],
            gpu_indexes: vec![gpu_index; 1],
            _phantom_1: PhantomData,
            _phantom_2: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_mut_c_ptr(&mut self, gpu_index: u32) -> *mut c_void {
        self.ptrs[gpu_index as usize]
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_c_ptr(&self, gpu_index: u32) -> *const c_void {
        self.ptrs[gpu_index as usize].cast_const()
    }

    /// Copies data between two `CudaSlice`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required.
    pub unsafe fn copy_from_gpu_async(
        &mut self,
        src: &Self,
        streams: &CudaStreams,
        stream_index: u32,
    ) where
        T: Numeric,
    {
        assert_eq!(self.len(stream_index), src.len(stream_index));
        let size = src.len(stream_index) * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_gpu_to_gpu(
                self.as_mut_c_ptr(stream_index),
                src.as_c_ptr(stream_index),
                size as u64,
                streams.ptr[stream_index as usize],
                streams.gpu_indexes[stream_index as usize],
            );
        }
    }

    #[allow(dead_code)]
    /// Copies data of a `CudaSlice` to the CPU
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required.
    pub unsafe fn copy_to_cpu_async(&self, dest: &mut [T], streams: &CudaStreams, stream_index: u32)
    where
        T: Numeric,
    {
        assert_eq!(self.len(stream_index), dest.len());
        let size = self.len(stream_index) * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_to_cpu(
                dest.as_mut_ptr().cast::<c_void>(),
                self.as_c_ptr(stream_index),
                size as u64,
                streams.ptr[stream_index as usize],
                streams.gpu_indexes[stream_index as usize],
            );
        }
    }

    /// Returns the number of elements in the vector, also referred to as its ‘length’.
    pub fn len(&self, index: u32) -> usize {
        self.lengths[index as usize]
    }

    /// Returns true if the ptr is empty
    pub fn is_empty(&self, index: u32) -> bool {
        self.lengths[index as usize] == 0
    }

    pub(crate) fn get_mut<R>(&mut self, range: R, index: u32) -> Option<CudaSliceMut<T>>
    where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(index), range).into_inner();

        // Check the range is compatible with the vec
        if end <= start || end > self.lengths[index as usize] - 1 {
            None
        } else {
            // Shift ptr
            let shifted_ptr: *mut c_void =
                self.ptrs[index as usize].wrapping_byte_add(start * std::mem::size_of::<T>());

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe {
                CudaSliceMut::new(shifted_ptr, new_len, self.gpu_indexes[index as usize])
            })
        }
    }

    pub(crate) fn split_at_mut(
        &mut self,
        mid: usize,
        index: u32,
    ) -> (Option<CudaSliceMut<T>>, Option<CudaSliceMut<T>>)
    where
        T: Numeric,
    {
        // Check the index is compatible with the vec
        if mid > self.lengths[index as usize] - 1 {
            (None, None)
        } else if mid == 0 {
            (
                None,
                Some(unsafe {
                    CudaSliceMut::new(
                        self.ptrs[index as usize],
                        self.lengths[index as usize],
                        index,
                    )
                }),
            )
        } else if mid == self.lengths[index as usize] - 1 {
            (
                Some(unsafe {
                    CudaSliceMut::new(
                        self.ptrs[index as usize],
                        self.lengths[index as usize],
                        index,
                    )
                }),
                None,
            )
        } else {
            let new_len_1 = mid;
            let new_len_2 = self.lengths[index as usize] - mid;
            // Shift ptr
            let shifted_ptr: *mut c_void =
                self.ptrs[index as usize].wrapping_byte_add(mid * std::mem::size_of::<T>());

            // Create the slice
            (
                Some(unsafe { CudaSliceMut::new(self.ptrs[index as usize], new_len_1, index) }),
                Some(unsafe { CudaSliceMut::new(shifted_ptr, new_len_2, index) }),
            )
        }
    }
    pub(crate) fn gpu_index(&self, index: u32) -> u32 {
        self.gpu_indexes[index as usize]
    }
}
