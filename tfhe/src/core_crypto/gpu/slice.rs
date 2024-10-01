use crate::core_crypto::gpu::vec::{range_bounds_to_start_end, GpuIndex};
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::Numeric;
use std::ffi::c_void;
use std::marker::PhantomData;
use tfhe_cuda_backend::cuda_bind::{cuda_memcpy_async_gpu_to_gpu, cuda_memcpy_async_to_cpu};

#[derive(Debug, Clone)]
pub struct CudaSlice<'a, T: Numeric> {
    ptrs: Vec<*const c_void>,
    _lengths: Vec<usize>,
    gpu_indexes: Vec<GpuIndex>,
    _phantom_1: PhantomData<T>,
    _phantom_2: PhantomData<&'a ()>,
}

#[derive(Debug)]
pub struct CudaSliceMut<'a, T: Numeric> {
    ptrs: Vec<*mut c_void>,
    lengths: Vec<usize>,
    gpu_indexes: Vec<GpuIndex>,
    _phantom_1: PhantomData<T>,
    _phantom_2: PhantomData<&'a mut ()>,
}

impl<T> CudaSlice<'_, T>
where
    T: Numeric,
{
    /// # Safety
    ///
    /// The ptr must be valid for reads for len * std::mem::size_of::<T> bytes on
    /// the cuda side.
    pub(crate) unsafe fn new(ptr: *const c_void, len: usize, gpu_index: GpuIndex) -> Self {
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
    pub(crate) unsafe fn as_c_ptr(&self, index: usize) -> *const c_void {
        self.ptrs[index]
    }
    pub(crate) fn gpu_index(&self, index: usize) -> GpuIndex {
        self.gpu_indexes[index]
    }
}

impl<T> CudaSliceMut<'_, T>
where
    T: Numeric,
{
    /// # Safety
    ///
    /// The ptr must be valid for reads and writes for len * std::mem::size_of::<T> bytes on
    /// the cuda side.
    pub(crate) unsafe fn new(ptr: *mut c_void, len: usize, gpu_index: GpuIndex) -> Self {
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
    pub(crate) unsafe fn as_mut_c_ptr(&mut self, index: usize) -> *mut c_void {
        self.ptrs[index]
    }

    /// # Safety
    ///
    /// The caller must ensure that the slice outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    pub(crate) unsafe fn as_c_ptr(&self, index: usize) -> *const c_void {
        self.ptrs[index].cast_const()
    }

    /// Copies data between two `CudaSlice`
    ///
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after the copy as soon as synchronization is
    ///   required.
    pub unsafe fn copy_from_gpu_async(&mut self, src: &Self, streams: &CudaStreams, index: usize)
    where
        T: Numeric,
    {
        assert_eq!(self.len(index), src.len(index));
        let size = src.len(index) * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_gpu_to_gpu(
                self.as_mut_c_ptr(index),
                src.as_c_ptr(index),
                size as u64,
                streams.ptr[index],
                streams.gpu_indexes[index].0,
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
    pub unsafe fn copy_to_cpu_async(&self, dest: &mut [T], streams: &CudaStreams, index: usize)
    where
        T: Numeric,
    {
        assert_eq!(self.len(index), dest.len());
        let size = self.len(index) * std::mem::size_of::<T>();
        // We check that src is not empty to avoid invalid pointers
        if size > 0 {
            cuda_memcpy_async_to_cpu(
                dest.as_mut_ptr().cast::<c_void>(),
                self.as_c_ptr(index),
                size as u64,
                streams.ptr[index],
                streams.gpu_indexes[index].0,
            );
        }
    }

    /// Returns the number of elements in the vector, also referred to as its ‘length’.
    pub fn len(&self, index: usize) -> usize {
        self.lengths[index]
    }

    /// Returns true if the ptr is empty
    pub fn is_empty(&self, index: usize) -> bool {
        self.lengths[index] == 0
    }

    pub(crate) fn get_mut<R>(&mut self, range: R, index: usize) -> Option<CudaSliceMut<T>>
    where
        R: std::ops::RangeBounds<usize>,
        T: Numeric,
    {
        let (start, end) = range_bounds_to_start_end(self.len(index), range).into_inner();

        // Check the range is compatible with the vec
        if end <= start || end > self.lengths[index] - 1 {
            None
        } else {
            // Shift ptr
            let shifted_ptr: *mut c_void =
                self.ptrs[index].wrapping_byte_add(start * std::mem::size_of::<T>());

            // Compute the length
            let new_len = end - start + 1;

            // Create the slice
            Some(unsafe { CudaSliceMut::new(shifted_ptr, new_len, self.gpu_indexes[index]) })
        }
    }

    pub(crate) fn split_at_mut(
        &mut self,
        mid: usize,
        index: usize,
    ) -> (Option<CudaSliceMut<T>>, Option<CudaSliceMut<T>>)
    where
        T: Numeric,
    {
        // Check the index is compatible with the vec
        if mid > self.lengths[index] - 1 {
            (None, None)
        } else if mid == 0 {
            (
                None,
                Some(unsafe {
                    CudaSliceMut::new(
                        self.ptrs[index],
                        self.lengths[index],
                        self.gpu_indexes[index],
                    )
                }),
            )
        } else if mid == self.lengths[index] - 1 {
            (
                Some(unsafe {
                    CudaSliceMut::new(
                        self.ptrs[index],
                        self.lengths[index],
                        self.gpu_indexes[index],
                    )
                }),
                None,
            )
        } else {
            let new_len_1 = mid;
            let new_len_2 = self.lengths[index] - mid;
            // Shift ptr
            let shifted_ptr: *mut c_void =
                self.ptrs[index].wrapping_byte_add(mid * std::mem::size_of::<T>());

            // Create the slice
            (
                Some(unsafe {
                    CudaSliceMut::new(self.ptrs[index], new_len_1, self.gpu_indexes[index])
                }),
                Some(unsafe { CudaSliceMut::new(shifted_ptr, new_len_2, self.gpu_indexes[index]) }),
            )
        }
    }
    pub(crate) fn gpu_index(&self, index: usize) -> GpuIndex {
        self.gpu_indexes[index]
    }
}
