use std::ffi::c_void;

#[link(name = "tfhe_cuda_backend", kind = "static")]
extern "C" {

    pub fn cuda_create_stream(gpu_index: u32) -> *mut c_void;

    pub fn cuda_destroy_stream(stream: *mut c_void, gpu_index: u32);

    pub fn cuda_synchronize_stream(stream: *mut c_void, gpu_index: u32);

    pub fn cuda_is_available() -> u32;

    pub fn cuda_malloc(size: u64, gpu_index: u32) -> *mut c_void;

    pub fn cuda_malloc_async(size: u64, stream: *mut c_void, gpu_index: u32) -> *mut c_void;
    pub fn cuda_check_valid_malloc(size: u64, gpu_index: u32) -> bool;
    pub fn cuda_device_total_memory(gpu_index: u32) -> u64;

    pub fn cuda_memcpy_async_to_gpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_memcpy_gpu_to_gpu(dest: *mut c_void, src: *const c_void, size: u64, gpu_index: u32);

    pub fn cuda_memcpy_async_gpu_to_gpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_memcpy_async_to_cpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_memset_async(
        dest: *mut c_void,
        val: u64,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_get_number_of_gpus() -> i32;

    pub fn cuda_get_number_of_sms() -> i32;

    pub fn cuda_synchronize_device(gpu_index: u32);

    pub fn cuda_drop(ptr: *mut c_void, gpu_index: u32);

} // extern "C"

/// Single CUDA stream handle with automatic cleanup.
///
/// Wraps a `cudaStream_t` (opaque `*mut c_void`) and the GPU index it belongs to.
/// The stream is destroyed on drop.
pub struct CudaStream {
    ptr: *mut c_void,
    gpu_index: u32,
}

// SAFETY: CUDA stream handles are safe to use from any host thread for
// submission. The CUDA runtime serializes operations enqueued on the same
// stream regardless of which host thread submits them.
unsafe impl Send for CudaStream {}
unsafe impl Sync for CudaStream {}

impl CudaStream {
    pub fn new(gpu_index: u32) -> Self {
        // SAFETY: gpu_index must refer to a valid CUDA device. The caller is
        // responsible for ensuring the device ordinal is in range (upstream code
        // validates via cuda_get_number_of_gpus).
        let ptr = unsafe { cuda_create_stream(gpu_index) };
        assert!(
            !ptr.is_null(),
            "cuda_create_stream returned null for gpu_index {gpu_index}"
        );
        Self { ptr, gpu_index }
    }

    pub fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn gpu_index(&self) -> u32 {
        self.gpu_index
    }
}

impl std::fmt::Debug for CudaStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CudaStream")
            .field("gpu_index", &self.gpu_index)
            .field("ptr", &self.ptr)
            .finish()
    }
}

impl Drop for CudaStream {
    fn drop(&mut self) {
        // SAFETY: self.ptr was allocated by cuda_create_stream in new().
        unsafe { cuda_destroy_stream(self.ptr, self.gpu_index) };
    }
}
