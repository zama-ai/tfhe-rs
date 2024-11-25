use std::ffi::c_void;

#[link(name = "tfhe_cuda_backend", kind = "static")]
extern "C" {

    pub fn cuda_create_stream(gpu_index: u32) -> *mut c_void;

    pub fn cuda_destroy_stream(stream: *mut c_void, gpu_index: u32);

    pub fn cuda_synchronize_stream(stream: *mut c_void, gpu_index: u32);

    pub fn cuda_is_available() -> u32;

    pub fn cuda_malloc(size: u64, gpu_index: u32) -> *mut c_void;

    pub fn cuda_malloc_async(size: u64, stream: *mut c_void, gpu_index: u32) -> *mut c_void;

    pub fn cuda_check_valid_malloc(size: u64, gpu_index: u32);

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

    pub fn cuda_synchronize_device(gpu_index: u32);

    pub fn cuda_drop(ptr: *mut c_void, gpu_index: u32);

    pub fn cuda_drop_async(ptr: *mut c_void, stream: *mut c_void, gpu_index: u32);

    pub fn cuda_setup_multi_gpu() -> i32;

} // extern "C"
