#include "device.h"
#include "utils/helper.cuh"
#include <cstdint>
#include <cuda_runtime.h>
#include <mutex>
#ifdef USE_NVTOOLS
#include <cuda_profiler_api.h>
#endif

void validate_device_ptr_and_gpu_index(const void *ptr, uint32_t gpu_index) {
  GPU_ASSERT(ptr != nullptr, "Cuda error: null device ptr");

  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, ptr));
  if (attr.device != gpu_index || attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid device pointer.")
  }
}

int validate_device_ptr(const void *ptr) {
  GPU_ASSERT(ptr != nullptr, "Cuda error: null device ptr");

  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, ptr));
  if (attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid device pointer.")
  }
  return attr.device;
}

uint32_t cuda_get_device() {
  int device;
  check_cuda_error(cudaGetDevice(&device));
  return static_cast<uint32_t>(device);
}
std::mutex pool_mutex;
bool mem_pools_enabled = false;

// We use memory pools to reduce some overhead of memory allocations due
// to our scratch/release pattern. This function is the simplest way of using
// mempools, it modifies the default memory pool to use a threshold of 5% of the
// free memory:
//  - Enabled opportunistic reuse to maximize reuse in malloc/free patterns
//  - Prevent memory from being released back to the OS too soon if is within
//  our threshold
//  - Warm up the pool by allocating and freeing a large block of memory
// This function is called only once, the first time a GPU is set, and it
// configures all the GPUs available.
// We have measured an improvement of around 10% in our integer operations,
// especially the ones involving many allocations.
// We tested more complex configurations of mempools, but they did not yield
// better results.
void cuda_setup_mempool(uint32_t caller_gpu_index) {
  if (!mem_pools_enabled) {
    std::lock_guard lock(pool_mutex);
    if (mem_pools_enabled) // double-check - mem_pools_enabled might have been
                           // changed in a different thread
      return; // If mem pools are already enabled, we don't need to do anything

    // We do it only once for all GPUs
    mem_pools_enabled = true;
    uint32_t num_gpus = cuda_get_number_of_gpus();
    for (uint32_t gpu_index = 0; gpu_index < num_gpus; gpu_index++) {
      cuda_set_device(gpu_index);

      size_t total_mem, free_mem;
      check_cuda_error(cudaMemGetInfo(&free_mem, &total_mem));

      // If we have more than 5% of free memory, we can set up the mempool
      uint64_t mem_pool_threshold = total_mem / 20; // 5% of total memory
      mem_pool_threshold =
          mem_pool_threshold - (mem_pool_threshold % 1024); // Align to 1KB
      if (mem_pool_threshold < free_mem) {
        // Get default memory pool
        cudaMemPool_t default_pool;
        check_cuda_error(cudaDeviceGetDefaultMemPool(&default_pool, gpu_index));

        // Enable opportunistic reuse
        int reuse = 1;
        check_cuda_error(cudaMemPoolSetAttribute(
            default_pool, cudaMemPoolReuseAllowOpportunistic, &reuse));

        // Prevent memory from being released back to the OS too soon
        check_cuda_error(cudaMemPoolSetAttribute(
            default_pool, cudaMemPoolAttrReleaseThreshold,
            &mem_pool_threshold));

        // Warm up the pool by allocating and freeing a large block
        cudaStream_t stream;
        stream = cuda_create_stream(gpu_index);
        void *warmup_ptr = nullptr;
        warmup_ptr = cuda_malloc_async(mem_pool_threshold, stream, gpu_index);
        cuda_drop_async(warmup_ptr, stream, gpu_index);

        // Sync to ensure pool is grown
        cuda_synchronize_stream(stream, gpu_index);

        // Clean up
        cuda_destroy_stream(stream, gpu_index);
      }
    }
    // We return to the original gpu_index
    cuda_set_device(caller_gpu_index);
  }
}

void cuda_set_device(uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
  // Mempools are initialized only once in all the GPUS available
  cuda_setup_mempool(gpu_index);
#ifdef USE_NVTOOLS
  check_cuda_error(cudaProfilerStart());
#endif
}

cudaEvent_t cuda_create_event(uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  cudaEvent_t event;
  check_cuda_error(cudaEventCreate(&event));
  return event;
}

void cuda_event_record(cudaEvent_t event, cudaStream_t stream,
                       uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaEventRecord(event, stream));
}

void cuda_stream_wait_event(cudaStream_t stream, cudaEvent_t event,
                            uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaStreamWaitEvent(stream, event, 0));
}

void cuda_event_destroy(cudaEvent_t event, uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaEventDestroy(event));
}

/// Unsafe function to create a CUDA stream, must check first that GPU exists
cudaStream_t cuda_create_stream(uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  cudaStream_t stream;
  check_cuda_error(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking));
  return stream;
}

/// Unsafe function to destroy CUDA stream, must check first the GPU exists
void cuda_destroy_stream(cudaStream_t stream, uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaStreamDestroy(stream));
}

void cuda_synchronize_stream(cudaStream_t stream, uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaStreamSynchronize(stream));
}

// Determine if a CUDA device is available at runtime
uint32_t cuda_is_available() { return cudaSetDevice(0) == cudaSuccess; }

/// Unsafe function that will try to allocate even if gpu_index is invalid
/// or if there's not enough memory. A safe wrapper around it must call
/// cuda_check_valid_malloc() first
void *cuda_malloc(uint64_t size, uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  void *ptr;
  check_cuda_error(cudaMalloc((void **)&ptr, size));

  return ptr;
}

/// Allocates a size-byte array at the device memory. Tries to do it
/// asynchronously.
void *cuda_malloc_with_size_tracking_async(uint64_t size, cudaStream_t stream,
                                           uint32_t gpu_index,
                                           uint64_t &size_tracker,
                                           bool allocate_gpu_memory) {
  size_tracker += size;
  void *ptr = nullptr;
  if (!allocate_gpu_memory)
    return ptr;

  cuda_set_device(gpu_index);

#ifndef CUDART_VERSION
#error CUDART_VERSION Undefined!
#elif (CUDART_VERSION >= 11020)
  int support_async_alloc;
  check_cuda_error(cudaDeviceGetAttribute(
      &support_async_alloc, cudaDevAttrMemoryPoolsSupported, gpu_index));

  if (support_async_alloc) {
    check_cuda_error(cudaMallocAsync((void **)&ptr, size, stream));
  } else {
    check_cuda_error(cudaMalloc((void **)&ptr, size));
  }
#else
  check_cuda_error(cudaMalloc((void **)&ptr, size));
#endif
  return ptr;
}

/// Allocates a size-byte array at the device memory. Tries to do it
/// asynchronously.
void *cuda_malloc_async(uint64_t size, cudaStream_t stream,
                        uint32_t gpu_index) {
  uint64_t size_tracker = 0;
  return cuda_malloc_with_size_tracking_async(size, stream, gpu_index,
                                              size_tracker, true);
}

/// Check that allocation is valid
bool cuda_check_valid_malloc(uint64_t size, uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  size_t total_mem, free_mem;
  check_cuda_error(cudaMemGetInfo(&free_mem, &total_mem));
  if (size > free_mem) {
    return false;
  } else {
    return true;
  }
}

uint64_t cuda_device_total_memory(uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  size_t total_mem = 0, free_mem = 0;
  check_cuda_error(cudaMemGetInfo(&free_mem, &total_mem));
  return total_mem;
}

/// Returns
///  false if Cooperative Groups is not supported.
///  true otherwise
bool cuda_check_support_cooperative_groups() {
  int cooperative_groups_supported = 0;
  check_cuda_error(cudaDeviceGetAttribute(&cooperative_groups_supported,
                                          cudaDevAttrCooperativeLaunch, 0));

  return cooperative_groups_supported > 0;
}

/// Returns
///  false if Thread Block Cluster is not supported.
///  true otherwise
bool cuda_check_support_thread_block_clusters() {
#if CUDA_ARCH >= 900
  // To-do: Is this really the best way to check support?
  int tbc_supported = 0;
  check_cuda_error(
      cudaDeviceGetAttribute(&tbc_supported, cudaDevAttrClusterLaunch, 0));

  return tbc_supported > 0;
#else
  return false;
#endif
}

/// Copy memory from the CPU to a GPU with size tracking.
/// This copy is asynchronous only if the CPU memory was pinned, i.e.
/// allocated using cudaMallocHost. This was shown to come with a performance
/// penalty if we allocate all CPU data in this way in the backend, so
/// cudaMallocHost is only used in specific places where we need an
/// asynchronous data copy from the CPU to all the GPUs simultaneously (for
/// example to copy the bootstrapping key).
/// The copy only happens if gpu_memory_allocated is true.
void cuda_memcpy_with_size_tracking_async_to_gpu(void *dest, const void *src,
                                                 uint64_t size,
                                                 cudaStream_t stream,
                                                 uint32_t gpu_index,
                                                 bool gpu_memory_allocated) {

  GPU_ASSERT(src != nullptr, "Cuda error: null device ptr");

  if (size == 0 || !gpu_memory_allocated)
    return;
  validate_device_ptr_and_gpu_index(dest, gpu_index);

  cuda_set_device(gpu_index);
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyHostToDevice, stream));
}

/// Copy memory from the CPU to a GPU.
/// This copy is asynchronous only if the CPU memory was pinned, i.e.
/// allocated using cudaMallocHost. This was shown to come with a performance
/// penalty if we allocate all CPU data in this way in the backend, so
/// cudaMallocHost is only used in specific places where we need an
/// asynchronous data copy from the CPU to all the GPUs simultaneously (for
/// example to copy the bootstrapping key).
void cuda_memcpy_async_to_gpu(void *dest, const void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index) {
  cuda_memcpy_with_size_tracking_async_to_gpu(dest, src, size, stream,
                                              gpu_index, true);
}

/// Copy memory within a GPU asynchronously.
/// The copy only happens if gpu_memory_allocated is true
void cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
    void *dest, void const *src, uint64_t size, cudaStream_t stream,
    uint32_t gpu_index, bool gpu_memory_allocated) {
  if (size == 0 || !gpu_memory_allocated)
    return;

  int src_gpu_index = validate_device_ptr(src);
  int dest_gpu_index = validate_device_ptr(dest);
  cuda_set_device(gpu_index);
  if (src_gpu_index == dest_gpu_index) {
    check_cuda_error(
        cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToDevice, stream));
  } else {
    check_cuda_error(cudaMemcpyPeerAsync(dest, dest_gpu_index, src,
                                         src_gpu_index, size, stream));
  }
}
void cuda_memcpy_async_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                                  cudaStream_t stream, uint32_t gpu_index) {

  cuda_memcpy_with_size_tracking_async_gpu_to_gpu(dest, src, size, stream,
                                                  gpu_index, true);
}

/// Copy memory within a GPU
void cuda_memcpy_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                            uint32_t gpu_index) {
  if (size == 0)
    return;
  cudaPointerAttributes attr_dest;
  check_cuda_error(cudaPointerGetAttributes(&attr_dest, dest));
  PANIC_IF_FALSE(
      attr_dest.type == cudaMemoryTypeDevice,
      "Cuda error: invalid dest device pointer in copy from GPU to GPU.");
  cudaPointerAttributes attr_src;
  check_cuda_error(cudaPointerGetAttributes(&attr_src, src));
  PANIC_IF_FALSE(
      attr_src.type == cudaMemoryTypeDevice,
      "Cuda error: invalid src device pointer in copy from GPU to GPU.");
  cuda_set_device(gpu_index);
  if (attr_src.device == attr_dest.device) {
    check_cuda_error(cudaMemcpy(dest, src, size, cudaMemcpyDeviceToDevice));
  } else {
    check_cuda_error(
        cudaMemcpyPeer(dest, attr_dest.device, src, attr_src.device, size));
  }
}

/// Synchronizes device
void cuda_synchronize_device(uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaDeviceSynchronize());
}

/// cuda_memset sets bytes, we basically only use it to initialize data to 0
/// The memset only happens if gpu_memory_allocated is true
void cuda_memset_with_size_tracking_async(void *dest, uint64_t val,
                                          uint64_t size, cudaStream_t stream,
                                          uint32_t gpu_index,
                                          bool gpu_memory_allocated) {
  if (size == 0 || !gpu_memory_allocated)
    return;
  validate_device_ptr_and_gpu_index(dest, gpu_index);
  cuda_set_device(gpu_index);
  check_cuda_error(cudaMemsetAsync(dest, val, size, stream));
}

/// cuda_memset sets bytes, we basically only use it to initialize data to 0
void cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                       cudaStream_t stream, uint32_t gpu_index) {
  cuda_memset_with_size_tracking_async(dest, val, size, stream, gpu_index,
                                       true);
}

template <typename Torus>
__global__ void cuda_set_value_kernel(Torus *array, Torus value, Torus n) {
  int index = threadIdx.x + blockIdx.x * blockDim.x;
  if (index < n)
    array[index] = value;
}

template <typename Torus>
void cuda_set_value_async(cudaStream_t stream, uint32_t gpu_index,
                          Torus *d_array, Torus value, Torus n) {
  if (n > 0) {
    cudaPointerAttributes attr;
    check_cuda_error(cudaPointerGetAttributes(&attr, d_array));
    if (attr.type != cudaMemoryTypeDevice) {
      PANIC("Cuda error: invalid dest device pointer in cuda set value.")
    }
    cuda_set_device(gpu_index);
    int block_size = 256;
    int num_blocks = CEIL_DIV(n, block_size);

    // Launch the kernel
    cuda_set_value_kernel<Torus>
        <<<num_blocks, block_size, 0, stream>>>(d_array, value, n);
    check_cuda_error(cudaGetLastError());
  }
}

/// Explicitly instantiate cuda_set_value_async for 32 and 64 bits
template void cuda_set_value_async(cudaStream_t stream, uint32_t gpu_index,
                                   uint64_t *d_array, uint64_t value,
                                   uint64_t n);
template void cuda_set_value_async(cudaStream_t stream, uint32_t gpu_index,
                                   uint32_t *d_array, uint32_t value,
                                   uint32_t n);

/// Copy memory to the CPU asynchronously
/// This comes with a big penalty on performance even if the CPU
/// memory is pinned (using cudaMallocHost for the CPU allocation),
/// so it should be avoided at all costs
void cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index) {
  GPU_ASSERT(dest != nullptr, "Cuda error: null host ptr");
  if (size == 0)
    return;
  validate_device_ptr_and_gpu_index(src, gpu_index);

  cuda_set_device(gpu_index);
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToHost, stream));
}

/// Return number of GPUs available
int cuda_get_number_of_gpus() {
  int num_gpus;
  check_cuda_error(cudaGetDeviceCount(&num_gpus));
  return num_gpus;
}

int cuda_get_number_of_sms() {
  int num_sms = 0;
  check_cuda_error(
      cudaDeviceGetAttribute(&num_sms, cudaDevAttrMultiProcessorCount, 0));
  return num_sms;
}

/// Drop a cuda array
void cuda_drop(void *ptr, uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaFree(ptr));
}

/// Drop a cuda array asynchronously, if the data was allocated & it's supported
/// on the device
void cuda_drop_with_size_tracking_async(void *ptr, cudaStream_t stream,
                                        uint32_t gpu_index,
                                        bool gpu_memory_allocated) {

  if (!gpu_memory_allocated)
    return;
  cuda_set_device(gpu_index);
#ifndef CUDART_VERSION
#error CUDART_VERSION Undefined!
#elif (CUDART_VERSION >= 11020)
  int support_async_alloc;
  check_cuda_error(cudaDeviceGetAttribute(
      &support_async_alloc, cudaDevAttrMemoryPoolsSupported, gpu_index));

  if (support_async_alloc) {
    check_cuda_error(cudaFreeAsync(ptr, stream));
  } else {
    check_cuda_error(cudaFree(ptr));
  }
#else
  check_cuda_error(cudaFree(ptr));
#endif
}

/// Drop a cuda array asynchronously, if supported on the device
void cuda_drop_async(void *ptr, cudaStream_t stream, uint32_t gpu_index) {
  cuda_drop_with_size_tracking_async(ptr, stream, gpu_index, true);
}

/// Get the maximum size for the shared memory per streaming multiprocessors
uint32_t cuda_get_max_shared_memory(uint32_t gpu_index) {
  auto max_shared_memory = 0;
#if CUDA_ARCH == 900
  max_shared_memory = 226000;
#elif CUDA_ARCH == 890
  max_shared_memory = 100000;
#elif CUDA_ARCH == 860
  max_shared_memory = 100000;
#elif CUDA_ARCH == 800
  max_shared_memory = 163000;
#elif CUDA_ARCH == 700
  max_shared_memory = 95000;
#else
  cudaDeviceGetAttribute(&max_shared_memory,
                         cudaDevAttrMaxSharedMemoryPerMultiprocessor,
                         gpu_index);
  check_cuda_error(cudaGetLastError());
#endif
  return (uint32_t)(max_shared_memory);
}

/// Get the maximum size for the shared memory per block
uint32_t cuda_get_max_shared_memory_per_block(uint32_t gpu_index) {
  int max_shared_memory_per_block = 0;
  cuda_set_device(gpu_index);
  check_cuda_error(cudaDeviceGetAttribute(&max_shared_memory_per_block,
                                          cudaDevAttrMaxSharedMemoryPerBlock,
                                          gpu_index));
  return static_cast<uint32_t>(max_shared_memory_per_block);
}
