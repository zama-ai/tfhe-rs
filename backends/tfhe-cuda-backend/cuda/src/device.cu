#include "device.h"
#include <cstdint>
#include <cuda_runtime.h>
#include <list>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#include <bits/this_thread_sleep.h>
#include <unordered_map>

uint32_t cuda_get_device() {
  int device;
  check_cuda_error(cudaGetDevice(&device));
  return static_cast<uint32_t>(device);
}

void cuda_set_device(uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
}

enum CudaMemBlockUsageType { ALLOC = 0, MEMSET, MEMCPY_SRC, MEMCPY_DEST, FREE };

struct CudaMemBlockUsage {
  std::string location;
  uint64_t timestamp;
  CudaMemBlockUsageType type;
};

struct CudaMemBlock {
  int8_t *ptr;
  uint64_t size;
  cudaStream_t stream;
  uint32_t gpu_index;
  size_t thread_id;
  std::vector<CudaMemBlockUsage> usages;
};

class CudaMemoryManager {
  std::list<CudaMemBlock> cuda_allocs;
  std::list<CudaMemBlock> cuda_freed;

  std::mutex allocs_mutex;

  std::string make_location(const char *file, int line) {
    std::stringstream sstr;
    sstr << file << ":" << line;
    return sstr.str();
  }
  uint64_t make_timestamp() {
    const std::chrono::time_point<std::chrono::system_clock> now =
        std::chrono::system_clock::now();

    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                  now.time_since_epoch())
                  .count() %
              1000000;
    return us;
  }

  void check_range_is_valid(CudaMemBlockUsageType usage_type, int8_t *dest,
                            uint64_t size, cudaStream_t stream,
                            const char *file, int line) {
    CudaMemBlockUsage usage = {make_location(file, line), make_timestamp(),
                               usage_type};

    const char *info = NULL;
    switch (usage_type) {
    case MEMSET:
      info = "memset";
      break;
    case MEMCPY_SRC:
      info = "memcpy source";
      break;
    case MEMCPY_DEST:
      info = "memcpy dest";
      break;
    default:
      info = "unknown";
    }

    auto device_id = cuda_get_device();

    bool found = false;
    for (auto it = cuda_allocs.begin(); it != cuda_allocs.end(); it++) {
      if (it->ptr == dest && it->gpu_index == device_id) {
        printf("%s with size tracking: found ptr %p\n", info, dest);
        if (size > it->size) {
          PANIC("%s OF %lu bytes TOO BIG TO %p OF SIZE %ld\n", info, size, dest,
                it->size);
        }
        it->usages.push_back(usage);
        found = true;
      } else {
        if (dest > it->ptr && dest < it->ptr + it->size &&
            it->gpu_index == device_id) {
          printf("%s with size tracking: indirect ptr %p in buffer %p\n", info,
                 dest, it->ptr);
          if (dest + size > it->ptr + it->size) {
            auto remain_bytes = it->ptr + it->size - dest;
            PANIC("%s OF %lu bytes TOO BIG TO %p WHICH HAS ROOM ONLY FOR %d\n",
                  info, size, dest, remain_bytes);
          }
          it->usages.push_back(usage);
          found = true;
        }
      }
    }
    if (!found) {
      PANIC("Cuda %s to %p of size %lu, unknown pointer", info, dest, size);
    }
  }

public:
  void alloc(int8_t *ptr, uint64_t size, cudaStream_t stream, const char *file,
             int line) {
    std::lock_guard<std::mutex> guard(allocs_mutex);

    if (ptr == nullptr) {
      if (size > 0) {
        PANIC("Allocation failed for %lu bytes, allocator returned %p", size,
              ptr);
      }
      return;
    }

    auto device_id = cuda_get_device();
    CudaMemBlockUsage usage = {make_location(file, line), make_timestamp(),
                               ALLOC};
    auto thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
    CudaMemBlock block = {ptr,       size,
                          stream,    device_id,
                          thread_id, std::vector<CudaMemBlockUsage>()};
    block.usages.push_back(usage);

    printf("Cuda Allocated %p of size %lu on gpu %d in %s\n", ptr, size,
           device_id, usage.location.c_str());

    cuda_allocs.push_back(block);
  }
  void memset(int8_t *dest, uint64_t size, cudaStream_t stream,
              const char *file, int line) {
    std::lock_guard<std::mutex> guard(allocs_mutex);

    check_range_is_valid(MEMSET, dest, size, stream, file, line);
  }

  void memcpy(int8_t *dest, int8_t *src, uint64_t size, cudaStream_t stream,
              const char *file, int line) {
    std::lock_guard<std::mutex> guard(allocs_mutex);

    check_range_is_valid(MEMCPY_SRC, src, size, stream, file, line);
    check_range_is_valid(MEMCPY_DEST, src, size, stream, file, line);
  }

  void free(int8_t *ptr, const char *file, int line) {
    std::lock_guard<std::mutex> guard(allocs_mutex);

    if (ptr == nullptr)
      return;

    auto device_id = cuda_get_device();

    bool found = false;
    for (auto it = cuda_allocs.begin(); it != cuda_allocs.end(); it++) {
      if (it->ptr == ptr && it->gpu_index == device_id) {
        found = true;
        cuda_freed.push_back(*it);
        cuda_allocs.erase(it++);
        printf("cuda dropped buffer %p of size %lu on gpu %d\n", ptr, it->size,
               device_id);
      }
    }

    if (!found) {
      for (auto it = cuda_freed.begin(); it != cuda_freed.end(); it++) {
        if (it->ptr == ptr && it->gpu_index == device_id) {
          found = true;
          printf("Drop in %s: %d\n", file, line);
          printf("Alloc in %s\n", it->usages[0].location.c_str());
          PANIC("cuda drop already dropped buffer %p of size %lu on gpu %d\n",
                ptr, it->size, device_id);
        }
      }
    }

    if (!found) {
      PANIC("cuda drop unknown buffer %p\n", ptr);
    }
  }
  ~CudaMemoryManager() {
    printf("%lu ALLOCATIONS AT PROGRAM EXIT\n", cuda_allocs.size());
    for (auto &cuda_alloc : cuda_allocs) {
      printf("%p of size %lu allocated at %s\n", cuda_alloc.ptr,
             cuda_alloc.size, cuda_alloc.usages[0].location.c_str());
    }
  }
};

CudaMemoryManager gCudaMemoryManager;

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

void synchronize_streams(cudaStream_t const *streams,
                         uint32_t const *gpu_indexes, uint32_t gpu_count) {
  for (uint i = 0; i < gpu_count; i++) {
    cuda_synchronize_stream(streams[i], gpu_indexes[i]);
  }
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
  gCudaMemoryManager.alloc((int8_t *)ptr, size, 0, "rust_code", 0);
  return ptr;
}

void *cuda_ext_malloc(uint64_t size, uint32_t gpu_index) {
  return cuda_malloc(size, gpu_index);
}

/// Allocates a size-byte array at the device memory. Tries to do it
/// asynchronously.
void *cuda_intern_malloc_with_size_tracking_async(uint64_t size,
                                                  cudaStream_t stream,
                                                  uint32_t gpu_index,
                                                  uint64_t &size_tracker,
                                                  bool allocate_gpu_memory,
                                                  const char *file, int line) {
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
  gCudaMemoryManager.alloc((int8_t *)ptr, size, stream, file, line);
  return ptr;
}

/// Allocates a size-byte array at the device memory. Tries to do it
/// asynchronously.
void *cuda_int_malloc_async(uint64_t size, cudaStream_t stream,
                            uint32_t gpu_index, const char *file, int line) {
  uint64_t size_tracker = 0;
  return cuda_intern_malloc_with_size_tracking_async(
      size, stream, gpu_index, size_tracker, true, file, line);
}

void *cuda_ext_malloc_async(uint64_t size, cudaStream_t stream,
                            uint32_t gpu_index) {
  return cuda_malloc_async(size, stream, gpu_index);
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

/// Copy memory to the GPU asynchronously
void cuda_memcpy_with_size_tracking_async_to_gpu(void *dest, const void *src,
                                                 uint64_t size,
                                                 cudaStream_t stream,
                                                 uint32_t gpu_index,
                                                 bool gpu_memory_allocated) {
  if (size == 0 || !gpu_memory_allocated)
    return;
  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, dest));
  if (attr.device != gpu_index && attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid device pointer in async copy to GPU.")
  }

  cuda_set_device(gpu_index);
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyHostToDevice, stream));
}

/// Copy memory to the GPU asynchronously
void cuda_memcpy_async_to_gpu(void *dest, const void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index) {
  cuda_memcpy_with_size_tracking_async_to_gpu(dest, src, size, stream,
                                              gpu_index, true);
}

void cuda_ext_memcpy_async_to_gpu(void *dest, const void *src, uint64_t size,
                                  cudaStream_t stream, uint32_t gpu_index) {
  cuda_memcpy_async_to_gpu(dest, src, size, stream, gpu_index);
}

/// Copy memory within a GPU asynchronously
void cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
    void *dest, void const *src, uint64_t size, cudaStream_t stream,
    uint32_t gpu_index, bool gpu_memory_allocated) {
  if (size == 0 || !gpu_memory_allocated)
    return;
  cudaPointerAttributes attr_dest;
  check_cuda_error(cudaPointerGetAttributes(&attr_dest, dest));
  if (attr_dest.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid dest device pointer in copy from GPU to GPU.")
  }
  cudaPointerAttributes attr_src;
  check_cuda_error(cudaPointerGetAttributes(&attr_src, src));
  if (attr_src.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid src device pointer in copy from GPU to GPU.")
  }
  cuda_set_device(gpu_index);
  if (attr_src.device == attr_dest.device) {
    check_cuda_error(
        cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToDevice, stream));
  } else {
    check_cuda_error(cudaMemcpyPeerAsync(dest, attr_dest.device, src,
                                         attr_src.device, size, stream));
  }
}
void cuda_memcpy_async_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                                  cudaStream_t stream, uint32_t gpu_index) {

  cuda_memcpy_with_size_tracking_async_gpu_to_gpu(dest, src, size, stream,
                                                  gpu_index, true);
}

void cuda_ext_memcpy_async_gpu_to_gpu(void *dest, void const *src,
                                      uint64_t size, cudaStream_t stream,
                                      uint32_t gpu_index) {
  cuda_memcpy_async_gpu_to_gpu(dest, src, size, stream, gpu_index);
}

/// Copy memory within a GPU
void cuda_memcpy_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                            uint32_t gpu_index) {
  if (size == 0)
    return;
  cudaPointerAttributes attr_dest;
  check_cuda_error(cudaPointerGetAttributes(&attr_dest, dest));
  if (attr_dest.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid dest device pointer in copy from GPU to GPU.")
  }
  cudaPointerAttributes attr_src;
  check_cuda_error(cudaPointerGetAttributes(&attr_src, src));
  if (attr_src.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid src device pointer in copy from GPU to GPU.")
  }
  cuda_set_device(gpu_index);
  if (attr_src.device == attr_dest.device) {
    check_cuda_error(cudaMemcpy(dest, src, size, cudaMemcpyDeviceToDevice));
  } else {
    check_cuda_error(
        cudaMemcpyPeer(dest, attr_dest.device, src, attr_src.device, size));
  }
}

void cuda_ext_memcpy_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                                uint32_t gpu_index) {
  cuda_memcpy_gpu_to_gpu(dest, src, size, gpu_index);
}

/// Synchronizes device
void cuda_synchronize_device(uint32_t gpu_index) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaDeviceSynchronize());
}

void cuda_memset_with_size_tracking_async(void *dest, uint64_t val,
                                          uint64_t size, cudaStream_t stream,
                                          uint32_t gpu_index,
                                          bool gpu_memory_allocated) {
  if (size == 0 || !gpu_memory_allocated)
    return;
  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, dest));
  if (attr.device != gpu_index && attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid dest device pointer in cuda memset.")
  }
  cuda_set_device(gpu_index);
  check_cuda_error(cudaMemsetAsync(dest, val, size, stream));
  gCudaMemoryManager.memset((int8_t *)dest, size, stream, "", 0);
}

void cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                       cudaStream_t stream, uint32_t gpu_index) {
  cuda_memset_with_size_tracking_async(dest, val, size, stream, gpu_index,
                                       true);
}

void cuda_ext_memset_async(void *dest, uint64_t val, uint64_t size,
                           cudaStream_t stream, uint32_t gpu_index) {
  cuda_memset_async(dest, val, size, stream, gpu_index);
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
    int num_blocks = (n + block_size - 1) / block_size;

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
void cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index) {
  if (size == 0)
    return;
  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, src));
  if (attr.device != gpu_index && attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid src device pointer in copy to CPU async.")
  }

  cuda_set_device(gpu_index);
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToHost, stream));
}

void cuda_ext_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                                  cudaStream_t stream, uint32_t gpu_index) {
  cuda_memcpy_async_to_cpu(dest, src, size, stream, gpu_index);
}

/// Return number of GPUs available
int cuda_get_number_of_gpus() {
  int num_gpus;
  check_cuda_error(cudaGetDeviceCount(&num_gpus));
  return num_gpus;
}

/// Drop a cuda array
void cuda_int_drop(void *ptr, uint32_t gpu_index, const char *file, int line) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaFree(ptr));
  gCudaMemoryManager.free((int8_t *)ptr, file, line);
}

void cuda_ext_drop(void *ptr, uint32_t gpu_index) { cuda_drop(ptr, gpu_index); }

/// Drop a cuda array asynchronously, if the data was allocated & it's supported
/// on the device
void cuda_int_drop_with_size_tracking_async(void *ptr, cudaStream_t stream,
                                            uint32_t gpu_index,
                                            bool gpu_memory_allocated,
                                            const char *file, int line) {

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
  gCudaMemoryManager.free((int8_t *)ptr, file, line);
}

/// Drop a cuda array asynchronously, if supported on the device
void cuda_int_drop_async(void *ptr, cudaStream_t stream, uint32_t gpu_index,
                         const char *file, int line) {
  cuda_int_drop_with_size_tracking_async(ptr, stream, gpu_index, true, file,
                                         line);
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
