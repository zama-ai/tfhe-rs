#include "device.h"
#include <cstdint>
#include <cuda_runtime.h>

/// Unsafe function to create a CUDA stream, must check first that GPU exists
cuda_stream_t *cuda_create_stream(uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
  cuda_stream_t *stream = new cuda_stream_t(gpu_index);
  return stream;
}

/// Unsafe function to destroy CUDA stream, must check first the GPU exists
void cuda_destroy_stream(cuda_stream_t *stream) { stream->release(); }

/// Unsafe function that will try to allocate even if gpu_index is invalid
/// or if there's not enough memory. A safe wrapper around it must call
/// cuda_check_valid_malloc() first
void *cuda_malloc(uint64_t size, uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
  void *ptr;
  check_cuda_error(cudaMalloc((void **)&ptr, size));

  return ptr;
}

/// Allocates a size-byte array at the device memory. Tries to do it
/// asynchronously.
void *cuda_malloc_async(uint64_t size, cuda_stream_t *stream) {
  check_cuda_error(cudaSetDevice(stream->gpu_index));
  void *ptr;

#ifndef CUDART_VERSION
#error CUDART_VERSION Undefined!
#elif (CUDART_VERSION >= 11020)
  int support_async_alloc;
  check_cuda_error(cudaDeviceGetAttribute(&support_async_alloc,
                                          cudaDevAttrMemoryPoolsSupported,
                                          stream->gpu_index));

  if (support_async_alloc) {
    check_cuda_error(cudaMallocAsync((void **)&ptr, size, stream->stream));
  } else {
    check_cuda_error(cudaMalloc((void **)&ptr, size));
  }
#else
  check_cuda_error(cudaMalloc((void **)&ptr, size));
#endif
  return ptr;
}

/// Check that allocation is valid
void cuda_check_valid_malloc(uint64_t size, uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
  size_t total_mem, free_mem;
  check_cuda_error(cudaMemGetInfo(&free_mem, &total_mem));
  if (size > free_mem) {
    PANIC("Cuda error: not enough memory on device. "
          "Available: %zu vs Requested: %lu",
          free_mem, size)
  }
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

/// Copy memory to the GPU asynchronously
void cuda_memcpy_async_to_gpu(void *dest, void *src, uint64_t size,
                              cuda_stream_t *stream) {
  if (size == 0)
    return;
  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, dest));
  if (attr.device != stream->gpu_index && attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid device pointer in async copy to GPU.")
  }

  check_cuda_error(cudaSetDevice(stream->gpu_index));
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyHostToDevice, stream->stream));
}

/// Copy memory within a GPU asynchronously
void cuda_memcpy_async_gpu_to_gpu(void *dest, void *src, uint64_t size,
                                  cuda_stream_t *stream) {
  if (size == 0)
    return;
  cudaPointerAttributes attr_dest;
  check_cuda_error(cudaPointerGetAttributes(&attr_dest, dest));
  if (attr_dest.device != stream->gpu_index &&
      attr_dest.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid dest device pointer in copy from GPU to GPU.")
  }
  cudaPointerAttributes attr_src;
  check_cuda_error(cudaPointerGetAttributes(&attr_src, src));
  if (attr_src.device != stream->gpu_index &&
      attr_src.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid src device pointer in copy from GPU to GPU.")
  }
  if (attr_src.device != attr_dest.device) {
    PANIC("Cuda error: different devices specified in copy from GPU to GPU.")
  }

  check_cuda_error(cudaSetDevice(stream->gpu_index));
  check_cuda_error(cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToDevice,
                                   stream->stream));
}

/// Synchronizes device
void cuda_synchronize_device(uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
  check_cuda_error(cudaDeviceSynchronize());
}

void cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                       cuda_stream_t *stream) {
  if (size == 0)
    return;
  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, dest));
  if (attr.device != stream->gpu_index && attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid dest device pointer in cuda memset.")
  }
  check_cuda_error(cudaSetDevice(stream->gpu_index));
  check_cuda_error(cudaMemsetAsync(dest, val, size, stream->stream));
}

template <typename Torus>
__global__ void cuda_set_value_kernel(Torus *array, Torus value, Torus n) {
  int index = threadIdx.x + blockIdx.x * blockDim.x;
  if (index < n)
    array[index] = value;
}

template <typename Torus>
void cuda_set_value_async(cudaStream_t *stream, Torus *d_array, Torus value,
                          Torus n) {
  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, d_array));
  if (attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid dest device pointer in cuda set value.")
  }
  int block_size = 256;
  int num_blocks = (n + block_size - 1) / block_size;

  // Launch the kernel
  cuda_set_value_kernel<<<num_blocks, block_size, 0, *stream>>>(d_array, value,
                                                                n);
  check_cuda_error(cudaGetLastError());
}

/// Explicitly instantiate cuda_set_value_async for 32 and 64 bits
template void cuda_set_value_async(cudaStream_t *stream, uint64_t *d_array,
                                   uint64_t value, uint64_t n);
template void cuda_set_value_async(cudaStream_t *stream, uint32_t *d_array,
                                   uint32_t value, uint32_t n);

/// Copy memory to the CPU asynchronously
void cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                              cuda_stream_t *stream) {
  if (size == 0)
    return;
  cudaPointerAttributes attr;
  check_cuda_error(cudaPointerGetAttributes(&attr, src));
  if (attr.device != stream->gpu_index && attr.type != cudaMemoryTypeDevice) {
    PANIC("Cuda error: invalid src device pointer in copy to CPU async.")
  }

  check_cuda_error(cudaSetDevice(stream->gpu_index));
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToHost, stream->stream));
}

/// Return number of GPUs available
int cuda_get_number_of_gpus() {
  int num_gpus;
  check_cuda_error(cudaGetDeviceCount(&num_gpus));
  return num_gpus;
}

/// Drop a cuda array
void cuda_drop(void *ptr, uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
  check_cuda_error(cudaFree(ptr));
}

/// Drop a cuda array asynchronously, if supported on the device
void cuda_drop_async(void *ptr, cuda_stream_t *stream) {

  check_cuda_error(cudaSetDevice(stream->gpu_index));
#ifndef CUDART_VERSION
#error CUDART_VERSION Undefined!
#elif (CUDART_VERSION >= 11020)
  int support_async_alloc;
  check_cuda_error(cudaDeviceGetAttribute(&support_async_alloc,
                                          cudaDevAttrMemoryPoolsSupported,
                                          stream->gpu_index));

  if (support_async_alloc) {
    check_cuda_error(cudaFreeAsync(ptr, stream->stream));
  } else {
    check_cuda_error(cudaFree(ptr));
  }
#else
  check_cuda_error(cudaFree(ptr));
#endif
}

/// Get the maximum size for the shared memory
int cuda_get_max_shared_memory(uint32_t gpu_index) {
  check_cuda_error(cudaSetDevice(gpu_index));
  int max_shared_memory = 0;
  cudaDeviceGetAttribute(&max_shared_memory, cudaDevAttrMaxSharedMemoryPerBlock,
                         gpu_index);
  check_cuda_error(cudaGetLastError());
  return max_shared_memory;
}

void cuda_synchronize_stream(cuda_stream_t *stream) { stream->synchronize(); }

void cuda_stream_add_callback(cuda_stream_t *stream,
                              cudaStreamCallback_t callback, void *user_data) {

  check_cuda_error(
      cudaStreamAddCallback(stream->stream, callback, user_data, 0));
}

void host_free_on_stream_callback(cudaStream_t stream, cudaError_t status,
                                  void *host_pointer) {
  free(host_pointer);
}
