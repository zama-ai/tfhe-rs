#include "device.h"
#include <cstdint>
#include <cuda_runtime.h>

/// Unsafe function to create a CUDA stream, must check first that GPU exists
cuda_stream_t *cuda_create_stream(uint32_t gpu_index) {
  cudaSetDevice(gpu_index);
  cuda_stream_t *stream = new cuda_stream_t(gpu_index);
  return stream;
}

/// Unsafe function to destroy CUDA stream, must check first the GPU exists
int cuda_destroy_stream(cuda_stream_t *stream) {
  stream->release();
  return 0;
}

/// Unsafe function that will try to allocate even if gpu_index is invalid
/// or if there's not enough memory. A safe wrapper around it must call
/// cuda_check_valid_malloc() first
void *cuda_malloc(uint64_t size, uint32_t gpu_index) {
  cudaSetDevice(gpu_index);
  void *ptr;
  cudaMalloc((void **)&ptr, size);
  check_cuda_error(cudaGetLastError());

  return ptr;
}

/// Allocates a size-byte array at the device memory. Tries to do it
/// asynchronously.
void *cuda_malloc_async(uint64_t size, cuda_stream_t *stream) {
  cudaSetDevice(stream->gpu_index);
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

/// Checks that allocation is valid
/// 0: valid
/// -1: invalid, not enough memory in device
/// -2: invalid, gpu index doesn't exist
int cuda_check_valid_malloc(uint64_t size, uint32_t gpu_index) {

  if (gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaSetDevice(gpu_index);
  size_t total_mem, free_mem;
  cudaMemGetInfo(&free_mem, &total_mem);
  if (size > free_mem) {
    // error code: not enough memory
    return -1;
  }
  return 0;
}

/// Returns
///  -> 0 if Cooperative Groups is not supported.
///  -> 1 otherwise
int cuda_check_support_cooperative_groups() {
  int cooperative_groups_supported = 0;
  cudaDeviceGetAttribute(&cooperative_groups_supported,
                         cudaDevAttrCooperativeLaunch, 0);

  return cooperative_groups_supported > 0;
}

/// Tries to copy memory to the GPU asynchronously
/// 0: success
/// -1: error, invalid device pointer
/// -2: error, gpu index doesn't exist
/// -3: error, zero copy size
int cuda_memcpy_async_to_gpu(void *dest, void *src, uint64_t size,
                             cuda_stream_t *stream) {
  if (size == 0) {
    // error code: zero copy size
    return -3;
  }

  if (stream->gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaPointerAttributes attr;
  cudaPointerGetAttributes(&attr, dest);
  if (attr.device != stream->gpu_index && attr.type != cudaMemoryTypeDevice) {
    // error code: invalid device pointer
    return -1;
  }

  cudaSetDevice(stream->gpu_index);
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyHostToDevice, stream->stream));
  return 0;
}

/// Tries to copy memory to the GPU synchronously
/// 0: success
/// -1: error, invalid device pointer
/// -2: error, gpu index doesn't exist
/// -3: error, zero copy size
int cuda_memcpy_to_gpu(void *dest, void *src, uint64_t size) {
  if (size == 0) {
    // error code: zero copy size
    return -3;
  }

  cudaPointerAttributes attr;
  cudaPointerGetAttributes(&attr, dest);
  if (attr.type != cudaMemoryTypeDevice) {
    // error code: invalid device pointer
    return -1;
  }

  check_cuda_error(cudaMemcpy(dest, src, size, cudaMemcpyHostToDevice));
  return 0;
}

/// Tries to copy memory to the CPU synchronously
/// 0: success
/// -1: error, invalid device pointer
/// -2: error, gpu index doesn't exist
/// -3: error, zero copy size
int cuda_memcpy_to_cpu(void *dest, void *src, uint64_t size) {
  if (size == 0) {
    // error code: zero copy size
    return -3;
  }

  cudaPointerAttributes attr;
  cudaPointerGetAttributes(&attr, src);
  if (attr.type != cudaMemoryTypeDevice) {
    // error code: invalid device pointer
    return -1;
  }

  check_cuda_error(cudaMemcpy(dest, src, size, cudaMemcpyDeviceToHost));
  return 0;
}

/// Tries to copy memory within a GPU asynchronously
/// 0: success
/// -1: error, invalid device pointer
/// -2: error, gpu index doesn't exist
/// -3: error, zero copy size
int cuda_memcpy_async_gpu_to_gpu(void *dest, void *src, uint64_t size,
                                 cuda_stream_t *stream) {
  if (size == 0) {
    // error code: zero copy size
    return -3;
  }

  if (stream->gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaPointerAttributes attr_dest;
  cudaPointerGetAttributes(&attr_dest, dest);
  if (attr_dest.device != stream->gpu_index &&
      attr_dest.type != cudaMemoryTypeDevice) {
    // error code: invalid device pointer
    return -1;
  }
  cudaPointerAttributes attr_src;
  cudaPointerGetAttributes(&attr_src, src);
  if (attr_src.device != stream->gpu_index &&
      attr_src.type != cudaMemoryTypeDevice) {
    // error code: invalid device pointer
    return -1;
  }
  if (attr_src.device != attr_dest.device) {
    // error code: different devices
    return -1;
  }

  cudaSetDevice(stream->gpu_index);
  check_cuda_error(cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToDevice,
                                   stream->stream));
  return 0;
}

/// Synchronizes device
/// 0: success
/// -2: error, gpu index doesn't exist
int cuda_synchronize_device(uint32_t gpu_index) {
  if (gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaSetDevice(gpu_index);
  cudaDeviceSynchronize();
  return 0;
}

int cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                      cuda_stream_t *stream) {
  if (size == 0) {
    // error code: zero copy size
    return -3;
  }

  if (stream->gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaPointerAttributes attr;
  cudaPointerGetAttributes(&attr, dest);
  if (attr.device != stream->gpu_index && attr.type != cudaMemoryTypeDevice) {
    // error code: invalid device pointer
    return -1;
  }
  cudaSetDevice(stream->gpu_index);
  check_cuda_error(cudaMemsetAsync(dest, val, size, stream->stream));
  return 0;
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
  int block_size = 256;
  int num_blocks = (n + block_size - 1) / block_size;

  // Launch the kernel
  cuda_set_value_kernel<<<num_blocks, block_size, 0, *stream>>>(d_array, value,
                                                                n);
}

/// Explicitly instantiate cuda_set_value_async for 32 and 64 bits
template void cuda_set_value_async(cudaStream_t *stream, uint64_t *d_array,
                                   uint64_t value, uint64_t n);
template void cuda_set_value_async(cudaStream_t *stream, uint32_t *d_array,
                                   uint32_t value, uint32_t n);

/// Tries to copy memory to the GPU asynchronously
/// 0: success
/// -1: error, invalid device pointer
/// -2: error, gpu index doesn't exist
/// -3: error, zero copy size
int cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                             cuda_stream_t *stream) {
  if (size == 0) {
    // error code: zero copy size
    return -3;
  }

  if (stream->gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaPointerAttributes attr;
  cudaPointerGetAttributes(&attr, src);
  if (attr.device != stream->gpu_index && attr.type != cudaMemoryTypeDevice) {
    // error code: invalid device pointer
    return -1;
  }

  cudaSetDevice(stream->gpu_index);
  check_cuda_error(
      cudaMemcpyAsync(dest, src, size, cudaMemcpyDeviceToHost, stream->stream));
  return 0;
}

/// Return number of GPUs available
int cuda_get_number_of_gpus() {
  int num_gpus;
  cudaGetDeviceCount(&num_gpus);
  return num_gpus;
}

/// Drop a cuda array
int cuda_drop(void *ptr, uint32_t gpu_index) {
  if (gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaSetDevice(gpu_index);
  check_cuda_error(cudaFree(ptr));
  return 0;
}

/// Drop a cuda array. Tries to do it asynchronously
int cuda_drop_async(void *ptr, cuda_stream_t *stream) {

  cudaSetDevice(stream->gpu_index);
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
  return 0;
}

/// Get the maximum size for the shared memory
int cuda_get_max_shared_memory(uint32_t gpu_index) {
  if (gpu_index >= cuda_get_number_of_gpus()) {
    // error code: invalid gpu_index
    return -2;
  }
  cudaSetDevice(gpu_index);
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, gpu_index);
  int max_shared_memory = 0;
  if (prop.major >= 6) {
    max_shared_memory = prop.sharedMemPerMultiprocessor;
  } else {
    max_shared_memory = prop.sharedMemPerBlock;
  }
  return max_shared_memory;
}

int cuda_synchronize_stream(cuda_stream_t *stream) {
  stream->synchronize();
  return 0;
}
