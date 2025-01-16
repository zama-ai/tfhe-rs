#ifndef DEVICE_H
#define DEVICE_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>
#include <vector>

#define synchronize_threads_in_block() __syncthreads()
extern "C" {

#define check_cuda_error(ans)                                                  \
  { cuda_error((ans), __FILE__, __LINE__); }
inline void cuda_error(cudaError_t code, const char *file, int line) {
  if (code != cudaSuccess) {
    std::fprintf(stderr, "Cuda error: %s %s %d\n", cudaGetErrorString(code),
                 file, line);
    std::abort();
  }
}
#define PANIC(format, ...)                                                     \
  {                                                                            \
    std::fprintf(stderr, "%s::%d::%s: panic.\n" format "\n", __FILE__,         \
                 __LINE__, __func__, ##__VA_ARGS__);                           \
    std::abort();                                                              \
  }

cudaEvent_t cuda_create_event(uint32_t gpu_index);

void cuda_event_record(cudaEvent_t event, cudaStream_t stream,
                       uint32_t gpu_index);
void cuda_stream_wait_event(cudaStream_t stream, cudaEvent_t event,
                            uint32_t gpu_index);

void cuda_event_destroy(cudaEvent_t event, uint32_t gpu_index);

cudaStream_t cuda_create_stream(uint32_t gpu_index);

void cuda_destroy_stream(cudaStream_t stream, uint32_t gpu_index);

void cuda_synchronize_stream(cudaStream_t stream, uint32_t gpu_index);

void synchronize_streams(cudaStream_t const *streams,
                         uint32_t const *gpu_indexes, uint32_t gpu_count);

uint32_t cuda_is_available();

void *cuda_malloc(uint64_t size, uint32_t gpu_index);

void *cuda_malloc_async(uint64_t size, cudaStream_t stream, uint32_t gpu_index);

void cuda_check_valid_malloc(uint64_t size, uint32_t gpu_index);

void cuda_memcpy_async_to_gpu(void *dest, void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index);

void cuda_memcpy_async_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                                  cudaStream_t stream, uint32_t gpu_index);

void cuda_memcpy_gpu_to_gpu(void *dest, void *src, uint64_t size,
                            uint32_t gpu_index);

void cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index);

void cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                       cudaStream_t stream, uint32_t gpu_index);

int cuda_get_number_of_gpus();

void cuda_synchronize_device(uint32_t gpu_index);

void cuda_drop(void *ptr, uint32_t gpu_index);

void cuda_drop_async(void *ptr, cudaStream_t stream, uint32_t gpu_index);
}

int cuda_get_max_shared_memory(uint32_t gpu_index);

bool cuda_check_support_cooperative_groups();

bool cuda_check_support_thread_block_clusters();

template <typename Torus>
void cuda_set_value_async(cudaStream_t stream, uint32_t gpu_index,
                          Torus *d_array, Torus value, Torus n);
#endif
