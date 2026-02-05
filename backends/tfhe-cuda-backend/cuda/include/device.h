#ifndef DEVICE_H
#define DEVICE_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>

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

// The PANIC macro should be used to validate user-inputs to GPU functions
// it will execute in all targets, including production settings
// e.g., cudaMemCopy to the device should check that the destination pointer is
// a device pointer
#define PANIC(format, ...)                                                     \
  {                                                                            \
    std::fprintf(stderr, "%s::%d::%s: panic.\n" format "\n", __FILE__,         \
                 __LINE__, __func__, ##__VA_ARGS__);                           \
    std::abort();                                                              \
  }

// This is a generic assertion checking macro with user defined printf-style
// message
#define PANIC_IF_FALSE(cond, format, ...)                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      PANIC(format "\n\n %s\n", ##__VA_ARGS__, #cond);                         \
    }                                                                          \
  } while (0)

#ifndef GPU_ASSERTS_DISABLE
// The GPU assert should be used to validate assumptions in algorithms,
// for example, checking that two user-provided quantities have a certain
// relationship or that the size of the buffer  provided to a function is
// sufficient when it is filled with some algorithm that depends on
// user-provided inputs e.g., OPRF corrections buffer should not have a size
// higher than the number of blocks in the datatype that is generated
#define GPU_ASSERT(cond, format, ...)                                          \
  PANIC_IF_FALSE(cond, format, ##__VA_ARGS__)
#else
#define GPU_ASSERT(cond)                                                       \
  do {                                                                         \
  } while (0)
#endif

uint32_t cuda_get_device();
void cuda_set_device(uint32_t gpu_index);

cudaEvent_t cuda_create_event(uint32_t gpu_index);

void cuda_event_record(cudaEvent_t event, cudaStream_t stream,
                       uint32_t gpu_index);
void cuda_stream_wait_event(cudaStream_t stream, cudaEvent_t event,
                            uint32_t gpu_index);

void cuda_event_destroy(cudaEvent_t event, uint32_t gpu_index);

cudaStream_t cuda_create_stream(uint32_t gpu_index);

void cuda_destroy_stream(cudaStream_t stream, uint32_t gpu_index);

void cuda_synchronize_stream(cudaStream_t stream, uint32_t gpu_index);

uint32_t cuda_is_available();

void *cuda_malloc(uint64_t size, uint32_t gpu_index);

void *cuda_malloc_with_size_tracking_async(uint64_t size, cudaStream_t stream,
                                           uint32_t gpu_index,
                                           uint64_t &size_tracker,
                                           bool allocate_gpu_memory);

void *cuda_malloc_async(uint64_t size, cudaStream_t stream, uint32_t gpu_index);

bool cuda_check_valid_malloc(uint64_t size, uint32_t gpu_index);
uint64_t cuda_device_total_memory(uint32_t gpu_index);

void cuda_memcpy_with_size_tracking_async_to_gpu(void *dest, const void *src,
                                                 uint64_t size,
                                                 cudaStream_t stream,
                                                 uint32_t gpu_index,
                                                 bool gpu_memory_allocated);

void cuda_memcpy_async_to_gpu(void *dest, const void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index);

void cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
    void *dest, void const *src, uint64_t size, cudaStream_t stream,
    uint32_t gpu_index, bool gpu_memory_allocated);

void cuda_memcpy_async_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                                  cudaStream_t stream, uint32_t gpu_index);

void cuda_memcpy_gpu_to_gpu(void *dest, void const *src, uint64_t size,
                            uint32_t gpu_index);

void cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                              cudaStream_t stream, uint32_t gpu_index);

void cuda_memset_with_size_tracking_async(void *dest, uint64_t val,
                                          uint64_t size, cudaStream_t stream,
                                          uint32_t gpu_index,
                                          bool gpu_memory_allocated);

void cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                       cudaStream_t stream, uint32_t gpu_index);

int cuda_get_number_of_gpus();

int cuda_get_number_of_sms();

void cuda_synchronize_device(uint32_t gpu_index);

void cuda_drop(void *ptr, uint32_t gpu_index);

void cuda_drop_with_size_tracking_async(void *ptr, cudaStream_t stream,
                                        uint32_t gpu_index,
                                        bool gpu_memory_allocated);

void cuda_drop_async(void *ptr, cudaStream_t stream, uint32_t gpu_index);
}

uint32_t cuda_get_max_shared_memory(uint32_t gpu_index);

uint32_t cuda_get_max_shared_memory_per_block(uint32_t gpu_index);

bool cuda_check_support_cooperative_groups();

bool cuda_check_support_thread_block_clusters();

template <typename Torus>
void cuda_set_value_async(cudaStream_t stream, uint32_t gpu_index,
                          Torus *d_array, Torus value, Torus n);

#endif
