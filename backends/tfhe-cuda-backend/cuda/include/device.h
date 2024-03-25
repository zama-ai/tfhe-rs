#ifndef DEVICE_H
#define DEVICE_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>

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

struct cuda_stream_t {
  cudaStream_t stream;
  uint32_t gpu_index;

  cuda_stream_t(uint32_t gpu_index) {
    this->gpu_index = gpu_index;

    check_cuda_error(cudaStreamCreate(&stream));
  }

  void release() {
    check_cuda_error(cudaSetDevice(gpu_index));
    check_cuda_error(cudaStreamDestroy(stream));
  }

  void synchronize() { check_cuda_error(cudaStreamSynchronize(stream)); }
};

cuda_stream_t *cuda_create_stream(uint32_t gpu_index);

void cuda_destroy_stream(cuda_stream_t *stream);

void *cuda_malloc(uint64_t size, uint32_t gpu_index);

void *cuda_malloc_async(uint64_t size, cuda_stream_t *stream);

void cuda_check_valid_malloc(uint64_t size, uint32_t gpu_index);

bool cuda_check_support_cooperative_groups();

void cuda_memcpy_async_to_gpu(void *dest, void *src, uint64_t size,
                              cuda_stream_t *stream);

void cuda_memcpy_async_gpu_to_gpu(void *dest, void *src, uint64_t size,
                                  cuda_stream_t *stream);

void cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                              cuda_stream_t *stream);

void cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                       cuda_stream_t *stream);

int cuda_get_number_of_gpus();

void cuda_synchronize_device(uint32_t gpu_index);

void cuda_drop(void *ptr, uint32_t gpu_index);

void cuda_drop_async(void *ptr, cuda_stream_t *stream);

int cuda_get_max_shared_memory(uint32_t gpu_index);

void cuda_synchronize_stream(cuda_stream_t *stream);

void cuda_stream_add_callback(cuda_stream_t *stream,
                              cudaStreamCallback_t callback, void *user_data);

void host_free_on_stream_callback(cudaStream_t stream, cudaError_t status,
                                  void *host_pointer);
}

template <typename Torus>
void cuda_set_value_async(cudaStream_t *stream, Torus *d_array, Torus value,
                          Torus n);
#endif
