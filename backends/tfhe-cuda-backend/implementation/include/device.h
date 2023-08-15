#ifndef DEVICE_H
#define DEVICE_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>

#define synchronize_threads_in_block() __syncthreads()

extern "C" {

struct cuda_stream_t {
  cudaStream_t stream;
  uint32_t gpu_index;

  cuda_stream_t(uint32_t gpu_index) {
    this->gpu_index = gpu_index;

    cudaStreamCreate(&stream);
  }

  void release() {
    cudaSetDevice(gpu_index);
    cudaStreamDestroy(stream);
  }

  void synchronize() { cudaStreamSynchronize(stream); }
};

cuda_stream_t *cuda_create_stream(uint32_t gpu_index);

int cuda_destroy_stream(cuda_stream_t *stream);

void *cuda_malloc(uint64_t size, uint32_t gpu_index);

void *cuda_malloc_async(uint64_t size, cuda_stream_t *stream);

int cuda_check_valid_malloc(uint64_t size, uint32_t gpu_index);

int cuda_check_support_cooperative_groups();

int cuda_memcpy_to_cpu(void *dest, const void *src, uint64_t size);

int cuda_memcpy_async_to_gpu(void *dest, void *src, uint64_t size,
                             cuda_stream_t *stream);

int cuda_memcpy_async_gpu_to_gpu(void *dest, void *src, uint64_t size,
                                 cuda_stream_t *stream);

int cuda_memcpy_to_gpu(void *dest, void *src, uint64_t size);

int cuda_memcpy_async_to_cpu(void *dest, const void *src, uint64_t size,
                             cuda_stream_t *stream);

int cuda_memset_async(void *dest, uint64_t val, uint64_t size,
                      cuda_stream_t *stream);

int cuda_get_number_of_gpus();

int cuda_synchronize_device(uint32_t gpu_index);

int cuda_drop(void *ptr, uint32_t gpu_index);

int cuda_drop_async(void *ptr, cuda_stream_t *stream);

int cuda_get_max_shared_memory(uint32_t gpu_index);

int cuda_synchronize_stream(cuda_stream_t *stream);

#define check_cuda_error(ans)                                                  \
  { cuda_error((ans), __FILE__, __LINE__); }
inline void cuda_error(cudaError_t code, const char *file, int line,
                       bool abort = true) {
  if (code != cudaSuccess) {
    fprintf(stderr, "Cuda error: %s %s %d\n", cudaGetErrorString(code), file,
            line);
    if (abort)
      exit(code);
  }
}
}

template <typename Torus>
void cuda_set_value_async(cudaStream_t *stream, Torus *d_array, Torus value,
                          Torus n);
#endif
