#ifndef CNCRT_GGSW_CUH
#define CNCRT_GGSW_CUH

#include "checked_arithmetic.h"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "polynomial/parameters.cuh"

template <typename T, typename ST, class params, sharedMemDegree SMD>
__global__ void device_batch_fft_ggsw_vector(double2 *dest, T *src,
                                             int8_t *device_mem) {

  extern __shared__ int8_t sharedmem[];
  double2 *selected_memory;

  if constexpr (SMD == FULLSM)
    selected_memory = (double2 *)sharedmem;
  else
    selected_memory = (double2 *)device_mem[blockIdx.x * params::degree];

  // Compression
  int offset = blockIdx.x * blockDim.x;

  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    ST x = src[(tid) + params::opt * offset];
    ST y = src[(tid + params::degree / 2) + params::opt * offset];
    selected_memory[tid].x = x / (double)std::numeric_limits<T>::max();
    selected_memory[tid].y = y / (double)std::numeric_limits<T>::max();
    tid += params::degree / params::opt;
  }
  __syncthreads();

  // Switch to the FFT space
  NSMFFT_direct<HalfDegree<params>>(selected_memory);
  __syncthreads();

  // Write the output to global memory
  tid = threadIdx.x;
#pragma unroll
  for (int j = 0; j < params::opt / 2; j++) {
    dest[tid + (params::opt >> 1) * offset] = selected_memory[tid];
    tid += params::degree / params::opt;
  }
}

/**
 * Applies the FFT transform on sequence of GGSW ciphertexts already in the
 * global memory
 */
template <typename T, typename ST, class params>
void batch_fft_ggsw_vector(CudaStreams streams, double2 *dest, T *src,
                           int8_t *d_mem, uint32_t r, uint32_t glwe_dim,
                           uint32_t polynomial_size, uint32_t level_count,
                           uint32_t max_shared_memory) {
  PANIC_IF_FALSE(streams.count() == 1,
                 "GPU error (batch_fft_ggsw_vector): multi-GPU execution on %d "
                 "gpus is not supported yet.",
                 streams.count());

  cuda_set_device(streams.gpu_index(0));

  int shared_memory_size = safe_mul_sizeof<double>(polynomial_size);

  int gridSize = r * (glwe_dim + 1) * (glwe_dim + 1) * level_count;
  int blockSize = polynomial_size / params::opt;

  if (max_shared_memory < shared_memory_size) {
    device_batch_fft_ggsw_vector<T, ST, params, NOSM>
        <<<gridSize, blockSize, 0, streams.stream(0)>>>(dest, src, d_mem);
  } else {
    device_batch_fft_ggsw_vector<T, ST, params, FULLSM>
        <<<gridSize, blockSize, shared_memory_size, streams.stream(0)>>>(
            dest, src, d_mem);
  }
  check_cuda_error(cudaGetLastError());
}

#endif // CNCRT_GGSW_CUH
