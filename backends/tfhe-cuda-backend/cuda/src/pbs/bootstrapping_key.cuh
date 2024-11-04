#ifndef CUDA_BSK_CUH
#define CUDA_BSK_CUH

#include "device.h"
#include "fft/bnsmfft.cuh"
#include "pbs/programmable_bootstrap.h"
#include "pbs/programmable_bootstrap_multibit.h"
#include "polynomial/parameters.cuh"
#include <atomic>
#include <cstdint>

__device__ inline int get_start_ith_ggsw(int i, uint32_t polynomial_size,
                                         int glwe_dimension,
                                         uint32_t level_count) {
  return i * polynomial_size / 2 * (glwe_dimension + 1) * (glwe_dimension + 1) *
         level_count;
}

////////////////////////////////////////////////
template <typename T>
__device__ const T *get_ith_mask_kth_block(const T *ptr, int i, int k,
                                           int level, uint32_t polynomial_size,
                                           int glwe_dimension,
                                           uint32_t level_count) {
  return &ptr[get_start_ith_ggsw(i, polynomial_size, glwe_dimension,
                                 level_count) +
              (level_count - level - 1) * polynomial_size / 2 *
                  (glwe_dimension + 1) * (glwe_dimension + 1) +
              k * polynomial_size / 2 * (glwe_dimension + 1)];
}

template <typename T>
__device__ T *get_ith_mask_kth_block(T *ptr, int i, int k, int level,
                                     uint32_t polynomial_size,
                                     int glwe_dimension, uint32_t level_count) {
  return &ptr[get_start_ith_ggsw(i, polynomial_size, glwe_dimension,
                                 level_count) +
              (level_count - level - 1) * polynomial_size / 2 *
                  (glwe_dimension + 1) * (glwe_dimension + 1) +
              k * polynomial_size / 2 * (glwe_dimension + 1)];
}
template <typename T>
__device__ T *get_ith_body_kth_block(T *ptr, int i, int k, int level,
                                     uint32_t polynomial_size,
                                     int glwe_dimension, uint32_t level_count) {
  return &ptr[get_start_ith_ggsw(i, polynomial_size, glwe_dimension,
                                 level_count) +
              (level_count - level - 1) * polynomial_size / 2 *
                  (glwe_dimension + 1) * (glwe_dimension + 1) +
              k * polynomial_size / 2 * (glwe_dimension + 1) +
              glwe_dimension * polynomial_size / 2];
}

////////////////////////////////////////////////
__device__ inline int get_start_ith_lwe(uint32_t i, uint32_t grouping_factor,
                                        uint32_t polynomial_size,
                                        uint32_t glwe_dimension,
                                        uint32_t level_count) {
  return i * (1 << grouping_factor) * polynomial_size / 2 *
         (glwe_dimension + 1) * (glwe_dimension + 1) * level_count;
}

template <typename T>
__device__ const T *get_multi_bit_ith_lwe_gth_group_kth_block(
    const T *ptr, int g, int i, int k, int level, uint32_t grouping_factor,
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count) {
  const T *ptr_group =
      ptr + get_start_ith_lwe(i, grouping_factor, polynomial_size,
                              glwe_dimension, level_count);
  return get_ith_mask_kth_block(ptr_group, g, k, level, polynomial_size,
                                glwe_dimension, level_count);
}

////////////////////////////////////////////////
template <typename T, typename ST>
void cuda_convert_lwe_programmable_bootstrap_key(cudaStream_t stream,
                                                 uint32_t gpu_index,
                                                 double2 *dest, ST const *src,
                                                 uint32_t polynomial_size,
                                                 uint32_t total_polynomials) {
  cudaSetDevice(gpu_index);
  int shared_memory_size = sizeof(double) * polynomial_size;

  // Here the buffer size is the size of double2 times the number of polynomials
  // times the polynomial size over 2 because the polynomials are compressed
  // into the complex domain to perform the FFT
  size_t buffer_size =
      total_polynomials * polynomial_size / 2 * sizeof(double2);

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / choose_opt_amortized(polynomial_size);

  double2 *h_bsk;
  cudaMallocHost((void **)&h_bsk, buffer_size);

  double2 *d_bsk = (double2 *)cuda_malloc_async(buffer_size, stream, gpu_index);

  constexpr double two_pow_torus_bits = get_two_pow_torus_bits<T>();
  // compress real bsk to complex and divide it on DOUBLE_MAX
  for (int i = 0; i < total_polynomials; i++) {
    int complex_current_poly_idx = i * polynomial_size / 2;
    int torus_current_poly_idx = i * polynomial_size;
    for (int j = 0; j < polynomial_size / 2; j++) {
      h_bsk[complex_current_poly_idx + j].x = src[torus_current_poly_idx + j];
      h_bsk[complex_current_poly_idx + j].y =
          src[torus_current_poly_idx + j + polynomial_size / 2];
      h_bsk[complex_current_poly_idx + j].x /= two_pow_torus_bits;
      h_bsk[complex_current_poly_idx + j].y /= two_pow_torus_bits;
    }
  }

  cuda_memcpy_async_to_gpu(d_bsk, h_bsk, buffer_size, stream, gpu_index);

  double2 *buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
  switch (polynomial_size) {
  case 256:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
      check_cuda_error(cudaFuncSetAttribute(
          batch_NSMFFT<FFTDegree<AmortizedDegree<256>, ForwardFFT>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_NSMFFT<FFTDegree<AmortizedDegree<256>, ForwardFFT>, FULLSM>,
          cudaFuncCachePreferShared));
      batch_NSMFFT<FFTDegree<AmortizedDegree<256>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(d_bsk, dest,
                                                                buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_NSMFFT<FFTDegree<AmortizedDegree<256>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(d_bsk, dest, buffer);
    }
    break;
  case 512:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
      check_cuda_error(cudaFuncSetAttribute(
          batch_NSMFFT<FFTDegree<AmortizedDegree<512>, ForwardFFT>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_NSMFFT<FFTDegree<AmortizedDegree<512>, ForwardFFT>, FULLSM>,
          cudaFuncCachePreferShared));
      batch_NSMFFT<FFTDegree<AmortizedDegree<512>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(d_bsk, dest,
                                                                buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_NSMFFT<FFTDegree<AmortizedDegree<512>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(d_bsk, dest, buffer);
    }
    break;
  case 1024:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
      check_cuda_error(cudaFuncSetAttribute(
          batch_NSMFFT<FFTDegree<AmortizedDegree<1024>, ForwardFFT>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_NSMFFT<FFTDegree<AmortizedDegree<1024>, ForwardFFT>, FULLSM>,
          cudaFuncCachePreferShared));
      batch_NSMFFT<FFTDegree<AmortizedDegree<1024>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(d_bsk, dest,
                                                                buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_NSMFFT<FFTDegree<AmortizedDegree<1024>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(d_bsk, dest, buffer);
    }
    break;
  case 2048:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
      check_cuda_error(cudaFuncSetAttribute(
          batch_NSMFFT<FFTDegree<AmortizedDegree<2048>, ForwardFFT>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_NSMFFT<FFTDegree<AmortizedDegree<2048>, ForwardFFT>, FULLSM>,
          cudaFuncCachePreferShared));
      batch_NSMFFT<FFTDegree<AmortizedDegree<2048>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(d_bsk, dest,
                                                                buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_NSMFFT<FFTDegree<AmortizedDegree<2048>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(d_bsk, dest, buffer);
    }
    break;
  case 4096:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
      check_cuda_error(cudaFuncSetAttribute(
          batch_NSMFFT<FFTDegree<AmortizedDegree<4096>, ForwardFFT>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_NSMFFT<FFTDegree<AmortizedDegree<4096>, ForwardFFT>, FULLSM>,
          cudaFuncCachePreferShared));
      batch_NSMFFT<FFTDegree<AmortizedDegree<4096>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(d_bsk, dest,
                                                                buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_NSMFFT<FFTDegree<AmortizedDegree<4096>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(d_bsk, dest, buffer);
    }
    break;
  case 8192:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
      check_cuda_error(cudaFuncSetAttribute(
          batch_NSMFFT<FFTDegree<AmortizedDegree<8192>, ForwardFFT>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_NSMFFT<FFTDegree<AmortizedDegree<8192>, ForwardFFT>, FULLSM>,
          cudaFuncCachePreferShared));
      batch_NSMFFT<FFTDegree<AmortizedDegree<8192>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(d_bsk, dest,
                                                                buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_NSMFFT<FFTDegree<AmortizedDegree<8192>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(d_bsk, dest, buffer);
    }
    break;
  case 16384:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
      check_cuda_error(cudaFuncSetAttribute(
          batch_NSMFFT<FFTDegree<AmortizedDegree<16384>, ForwardFFT>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_NSMFFT<FFTDegree<AmortizedDegree<16384>, ForwardFFT>, FULLSM>,
          cudaFuncCachePreferShared));
      batch_NSMFFT<FFTDegree<AmortizedDegree<16384>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(d_bsk, dest,
                                                                buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_NSMFFT<FFTDegree<AmortizedDegree<16384>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(d_bsk, dest, buffer);
    }
    break;
  default:
    PANIC("Cuda error (convert KSK): unsupported polynomial size. Supported "
          "N's are powers of two in the interval [256..16384].")
  }

  cuda_drop_async(d_bsk, stream, gpu_index);
  cuda_drop_async(buffer, stream, gpu_index);
  cudaFreeHost(h_bsk);
}

#endif // CNCRT_BSK_H
