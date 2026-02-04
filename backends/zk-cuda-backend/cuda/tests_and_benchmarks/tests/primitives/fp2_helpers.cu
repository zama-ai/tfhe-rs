// Test-only GPU helper kernels and batch operations for Fp2
// These are moved from fp2.cu to keep the main codebase focused on MSM
// operations. This file is only compiled for tests and benchmarks

#include "device.h"
#include "fp2.h"
#include <cuda_runtime.h>

// ============================================================================
// CUDA Kernels for parallel Fp2 operations (test-only)
// ============================================================================

__global__ void kernel_fp2_add_array(Fp2 *c, const Fp2 *a, const Fp2 *b,
                                     uint32_t n) {
  const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (idx < n) {
    fp2_add(c[idx], a[idx], b[idx]);
  }
}

__global__ void kernel_fp2_mul_array(Fp2 *c, const Fp2 *a, const Fp2 *b,
                                     uint32_t n) {
  const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (idx < n) {
    fp2_mul(c[idx], a[idx], b[idx]);
  }
}

// ============================================================================
// Single-thread kernels for testing (test-only)
// ============================================================================

__global__ void kernel_fp2_add(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  fp2_add(*result, *a, *b);
}

__global__ void kernel_fp2_sub(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  fp2_sub(*result, *a, *b);
}

__global__ void kernel_fp2_mul(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  fp2_mul(*result, *a, *b);
}

__global__ void kernel_fp2_neg(Fp2 *result, const Fp2 *a) {
  fp2_neg(*result, *a);
}

__global__ void kernel_fp2_conjugate(Fp2 *result, const Fp2 *a) {
  fp2_conjugate(*result, *a);
}

__global__ void kernel_fp2_square(Fp2 *result, const Fp2 *a) {
  fp2_square(*result, *a);
}

__global__ void kernel_fp2_inv(Fp2 *result, const Fp2 *a) {
  fp2_inv(*result, *a);
}

__global__ void kernel_fp2_div(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  fp2_div(*result, *a, *b);
}

__global__ void kernel_fp2_mul_by_i(Fp2 *result, const Fp2 *a) {
  fp2_mul_by_i(*result, *a);
}

__global__ void kernel_fp2_frobenius(Fp2 *result, const Fp2 *a) {
  fp2_frobenius(*result, *a);
}

__global__ void kernel_fp2_cmp(int *result, const Fp2 *a, const Fp2 *b) {
  *result = static_cast<int>(fp2_cmp(*a, *b));
}

__global__ void kernel_fp2_is_zero(bool *result, const Fp2 *a) {
  *result = fp2_is_zero(*a);
}

__global__ void kernel_fp2_is_one(bool *result, const Fp2 *a) {
  *result = fp2_is_one(*a);
}

__global__ void kernel_fp2_copy(Fp2 *result, const Fp2 *a) {
  fp2_copy(*result, *a);
}

__global__ void kernel_fp2_cmov(Fp2 *result, const Fp2 *src,
                                uint64_t condition) {
  fp2_cmov(*result, *src, condition);
}

// ============================================================================
// Batch operations on host (handles host/device memory transfers) - test-only
// ============================================================================

void fp2_add_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp2 *c,
                           const Fp2 *a, const Fp2 *b, uint32_t n) {
  if (n == 0) {
    return;
  }
  PANIC_IF_FALSE(c != nullptr && a != nullptr && b != nullptr,
                 "fp2_add_batch_on_host: null pointer argument");

  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  const uint32_t threadsPerBlock = 256;
  const uint32_t blocksPerGrid = CEIL_DIV(n, threadsPerBlock);

  auto *d_c = static_cast<Fp2 *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Fp2), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Fp2), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp2 *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Fp2), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, n * sizeof(Fp2), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, n * sizeof(Fp2), stream,
                                              gpu_index, true);

  kernel_fp2_add_array<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_c, d_a,
                                                                      d_b, n);

  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(c, d_c, n * sizeof(Fp2), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_c != nullptr) {
    cuda_drop_with_size_tracking_async(d_c, stream, gpu_index, true);
  }
  if (d_a != nullptr) {
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  }
  if (d_b != nullptr) {
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
  }
}

void fp2_mul_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp2 *c,
                           const Fp2 *a, const Fp2 *b, uint32_t n) {
  if (n == 0) {
    return;
  }
  PANIC_IF_FALSE(c != nullptr && a != nullptr && b != nullptr,
                 "fp2_mul_batch_on_host: null pointer argument");

  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  const uint32_t threadsPerBlock = 256;
  const uint32_t blocksPerGrid = CEIL_DIV(n, threadsPerBlock);

  auto *d_c = static_cast<Fp2 *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Fp2), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Fp2), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp2 *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Fp2), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, n * sizeof(Fp2), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, n * sizeof(Fp2), stream,
                                              gpu_index, true);

  kernel_fp2_mul_array<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_c, d_a,
                                                                      d_b, n);

  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(c, d_c, n * sizeof(Fp2), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_c != nullptr) {
    cuda_drop_with_size_tracking_async(d_c, stream, gpu_index, true);
  }
  if (d_a != nullptr) {
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  }
  if (d_b != nullptr) {
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
  }
}
