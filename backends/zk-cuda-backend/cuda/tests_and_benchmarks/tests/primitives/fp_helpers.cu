// Test-only GPU helper kernels and batch operations for Fp
// These are moved from fp.cu to keep the main codebase focused on MSM
// operations. This file is only compiled for tests and benchmarks

#include "device.h"
#include "fp.h"
#include <cuda_runtime.h>

#include "checked_arithmetic.h"

// ============================================================================
// CUDA Kernels for parallel Fp operations (test-only)
// ============================================================================

// Kernel: Add two arrays of Fp elements
// a[i] + b[i] -> c[i] for all i
__global__ void kernel_fp_add_array(Fp *c, const Fp *a, const Fp *b,
                                    uint32_t n) {
  const uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    fp_add(c[idx], a[idx], b[idx]);
  }
}

// Kernel: Multiply two arrays of Fp elements
// a[i] * b[i] -> c[i] for all i
// Uses Montgomery form internally for efficiency
__global__ void kernel_fp_mul_array(Fp *c, const Fp *a, const Fp *b,
                                    uint32_t n) {
  const uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    Fp a_mont, b_mont, c_mont;
    fp_to_montgomery(a_mont, a[idx]);
    fp_to_montgomery(b_mont, b[idx]);
    fp_mont_mul(c_mont, a_mont, b_mont);
    fp_from_montgomery(c[idx], c_mont);
  }
}

// Kernel: Scalar multiplication (all elements multiplied by same scalar)
// a[i] * scalar -> c[i] for all i
// Uses Montgomery form internally for efficiency
__global__ void kernel_fp_mul_scalar(Fp *c, const Fp *a, const Fp *scalar,
                                     uint32_t n) {
  const uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    Fp a_mont, scalar_mont, c_mont;
    fp_to_montgomery(a_mont, a[idx]);
    fp_to_montgomery(scalar_mont, *scalar);
    fp_mont_mul(c_mont, a_mont, scalar_mont);
    fp_from_montgomery(c[idx], c_mont);
  }
}

// ============================================================================
// Single-thread kernels for testing (test-only)
// ============================================================================

// single addition on GPU
__global__ void kernel_fp_add(Fp *result, const Fp *a, const Fp *b) {
  fp_add(*result, *a, *b);
}

// single subtraction on GPU
__global__ void kernel_fp_sub(Fp *result, const Fp *a, const Fp *b) {
  fp_sub(*result, *a, *b);
}

// single multiplication on GPU
// Uses Montgomery form internally for efficiency
__global__ void kernel_fp_mul(Fp *result, const Fp *a, const Fp *b) {
  Fp a_mont, b_mont, c_mont;
  fp_to_montgomery(a_mont, *a);
  fp_to_montgomery(b_mont, *b);
  fp_mont_mul(c_mont, a_mont, b_mont);
  fp_from_montgomery(*result, c_mont);
}

// single negation on GPU
__global__ void kernel_fp_neg(Fp *result, const Fp *a) { fp_neg(*result, *a); }

// single inversion on GPU
__global__ void kernel_fp_inv(Fp *result, const Fp *a) { fp_inv(*result, *a); }

// single division on GPU
__global__ void kernel_fp_div(Fp *result, const Fp *a, const Fp *b) {
  fp_div(*result, *a, *b);
}

// Montgomery conversion on GPU
__global__ void kernel_fp_to_montgomery(Fp *result, const Fp *a) {
  fp_to_montgomery(*result, *a);
}

__global__ void kernel_fp_from_montgomery(Fp *result, const Fp *a) {
  fp_from_montgomery(*result, *a);
}

// Montgomery multiplication on GPU
__global__ void kernel_fp_mont_mul(Fp *result, const Fp *a, const Fp *b) {
  fp_mont_mul(*result, *a, *b);
}

// comparison on GPU
__global__ void kernel_fp_cmp(int *result, const Fp *a, const Fp *b) {
  *result = static_cast<int>(fp_cmp(*a, *b));
}

// check if zero on GPU
__global__ void kernel_fp_is_zero(bool *result, const Fp *a) {
  *result = fp_is_zero(*a);
}

// check if one on GPU
__global__ void kernel_fp_is_one(bool *result, const Fp *a) {
  *result = fp_is_one(*a);
}

// copy on GPU
__global__ void kernel_fp_copy(Fp *result, const Fp *a) {
  fp_copy(*result, *a);
}

// conditional move on GPU
__global__ void kernel_fp_cmov(Fp *result, const Fp *src, uint64_t condition) {
  fp_cmov(*result, *src, condition);
}

// square root on GPU
__global__ void kernel_fp_sqrt(bool *has_sqrt, Fp *result, const Fp *a) {
  *has_sqrt = fp_sqrt(*result, *a);
}

// check if quadratic residue on GPU
__global__ void kernel_fp_is_quadratic_residue(bool *result, const Fp *a) {
  *result = fp_is_quadratic_residue(*a);
}

// exponentiation with uint64_t exponent on GPU
__global__ void kernel_fp_pow_u64(Fp *result, const Fp *base, uint64_t exp) {
  fp_pow_u64(*result, *base, exp);
}

// set to zero on GPU
__global__ void kernel_fp_zero(Fp *result) { fp_zero(*result); }

// set to one on GPU
__global__ void kernel_fp_one(Fp *result) { fp_one(*result); }

// ============================================================================
// Batch operations on host (handles host/device memory transfers) - test-only
// ============================================================================

// Host wrapper function that performs element-wise addition of two arrays of Fp
// elements on GPU. Handles all memory management and data transfer between host
// and device
void fp_add_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp *c,
                          const Fp *a, const Fp *b, uint32_t n) {
  // Validate inputs
  // n is uint32_t, so it's always >= 0
  if (n == 0) {
    return; // Nothing to do
  }
  PANIC_IF_FALSE(c != nullptr && a != nullptr && b != nullptr,
                 "fp_add_batch_on_host: null pointer argument");

  // Set the device context
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  // Declare all variables at the top to avoid goto issues
  const uint32_t threadsPerBlock = 256;
  const uint32_t blocksPerGrid = CEIL_DIV(n, threadsPerBlock);

  // Allocate device memory (asynchronous with stream)
  auto *d_c = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      size_tracker, true));

  // Copy to device (asynchronous with stream)
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_a, a, safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_b, b, safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      true);

  // Launch kernel (with stream)
  kernel_fp_add_array<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_c, d_a,
                                                                     d_b, n);

  // Check for kernel launch errors
  check_cuda_error(cudaGetLastError());

  // Synchronize stream to ensure kernel completes before copying back
  cuda_synchronize_stream(stream, gpu_index);

  // Copy back (synchronous after stream sync)
  cuda_memcpy_async_to_cpu(c, d_c, safe_mul_sizeof<Fp>(static_cast<size_t>(n)),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Free device memory (asynchronous with stream)
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

void fp_mul_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp *c,
                          const Fp *a, const Fp *b, uint32_t n) {
  // Validate inputs
  // n is uint32_t, so it's always >= 0
  if (n == 0) {
    return; // Nothing to do
  }
  PANIC_IF_FALSE(c != nullptr && a != nullptr && b != nullptr,
                 "fp_mul_batch_on_host: null pointer argument");

  // Set the device context
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  // Declare all variables at the top to avoid goto issues
  const uint32_t threadsPerBlock = 256;
  const uint32_t blocksPerGrid = CEIL_DIV(n, threadsPerBlock);

  // Allocate device memory (asynchronous with stream)
  auto *d_c = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      size_tracker, true));

  // Copy to device (asynchronous with stream)
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_a, a, safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_b, b, safe_mul_sizeof<Fp>(static_cast<size_t>(n)), stream, gpu_index,
      true);

  // Launch kernel (with stream)
  kernel_fp_mul_array<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_c, d_a,
                                                                     d_b, n);

  // Check for kernel launch errors
  check_cuda_error(cudaGetLastError());

  // Synchronize stream to ensure kernel completes before copying back
  cuda_synchronize_stream(stream, gpu_index);

  // Copy back (synchronous after stream sync)
  cuda_memcpy_async_to_cpu(c, d_c, safe_mul_sizeof<Fp>(static_cast<size_t>(n)),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Free device memory (asynchronous with stream)
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

// Device-resident API: assumes all pointers are already on device
void fp_add_array_on_device(cudaStream_t stream, uint32_t gpu_index, Fp *d_c,
                            const Fp *d_a, const Fp *d_b, uint32_t n) {
  // Validate inputs
  // n is uint32_t, so it's always >= 0
  if (n == 0) {
    return; // Nothing to do
  }
  PANIC_IF_FALSE(d_c != nullptr && d_a != nullptr && d_b != nullptr,
                 "fp_add_array_on_device: null pointer argument");

  // Set the device context
  cuda_set_device(gpu_index);

  uint32_t threadsPerBlock = 256;
  uint32_t blocksPerGrid = CEIL_DIV(n, threadsPerBlock);

  // Launch kernel (with stream)
  kernel_fp_add_array<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_c, d_a,
                                                                     d_b, n);

  // Check for kernel launch errors
  check_cuda_error(cudaGetLastError());
}

void fp_mul_array_on_device(cudaStream_t stream, uint32_t gpu_index, Fp *d_c,
                            const Fp *d_a, const Fp *d_b, uint32_t n) {
  // Validate inputs
  // n is uint32_t, so it's always >= 0
  if (n == 0) {
    return; // Nothing to do
  }
  PANIC_IF_FALSE(d_c != nullptr && d_a != nullptr && d_b != nullptr,
                 "fp_mul_array_on_device: null pointer argument");

  // Set the device context
  cuda_set_device(gpu_index);

  uint32_t threadsPerBlock = 256;
  uint32_t blocksPerGrid = CEIL_DIV(n, threadsPerBlock);

  // Launch kernel (with stream)
  kernel_fp_mul_array<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_c, d_a,
                                                                     d_b, n);

  // Check for kernel launch errors
  check_cuda_error(cudaGetLastError());
}
