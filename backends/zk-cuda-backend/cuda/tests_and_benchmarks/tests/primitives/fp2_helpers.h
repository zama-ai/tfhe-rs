#pragma once

#include "device.h"
#include "fp2.h"
#include <cuda_runtime.h>

// ============================================================================
// CUDA Kernels for parallel Fp2 operations (test-only)
// ============================================================================

__global__ void kernel_fp2_add_array(Fp2 *c, const Fp2 *a, const Fp2 *b,
                                     uint32_t n);
__global__ void kernel_fp2_mul_array(Fp2 *c, const Fp2 *a, const Fp2 *b,
                                     uint32_t n);

// ============================================================================
// Single-thread kernels for testing (test-only)
// ============================================================================

__global__ void kernel_fp2_add(Fp2 *result, const Fp2 *a, const Fp2 *b);
__global__ void kernel_fp2_sub(Fp2 *result, const Fp2 *a, const Fp2 *b);
__global__ void kernel_fp2_mul(Fp2 *result, const Fp2 *a, const Fp2 *b);
__global__ void kernel_fp2_neg(Fp2 *result, const Fp2 *a);
__global__ void kernel_fp2_conjugate(Fp2 *result, const Fp2 *a);
__global__ void kernel_fp2_square(Fp2 *result, const Fp2 *a);
__global__ void kernel_fp2_inv(Fp2 *result, const Fp2 *a);
__global__ void kernel_fp2_div(Fp2 *result, const Fp2 *a, const Fp2 *b);
__global__ void kernel_fp2_mul_by_i(Fp2 *result, const Fp2 *a);
__global__ void kernel_fp2_frobenius(Fp2 *result, const Fp2 *a);
__global__ void kernel_fp2_cmp(int *result, const Fp2 *a, const Fp2 *b);
__global__ void kernel_fp2_is_zero(bool *result, const Fp2 *a);
__global__ void kernel_fp2_is_one(bool *result, const Fp2 *a);
__global__ void kernel_fp2_copy(Fp2 *result, const Fp2 *a);
__global__ void kernel_fp2_cmov(Fp2 *result, const Fp2 *src,
                                uint64_t condition);

// ============================================================================
// Batch operations (test-only)
// ============================================================================

void fp2_add_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp2 *c,
                           const Fp2 *a, const Fp2 *b, uint32_t n);
void fp2_mul_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp2 *c,
                           const Fp2 *a, const Fp2 *b, uint32_t n);
