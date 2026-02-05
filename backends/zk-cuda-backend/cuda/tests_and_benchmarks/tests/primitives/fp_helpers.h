#pragma once

#include "device.h"
#include "fp.h"
#include <cuda_runtime.h>

// ============================================================================
// CUDA Kernels for parallel Fp operations (test-only)
// ============================================================================

__global__ void kernel_fp_add_array(Fp *c, const Fp *a, const Fp *b,
                                    uint32_t n);
__global__ void kernel_fp_mul_array(Fp *c, const Fp *a, const Fp *b,
                                    uint32_t n);
__global__ void kernel_fp_mul_scalar(Fp *c, const Fp *a, const Fp *scalar,
                                     uint32_t n);

// ============================================================================
// Single-thread kernels for testing (test-only)
// ============================================================================

__global__ void kernel_fp_add(Fp *result, const Fp *a, const Fp *b);
__global__ void kernel_fp_sub(Fp *result, const Fp *a, const Fp *b);
__global__ void kernel_fp_mul(Fp *result, const Fp *a, const Fp *b);
__global__ void kernel_fp_neg(Fp *result, const Fp *a);
__global__ void kernel_fp_inv(Fp *result, const Fp *a);
__global__ void kernel_fp_div(Fp *result, const Fp *a, const Fp *b);
__global__ void kernel_fp_to_montgomery(Fp *result, const Fp *a);
__global__ void kernel_fp_from_montgomery(Fp *result, const Fp *a);
__global__ void kernel_fp_mont_mul(Fp *result, const Fp *a, const Fp *b);
__global__ void kernel_fp_cmp(int *result, const Fp *a, const Fp *b);
__global__ void kernel_fp_is_zero(bool *result, const Fp *a);
__global__ void kernel_fp_is_one(bool *result, const Fp *a);
__global__ void kernel_fp_copy(Fp *result, const Fp *a);
__global__ void kernel_fp_cmov(Fp *result, const Fp *src, uint64_t condition);
__global__ void kernel_fp_sqrt(bool *has_sqrt, Fp *result, const Fp *a);
__global__ void kernel_fp_is_quadratic_residue(bool *result, const Fp *a);
__global__ void kernel_fp_pow_u64(Fp *result, const Fp *base, uint64_t exp);
__global__ void kernel_fp_zero(Fp *result);
__global__ void kernel_fp_one(Fp *result);

// ============================================================================
// Batch operations (test-only)
// ============================================================================

void fp_add_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp *c,
                          const Fp *a, const Fp *b, uint32_t n);
void fp_mul_batch_on_host(cudaStream_t stream, uint32_t gpu_index, Fp *c,
                          const Fp *a, const Fp *b, uint32_t n);
void fp_add_array_on_device(cudaStream_t stream, uint32_t gpu_index, Fp *d_c,
                            const Fp *d_a, const Fp *d_b, uint32_t n);
void fp_mul_array_on_device(cudaStream_t stream, uint32_t gpu_index, Fp *d_c,
                            const Fp *d_a, const Fp *d_b, uint32_t n);
