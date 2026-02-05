#pragma once

#include "curve.h"
#include "fp.h"
#include "fp2.h"
#include <cuda_runtime.h>

// Multi-Scalar Multiplication (MSM) operations for BLS12-446 elliptic curves
// Implements Pippenger's algorithm (bucket method) for computing:
// result = sum(scalars[i] * points[i]) for i = 0 to n-1

// ============================================================================
// MSM Constants
// ============================================================================

// Kernel thread configuration
#define KERNEL_THREADS_MAX 256 // Maximum threads per block for general kernels

// G1 dynamic window selection thresholds
#define MSM_G1_SMALL_THRESHOLD 256   // n <= 256: use 4-bit windows
#define MSM_G1_MEDIUM_THRESHOLD 4096 // n <= 4096: use 5-bit windows

// Pippenger algorithm parameters
#define MSM_G1_WINDOW_SIZE 4   // 4-bit windows for G1
#define MSM_G1_BUCKET_COUNT 16 // 2^MSM_G1_WINDOW_SIZE buckets (0-15)

// G2-specific parameters: larger window = fewer Horner doublings
// G2 benefits from larger windows because its field ops are 2x more expensive
#define MSM_G2_WINDOW_SIZE 5   // 5-bit windows for G2
#define MSM_G2_BUCKET_COUNT 32 // 2^MSM_G2_WINDOW_SIZE buckets (0-31)

// Threads per block for MSM kernels (must match implementation)
// These values are used for scratch space calculation in wrappers
#define MSM_G1_THREADS_PER_BLOCK 128 // G1 uses 128 threads per block
#define MSM_G2_THREADS_PER_BLOCK                                               \
  128 // G2 uses 128 threads per block (register-based bucket accumulation)

// Helper function to get optimal threads per block for MSM based on point type.
// Uses 128 threads for both G1 and G2 for optimal SM occupancy on H100:
// - G1 with 128 threads: 15.6KB shared mem, allows 3 blocks per SM
// - G2 with 128 threads: 29.8KB shared mem, allows 1 block per SM
// Testing showed 64 threads is worse (25% slower for G2/4096).
template <typename PointType> int get_msm_threads_per_block(uint32_t n) {
  (void)n;
  return 128;
}

// Helper template to get the correct window size based on point type
// Specializations for G1 and G2 point types
template <typename PointType> struct MSMWindowSize;

template <> struct MSMWindowSize<G1Affine> {
  static constexpr uint32_t value = MSM_G1_WINDOW_SIZE;
};

template <> struct MSMWindowSize<G1Projective> {
  static constexpr uint32_t value = MSM_G1_WINDOW_SIZE;
};

template <> struct MSMWindowSize<G2Point> {
  static constexpr uint32_t value = MSM_G2_WINDOW_SIZE;
};

template <> struct MSMWindowSize<G2ProjectivePoint> {
  static constexpr uint32_t value = MSM_G2_WINDOW_SIZE;
};

// ============================================================================
// MSM with BigInt Scalars (320-bit scalars, default implementation)
// ============================================================================

// MSM for G1 points with BigInt scalars (projective result)
// Computes: result = sum(scalars[i] * points[i])
// Arguments:
//   stream: CUDA stream for async execution
//   gpu_index: GPU device index
//   d_result: Device pointer to output (projective G1 point)
//   d_points: Device pointer to input affine G1 points (array of n points)
//   d_scalars: Device pointer to input BigInt scalars (array of n scalars)
//   d_scratch: Device pointer to scratch buffer for intermediate results
//              Required size: (num_blocks + 1) * MSM_G1_BUCKET_COUNT *
//              sizeof(G1Projective)
//   n: Number of points/scalars
void point_msm_async_g1(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *d_result, const G1Affine *d_points,
                        const Scalar *d_scalars, G1Projective *d_scratch,
                        uint32_t n);

void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *d_result, const G1Affine *d_points,
                  const Scalar *d_scalars, G1Projective *d_scratch, uint32_t n);

// MSM for G2 points with BigInt scalars (projective result)
void point_msm_async_g2(cudaStream_t stream, uint32_t gpu_index,
                        G2ProjectivePoint *d_result, const G2Point *d_points,
                        const Scalar *d_scalars, G2ProjectivePoint *d_scratch,
                        uint32_t n);

void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2ProjectivePoint *d_result, const G2Point *d_points,
                  const Scalar *d_scalars, G2ProjectivePoint *d_scratch,
                  uint32_t n);
