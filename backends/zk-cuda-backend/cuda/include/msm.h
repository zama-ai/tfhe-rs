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
constexpr uint32_t KERNEL_THREADS_MAX = 256;

// G1 dynamic window selection thresholds
constexpr uint32_t MSM_G1_SMALL_THRESHOLD = 256; // n <= 256: use 4-bit windows
constexpr uint32_t MSM_G1_MEDIUM_THRESHOLD =
    4096; // n <= 4096: use 5-bit windows

// Pippenger algorithm parameters
constexpr uint32_t MSM_G1_WINDOW_SIZE = 4;   // 4-bit windows for G1
constexpr uint32_t MSM_G1_BUCKET_COUNT = 16; // 2^MSM_G1_WINDOW_SIZE buckets

// G2-specific parameters: larger window = fewer Horner doublings
// G2 benefits from larger windows because its field ops are 2x more expensive
constexpr uint32_t MSM_G2_WINDOW_SIZE = 5;   // 5-bit windows for G2
constexpr uint32_t MSM_G2_BUCKET_COUNT = 32; // 2^MSM_G2_WINDOW_SIZE buckets

// Threads per block for MSM kernels (must match implementation)
// These values are used for scratch space calculation in wrappers
constexpr uint32_t MSM_G1_THREADS_PER_BLOCK = 128;
constexpr uint32_t MSM_G2_THREADS_PER_BLOCK = 128;

// Helper function to get optimal threads per block for MSM based on point type.
// Uses 128 threads for both G1 and G2 for optimal SM occupancy on H100:
// - G1 with 128 threads: 15.6KB shared mem, allows 3 blocks per SM
// - G2 with 128 threads: 29.8KB shared mem, allows 1 block per SM
// Testing showed 64 threads is worse (25% slower for G2/4096).
template <typename PointType> uint32_t msm_threads_per_block(uint32_t n) {
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
// Scratch Size Helpers
// ============================================================================
// Compute the exact scratch buffer size (in bytes) needed by the Pippenger MSM
// implementation for a given input count. These match the internal scratch
// partitioning exactly: all_block_buckets + all_final_buckets + window_sums.
// The gpu_index is needed to query device shared memory limits, which affect
// the per-window block count.

size_t pippenger_scratch_size_g1(uint32_t n, uint32_t gpu_index);
size_t pippenger_scratch_size_g2(uint32_t n, uint32_t gpu_index);

// ============================================================================
// MSM with BigInt Scalars (320-bit scalars, default implementation)
// ============================================================================

// MSM for G1 points with BigInt scalars (projective result)
// Computes: result = sum(scalars[i] * points[i])
// Result is written directly to a host pointer (no device allocation needed for
// the result). Scratch space must be pre-allocated by the caller and passed via
// d_scratch as a typed projective pointer (G1Projective* for G1,
// G2ProjectivePoint* for G2). Use the scratch size helpers to query the
// required allocation size in bytes, then cast the allocation to the
// appropriate projective type.
// Arguments:
//   stream: CUDA stream for async execution
//   gpu_index: GPU device index
//   h_result: Host pointer to output (projective G1 point)
//   d_points: Device pointer to input affine G1 points (array of n points)
//   d_scalars: Device pointer to input BigInt scalars (array of n scalars)
//   n: Number of points/scalars
//   d_scratch: Caller-provided device scratch buffer for intermediate results
//   size_tracker: Reference for tracking GPU memory allocation sizes
void point_msm_g1_async(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *h_result, const G1Affine *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G1Projective *d_scratch, uint64_t &size_tracker,
                        bool gpu_memory_allocated);

void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *h_result, const G1Affine *d_points,
                  const Scalar *d_scalars, uint32_t n, G1Projective *d_scratch,
                  uint64_t &size_tracker, bool gpu_memory_allocated);

// MSM for G2 points with BigInt scalars (projective result)
// Result is written directly to a host pointer.
void point_msm_g2_async(cudaStream_t stream, uint32_t gpu_index,
                        G2ProjectivePoint *h_result, const G2Point *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G2ProjectivePoint *d_scratch, uint64_t &size_tracker,
                        bool gpu_memory_allocated);

void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2ProjectivePoint *h_result, const G2Point *d_points,
                  const Scalar *d_scalars, uint32_t n,
                  G2ProjectivePoint *d_scratch, uint64_t &size_tracker,
                  bool gpu_memory_allocated);
