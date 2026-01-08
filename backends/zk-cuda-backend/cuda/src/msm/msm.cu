#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstring>

// Multi-Scalar Multiplication (MSM) implementations for BLS12-446
// Supports both naive (simple loop) and Pippenger (bucket-based) algorithms

// Compilation flag to select MSM algorithm
// Define USE_NAIVE_MSM to use the simple loop-based MSM
// Otherwise, use the Pippenger algorithm (default)
#ifndef USE_NAIVE_MSM
#define USE_NAIVE_MSM 0
#endif

// Forward declarations for naive implementations
void point_msm_async_g1_naive(cudaStream_t stream, uint32_t gpu_index,
                              G1Projective *d_result, const G1Affine *d_points,
                              const Scalar *d_scalars, G1Projective *d_scratch,
                              uint32_t n);
void point_msm_async_g2_naive(cudaStream_t stream, uint32_t gpu_index,
                              G2ProjectivePoint *d_result,
                              const G2Point *d_points, const Scalar *d_scalars,
                              G2ProjectivePoint *d_scratch, uint32_t n);

// Forward declarations for Pippenger implementations
void point_msm_async_g1_pippenger(cudaStream_t stream, uint32_t gpu_index,
                                  G1Projective *d_result,
                                  const G1Affine *d_points,
                                  const Scalar *d_scalars,
                                  G1Projective *d_scratch, uint32_t n);
void point_msm_async_g2_pippenger(cudaStream_t stream, uint32_t gpu_index,
                                  G2ProjectivePoint *d_result,
                                  const G2Point *d_points,
                                  const Scalar *d_scalars,
                                  G2ProjectivePoint *d_scratch, uint32_t n);

// ============================================================================
// Public MSM API for BigInt scalars
// ============================================================================

// MSM with BigInt scalars for G1 (projective coordinates internally)
void point_msm_async_g1(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *d_result, const G1Affine *d_points,
                        const Scalar *d_scalars, G1Projective *d_scratch,
                        uint32_t n) {
#if USE_NAIVE_MSM
  point_msm_async_g1_naive(stream, gpu_index, d_result, d_points, d_scalars,
                           d_scratch, n);
#else
  point_msm_async_g1_pippenger(stream, gpu_index, d_result, d_points, d_scalars,
                               d_scratch, n);
#endif
}

// MSM with BigInt scalars for G2 (projective coordinates internally)
void point_msm_async_g2(cudaStream_t stream, uint32_t gpu_index,
                        G2ProjectivePoint *d_result, const G2Point *d_points,
                        const Scalar *d_scalars, G2ProjectivePoint *d_scratch,
                        uint32_t n) {
#if USE_NAIVE_MSM
  point_msm_async_g2_naive(stream, gpu_index, d_result, d_points, d_scalars,
                           d_scratch, n);
#else
  point_msm_async_g2_pippenger(stream, gpu_index, d_result, d_points, d_scalars,
                               d_scratch, n);
#endif
}

void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *d_result, const G1Affine *d_points,
                  const Scalar *d_scalars, G1Projective *d_scratch,
                  uint32_t n) {
  point_msm_async_g1(stream, gpu_index, d_result, d_points, d_scalars,
                     d_scratch, n);
  cuda_synchronize_stream(stream, gpu_index);
}

void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2ProjectivePoint *d_result, const G2Point *d_points,
                  const Scalar *d_scalars, G2ProjectivePoint *d_scratch,
                  uint32_t n) {
  point_msm_async_g2(stream, gpu_index, d_result, d_points, d_scalars,
                     d_scratch, n);
  cuda_synchronize_stream(stream, gpu_index);
}
