#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstring>

// Multi-Scalar Multiplication (MSM) using Pippenger algorithm for BLS12-446

// Forward declarations for Pippenger implementations
void point_msm_async_g1_pippenger(cudaStream_t stream, uint32_t gpu_index,
                                  G1Projective *d_result,
                                  const G1Affine *d_points,
                                  const Scalar *d_scalars,
                                  G1Projective *d_scratch, uint32_t n,
                                  uint64_t &size_tracker);
void point_msm_async_g2_pippenger(cudaStream_t stream, uint32_t gpu_index,
                                  G2ProjectivePoint *d_result,
                                  const G2Point *d_points,
                                  const Scalar *d_scalars,
                                  G2ProjectivePoint *d_scratch, uint32_t n,
                                  uint64_t &size_tracker);

// ============================================================================
// Public MSM API for BigInt scalars
// ============================================================================

// MSM with BigInt scalars for G1 (projective coordinates internally)
void point_msm_async_g1(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *d_result, const G1Affine *d_points,
                        const Scalar *d_scalars, G1Projective *d_scratch,
                        uint32_t n, uint64_t &size_tracker) {
  point_msm_async_g1_pippenger(stream, gpu_index, d_result, d_points, d_scalars,
                               d_scratch, n, size_tracker);
}

// MSM with BigInt scalars for G2 (projective coordinates internally)
void point_msm_async_g2(cudaStream_t stream, uint32_t gpu_index,
                        G2ProjectivePoint *d_result, const G2Point *d_points,
                        const Scalar *d_scalars, G2ProjectivePoint *d_scratch,
                        uint32_t n, uint64_t &size_tracker) {
  point_msm_async_g2_pippenger(stream, gpu_index, d_result, d_points, d_scalars,
                               d_scratch, n, size_tracker);
}

void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *d_result, const G1Affine *d_points,
                  const Scalar *d_scalars, G1Projective *d_scratch, uint32_t n,
                  uint64_t &size_tracker) {
  point_msm_async_g1(stream, gpu_index, d_result, d_points, d_scalars,
                     d_scratch, n, size_tracker);
  cuda_synchronize_stream(stream, gpu_index);
}

void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2ProjectivePoint *d_result, const G2Point *d_points,
                  const Scalar *d_scalars, G2ProjectivePoint *d_scratch,
                  uint32_t n, uint64_t &size_tracker) {
  point_msm_async_g2(stream, gpu_index, d_result, d_points, d_scalars,
                     d_scratch, n, size_tracker);
  cuda_synchronize_stream(stream, gpu_index);
}
