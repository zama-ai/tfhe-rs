#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstring>

// Multi-Scalar Multiplication (MSM) using Pippenger algorithm for BLS12-446

// Forward declarations for Pippenger implementations
void point_msm_g1_pippenger_async(
    cudaStream_t stream, uint32_t gpu_index, G1Projective *d_result,
    const G1Affine *d_points, const Scalar *d_scalars, uint32_t n,
    G1Projective *d_scratch, uint64_t &size_tracker, bool gpu_memory_allocated);
void point_msm_g2_pippenger_async(cudaStream_t stream, uint32_t gpu_index,
                                  G2ProjectivePoint *d_result,
                                  const G2Point *d_points,
                                  const Scalar *d_scalars, uint32_t n,
                                  G2ProjectivePoint *d_scratch,
                                  uint64_t &size_tracker,
                                  bool gpu_memory_allocated);

// ============================================================================
// Public MSM API for BigInt scalars
// ============================================================================

// MSM with BigInt scalars for G1 (projective coordinates internally)
void point_msm_g1_async(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *d_result, const G1Affine *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G1Projective *d_scratch, uint64_t &size_tracker,
                        bool gpu_memory_allocated) {
  point_msm_g1_pippenger_async(stream, gpu_index, d_result, d_points, d_scalars,
                               n, d_scratch, size_tracker,
                               gpu_memory_allocated);
}

// MSM with BigInt scalars for G2 (projective coordinates internally)
void point_msm_g2_async(cudaStream_t stream, uint32_t gpu_index,
                        G2ProjectivePoint *d_result, const G2Point *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G2ProjectivePoint *d_scratch, uint64_t &size_tracker,
                        bool gpu_memory_allocated) {
  point_msm_g2_pippenger_async(stream, gpu_index, d_result, d_points, d_scalars,
                               n, d_scratch, size_tracker,
                               gpu_memory_allocated);
}

void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *d_result, const G1Affine *d_points,
                  const Scalar *d_scalars, uint32_t n, G1Projective *d_scratch,
                  uint64_t &size_tracker, bool gpu_memory_allocated) {
  point_msm_g1_async(stream, gpu_index, d_result, d_points, d_scalars, n,
                     d_scratch, size_tracker, gpu_memory_allocated);
  cuda_synchronize_stream(stream, gpu_index);
}

void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2ProjectivePoint *d_result, const G2Point *d_points,
                  const Scalar *d_scalars, uint32_t n,
                  G2ProjectivePoint *d_scratch, uint64_t &size_tracker,
                  bool gpu_memory_allocated) {
  point_msm_g2_async(stream, gpu_index, d_result, d_points, d_scalars, n,
                     d_scratch, size_tracker, gpu_memory_allocated);
  cuda_synchronize_stream(stream, gpu_index);
}
