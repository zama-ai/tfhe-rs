#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstring>

// Multi-Scalar Multiplication (MSM) using Pippenger algorithm for BLS12-446

// Forward declarations for Pippenger implementations
void point_msm_g1_pippenger_async(cudaStream_t stream, uint32_t gpu_index,
                                  G1Projective *h_result,
                                  const G1Affine *d_points,
                                  const Scalar *d_scalars, uint32_t n,
                                  G1Projective *d_scratch);
void point_msm_g2_pippenger_async(cudaStream_t stream, uint32_t gpu_index,
                                  G2ProjectivePoint *h_result,
                                  const G2Point *d_points,
                                  const Scalar *d_scalars, uint32_t n,
                                  G2ProjectivePoint *d_scratch);

// Forward declarations for split launch/finalize (G2 only)
void point_msm_g2_pippenger_launch_async(
    cudaStream_t stream, uint32_t gpu_index, G2ProjectivePoint *h_window_sums,
    const G2Point *d_points, const Scalar *d_scalars, uint32_t n,
    G2ProjectivePoint *d_scratch, uint32_t &out_num_windows,
    uint32_t &out_window_size);
void point_msm_g2_horner_finalize(G2ProjectivePoint *h_result,
                                  const G2ProjectivePoint *h_window_sums,
                                  uint32_t num_windows, uint32_t window_size);

// ============================================================================
// Public MSM API for BigInt scalars
// ============================================================================

// MSM with BigInt scalars for G1 (projective coordinates internally)
// Result is written directly to the host pointer h_result.
void point_msm_g1_async(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *h_result, const G1Affine *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G1Projective *d_scratch) {
  point_msm_g1_pippenger_async(stream, gpu_index, h_result, d_points, d_scalars,
                               n, d_scratch);
}

// MSM with BigInt scalars for G2 (projective coordinates internally)
// Result is written directly to the host pointer h_result.
void point_msm_g2_async(cudaStream_t stream, uint32_t gpu_index,
                        G2ProjectivePoint *h_result, const G2Point *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G2ProjectivePoint *d_scratch) {
  point_msm_g2_pippenger_async(stream, gpu_index, h_result, d_points, d_scalars,
                               n, d_scratch);
}

void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *h_result, const G1Affine *d_points,
                  const Scalar *d_scalars, uint32_t n,
                  G1Projective *d_scratch) {
  point_msm_g1_async(stream, gpu_index, h_result, d_points, d_scalars, n,
                     d_scratch);
  // The async impl already syncs internally before the CPU-side Horner phase,
  // so the stream is idle here. This sync is kept for defensive correctness.
  cuda_synchronize_stream(stream, gpu_index);
}

void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2ProjectivePoint *h_result, const G2Point *d_points,
                  const Scalar *d_scalars, uint32_t n,
                  G2ProjectivePoint *d_scratch) {
  point_msm_g2_async(stream, gpu_index, h_result, d_points, d_scalars, n,
                     d_scratch);
  // See comment in point_msm_g1 above.
  cuda_synchronize_stream(stream, gpu_index);
}

// ============================================================================
// Split Launch / Finalize for Pipelined G2 MSM
// ============================================================================

void point_msm_g2_launch_async(cudaStream_t stream, uint32_t gpu_index,
                               G2ProjectivePoint *h_window_sums,
                               const G2Point *d_points, const Scalar *d_scalars,
                               uint32_t n, G2ProjectivePoint *d_scratch,
                               uint32_t &out_num_windows,
                               uint32_t &out_window_size) {
  point_msm_g2_pippenger_launch_async(stream, gpu_index, h_window_sums,
                                      d_points, d_scalars, n, d_scratch,
                                      out_num_windows, out_window_size);
}

// Note: point_msm_g2_horner_finalize is defined in msm_pippenger.cu and
// declared in msm.h — no additional wrapper needed here since the Pippenger
// TU already provides the non-template definition.
