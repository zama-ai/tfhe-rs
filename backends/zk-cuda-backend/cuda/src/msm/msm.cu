#include "checked_arithmetic.h"
#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstdlib>
#include <cstring>

// Multi-Scalar Multiplication (MSM) using Pippenger algorithm for BLS12-446
//
// The split primitives (launch_async + horner_finalize) are the fundamental
// building blocks. The blocking _async functions compose them with a sync
// in between, and the fully-blocking non-_async functions add a final sync.

// Forward declarations for split launch/finalize primitives (defined in
// msm_pippenger.cu). These are the canonical entry points into Pippenger.
void point_msm_g1_pippenger_launch_async(
    cudaStream_t stream, uint32_t gpu_index, G1Projective *h_window_sums,
    const G1Affine *d_points, const Scalar *d_scalars, uint32_t n,
    G1Projective *d_scratch, uint32_t &out_num_windows,
    uint32_t &out_window_size);
void point_msm_g1_horner_finalize(G1Projective *h_result,
                                  const G1Projective *h_window_sums,
                                  uint32_t num_windows, uint32_t window_size);

void point_msm_g2_pippenger_launch_async(
    cudaStream_t stream, uint32_t gpu_index, G2ProjectivePoint *h_window_sums,
    const G2Point *d_points, const Scalar *d_scalars, uint32_t n,
    G2ProjectivePoint *d_scratch, uint32_t &out_num_windows,
    uint32_t &out_window_size);
void point_msm_g2_horner_finalize(G2ProjectivePoint *h_result,
                                  const G2ProjectivePoint *h_window_sums,
                                  uint32_t num_windows, uint32_t window_size);

// ============================================================================
// Split Launch / Finalize wrappers (thin forwarding)
// ============================================================================

void point_msm_g1_launch_async(cudaStream_t stream, uint32_t gpu_index,
                               G1Projective *h_window_sums,
                               const G1Affine *d_points,
                               const Scalar *d_scalars, uint32_t n,
                               G1Projective *d_scratch,
                               uint32_t &out_num_windows,
                               uint32_t &out_window_size) {
  point_msm_g1_pippenger_launch_async(stream, gpu_index, h_window_sums,
                                      d_points, d_scalars, n, d_scratch,
                                      out_num_windows, out_window_size);
}

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

// ============================================================================
// Public MSM API for BigInt scalars
// ============================================================================
// These compose launch + sync + finalize. The temporary h_window_sums buffer
// is host-heap-allocated (via malloc) since the blocking pattern does not benefit
// from pinned memory — the sync happens before finalize reads the data.

void point_msm_g1_async(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *h_result, const G1Affine *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G1Projective *d_scratch) {
  uint32_t num_windows = 0, window_size = 0;
  constexpr uint32_t max_windows =
      CEIL_DIV(Scalar::NUM_BITS, MSM_G1_WINDOW_SIZE);

  // Temporary host buffer for window sums
  // TODO: benchmark cudaMallocHost (pinned memory) — it may improve async D2H
  // overlap
  auto *h_window_sums = static_cast<G1Projective *>(
      malloc(safe_mul_sizeof<G1Projective>(static_cast<size_t>(max_windows))));
  PANIC_IF_FALSE(h_window_sums != nullptr, "point_msm_g1_async: malloc failed");

  point_msm_g1_launch_async(stream, gpu_index, h_window_sums, d_points,
                            d_scalars, n, d_scratch, num_windows, window_size);
  cuda_synchronize_stream(stream, gpu_index);
  point_msm_g1_horner_finalize(h_result, h_window_sums, num_windows,
                               window_size);

  free(h_window_sums);
}

void point_msm_g2_async(cudaStream_t stream, uint32_t gpu_index,
                        G2ProjectivePoint *h_result, const G2Point *d_points,
                        const Scalar *d_scalars, uint32_t n,
                        G2ProjectivePoint *d_scratch) {
  uint32_t num_windows = 0, window_size = 0;
  constexpr uint32_t max_windows =
      CEIL_DIV(Scalar::NUM_BITS, MSM_G2_WINDOW_SIZE);

  // TODO: benchmark cudaMallocHost (pinned memory) — it may improve async D2H
  // overlap
  auto *h_window_sums = static_cast<G2ProjectivePoint *>(malloc(
      safe_mul_sizeof<G2ProjectivePoint>(static_cast<size_t>(max_windows))));
  PANIC_IF_FALSE(h_window_sums != nullptr, "point_msm_g2_async: malloc failed");

  point_msm_g2_launch_async(stream, gpu_index, h_window_sums, d_points,
                            d_scalars, n, d_scratch, num_windows, window_size);
  cuda_synchronize_stream(stream, gpu_index);
  point_msm_g2_horner_finalize(h_result, h_window_sums, num_windows,
                               window_size);

  free(h_window_sums);
}

// Fully-blocking wrappers. The _async functions above already sync internally
// (between launch and finalize), so the stream is idle when they return. This
// extra sync is kept for defensive correctness.
void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *h_result, const G1Affine *d_points,
                  const Scalar *d_scalars, uint32_t n,
                  G1Projective *d_scratch) {
  point_msm_g1_async(stream, gpu_index, h_result, d_points, d_scalars, n,
                     d_scratch);
  cuda_synchronize_stream(stream, gpu_index);
}

void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2ProjectivePoint *h_result, const G2Point *d_points,
                  const Scalar *d_scalars, uint32_t n,
                  G2ProjectivePoint *d_scratch) {
  point_msm_g2_async(stream, gpu_index, h_result, d_points, d_scalars, n,
                     d_scratch);
  cuda_synchronize_stream(stream, gpu_index);
}
