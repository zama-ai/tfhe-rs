// Basic Multi-Scalar Multiplication (MSM) on BLS12-446 G1.
//
// Demonstrates the unmanaged GPU MSM API:
//   - Allocating device memory for points, scalars, result, and scratch space
//   - Copying data to the GPU and running point_msm_g1()
//   - Reading the result back and verifying against a naive scalar-mul sum
//
// The unmanaged API requires the caller to manage all allocations.  For a
// higher-level interface that handles memory internally, see the Rust bindings
// (G1Projective::msm in the Rust API).
//
// See README.md and include/msm.h for the full API reference.
//
// Build (from cuda/):
//   cmake -B build -DZK_CUDA_BACKEND_BUILD_TESTS=ON
//   cmake --build build --target basic_msm
//   ./build/tests_and_benchmarks/tests/basic/basic_msm

#include "curve.h"
#include "device.h"
#include "fp.h"
#include "msm.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
  if (!cuda_is_available()) {
    printf("CUDA not available, skipping.\n");
    return 0;
  }

  const uint32_t gpu_index = 0;
  const uint32_t n = 4; // number of points / scalars
  uint64_t size_tracker = 0;

  // ---- Prepare host-side points in Montgomery form ----
  // Use n doublings of the G1 generator: G, 2*G, 4*G, 8*G.
  const G1Affine &gen_normal = g1_generator();
  G1Affine gen = gen_normal;
  point_to_montgomery_inplace(gen);

  std::vector<G1Affine> h_points(n);
  h_points[0] = gen;
  for (uint32_t i = 1; i < n; i++) {
    point_double(h_points[i], h_points[i - 1]);
  }

  // ---- Prepare host-side scalars ----
  // Each scalar is a 320-bit little-endian integer (ZP_LIMBS × LIMB_BITS).
  // Use scalar[i] = i + 1, so MSM = 1*G + 2*(2G) + 3*(4G) + 4*(8G).
  std::vector<Scalar> h_scalars(n);
  for (uint32_t i = 0; i < n; i++) {
    memset(&h_scalars[i], 0, sizeof(Scalar));
    h_scalars[i].limb[0] = i + 1;
  }

  // ---- Allocate device memory ----
  cudaStream_t stream = cuda_create_stream(gpu_index);

  auto *d_points =
      static_cast<G1Affine *>(cuda_malloc(n * sizeof(G1Affine), gpu_index));
  auto *d_scalars =
      static_cast<Scalar *>(cuda_malloc(n * sizeof(Scalar), gpu_index));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc(sizeof(G1Projective), gpu_index));

  // Use pippenger_scratch_size_g1() to compute the required scratch allocation.
  size_t scratch_bytes = pippenger_scratch_size_g1(n, gpu_index);
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc(scratch_bytes, gpu_index));

  // ---- Copy inputs to the GPU ----
  cuda_memcpy_async_to_gpu(d_points, h_points.data(), n * sizeof(G1Affine),
                           stream, gpu_index);
  cuda_memcpy_async_to_gpu(d_scalars, h_scalars.data(), n * sizeof(Scalar),
                           stream, gpu_index);

  // ---- Run MSM (synchronous wrapper; internally async) ----
  // gpu_memory_allocated=true signals that all device pointers are already
  // allocated (i.e. d_points, d_scalars, d_result, d_scratch are on device).
  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, n, d_scratch,
               size_tracker, true);

  // ---- Read the result back ----
  G1Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G1Projective), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // ---- Verify against naive sequential computation on the host ----
  // Expected = sum over i of (scalar[i] * point[i]).
  // Use projective * Scalar operator; host-side affine scalar_mul is internal
  // only.
  G1Projective expected;
  g1_projective_point_at_infinity(expected);

  for (uint32_t i = 0; i < n; i++) {
    G1Projective term_proj;
    affine_to_projective(term_proj, h_points[i]);
    expected = expected + term_proj * h_scalars[i];
  }

  // Normalise to Z = 1 (Montgomery) before comparing projective coordinates.
  normalize_projective_g1(h_result);
  normalize_projective_g1(expected);
  assert(h_result == expected);
  printf("MSM result matches naive sequential computation.\n");

  // ---- Cleanup ----
  cuda_drop(d_points, gpu_index);
  cuda_drop(d_scalars, gpu_index);
  cuda_drop(d_result, gpu_index);
  cuda_drop(d_scratch, gpu_index);
  cuda_destroy_stream(stream, gpu_index);

  printf("All MSM basic operations passed.\n");
  return 0;
}
