#include "../common.cuh"
#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstdio>

// Template kernel_clear_buckets and projective_scalar_mul are defined in
// msm/common.cuh

// ============================================================================
// Naive MSM Kernels
// ============================================================================
// Naive MSM with block-level reduction: Each thread computes scalar[i] *
// point[i], then reduces within the block, producing one result per block
template <typename AffineType, typename ProjectiveType>
__global__ void kernel_naive_msm_compute_and_reduce(
    ProjectiveType *block_results, // One result per block
    const AffineType *points, const Scalar *scalars, uint32_t n) {
  using ProjectivePoint = ProjectiveSelector<ProjectiveType>;

  const uint32_t tid = threadIdx.x + blockIdx.x * blockDim.x;

  // Each thread computes its scalar * point
  ProjectiveType local_result;
  if (tid < n) {
    // Convert affine to projective
    ProjectiveType proj_point;
    ProjectivePoint::affine_to_projective(proj_point, points[tid]);

    // Compute scalar * point (works even if point is at infinity)
    projective_scalar_mul(local_result, proj_point, scalars[tid]);
  } else {
    // Threads beyond n: set to infinity
    ProjectivePoint::point_at_infinity(local_result);
  }

  extern __shared__ char shared_mem[];
  auto *shared_results = reinterpret_cast<ProjectiveType *>(shared_mem);
  shared_results[threadIdx.x] = local_result;
  __syncthreads();

  // Use shared memory for block-level reduction
  if (threadIdx.x == 0) {
    ProjectiveType block_sum;
    ProjectivePoint::point_at_infinity(block_sum);

    for (uint32_t i = 0; i < blockDim.x; i++) {
      const uint32_t global_idx = blockIdx.x * blockDim.x + i;
      if (global_idx < n && !ProjectivePoint::is_infinity(shared_results[i])) {
        if (ProjectivePoint::is_infinity(block_sum)) {
          ProjectivePoint::point_copy(block_sum, shared_results[i]);
        } else {
          ProjectiveType temp;
          ProjectivePoint::projective_add(temp, block_sum, shared_results[i]);
          ProjectivePoint::point_copy(block_sum, temp);
        }
      }
    }

    // Write block result
    ProjectivePoint::point_copy(block_results[blockIdx.x], block_sum);
  }
}

// Final reduction: Single thread sums all block results
template <typename ProjectiveType>
__global__ void
kernel_naive_msm_final_reduce(ProjectiveType *result,
                              const ProjectiveType *block_results,
                              uint32_t num_blocks) {
  using ProjectivePoint = ProjectiveSelector<ProjectiveType>;

  // Only thread 0 in block 0 does the final reduction
  if (threadIdx.x == 0 && blockIdx.x == 0) {
    ProjectiveType sum;
    ProjectivePoint::point_at_infinity(sum);

    // Sum all block results
    for (uint32_t i = 0; i < num_blocks; i++) {
      if (!ProjectivePoint::is_infinity(block_results[i])) {
        if (ProjectivePoint::is_infinity(sum)) {
          ProjectivePoint::point_copy(sum, block_results[i]);
        } else {
          ProjectiveType temp;
          ProjectivePoint::projective_add(temp, sum, block_results[i]);
          ProjectivePoint::point_copy(sum, temp);
        }
      }
    }

    ProjectivePoint::point_copy(*result, sum);
  }
}

// ============================================================================
// Naive MSM Implementation for G1
// ============================================================================

void point_msm_async_g1_naive(cudaStream_t stream, uint32_t gpu_index,
                              G1Projective *d_result, const G1Affine *d_points,
                              const Scalar *d_scalars, G1Projective *d_scratch,
                              uint32_t n) {
  (void)gpu_index; // Unused parameter

  if (n == 0) {
    kernel_clear_buckets<G1Projective><<<1, 1, 0, stream>>>(d_result, 1);
    check_cuda_error(cudaGetLastError());
    return;
  }
  // Naive MSM with block-level reduction
  // Step 1: Each thread computes scalar[i] * point[i], then reduce within block
  // Step 2: Reduce all block results to final result

  const uint32_t threadsPerBlock = 256;
  const uint32_t num_blocks = (n + threadsPerBlock - 1) / threadsPerBlock;

  G1Projective *d_block_results = d_scratch;

  const size_t shared_mem_size = threadsPerBlock * sizeof(G1Projective);
  kernel_naive_msm_compute_and_reduce<G1Affine, G1Projective>
      <<<num_blocks, threadsPerBlock, shared_mem_size, stream>>>(
          d_block_results, d_points, d_scalars, n);
  check_cuda_error(cudaGetLastError());

  kernel_naive_msm_final_reduce<G1Projective>
      <<<1, 1, 0, stream>>>(d_result, d_block_results, num_blocks);
  check_cuda_error(cudaGetLastError());
}

// ============================================================================
// Naive MSM Implementation for G2
// ============================================================================

void point_msm_async_g2_naive(cudaStream_t stream, uint32_t gpu_index,
                              G2ProjectivePoint *d_result,
                              const G2Point *d_points, const Scalar *d_scalars,
                              G2ProjectivePoint *d_scratch, uint32_t n) {
  (void)gpu_index; // Unused parameter

  if (n == 0) {
    kernel_clear_buckets<G2ProjectivePoint><<<1, 1, 0, stream>>>(d_result, 1);
    check_cuda_error(cudaGetLastError());
    return;
  }

  // G2 points are larger, use fewer threads per block
  const uint32_t threadsPerBlock = 128;
  const uint32_t num_blocks = (n + threadsPerBlock - 1) / threadsPerBlock;

  G2ProjectivePoint *d_block_results = d_scratch;

  const size_t shared_mem_size = threadsPerBlock * sizeof(G2ProjectivePoint);
  kernel_naive_msm_compute_and_reduce<G2Point, G2ProjectivePoint>
      <<<num_blocks, threadsPerBlock, shared_mem_size, stream>>>(
          d_block_results, d_points, d_scalars, n);
  check_cuda_error(cudaGetLastError());

  kernel_naive_msm_final_reduce<G2ProjectivePoint>
      <<<1, 1, 0, stream>>>(d_result, d_block_results, num_blocks);
  check_cuda_error(cudaGetLastError());
}
