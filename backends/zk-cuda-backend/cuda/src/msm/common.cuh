#pragma once

#include "point_traits.h"

// ============================================================================
// MSM Kernel Templates (defined here so they're visible when instantiated)
// ============================================================================

// Pippenger kernel: Clear buckets (works for both affine and projective points)
template <typename PointType>
__global__ void kernel_clear_buckets(PointType *__restrict__ buckets,
                                     uint32_t num_buckets) {
  using AffinePoint = typename SelectorChooser<PointType>::Selection;

  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < num_buckets) {
    AffinePoint::point_at_infinity(buckets[idx]);
  }
}

// Pippenger kernel: Final reduction of bucket contributions from multiple
// blocks OPTIMIZED: Uses parallel tree reduction instead of sequential loop
// Launch config: <<<num_buckets, min(num_blocks, 256), shared_mem>>>
template <typename ProjectiveType>
__global__ void
kernel_reduce_buckets(ProjectiveType *__restrict__ final_buckets,
                      const ProjectiveType *__restrict__ block_buckets,
                      uint32_t num_blocks, uint32_t num_buckets) {
  using ProjectivePoint = Projective<ProjectiveType>;

  // Each block handles one bucket, threads cooperate to reduce all block
  // contributions
  uint32_t bucket_idx = blockIdx.x;
  if (bucket_idx == 0 || bucket_idx >= num_buckets) {
    if (threadIdx.x == 0 && bucket_idx == 0) {
      ProjectivePoint::point_at_infinity(final_buckets[0]);
    }
    return;
  }

  // Shared memory for parallel reduction
  extern __shared__ char shared_mem[];
  auto *shared_points = reinterpret_cast<ProjectiveType *>(shared_mem);

  // Each thread loads one block's contribution (or infinity if out of range)
  ProjectiveType my_point;
  if (threadIdx.x < num_blocks) {
    uint32_t idx = threadIdx.x * num_buckets + bucket_idx;
    my_point = block_buckets[idx];
  } else {
    ProjectivePoint::point_at_infinity(my_point);
  }

  // If num_blocks > blockDim.x, accumulate multiple blocks per thread
  for (uint32_t i = threadIdx.x + blockDim.x; i < num_blocks; i += blockDim.x) {
    uint32_t idx = i * num_buckets + bucket_idx;
    const ProjectiveType &contrib = block_buckets[idx];
    if (!ProjectivePoint::is_infinity(contrib)) {
      if (ProjectivePoint::is_infinity(my_point)) {
        my_point = contrib;
      } else {
        ProjectiveType temp;
        ProjectivePoint::projective_add(temp, my_point, contrib);
        my_point = temp;
      }
    }
  }

  shared_points[threadIdx.x] = my_point;
  __syncthreads();

  // Parallel tree reduction
  for (uint32_t stride = blockDim.x / 2; stride > 0; stride >>= 1) {
    if (threadIdx.x < stride) {
      if (!ProjectivePoint::is_infinity(shared_points[threadIdx.x + stride])) {
        if (ProjectivePoint::is_infinity(shared_points[threadIdx.x])) {
          shared_points[threadIdx.x] = shared_points[threadIdx.x + stride];
        } else {
          ProjectiveType temp;
          ProjectivePoint::projective_add(temp, shared_points[threadIdx.x],
                                          shared_points[threadIdx.x + stride]);
          shared_points[threadIdx.x] = temp;
        }
      }
    }
    __syncthreads();
  }

  // Thread 0 writes final result
  if (threadIdx.x == 0) {
    final_buckets[bucket_idx] = shared_points[0];
  }
}
