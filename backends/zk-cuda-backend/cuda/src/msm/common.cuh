#include "curve.h"
#include "fp.h"
#include "fp2.h"

// Forward declarations for projective point operations (implemented in
// curve.cu)
__host__ __device__ void projective_point_add(G1Projective &result,
                                              const G1Projective &p1,
                                              const G1Projective &p2);
__host__ __device__ void projective_point_add(G2Projective &result,
                                              const G2Projective &p1,
                                              const G2Projective &p2);
__host__ __device__ void projective_point_double(G1Projective &result,
                                                 const G1Projective &p);
__host__ __device__ void projective_point_double(G2Projective &result,
                                                 const G2Projective &p);
// Mixed addition: projective + affine (saves 3 field muls vs
// projective+projective)
__host__ __device__ void projective_mixed_add(G1Projective &result,
                                              const G1Projective &p1,
                                              const G1Affine &p2);
__host__ __device__ void projective_mixed_add(G2Projective &result,
                                              const G2Projective &p1,
                                              const G2Affine &p2);

// Multi-Scalar Multiplication (MSM) common code
// Template traits used by MSM algorithms
// Note: projective_point_add and projective_point_double are declared in
// curve.h

// ============================================================================
// Template Traits (needed by MSM kernels)
// ============================================================================

template <typename PointType> struct PointSelector;

// Specialization for G1Point (uses Fp)
template <> struct PointSelector<G1Affine> {
  using FieldType = Fp;

  __host__ __device__ static void field_zero(FieldType &a) { fp_zero(a); }
  __host__ __device__ static void field_copy(FieldType &dst,
                                             const FieldType &src) {
    dst = src;
  }
  __host__ __device__ static void field_neg(FieldType &c, const FieldType &a) {
    c = -a;
  }
  __host__ __device__ static void field_add(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    c = a + b;
  }
  __host__ __device__ static void field_sub(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    c = a - b;
  }
  __host__ __device__ static void field_mul(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    fp_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_inv(FieldType &c, const FieldType &a) {
    fp_mont_inv(c, a);
  }
  __host__ __device__ static ComparisonType field_cmp(const FieldType &a,
                                                      const FieldType &b) {
    return fp_cmp(a, b);
  }
  __host__ __device__ static bool field_is_zero(const FieldType &a) {
    return fp_is_zero(a);
  }
  __host__ __device__ static void field_to_montgomery(FieldType &c,
                                                      const FieldType &a) {
    fp_to_montgomery(c, a);
  }
  __host__ __device__ static void field_from_montgomery(FieldType &c,
                                                        const FieldType &a) {
    fp_from_montgomery(c, a);
  }

  __host__ __device__ static void point_at_infinity(G1Affine &point) {
    g1_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G1Affine &point) {
    return g1_is_infinity(point);
  }
  __host__ __device__ static const FieldType &curve_b() { return curve_b_g1(); }
  __host__ __device__ static void point_copy(G1Affine &dst,
                                             const G1Affine &src) {
    dst = src;
  }
};

// Specialization for G2Point (uses Fp2)
template <> struct PointSelector<G2Point> {
  using FieldType = Fp2;

  __host__ __device__ static void field_zero(FieldType &a) { fp2_zero(a); }
  __host__ __device__ static void field_copy(FieldType &dst,
                                             const FieldType &src) {
    dst = src;
  }
  __host__ __device__ static void field_neg(FieldType &c, const FieldType &a) {
    c = -a;
  }
  __host__ __device__ static void field_add(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    c = a + b;
  }
  __host__ __device__ static void field_sub(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    c = a - b;
  }
  __host__ __device__ static void field_mul(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    fp2_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_inv(FieldType &c, const FieldType &a) {
    fp2_mont_inv(c, a);
  }
  __host__ __device__ static ComparisonType field_cmp(const FieldType &a,
                                                      const FieldType &b) {
    return fp2_cmp(a, b);
  }
  __host__ __device__ static bool field_is_zero(const FieldType &a) {
    return fp2_is_zero(a);
  }
  __host__ __device__ static void field_to_montgomery(FieldType &c,
                                                      const FieldType &a) {
    fp_to_montgomery(c.c0, a.c0);
    fp_to_montgomery(c.c1, a.c1);
  }
  __host__ __device__ static void field_from_montgomery(FieldType &c,
                                                        const FieldType &a) {
    fp_from_montgomery(c.c0, a.c0);
    fp_from_montgomery(c.c1, a.c1);
  }

  __host__ __device__ static void point_at_infinity(G2Point &point) {
    g2_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G2Point &point) {
    return g2_is_infinity(point);
  }
  __host__ __device__ static const FieldType &curve_b() { return curve_b_g2(); }
  __host__ __device__ static void point_copy(G2Point &dst, const G2Point &src) {
    dst = src;
  }
};

template <typename ProjectiveType> struct ProjectiveSelector;

// Specialization for G1Projective (uses Fp)
template <> struct ProjectiveSelector<G1Projective> {
  using FieldType = Fp;
  using AffineType = G1Affine;

  __host__ __device__ static void field_zero(FieldType &a) { fp_zero(a); }
  __host__ __device__ static void field_copy(FieldType &dst,
                                             const FieldType &src) {
    dst = src;
  }
  __host__ __device__ static bool field_is_zero(const FieldType &a) {
    return fp_is_zero(a);
  }
  __host__ __device__ static void field_mul(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    fp_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_sub(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    c = a - b;
  }

  __host__ __device__ static void point_at_infinity(G1Projective &point) {
    g1_projective_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G1Projective &point) {
    return fp_is_zero(point.Z);
  }
  __host__ __device__ static void affine_to_projective(G1Projective &proj,
                                                       const G1Affine &affine) {
    ::affine_to_projective(proj, affine);
  }
  __host__ __device__ static void projective_add(G1Projective &result,
                                                 const G1Projective &p1,
                                                 const G1Projective &p2) {
    projective_point_add(result, p1, p2);
  }
  __host__ __device__ static void projective_double(G1Projective &result,
                                                    const G1Projective &p) {
    projective_point_double(result, p);
  }
  // Mixed addition: adds affine point to projective (saves 3 field muls)
  __host__ __device__ static void
  mixed_add(G1Projective &result, const G1Projective &p1, const G1Affine &p2) {
    projective_mixed_add(result, p1, p2);
  }
  __host__ __device__ static void point_copy(G1Projective &dst,
                                             const G1Projective &src) {
    dst = src;
  }
};

// Specialization for G2ProjectivePoint (uses Fp2)
// Note: G2ProjectivePoint is a type alias for G2Projective
template <> struct ProjectiveSelector<G2ProjectivePoint> {
  using FieldType = Fp2;
  using AffineType = G2Point;

  __host__ __device__ static void field_zero(FieldType &a) { fp2_zero(a); }
  __host__ __device__ static void field_copy(FieldType &dst,
                                             const FieldType &src) {
    dst = src;
  }
  __host__ __device__ static bool field_is_zero(const FieldType &a) {
    return fp2_is_zero(a);
  }
  __host__ __device__ static void field_mul(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    fp2_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_sub(FieldType &c, const FieldType &a,
                                            const FieldType &b) {
    c = a - b;
  }

  __host__ __device__ static void point_at_infinity(G2ProjectivePoint &point) {
    g2_projective_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G2ProjectivePoint &point) {
    return fp2_is_zero(point.Z);
  }
  __host__ __device__ static void affine_to_projective(G2ProjectivePoint &proj,
                                                       const G2Point &affine) {
    ::affine_to_projective(proj, affine);
  }
  __host__ __device__ static void projective_add(G2ProjectivePoint &result,
                                                 const G2ProjectivePoint &p1,
                                                 const G2ProjectivePoint &p2) {
    projective_point_add(result, p1, p2);
  }
  __host__ __device__ static void
  projective_double(G2ProjectivePoint &result, const G2ProjectivePoint &p) {
    projective_point_double(result, p);
  }
  // Mixed addition: adds affine point to projective (saves 3 field muls)
  __host__ __device__ static void mixed_add(G2ProjectivePoint &result,
                                            const G2ProjectivePoint &p1,
                                            const G2Point &p2) {
    projective_mixed_add(result, p1, p2);
  }
  __host__ __device__ static void point_copy(G2ProjectivePoint &dst,
                                             const G2ProjectivePoint &src) {
    dst = src;
  }
};

// ============================================================================
// MSM Kernel Templates (defined here so they're visible when instantiated)
// ============================================================================

// Helper to select appropriate selector for a point type (affine or projective)
template <typename PointType> struct SelectorChooser;

template <> struct SelectorChooser<G1Affine> {
  using Selection = PointSelector<G1Affine>;
};

template <> struct SelectorChooser<G2Point> {
  using Selection = PointSelector<G2Point>;
};

template <> struct SelectorChooser<G1Projective> {
  using Selection = ProjectiveSelector<G1Projective>;
};

template <> struct SelectorChooser<G2ProjectivePoint> {
  using Selection = ProjectiveSelector<G2ProjectivePoint>;
};

// Pippenger kernel: Clear buckets (works for both affine and projective points)
template <typename PointType>
__global__ void kernel_clear_buckets(PointType *buckets, uint32_t num_buckets) {
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
__global__ void kernel_reduce_buckets(ProjectiveType *final_buckets,
                                      const ProjectiveType *block_buckets,
                                      uint32_t num_blocks,
                                      uint32_t num_buckets) {
  using ProjectivePoint = ProjectiveSelector<ProjectiveType>;

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
