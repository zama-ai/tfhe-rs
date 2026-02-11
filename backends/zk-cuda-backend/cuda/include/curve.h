#pragma once

#include "fp.h"
#include "fp2.h"
#include <cstdint>
#include <cuda_runtime.h>

// Typedef for scalar type (320-bit integers, 5 limbs)
// Compatible with tfhe_zk_pok::curve_api::bls12_446::zp (BigInt<5>)
using Scalar = BigInt<ZP_LIMBS>;

// Forward declarations for zero initialization functions
__host__ __device__ void fp_zero(Fp &a);
__host__ __device__ void fp2_zero(Fp2 &a);

// Elliptic curve point structures for BLS12-446

// G1 point: (x, y) coordinates in Fp
// Curve equation: y^2 = x^3 + b (short Weierstrass form with a = 0)
struct G1Affine {
  Fp x;
  Fp y;
  bool infinity; // true if point at infinity (identity element)

  // Note: No constructor to allow aggregate initialization for __constant__
  // variables Use g1_point_at_infinity() helper function to initialize to point
  // at infinity

  // Operator overloads
  __host__ __device__ G1Affine operator+(const G1Affine &other) const;
  __host__ __device__ G1Affine operator-() const; // Unary negation
  __host__ __device__ bool operator==(const G1Affine &other) const;
  __host__ __device__ bool operator!=(const G1Affine &other) const;
  __host__ __device__ G1Affine &operator+=(const G1Affine &other);
};

// G2 point: (x, y) coordinates in Fp2
// Curve equation: y^2 = x^3 + b' (twisted curve over Fp2)
struct G2Affine {
  Fp2 x;
  Fp2 y;
  bool infinity; // true if point at infinity (identity element)

  // Note: No constructor to allow aggregate initialization for __constant__
  // variables Use g2_point_at_infinity() helper function to initialize to point
  // at infinity

  // Operator overloads
  __host__ __device__ G2Affine operator+(const G2Affine &other) const;
  __host__ __device__ G2Affine operator-() const; // Unary negation
  __host__ __device__ bool operator==(const G2Affine &other) const;
  __host__ __device__ bool operator!=(const G2Affine &other) const;
  __host__ __device__ G2Affine &operator+=(const G2Affine &other);
};

// G1 projective point: (X, Y, Z) coordinates in Fp (homogeneous coordinates)
// Represents the point (X/Z, Y/Z) in affine coordinates
struct G1Projective {
  Fp X;
  Fp Y;
  Fp Z;

  // Default constructor: initializes to point at infinity
  __host__ __device__ G1Projective() {
    fp_zero(X);
    fp_zero(Y);
    fp_zero(Z);
  }

  // Operator overloads
  __host__ __device__ G1Projective operator+(const G1Projective &other) const;
  __host__ __device__ G1Projective operator-() const; // Unary negation
  __host__ __device__ bool operator==(const G1Projective &other) const;
  __host__ __device__ bool operator!=(const G1Projective &other) const;
  __host__ __device__ G1Projective &operator+=(const G1Projective &other);
};

// G2 projective point: (X, Y, Z) coordinates in Fp2 (homogeneous coordinates)
// Represents the point (X/Z, Y/Z) in affine coordinates
struct G2Projective {
  Fp2 X;
  Fp2 Y;
  Fp2 Z;

  // Default constructor: initializes to point at infinity
  __host__ __device__ G2Projective() {
    fp2_zero(X);
    fp2_zero(Y);
    fp2_zero(Z);
  }

  // Operator overloads
  __host__ __device__ G2Projective operator+(const G2Projective &other) const;
  __host__ __device__ G2Projective operator-() const; // Unary negation
  __host__ __device__ bool operator==(const G2Projective &other) const;
  __host__ __device__ bool operator!=(const G2Projective &other) const;
  __host__ __device__ G2Projective &operator+=(const G2Projective &other);
};

// Type aliases for MSM compatibility
using G2Point = G2Affine;
using G2ProjectivePoint = G2Projective;

// Scalar multiplication operators (non-member functions)
// These allow natural syntax: scalar * point and point * scalar
__host__ __device__ G1Projective operator*(const Scalar &scalar,
                                           const G1Projective &point);
__host__ __device__ G1Projective operator*(const G1Projective &point,
                                           const Scalar &scalar);
__host__ __device__ G2Projective operator*(const Scalar &scalar,
                                           const G2Projective &point);
__host__ __device__ G2Projective operator*(const G2Projective &point,
                                           const Scalar &scalar);

// Curve parameters for BLS12-446
// These are constants that define the curve equation

// Get the curve coefficient b for G1 (y^2 = x^3 + b)
// Returns b as an Fp element
__host__ __device__ const Fp &curve_b_g1();

// Get the curve coefficient b' for G2 (y^2 = x^3 + b')
// Returns b' as an Fp2 element
__host__ __device__ const Fp2 &curve_b_g2();

// Check if a G1 point is on the curve
// Returns true if the point satisfies y^2 = x^3 + b (or is point at infinity)
__host__ __device__ bool is_on_curve_g1(const G1Affine &point);

// Check if a G2 point is on the curve
// Returns true if the point satisfies y^2 = x^3 + b' (or is point at infinity)
__host__ __device__ bool is_on_curve_g2(const G2Affine &point);

// Helper functions for point creation

// Create G1 point at infinity (identity element)
__host__ __device__ void g1_point_at_infinity(G1Affine &point);

// Create G2 point at infinity (identity element)
__host__ __device__ void g2_point_at_infinity(G2Affine &point);

// Check if G1 point is at infinity
__host__ __device__ bool g1_is_infinity(const G1Affine &point);

// Check if G2 point is at infinity
__host__ __device__ bool g2_is_infinity(const G2Affine &point);

// Projective point operations

// Convert affine point to projective: (x, y) -> (x, y, 1)
__host__ __device__ void affine_to_projective(G1Projective &proj,
                                              const G1Affine &affine);
__host__ __device__ void affine_to_projective(G2Projective &proj,
                                              const G2Affine &affine);

// Convert projective point to affine: (X, Y, Z) -> (X/Z, Y/Z)
__host__ __device__ void projective_to_affine_g1(G1Affine &affine,
                                                 const G1Projective &proj);
__host__ __device__ void projective_to_affine_g2(G2Affine &affine,
                                                 const G2Projective &proj);

// Create projective point at infinity: (0, 0, 0)
// Using Z=0 convention: a point is at infinity iff Z=0
__host__ __device__ void g1_projective_point_at_infinity(G1Projective &point);
__host__ __device__ void g2_projective_point_at_infinity(G2Projective &point);

// Convert point to Montgomery form in-place
// Single entry point that works for G1Affine, G2Affine, G1Projective, or
// G2Projective
__host__ void point_to_montgomery_inplace(G1Affine &point);
__host__ void point_to_montgomery_inplace(G2Affine &point);
__host__ void point_to_montgomery_inplace(G1Projective &point);
__host__ void point_to_montgomery_inplace(G2Projective &point);

// Convert projective point from Montgomery form in-place
__host__ void point_from_montgomery_inplace(G1Projective &point);
__host__ void point_from_montgomery_inplace(G2Projective &point);

// Normalize projective coordinates to Z=1 (for G1) or Z=(1,0) (for G2)
// Divides X and Y by Z, then sets Z to normalized form
// Point at infinity (Z=0) is left unchanged
__host__ void normalize_projective_g1(G1Projective &point);
__host__ void normalize_projective_g2(G2Projective &point);

// Convert from Montgomery form and normalize to Z=1 / Z=(1,0) in one pass.
// Input coordinates must be in Montgomery form. Output is in normal form with
// Z=1 (G1) or Z=(1,0) (G2). Avoids the redundant from_montgomery +
// to_montgomery round-trip of calling point_from_montgomery_inplace then
// normalize_projective_g*.
__host__ void normalize_from_montgomery_g1(G1Projective &point);
__host__ void normalize_from_montgomery_g2(G2Projective &point);

// Template point operations (work for both G1 and G2)
// These are generic functions that work with any point type via Affine

// Affine addition: result = p1 + p2
template <typename PointType>
__host__ __device__ void point_add(PointType &result, const PointType &p1,
                                   const PointType &p2);

// Affine doubling: result = 2 * p
template <typename PointType>
__host__ __device__ void point_double(PointType &result, const PointType &p);

// Affine negation: result = -p
template <typename PointType>
__host__ __device__ void point_neg(PointType &result, const PointType &p);

// Scalar multiplication: result = scalar * point
// scalar is represented as little-endian limbs (UNSIGNED_LIMB array)
// scalar_limbs is the number of limbs (at most FP_LIMBS)
template <typename PointType>
__host__ __device__ void
point_scalar_mul(PointType &result, const PointType &point,
                 const UNSIGNED_LIMB *scalar, uint32_t scalar_limbs);

// Generator points (hardcoded at compile time, like DEVICE_MODULUS)
extern __constant__ const G1Affine DEVICE_G1_GENERATOR;
extern __constant__ const G2Affine DEVICE_G2_GENERATOR;

// Get G1 generator point
__host__ __device__ const G1Affine &g1_generator();

// Get G2 generator point
__host__ __device__ const G2Affine &g2_generator();

// Multi-Scalar Multiplication (MSM)
// Computes: result = sum(scalars[i] * points[i]) for i = 0 to n-1
// Uses Pippenger's algorithm (bucket method) for efficiency
// The algorithm splits scalars into windows and uses buckets to accumulate
// points, significantly reducing the number of point operations compared to
// naive methods

// Pippenger algorithm constants
#define MSM_WINDOW_SIZE 4 // 4-bit windows
#define MSM_G1_BUCKET_COUNT                                                    \
  16 // 2^MSM_WINDOW_SIZE buckets (0-15) - legacy, kept for compatibility
#define MSM_SIGNED_BUCKET_COUNT                                                \
  8 // With signed recoding: buckets 1-8 (half the buckets)

// ============================================================================
// Template Async/Sync API for curve operations
// ============================================================================
// All pointers point to device memory (already allocated)
// _async versions: Launch kernels asynchronously, return immediately (no sync)
//  versions: Call _async then synchronize stream
// These template functions work for both G1 and G2 points
// ============================================================================

// Template point operations (all device pointers)

// Affine addition: d_result = d_p1 + d_p2
template <typename PointType>
void point_add_async(cudaStream_t stream, uint32_t gpu_index,
                     PointType *d_result, const PointType *d_p1,
                     const PointType *d_p2);
template <typename PointType>
void point_add(cudaStream_t stream, uint32_t gpu_index, PointType *d_result,
               const PointType *d_p1, const PointType *d_p2);

// Affine doubling: d_result = 2 * d_p
template <typename PointType>
void point_double_async(cudaStream_t stream, uint32_t gpu_index,
                        PointType *d_result, const PointType *d_p);
template <typename PointType>
void point_double(cudaStream_t stream, uint32_t gpu_index, PointType *d_result,
                  const PointType *d_p);

// Affine negation: d_result = -d_p
template <typename PointType>
void point_neg_async(cudaStream_t stream, uint32_t gpu_index,
                     PointType *d_result, const PointType *d_p);
template <typename PointType>
void point_neg(cudaStream_t stream, uint32_t gpu_index, PointType *d_result,
               const PointType *d_p);

// Scalar multiplication: d_result = scalar * d_point (single-limb scalar)
template <typename PointType>
void single_point_scalar_mul_async(cudaStream_t stream, uint32_t gpu_index,
                                   PointType *d_result,
                                   const PointType *d_point,
                                   UNSIGNED_LIMB scalar);
template <typename PointType>
void single_point_scalar_mul(cudaStream_t stream, uint32_t gpu_index,
                             PointType *d_result, const PointType *d_point,
                             UNSIGNED_LIMB scalar);

// Scalar multiplication: d_result = scalar * d_point (multi-limb scalar, device
// pointer)
template <typename PointType>
void point_scalar_mul_async(cudaStream_t stream, uint32_t gpu_index,
                            PointType *d_result, const PointType *d_point,
                            const UNSIGNED_LIMB *d_scalar,
                            uint32_t scalar_limbs);
template <typename PointType>
void point_scalar_mul(cudaStream_t stream, uint32_t gpu_index,
                      PointType *d_result, const PointType *d_point,
                      const UNSIGNED_LIMB *d_scalar, uint32_t scalar_limbs);

// Affine at infinity: d_result = O (identity element)
template <typename PointType>
void point_at_infinity_async(cudaStream_t stream, uint32_t gpu_index,
                             PointType *d_result);
template <typename PointType>
void point_at_infinity(cudaStream_t stream, uint32_t gpu_index,
                       PointType *d_result);

// Convert point to Montgomery form: d_result = to_montgomery(d_point)
// NOTE: All point operations assume points are in Montgomery form for
// performance
template <typename PointType>
void point_to_montgomery_async(cudaStream_t stream, uint32_t gpu_index,
                               PointType *d_result, const PointType *d_point);
template <typename PointType>
void point_to_montgomery(cudaStream_t stream, uint32_t gpu_index,
                         PointType *d_result, const PointType *d_point);

// Convert point from Montgomery form: d_result = from_montgomery(d_point)
template <typename PointType>
void point_from_montgomery_async(cudaStream_t stream, uint32_t gpu_index,
                                 PointType *d_result, const PointType *d_point);
template <typename PointType>
void point_from_montgomery(cudaStream_t stream, uint32_t gpu_index,
                           PointType *d_result, const PointType *d_point);

// Batch convert points to Montgomery form
template <typename PointType>
void point_to_montgomery_batch_async(cudaStream_t stream, uint32_t gpu_index,
                                     PointType *d_points, uint32_t n);
template <typename PointType>
void point_to_montgomery_batch(cudaStream_t stream, uint32_t gpu_index,
                               PointType *d_points, uint32_t n);

// ============================================================================
// Refactored MSM API (device pointers only, no allocations/copies/frees)
// ============================================================================
// All pointers are device pointers (already allocated by caller)
// Temporary buffer must be provided by caller:
//   - d_scratch: buffer of size (num_blocks + 1) * MSM_G1_BUCKET_COUNT *
//   sizeof(G1Point/G2Affine)
//     where num_blocks = CEIL_DIV(n, threadsPerBlock) (typically
//     256 threads per block) This provides space for:
//       * num_blocks * MSM_G1_BUCKET_COUNT points for per-block bucket
//       accumulations
//       * MSM_G1_BUCKET_COUNT points for final buckets
//     MSM_G1_BUCKET_COUNT is typically 16 (for 4-bit windows)
// Uses Pippenger algorithm (bucket method) with sppark-style single-pass
// accumulation

// Simple traits for MSM template (maps projective to affine point types)
template <typename ProjectivePointType> struct MSMTraits;

template <> struct MSMTraits<G1Projective> {
  using AffinePointType = G1Affine;
};

template <> struct MSMTraits<G2Projective> {
  using AffinePointType = G2Affine;
};

// ============================================================================
// MSM with BigInt5 scalars (default MSM implementation)
// ============================================================================
// These functions accept BigInt5* scalars (320-bit scalars, 5 limbs)
// BigInt5 represents a scalar as 5 limbs of 64 bits (320 bits total)
// Uses projective coordinates internally (no inversions!)

// MSM with BigInt scalars for G1 (projective result)
void point_msm_async_g1(cudaStream_t stream, uint32_t gpu_index,
                        G1Projective *d_result, const G1Affine *d_points,
                        const Scalar *d_scalars, G1Projective *d_scratch,
                        uint32_t n);
void point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                  G1Projective *d_result, const G1Affine *d_points,
                  const Scalar *d_scalars, G1Projective *d_scratch, uint32_t n);

// MSM with BigInt scalars for G2 (projective result)
void point_msm_async_g2(cudaStream_t stream, uint32_t gpu_index,
                        G2Projective *d_result, const G2Affine *d_points,
                        const Scalar *d_scalars, G2Projective *d_scratch,
                        uint32_t n);
void point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                  G2Projective *d_result, const G2Affine *d_points,
                  const Scalar *d_scalars, G2Projective *d_scratch, uint32_t n);

// Template MSM with BigInt scalars (works for both G1 and G2)
template <typename ProjectivePointType>
void point_msm_async(
    cudaStream_t stream, uint32_t gpu_index, ProjectivePointType *d_result,
    const typename MSMTraits<ProjectivePointType>::AffinePointType *d_points,
    const Scalar *d_scalars, ProjectivePointType *d_scratch, uint32_t n);

template <typename ProjectivePointType>
void point_msm(
    cudaStream_t stream, uint32_t gpu_index, ProjectivePointType *d_result,
    const typename MSMTraits<ProjectivePointType>::AffinePointType *d_points,
    const Scalar *d_scalars, ProjectivePointType *d_scratch, uint32_t n);
