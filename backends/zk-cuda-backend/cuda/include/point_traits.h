#pragma once

#include "curve.h"
#include "fp.h"
#include "fp2.h"

// ============================================================================
// Unified Trait System for Elliptic Curve Points
// ============================================================================
// Provides compile-time dispatch for field and point operations across G1/G2.
// Both affine (curve.cu) and MSM (msm/) code use these traits instead of
// maintaining separate copies.

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
__host__ __device__ void projective_mixed_add(G1Projective &result,
                                              const G1Projective &p1,
                                              const G1Affine &p2);
__host__ __device__ void projective_mixed_add(G2Projective &result,
                                              const G2Projective &p1,
                                              const G2Affine &p2);

// ============================================================================
// Affine<T>: trait for affine point operations
// ============================================================================

template <typename PointType> struct Affine;

template <> struct Affine<G1Affine> {
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

template <> struct Affine<G2Affine> {
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

  __host__ __device__ static void point_at_infinity(G2Affine &point) {
    g2_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G2Affine &point) {
    return g2_is_infinity(point);
  }
  __host__ __device__ static const FieldType &curve_b() { return curve_b_g2(); }
  __host__ __device__ static void point_copy(G2Affine &dst,
                                             const G2Affine &src) {
    dst = src;
  }
};

// ============================================================================
// Projective<T>: trait for projective point operations
// ============================================================================
// Includes mixed_add() for efficient projective + affine addition used by MSM.

template <typename PointType> struct Projective;

template <> struct Projective<G1Projective> {
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
  __host__ __device__ static void
  mixed_add(G1Projective &result, const G1Projective &p1, const G1Affine &p2) {
    projective_mixed_add(result, p1, p2);
  }
  __host__ __device__ static void point_copy(G1Projective &dst,
                                             const G1Projective &src) {
    dst = src;
  }
};

template <> struct Projective<G2Projective> {
  using FieldType = Fp2;
  using AffineType = G2Affine;

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

  __host__ __device__ static void point_at_infinity(G2Projective &point) {
    g2_projective_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G2Projective &point) {
    return fp2_is_zero(point.Z);
  }
  __host__ __device__ static void affine_to_projective(G2Projective &proj,
                                                       const G2Affine &affine) {
    ::affine_to_projective(proj, affine);
  }
  __host__ __device__ static void projective_add(G2Projective &result,
                                                 const G2Projective &p1,
                                                 const G2Projective &p2) {
    projective_point_add(result, p1, p2);
  }
  __host__ __device__ static void projective_double(G2Projective &result,
                                                    const G2Projective &p) {
    projective_point_double(result, p);
  }
  __host__ __device__ static void
  mixed_add(G2Projective &result, const G2Projective &p1, const G2Affine &p2) {
    projective_mixed_add(result, p1, p2);
  }
  __host__ __device__ static void point_copy(G2Projective &dst,
                                             const G2Projective &src) {
    dst = src;
  }
};

// ============================================================================
// SelectorChooser<T>: maps any point type to its trait struct
// ============================================================================

template <typename PointType> struct SelectorChooser;

template <> struct SelectorChooser<G1Affine> {
  using Selection = Affine<G1Affine>;
};

template <> struct SelectorChooser<G2Affine> {
  using Selection = Affine<G2Affine>;
};

template <> struct SelectorChooser<G1Projective> {
  using Selection = Projective<G1Projective>;
};

template <> struct SelectorChooser<G2Projective> {
  using Selection = Projective<G2Projective>;
};
