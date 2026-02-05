#include "curve.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"

// Multi-Scalar Multiplication (MSM) common code
// Template traits used by MSM algorithms

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
  __host__ __device__ static int field_cmp(const FieldType &a,
                                           const FieldType &b) {
    return static_cast<int>(fp_cmp(a, b));
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
  __host__ __device__ static int field_cmp(const FieldType &a,
                                           const FieldType &b) {
    return static_cast<int>(fp2_cmp(a, b));
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
};

// Specialization for G2ProjectivePoint (uses Fp2)
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
};
