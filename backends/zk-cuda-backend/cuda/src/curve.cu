#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstdio>
#include <cstring>

// ============================================================================
// Template Traits System for Affine Operations
// ============================================================================
// This traits system allows us to write generic point operations that work
// for both G1 (Fp) and G2 (Fp2) points using the same algorithm.

template <typename PointType> struct Affine;

// Specialization for G1Point (uses Fp)
template <> struct Affine<G1Affine> {
  using Field = Fp;

  __host__ __device__ static void field_zero(Field &a) { fp_zero(a); }
  __host__ __device__ static void field_copy(Field &dst, const Field &src) {
    dst = src;
  }
  __host__ __device__ static void field_neg(Field &c, const Field &a) {
    c = -a;
  }
  __host__ __device__ static void field_add(Field &c, const Field &a,
                                            const Field &b) {
    c = a + b;
  }
  __host__ __device__ static void field_sub(Field &c, const Field &a,
                                            const Field &b) {
    c = a - b;
  }
  __host__ __device__ static void field_mul(Field &c, const Field &a,
                                            const Field &b) {
    fp_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_inv(Field &c, const Field &a) {
    fp_mont_inv(c, a);
  }
  __host__ __device__ static ComparisonType field_cmp(const Field &a,
                                                      const Field &b) {
    return fp_cmp(a, b);
  }
  __host__ __device__ static bool field_is_zero(const Field &a) {
    return fp_is_zero(a);
  }
  __host__ __device__ static void field_to_montgomery(Field &c,
                                                      const Field &a) {
    fp_to_montgomery(c, a);
  }
  __host__ __device__ static void field_from_montgomery(Field &c,
                                                        const Field &a) {
    fp_from_montgomery(c, a);
  }

  __host__ __device__ static void point_at_infinity(G1Affine &point) {
    g1_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G1Affine &point) {
    return g1_is_infinity(point);
  }
  __host__ __device__ static const Field &curve_b() { return curve_b_g1(); }
  __host__ __device__ static void point_copy(G1Affine &dst,
                                             const G1Affine &src) {
    dst = src;
  }
};

// Specialization for G2Affine (uses Fp2)
template <> struct Affine<G2Affine> {
  using Field = Fp2;

  __host__ __device__ static void field_zero(Field &a) { fp2_zero(a); }
  __host__ __device__ static void field_copy(Field &dst, const Field &src) {
    dst = src;
  }
  __host__ __device__ static void field_neg(Field &c, const Field &a) {
    c = -a;
  }
  __host__ __device__ static void field_add(Field &c, const Field &a,
                                            const Field &b) {
    c = a + b;
  }
  __host__ __device__ static void field_sub(Field &c, const Field &a,
                                            const Field &b) {
    c = a - b;
  }
  __host__ __device__ static void field_mul(Field &c, const Field &a,
                                            const Field &b) {
    fp2_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_inv(Field &c, const Field &a) {
    fp2_mont_inv(c, a);
  }
  __host__ __device__ static ComparisonType field_cmp(const Field &a,
                                                      const Field &b) {
    return fp2_cmp(a, b);
  }
  __host__ __device__ static bool field_is_zero(const Field &a) {
    return fp2_is_zero(a);
  }
  __host__ __device__ static void field_to_montgomery(Field &c,
                                                      const Field &a) {
    fp_to_montgomery(c.c0, a.c0);
    fp_to_montgomery(c.c1, a.c1);
  }
  __host__ __device__ static void field_from_montgomery(Field &c,
                                                        const Field &a) {
    fp_from_montgomery(c.c0, a.c0);
    fp_from_montgomery(c.c1, a.c1);
  }

  __host__ __device__ static void point_at_infinity(G2Affine &point) {
    g2_point_at_infinity(point);
  }
  __host__ __device__ static bool is_infinity(const G2Affine &point) {
    return g2_is_infinity(point);
  }
  __host__ __device__ static const Field &curve_b() { return curve_b_g2(); }
  __host__ __device__ static void point_copy(G2Affine &dst,
                                             const G2Affine &src) {
    dst = src;
  }
};

// Forward declarations for projective point operations (needed by Projective)
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

// ============================================================================
// Template Traits System for Projective Points
// ============================================================================

template <typename PointType> struct Projective;

// Specialization for G1Projective (uses Fp)
template <> struct Projective<G1Projective> {
  using Field = Fp;
  using Affine = G1Affine;

  __host__ __device__ static void field_zero(Field &a) { fp_zero(a); }
  __host__ __device__ static void field_copy(Field &dst, const Field &src) {
    dst = src;
  }
  __host__ __device__ static bool field_is_zero(const Field &a) {
    return fp_is_zero(a);
  }
  __host__ __device__ static void field_mul(Field &c, const Field &a,
                                            const Field &b) {
    fp_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_sub(Field &c, const Field &a,
                                            const Field &b) {
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
    affine_to_projective(proj, affine);
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
  __host__ __device__ static void point_copy(G1Projective &dst,
                                             const G1Projective &src) {
    dst = src;
  }
};

// Specialization for G2Projective (uses Fp2)
template <> struct Projective<G2Projective> {
  using Field = Fp2;
  using Affine = G2Affine;

  __host__ __device__ static void field_zero(Field &a) { fp2_zero(a); }
  __host__ __device__ static void field_copy(Field &dst, const Field &src) {
    dst = src;
  }
  __host__ __device__ static bool field_is_zero(const Field &a) {
    return fp2_is_zero(a);
  }
  __host__ __device__ static void field_mul(Field &c, const Field &a,
                                            const Field &b) {
    fp2_mont_mul(c, a, b);
  }
  __host__ __device__ static void field_sub(Field &c, const Field &a,
                                            const Field &b) {
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
    affine_to_projective(proj, affine);
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
  __host__ __device__ static void point_copy(G2Projective &dst,
                                             const G2Projective &src) {
    dst = src;
  }
};

// ============================================================================
// Template Scalar Multiplication for Projective Points
// ============================================================================

// Template scalar multiplication for projective points: result = scalar * point
// Works for both G1 and G2 using Projective
template <typename PointType>
__host__ __device__ void projective_scalar_mul(PointType &result,
                                               const PointType &point,
                                               const Scalar &scalar) {
  using ProjectivePoint = Projective<PointType>;

  // Start with point at infinity
  ProjectivePoint::point_at_infinity(result);

  if (ProjectivePoint::is_infinity(point)) {
    return;
  }

  // Check if scalar is zero
  bool all_zero = true;
  for (int i = 0; i < ZP_LIMBS; i++) {
    if (scalar.limb[i] != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    return;
  }

  PointType current = point;

  // Find the MSB (most significant non-zero bit)
  int msb_limb = -1;
  int msb_bit = -1;
  for (int limb = ZP_LIMBS - 1; limb >= 0; limb--) {
    if (scalar.limb[limb] != 0) {
      msb_limb = limb;
      // Find the MSB bit in this limb
      for (int bit = LIMB_BITS - 1; bit >= 0; bit--) {
        if ((scalar.limb[limb] >> bit) & 1) {
          msb_bit = bit;
          break;
        }
      }
      break;
    }
  }

  // If scalar is zero (shouldn't happen due to check above, but be safe)
  if (msb_limb == -1) {
    return;
  }

  // Process bits from MSB to LSB
  bool first_bit = true;
  for (int limb = msb_limb; limb >= 0; limb--) {
    int start_bit = (limb == msb_limb) ? msb_bit : (LIMB_BITS - 1);
    for (int bit = start_bit; bit >= 0; bit--) {
      if (first_bit) {
        // For the first (MSB) bit, if it's 1, set result = point, otherwise
        // leave as infinity
        if ((scalar.limb[limb] >> bit) & 1) {
          result = current;
        }
        first_bit = false;
      } else {
        // For subsequent bits: double, then add if bit is set
        ProjectivePoint::projective_double(result, result);
        if ((scalar.limb[limb] >> bit) & 1) {
          PointType temp;
          ProjectivePoint::projective_add(temp, result, current);
          result = temp;
        }
      }
    }
  }
}

// ============================================================================
// Point Struct Operator Implementations
// ============================================================================

// G1Affine operators
__host__ __device__ G1Affine G1Affine::operator+(const G1Affine &other) const {
  G1Affine result;
  point_add(result, *this, other);
  return result;
}

__host__ __device__ G1Affine G1Affine::operator-() const {
  G1Affine result;
  point_neg(result, *this);
  return result;
}

__host__ __device__ bool G1Affine::operator==(const G1Affine &other) const {
  if (infinity && other.infinity)
    return true;
  if (infinity != other.infinity)
    return false;
  return (x == other.x) && (y == other.y);
}

__host__ __device__ bool G1Affine::operator!=(const G1Affine &other) const {
  return !(*this == other);
}

__host__ __device__ G1Affine &G1Affine::operator+=(const G1Affine &other) {
  G1Affine result;
  point_add(result, *this, other);
  *this = result;
  return *this;
}

// G2Affine operators
__host__ __device__ G2Affine G2Affine::operator+(const G2Affine &other) const {
  G2Affine result;
  point_add(result, *this, other);
  return result;
}

__host__ __device__ G2Affine G2Affine::operator-() const {
  G2Affine result;
  point_neg(result, *this);
  return result;
}

__host__ __device__ bool G2Affine::operator==(const G2Affine &other) const {
  if (infinity && other.infinity)
    return true;
  if (infinity != other.infinity)
    return false;
  return (x == other.x) && (y == other.y);
}

__host__ __device__ bool G2Affine::operator!=(const G2Affine &other) const {
  return !(*this == other);
}

__host__ __device__ G2Affine &G2Affine::operator+=(const G2Affine &other) {
  G2Affine result;
  point_add(result, *this, other);
  *this = result;
  return *this;
}

// G1Projective operators
__host__ __device__ G1Projective
G1Projective::operator+(const G1Projective &other) const {
  G1Projective result;
  projective_point_add(result, *this, other);
  return result;
}

__host__ __device__ G1Projective G1Projective::operator-() const {
  G1Projective result;
  result.X = X;
  result.Y = -Y;
  result.Z = Z;
  return result;
}

__host__ __device__ bool
G1Projective::operator==(const G1Projective &other) const {
  // Both at infinity
  if (fp_is_zero(Z) && fp_is_zero(other.Z))
    return true;
  // One at infinity, other not
  if (fp_is_zero(Z) != fp_is_zero(other.Z))
    return false;
  // Compare in projective form: (X1/Z1, Y1/Z1) == (X2/Z2, Y2/Z2)
  // => X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
  Fp lhs1, rhs1, lhs2, rhs2;
  fp_mont_mul(lhs1, X, other.Z);
  fp_mont_mul(rhs1, other.X, Z);
  fp_mont_mul(lhs2, Y, other.Z);
  fp_mont_mul(rhs2, other.Y, Z);
  return (lhs1 == rhs1) && (lhs2 == rhs2);
}

__host__ __device__ bool
G1Projective::operator!=(const G1Projective &other) const {
  return !(*this == other);
}

__host__ __device__ G1Projective &
G1Projective::operator+=(const G1Projective &other) {
  G1Projective result;
  projective_point_add(result, *this, other);
  *this = result;
  return *this;
}

// G2Projective operators
__host__ __device__ G2Projective
G2Projective::operator+(const G2Projective &other) const {
  G2Projective result;
  projective_point_add(result, *this, other);
  return result;
}

__host__ __device__ G2Projective G2Projective::operator-() const {
  G2Projective result;
  result.X = X;
  result.Y = -Y;
  result.Z = Z;
  return result;
}

__host__ __device__ bool
G2Projective::operator==(const G2Projective &other) const {
  // Both at infinity
  if (fp2_is_zero(Z) && fp2_is_zero(other.Z))
    return true;
  // One at infinity, other not
  if (fp2_is_zero(Z) != fp2_is_zero(other.Z))
    return false;
  // Compare in projective form
  Fp2 lhs1, rhs1, lhs2, rhs2;
  fp2_mont_mul(lhs1, X, other.Z);
  fp2_mont_mul(rhs1, other.X, Z);
  fp2_mont_mul(lhs2, Y, other.Z);
  fp2_mont_mul(rhs2, other.Y, Z);
  return (lhs1 == rhs1) && (lhs2 == rhs2);
}

__host__ __device__ bool
G2Projective::operator!=(const G2Projective &other) const {
  return !(*this == other);
}

__host__ __device__ G2Projective &
G2Projective::operator+=(const G2Projective &other) {
  G2Projective result;
  projective_point_add(result, *this, other);
  *this = result;
  return *this;
}

// Scalar multiplication operators (non-member)
__host__ __device__ G1Projective operator*(const Scalar &scalar,
                                           const G1Projective &point) {
  G1Projective result;
  projective_scalar_mul(result, point, scalar);
  return result;
}

__host__ __device__ G1Projective operator*(const G1Projective &point,
                                           const Scalar &scalar) {
  return scalar * point;
}

__host__ __device__ G2Projective operator*(const Scalar &scalar,
                                           const G2Projective &point) {
  G2Projective result;
  projective_scalar_mul(result, point, scalar);
  return result;
}

__host__ __device__ G2Projective operator*(const G2Projective &point,
                                           const Scalar &scalar) {
  return scalar * point;
}

// ============================================================================
// Template Affine Operations
// ============================================================================

// Generic point negation: result = -p = (x, -y)
template <typename PointType>
__host__ __device__ void point_neg(PointType &result, const PointType &p) {
  using AffinePoint = Affine<PointType>;
  if (AffinePoint::is_infinity(p)) {
    AffinePoint::point_at_infinity(result);
    return;
  }
  AffinePoint::field_copy(result.x, p.x);
  AffinePoint::field_neg(result.y, p.y);
  result.infinity = false;
}

// Generic point doubling: result = 2 * p
template <typename PointType>
__host__ __device__ void point_double(PointType &result, const PointType &p) {
  using AffinePoint = Affine<PointType>;
  using FieldType = typename AffinePoint::Field;

  if (AffinePoint::is_infinity(p) || AffinePoint::field_is_zero(p.y)) {
    AffinePoint::point_at_infinity(result);
    return;
  }

  // Compute lambda = 3*x^2 / (2*y)
  FieldType x_squared, three_x_squared, two_y, lambda;
  AffinePoint::field_mul(x_squared, p.x, p.x);
  AffinePoint::field_add(three_x_squared, x_squared, x_squared);       // 2*x^2
  AffinePoint::field_add(three_x_squared, three_x_squared, x_squared); // 3*x^2

  AffinePoint::field_add(two_y, p.y, p.y);                 // 2*y
  AffinePoint::field_inv(lambda, two_y);                   // 1/(2*y)
  AffinePoint::field_mul(lambda, lambda, three_x_squared); // 3*x^2 / (2*y)

  // x_result = lambda^2 - 2*x
  FieldType lambda_squared, two_x, x_result;
  AffinePoint::field_mul(lambda_squared, lambda, lambda);
  AffinePoint::field_add(two_x, p.x, p.x); // 2*x
  AffinePoint::field_sub(x_result, lambda_squared, two_x);

  // y_result = lambda*(x - x_result) - y
  FieldType x_minus_xr, y_result;
  AffinePoint::field_sub(x_minus_xr, p.x, x_result);
  AffinePoint::field_mul(y_result, lambda, x_minus_xr);
  AffinePoint::field_sub(y_result, y_result, p.y);

  AffinePoint::field_copy(result.x, x_result);
  AffinePoint::field_copy(result.y, y_result);
  result.infinity = false;
}

// Generic point addition: result = p1 + p2
template <typename PointType>
__host__ __device__ void point_add(PointType &result, const PointType &p1,
                                   const PointType &p2) {
  using AffinePoint = Affine<PointType>;
  using Field = typename AffinePoint::Field;

  // Handle infinity cases
  if (AffinePoint::is_infinity(p1)) {
    result = p2;
    return;
  }
  if (AffinePoint::is_infinity(p2)) {
    result = p1;
    return;
  }

  // Check if p1 == -p2 (same x, opposite y)
  Field neg_y2;
  AffinePoint::field_neg(neg_y2, p2.y);
  if (AffinePoint::field_cmp(p1.x, p2.x) == ComparisonType::Equal &&
      AffinePoint::field_cmp(p1.y, neg_y2) == ComparisonType::Equal) {
    AffinePoint::point_at_infinity(result);
    return;
  }

  // Check if p1 == p2 (use doubling)
  if (AffinePoint::field_cmp(p1.x, p2.x) == ComparisonType::Equal &&
      AffinePoint::field_cmp(p1.y, p2.y) == ComparisonType::Equal) {
    point_double(result, p1);
    return;
  }

  // Standard addition: lambda = (y2 - y1) / (x2 - x1)
  Field dx, dy, lambda, lambda_squared, x_result;
  AffinePoint::field_sub(dx, p2.x, p1.x);
  AffinePoint::field_sub(dy, p2.y, p1.y);
  AffinePoint::field_inv(lambda, dx);         // 1 / (x2 - x1)
  AffinePoint::field_mul(lambda, lambda, dy); // (y2 - y1) / (x2 - x1)

  // x_result = lambda^2 - x1 - x2
  AffinePoint::field_mul(lambda_squared, lambda, lambda);
  AffinePoint::field_sub(x_result, lambda_squared, p1.x);
  AffinePoint::field_sub(x_result, x_result, p2.x);

  // y_result = lambda * (x1 - x_result) - y1
  Field x1_minus_xr, y_result;
  AffinePoint::field_sub(x1_minus_xr, p1.x, x_result);
  AffinePoint::field_mul(y_result, lambda, x1_minus_xr);
  AffinePoint::field_sub(y_result, y_result, p1.y);

  AffinePoint::field_copy(result.x, x_result);
  AffinePoint::field_copy(result.y, y_result);
  result.infinity = false;
}

// Generic scalar multiplication: result = scalar * point
template <typename PointType>
__host__ __device__ void
point_scalar_mul(PointType &result, const PointType &point,
                 const uint64_t *scalar, uint32_t scalar_limbs) {
  using AffinePoint = Affine<PointType>;

  // Start with point at infinity (initialize result first)
  AffinePoint::point_at_infinity(result);

  if (AffinePoint::is_infinity(point)) {
    return;
  }

  // Check if scalar is zero
  bool all_zero = true;
  for (int i = 0; i < scalar_limbs; i++) {
    if (scalar[i] != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    return;
  }

  PointType addend = point;

  // Find the MSB (most significant non-zero bit)
  int msb_limb = -1;
  int msb_bit = -1;
  for (int limb = scalar_limbs - 1; limb >= 0; limb--) {
    if (scalar[limb] != 0) {
      msb_limb = limb;
      // Find the MSB bit in this limb
      // TODO: Isn't there a intrinsic for that?
      for (int bit = LIMB_BITS - 1; bit >= 0; bit--) {
        if ((scalar[limb] >> bit) & 1) {
          msb_bit = bit;
          break;
        }
      }
      break;
    }
  }

  // If scalar is zero (shouldn't happen due to check above, but be safe)
  if (msb_limb == -1) {
    return;
  }

  // Process bits from LSB to MSB (matching Python algorithm)
  // For each bit: if set, add addend to result, then double addend
  for (int limb = 0; limb <= msb_limb; limb++) {
    int end_bit = (limb == msb_limb) ? msb_bit : (LIMB_BITS - 1);
    for (int j = 0; j <= end_bit; j++) {
      auto bit = (scalar[limb] >> j) & 1;
      if (bit) {
        point_add(result, result, addend);
      }
      point_double(addend, addend);
    }
  }
}

// Curve parameters for BLS12-446
// G1 curve: y^2 = x^3 + b
// G2 curve: y^2 = x^3 + b' where b' = b * ξ (ξ is a non-residue in Fp2)

// Device constants for curve parameters
// Hardcoded at compile time (like DEVICE_MODULUS) to avoid cudaMemcpyToSymbol
// According to https://std.neuromancer.sk/bls/BLS12-446, b = 1
// G1 curve coefficient: b = 1 (in normal form)
__constant__ const Fp DEVICE_CURVE_B_G1 = {
    {1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};

// G2 curve coefficient: b' = b * ξ where ξ = i (non-residue)
// So b' = (0 + 1*i) in Fp2 (in normal form)
__constant__ const Fp2 DEVICE_CURVE_B_G2 = {
    {{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}}, // c0 = 0
    {{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}}  // c1 = 1
};

// Get curve coefficient b for G1
__host__ __device__ const Fp &curve_b_g1() {
#ifdef __CUDA_ARCH__
  return DEVICE_CURVE_B_G1;
#else
  // Note: Value is in normal form
  static const Fp host_b = {{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};
  return host_b;
#endif
}

// Get curve coefficient b' for G2
__host__ __device__ const Fp2 &curve_b_g2() {
#ifdef __CUDA_ARCH__
  return DEVICE_CURVE_B_G2;
#else
  // Note: Values are in normal form
  static const Fp2 host_b = {
      {{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}}, // c0 = 0
      {{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}}  // c1 = 1
  };
  return host_b;
#endif
}

// ============================================================================
// Cached Montgomery Form Constants for Curve Operations
// ============================================================================
// These functions return references to cached Montgomery form constants
// to avoid recomputing them on every projective point operation call.
// For host code: uses static locals (thread-safe in C++11)
// For device code: computes once per call (cached via output parameter)

// Helper struct to hold cached Fp Montgomery constants
struct FpMontConstants {
  Fp two;
  Fp three;
  Fp four;
  Fp eight;
};

// Helper struct to hold cached Fp2 Montgomery constants
struct Fp2MontConstants {
  Fp2 two;
  Fp2 three;
  Fp2 four;
  Fp2 eight;
};

// Get cached Fp Montgomery constants (for host code)
__host__ const FpMontConstants &get_fp_mont_constants_host() {
  static FpMontConstants constants = []() {
    FpMontConstants c;
    fp_two_montgomery(c.two);
    fp_three_montgomery(c.three);
    fp_four_montgomery(c.four);
    fp_eight_montgomery(c.eight);
    return c;
  }();
  return constants;
}

// Get cached Fp2 Montgomery constants (for host code)
__host__ const Fp2MontConstants &get_fp2_mont_constants_host() {
  static Fp2MontConstants constants = []() {
    Fp2MontConstants c;
    fp2_two_montgomery(c.two);
    fp2_three_montgomery(c.three);
    fp2_four_montgomery(c.four);
    fp2_eight_montgomery(c.eight);
    return c;
  }();
  return constants;
}

// Initialize Fp Montgomery constants (for device code, called once per
// function)
__device__ void init_fp_mont_constants(Fp &two, Fp &three, Fp &four,
                                       Fp &eight) {
  fp_two_montgomery(two);
  fp_three_montgomery(three);
  fp_four_montgomery(four);
  fp_eight_montgomery(eight);
}

// Initialize Fp2 Montgomery constants (for device code, called once per
// function)
__device__ void init_fp2_mont_constants(Fp2 &two, Fp2 &three, Fp2 &four,
                                        Fp2 &eight) {
  fp2_two_montgomery(two);
  fp2_three_montgomery(three);
  fp2_four_montgomery(four);
  fp2_eight_montgomery(eight);
}

// Check if a G1 point is on the curve: y^2 = x^3 + b
// Uses Montgomery form internally for efficiency
__host__ __device__ bool is_on_curve_g1(const G1Affine &point) {
  // Affine at infinity is always on the curve
  if (point.infinity) {
    return true;
  }

  // Convert coordinates to Montgomery form
  Fp x_mont, y_mont;
  fp_to_montgomery(x_mont, point.x);
  fp_to_montgomery(y_mont, point.y);

  // Compute y^2 in Montgomery form
  Fp y_squared_mont;
  fp_mont_mul(y_squared_mont, y_mont, y_mont);

  // Compute x^3 in Montgomery form
  Fp x_squared_mont, x_cubed_mont;
  fp_mont_mul(x_squared_mont, x_mont, x_mont);
  fp_mont_mul(x_cubed_mont, x_squared_mont, x_mont);

  // Compute x^3 + b in Montgomery form
  const Fp &b = curve_b_g1();
  Fp b_mont;
  fp_to_montgomery(b_mont, b);
  Fp rhs_mont;
  fp_add(rhs_mont, x_cubed_mont, b_mont);

  // Check if y^2 == x^3 + b (comparison in Montgomery form)
  return fp_cmp(y_squared_mont, rhs_mont) == ComparisonType::Equal;
}

// Check if a G2 point is on the curve: y^2 = x^3 + b'
// Uses Montgomery form internally for efficiency
__host__ __device__ bool is_on_curve_g2(const G2Affine &point) {
  // Affine at infinity is always on the curve
  if (point.infinity) {
    return true;
  }

  // Convert coordinates to Montgomery form
  Fp2 x_mont, y_mont;
  fp_to_montgomery(x_mont.c0, point.x.c0);
  fp_to_montgomery(x_mont.c1, point.x.c1);
  fp_to_montgomery(y_mont.c0, point.y.c0);
  fp_to_montgomery(y_mont.c1, point.y.c1);

  // Compute y^2 in Montgomery form
  Fp2 y_squared_mont;
  fp2_mont_mul(y_squared_mont, y_mont, y_mont);

  // Compute x^3 in Montgomery form
  Fp2 x_squared_mont, x_cubed_mont;
  fp2_mont_mul(x_squared_mont, x_mont, x_mont);
  fp2_mont_mul(x_cubed_mont, x_squared_mont, x_mont);

  // Compute x^3 + b' in Montgomery form
  const Fp2 &b_prime = curve_b_g2();
  Fp2 b_prime_mont;
  fp_to_montgomery(b_prime_mont.c0, b_prime.c0);
  fp_to_montgomery(b_prime_mont.c1, b_prime.c1);
  Fp2 rhs_mont;
  fp2_add(rhs_mont, x_cubed_mont, b_prime_mont);

  // Check if y^2 == x^3 + b' (comparison in Montgomery form)
  return fp2_cmp(y_squared_mont, rhs_mont) == ComparisonType::Equal;
}

// Create G1 point at infinity
__host__ __device__ void g1_point_at_infinity(G1Affine &point) {
  fp_zero(point.x);
  fp_zero(point.y);
  point.infinity = true;
}

// Create G2 point at infinity
__host__ __device__ void g2_point_at_infinity(G2Affine &point) {
  fp2_zero(point.x);
  fp2_zero(point.y);
  point.infinity = true;
}

// Check if G1 point is at infinity
__host__ __device__ bool g1_is_infinity(const G1Affine &point) {
  return point.infinity;
}

// Check if G2 point is at infinity
__host__ __device__ bool g2_is_infinity(const G2Affine &point) {
  return point.infinity;
}

// ============================================================================
// Generator Points
// ============================================================================

// Device constants for generator points
// Hardcoded at compile time (like DEVICE_MODULUS) to avoid cudaMemcpyToSymbol
// Generator points from tfhe-rs:
// https://github.com/zama-ai/tfhe-rs/blob/main/tfhe-zk-pok/src/curve_446/mod.rs
// Values are stored in NORMAL form (not Montgomery form)

#if LIMB_BITS_CONFIG == 64
// 64-bit limb generator constants (7 limbs per Fp)
__constant__ const G1Affine DEVICE_G1_GENERATOR = {
    {{0x3bf9166c8236f4faULL, 0x8bc02b7cbe6a9e8dULL, 0x11c1e56b3e4bc80bULL,
      0x6b20d782901a6f62ULL, 0x2ce8c34265bf3841ULL, 0x11b73d3d76ae9851ULL,
      0x326ed6bd777fc6a3ULL}},
    {{0xfe6f792612016b30ULL, 0x22db0ce6034a9db9ULL, 0xb9093f32002756daULL,
      0x39d7f424b6660204ULL, 0xf843c947aa57f571ULL, 0xd6d62d244e413636ULL,
      0x1a7caf4a4d3887a6ULL}},
    false};

__constant__ const G2Affine DEVICE_G2_GENERATOR = {
    {{{0x0e529ee4dce9991dULL, 0xd6ebaf149094f1ccULL, 0x043c6bf16312d638ULL,
       0x062b61439640e885ULL, 0x18dad8ed784dd225ULL, 0xa57c0038441f7d15ULL,
       0x21f8d4a76f74541aULL}},
     {{0xcaf5185423a7d23aULL, 0x7cef6acb145b6413ULL, 0x2879dd439b019b8bULL,
       0x71449cdeca4f0007ULL, 0xdebaf4a2c5534527ULL, 0xa1b4e791d1b86560ULL,
       0x1e0f563c601bb8dcULL}}},
    {{{0x274315837455b919ULL, 0x82039e4221ff3507ULL, 0x00346cebad16a036ULL,
       0x0177bfd6654e681eULL, 0xddff621b5db3f897ULL, 0x0cc61570301497a7ULL,
       0x115ea2305a78f646ULL}},
     {{0x392236e9cf2976c2ULL, 0xd8ab17c84b9f03cdULL, 0x8a8e6755f9d82fd1ULL,
       0x7532834528cd5a64ULL, 0x0b0bcc3fb6f2161cULL, 0x76a2ffcb7d47679dULL,
       0x25ed2192b203c1feULL}}},
    false};

#elif LIMB_BITS_CONFIG == 32
// 32-bit limb generator constants (14 limbs per Fp)
// Each 64-bit value 0xHHHHHHHHLLLLLLLL splits into: 0xLLLLLLLL, 0xHHHHHHHH
__constant__ const G1Affine DEVICE_G1_GENERATOR = {
    {{0x8236f4faU, 0x3bf9166cU, 0xbe6a9e8dU, 0x8bc02b7cU, 0x3e4bc80bU,
      0x11c1e56bU, 0x901a6f62U, 0x6b20d782U, 0x65bf3841U, 0x2ce8c342U,
      0x76ae9851U, 0x11b73d3dU, 0x777fc6a3U, 0x326ed6bdU}},
    {{0x12016b30U, 0xfe6f7926U, 0x034a9db9U, 0x22db0ce6U, 0x002756daU,
      0xb9093f32U, 0xb6660204U, 0x39d7f424U, 0xaa57f571U, 0xf843c947U,
      0x4e413636U, 0xd6d62d24U, 0x4d3887a6U, 0x1a7caf4aU}},
    false};

__constant__ const G2Affine DEVICE_G2_GENERATOR = {
    {{{0xdce9991dU, 0x0e529ee4U, 0x9094f1ccU, 0xd6ebaf14U, 0x6312d638U,
       0x043c6bf1U, 0x9640e885U, 0x062b6143U, 0x784dd225U, 0x18dad8edU,
       0x441f7d15U, 0xa57c0038U, 0x6f74541aU, 0x21f8d4a7U}},
     {{0x23a7d23aU, 0xcaf51854U, 0x145b6413U, 0x7cef6acbU, 0x9b019b8bU,
       0x2879dd43U, 0xca4f0007U, 0x71449cdeU, 0xc5534527U, 0xdebaf4a2U,
       0xd1b86560U, 0xa1b4e791U, 0x601bb8dcU, 0x1e0f563cU}}},
    {{{0x7455b919U, 0x27431583U, 0x21ff3507U, 0x82039e42U, 0xad16a036U,
       0x00346cebU, 0x654e681eU, 0x0177bfd6U, 0x5db3f897U, 0xddff621bU,
       0x301497a7U, 0x0cc61570U, 0x5a78f646U, 0x115ea230U}},
     {{0xcf2976c2U, 0x392236e9U, 0x4b9f03cdU, 0xd8ab17c8U, 0xf9d82fd1U,
       0x8a8e6755U, 0x28cd5a64U, 0x75328345U, 0xb6f2161cU, 0x0b0bcc3fU,
       0x7d47679dU, 0x76a2ffcbU, 0xb203c1feU, 0x25ed2192U}}},
    false};
#endif

__host__ __device__ const G1Affine &g1_generator() {
#ifdef __CUDA_ARCH__
  return DEVICE_G1_GENERATOR;
#else
  // Host code: use the same hardcoded values as device (in normal form)
#if LIMB_BITS_CONFIG == 64
  static const G1Affine host_gen = {
      {{0x3bf9166c8236f4faULL, 0x8bc02b7cbe6a9e8dULL, 0x11c1e56b3e4bc80bULL,
        0x6b20d782901a6f62ULL, 0x2ce8c34265bf3841ULL, 0x11b73d3d76ae9851ULL,
        0x326ed6bd777fc6a3ULL}},
      {{0xfe6f792612016b30ULL, 0x22db0ce6034a9db9ULL, 0xb9093f32002756daULL,
        0x39d7f424b6660204ULL, 0xf843c947aa57f571ULL, 0xd6d62d244e413636ULL,
        0x1a7caf4a4d3887a6ULL}},
      false};
#elif LIMB_BITS_CONFIG == 32
  static const G1Affine host_gen = {
      {{0x8236f4faU, 0x3bf9166cU, 0xbe6a9e8dU, 0x8bc02b7cU, 0x3e4bc80bU,
        0x11c1e56bU, 0x901a6f62U, 0x6b20d782U, 0x65bf3841U, 0x2ce8c342U,
        0x76ae9851U, 0x11b73d3dU, 0x777fc6a3U, 0x326ed6bdU}},
      {{0x12016b30U, 0xfe6f7926U, 0x034a9db9U, 0x22db0ce6U, 0x002756daU,
        0xb9093f32U, 0xb6660204U, 0x39d7f424U, 0xaa57f571U, 0xf843c947U,
        0x4e413636U, 0xd6d62d24U, 0x4d3887a6U, 0x1a7caf4aU}},
      false};
#endif
  return host_gen;
#endif
}

__host__ __device__ const G2Affine &g2_generator() {
#ifdef __CUDA_ARCH__
  return DEVICE_G2_GENERATOR;
#else
  // Host code: use the same hardcoded values as device (in normal form)
#if LIMB_BITS_CONFIG == 64
  static const G2Affine host_gen = {
      {{{0x0e529ee4dce9991dULL, 0xd6ebaf149094f1ccULL, 0x043c6bf16312d638ULL,
         0x062b61439640e885ULL, 0x18dad8ed784dd225ULL, 0xa57c0038441f7d15ULL,
         0x21f8d4a76f74541aULL}},
       {{0xcaf5185423a7d23aULL, 0x7cef6acb145b6413ULL, 0x2879dd439b019b8bULL,
         0x71449cdeca4f0007ULL, 0xdebaf4a2c5534527ULL, 0xa1b4e791d1b86560ULL,
         0x1e0f563c601bb8dcULL}}},
      {{{0x274315837455b919ULL, 0x82039e4221ff3507ULL, 0x00346cebad16a036ULL,
         0x0177bfd6654e681eULL, 0xddff621b5db3f897ULL, 0x0cc61570301497a7ULL,
         0x115ea2305a78f646ULL}},
       {{0x392236e9cf2976c2ULL, 0xd8ab17c84b9f03cdULL, 0x8a8e6755f9d82fd1ULL,
         0x7532834528cd5a64ULL, 0x0b0bcc3fb6f2161cULL, 0x76a2ffcb7d47679dULL,
         0x25ed2192b203c1feULL}}},
      false};
#elif LIMB_BITS_CONFIG == 32
  static const G2Affine host_gen = {
      {{{0xdce9991dU, 0x0e529ee4U, 0x9094f1ccU, 0xd6ebaf14U, 0x6312d638U,
         0x043c6bf1U, 0x9640e885U, 0x062b6143U, 0x784dd225U, 0x18dad8edU,
         0x441f7d15U, 0xa57c0038U, 0x6f74541aU, 0x21f8d4a7U}},
       {{0x23a7d23aU, 0xcaf51854U, 0x145b6413U, 0x7cef6acbU, 0x9b019b8bU,
         0x2879dd43U, 0xca4f0007U, 0x71449cdeU, 0xc5534527U, 0xdebaf4a2U,
         0xd1b86560U, 0xa1b4e791U, 0x601bb8dcU, 0x1e0f563cU}}},
      {{{0x7455b919U, 0x27431583U, 0x21ff3507U, 0x82039e42U, 0xad16a036U,
         0x00346cebU, 0x654e681eU, 0x0177bfd6U, 0x5db3f897U, 0xddff621bU,
         0x301497a7U, 0x0cc61570U, 0x5a78f646U, 0x115ea230U}},
       {{0xcf2976c2U, 0x392236e9U, 0x4b9f03cdU, 0xd8ab17c8U, 0xf9d82fd1U,
         0x8a8e6755U, 0x28cd5a64U, 0x75328345U, 0xb6f2161cU, 0x0b0bcc3fU,
         0x7d47679dU, 0x76a2ffcbU, 0xb203c1feU, 0x25ed2192U}}},
      false};
#endif
  return host_gen;
#endif
}

// ============================================================================
// Multi-Scalar Multiplication (MSM) - Pippenger Algorithm
// ============================================================================

// Pippenger algorithm parameters
// MSM_G1_WINDOW_SIZE and MSM_G2_BUCKET_COUNT are defined in msm.h

// Helper function to extract a window from a multi-limb scalar (internal)
__device__ __forceinline__ uint32_t extract_window_multi_internal(
    const UNSIGNED_LIMB *scalar, uint32_t scalar_limbs, uint32_t window_idx,
    uint32_t window_size) {
  uint32_t total_bits = scalar_limbs * LIMB_BITS;
  uint32_t bit_offset = window_idx * window_size;
  if (bit_offset >= total_bits)
    return 0;

  uint32_t limb_idx = bit_offset / LIMB_BITS;
  uint32_t bit_in_limb = bit_offset % LIMB_BITS;

  if (limb_idx >= scalar_limbs)
    return 0;

  UNSIGNED_LIMB mask = (1ULL << window_size) - 1;
  UNSIGNED_LIMB window = (scalar[limb_idx] >> bit_in_limb) & mask;

  // If window spans two limbs, combine them
  if (bit_in_limb + window_size > LIMB_BITS && limb_idx + 1 < scalar_limbs) {
    uint32_t bits_from_next = (bit_in_limb + window_size) - LIMB_BITS;
    UNSIGNED_LIMB next_bits =
        scalar[limb_idx + 1] & ((1ULL << bits_from_next) - 1);
    window |= (next_bits << (window_size - bits_from_next));
  }

  return static_cast<uint32_t>(window);
}

// Wrapper for external API (scalar is uint64_t* from FFI)
// Handles conversion from 64-bit limbs to UNSIGNED_LIMB
__device__ __forceinline__ uint32_t
extract_window_multi(const uint64_t *scalar, uint32_t scalar_limbs_64,
                     uint32_t window_idx, uint32_t window_size) {
  const UNSIGNED_LIMB *scalar_native =
      reinterpret_cast<const UNSIGNED_LIMB *>(scalar);
  const uint32_t scalar_limbs_native = scalar_limbs_64 * (64 / LIMB_BITS);
  return extract_window_multi_internal(scalar_native, scalar_limbs_native,
                                       window_idx, window_size);
}

// Pippenger kernel: Clear buckets
template <typename PointType>
__global__ void kernel_clear_buckets(PointType *buckets, uint32_t num_buckets) {
  using AffinePoint = Affine<PointType>;

  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < num_buckets) {
    AffinePoint::point_at_infinity(buckets[idx]);
  }
}

// Forward declarations for projective point operations (needed by kernels)
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

// Pippenger kernel: Final reduction of bucket contributions from multiple
// blocks This kernel combines per-block bucket accumulations into final buckets
template <typename PointType>
__global__ void
kernel_reduce_buckets(PointType *final_buckets, const PointType *block_buckets,
                      uint32_t num_blocks, uint32_t num_buckets) {
  using AffinePoint = Affine<PointType>;

  // Each thread handles one bucket across all blocks
  uint32_t bucket_idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (bucket_idx == 0 || bucket_idx >= num_buckets)
    return;

  PointType bucket_sum;
  AffinePoint::point_at_infinity(bucket_sum);

  // Sum contributions from all blocks for this bucket
  for (uint32_t block = 0; block < num_blocks; block++) {
    uint32_t idx = block * num_buckets + bucket_idx;
    const PointType &block_contrib = block_buckets[idx];
    if (!AffinePoint::is_infinity(block_contrib)) {
      if (AffinePoint::is_infinity(bucket_sum)) {
        bucket_sum = block_contrib;
      } else {
        PointType temp;
        point_add(temp, bucket_sum, block_contrib);
        bucket_sum = temp;
      }
    }
  }

  // Write final result
  final_buckets[bucket_idx] = bucket_sum;
}

// Pippenger kernel: Accumulate points into buckets for multi-limb scalars
template <typename PointType>
__global__ void
kernel_accumulate_buckets_multi(PointType *buckets, const PointType *points,
                                const uint64_t *scalars, uint32_t scalar_limbs,
                                uint32_t n, uint32_t window_idx,
                                uint32_t window_size) {
  using AffinePoint = Affine<PointType>;
  // Same approach as u64 version: process each bucket sequentially
  uint32_t bucket_idx = blockIdx.x;
  if (bucket_idx == 0 || bucket_idx >= MSM_G1_BUCKET_COUNT)
    return;

  PointType bucket_sum;
  AffinePoint::point_at_infinity(bucket_sum);

  uint32_t points_per_thread = (n + blockDim.x - 1) / blockDim.x;
  uint32_t start_idx = threadIdx.x * points_per_thread;
  uint32_t end_idx = min(start_idx + points_per_thread, n);

  for (uint32_t i = start_idx; i < end_idx; i++) {
    uint32_t point_bucket = extract_window_multi(
        scalars + i * scalar_limbs, scalar_limbs, window_idx, window_size);
    if (point_bucket == bucket_idx) {
      if (AffinePoint::is_infinity(bucket_sum)) {
        bucket_sum = points[i];
      } else {
        PointType temp;
        point_add(temp, bucket_sum, points[i]);
        bucket_sum = temp;
      }
    }
  }

  // Reduce within block using dynamic shared memory
  extern __shared__ char shared_mem[];
  auto *shared_sums = reinterpret_cast<PointType *>(shared_mem);
  shared_sums[threadIdx.x] = bucket_sum;
  __syncthreads();

  // Thread 0 reduces all thread results
  if (threadIdx.x == 0) {
    PointType total_sum;
    AffinePoint::point_at_infinity(total_sum);
    for (uint32_t i = 0; i < blockDim.x; i++) {
      if (!AffinePoint::is_infinity(shared_sums[i])) {
        if (AffinePoint::is_infinity(total_sum)) {
          total_sum = shared_sums[i];
        } else {
          PointType temp;
          point_add(temp, total_sum, shared_sums[i]);
          total_sum = temp;
        }
      }
    }
    buckets[bucket_idx] = total_sum;
  }
}

// Pippenger kernel: Combine buckets for a window and accumulate into result
// Standard Pippenger: window_sum = bucket[1] * 1 + bucket[2] * 2 + ... +
// bucket[15] * 15 Using Horner's method: window_sum = bucket[1] + 2 *
// (bucket[2] + 2 * (bucket[3] + ... + 2 * bucket[15])) Then result = result *
// 2^window_size + window_sum Helper function: Compute k * P using binary method
// (for small k, 1 <= k <= 15)
template <typename PointType>
__device__ void point_scalar_mul_small(PointType &result, const PointType &P,
                                       int k) {
  using AffinePoint = Affine<PointType>;

  if (k == 0 || AffinePoint::is_infinity(P)) {
    AffinePoint::point_at_infinity(result);
    return;
  }

  if (k == 1) {
    result = P;
    return;
  }

  // Binary scalar multiplication: k * P
  // Start with P, then for each bit from MSB-1 to LSB: double, then add P if
  // bit is set
  PointType acc = P;

  // Find the MSB of k
  int msb =
      31 -
      __clz(k); // __clz counts leading zeros, so msb is the highest set bit

  // Process bits from msb-1 down to 0
  for (int bit = msb - 1; bit >= 0; bit--) {
    point_double(acc, acc);
    if (k & (1 << bit)) {
      PointType temp;
      point_add(temp, acc, P);
      acc = temp;
    }
  }

  result = acc;
}

template <typename PointType>
__global__ void kernel_combine_buckets(PointType *result, PointType *buckets,
                                       uint32_t num_buckets,
                                       uint32_t window_idx) {
  using AffinePoint = Affine<PointType>;

  // Shared memory for storing weighted buckets and reduction tree
  extern __shared__ char shared_mem[];
  auto *shared_weighted = reinterpret_cast<PointType *>(shared_mem);

  // Each thread processes one bucket (bucket index = threadIdx.x + 1, since
  // bucket[0] is not used)
  uint32_t bucket_idx = threadIdx.x + 1;

  // Compute i * bucket[i] for this thread's bucket using binary scalar
  // multiplication
  if (bucket_idx < num_buckets) {
    if (!AffinePoint::is_infinity(buckets[bucket_idx])) {
      point_scalar_mul_small(shared_weighted[threadIdx.x], buckets[bucket_idx],
                             bucket_idx);
    } else {
      AffinePoint::point_at_infinity(shared_weighted[threadIdx.x]);
    }
  } else {
    // Threads beyond num_buckets-1 set to infinity
    AffinePoint::point_at_infinity(shared_weighted[threadIdx.x]);
  }

  __syncthreads();

  // Reduction tree: combine all weighted buckets
  // Use standard parallel reduction pattern
  int active_threads =
      num_buckets -
      1; // Number of buckets to process (buckets 1 to num_buckets-1)

  for (uint32_t stride = blockDim.x / 2; stride > 0; stride >>= 1) {
    if (threadIdx.x < stride && threadIdx.x + stride < active_threads) {
      if (!AffinePoint::is_infinity(shared_weighted[threadIdx.x + stride])) {
        if (AffinePoint::is_infinity(shared_weighted[threadIdx.x])) {
          shared_weighted[threadIdx.x] = shared_weighted[threadIdx.x + stride];
        } else {
          PointType temp;
          point_add(temp, shared_weighted[threadIdx.x],
                    shared_weighted[threadIdx.x + stride]);
          shared_weighted[threadIdx.x] = temp;
        }
      }
    }
    __syncthreads();
  }

  // Thread 0 has the final window_sum, add it to result
  if (threadIdx.x == 0) {
    PointType window_sum = shared_weighted[0];

    // Add window sum to result
    // For windows processed from MSB to LSB:
    // - First window (MSB, highest window_idx): result = window_sum (no
    // multiplication)
    // - Subsequent windows: result = result * 2^window_size + window_sum
    if (!AffinePoint::is_infinity(window_sum)) {
      if (AffinePoint::is_infinity(*result)) {
        // First non-zero window: just copy window_sum
        *result = window_sum;
      } else {
        // Multiply result by 2^window_size before adding window_sum
        constexpr uint32_t window_size = MSMWindowSize<PointType>::value;
        for (uint32_t i = 0; i < window_size; i++) {
          point_double(*result, *result);
        }
        // Add window_sum to result
        PointType temp;
        point_add(temp, *result, window_sum);
        *result = temp;
      }
    } else if (!AffinePoint::is_infinity(*result)) {
      // Window sum is zero but result is not: still need to multiply result
      constexpr uint32_t window_size = MSMWindowSize<PointType>::value;
      for (uint32_t i = 0; i < window_size; i++) {
        point_double(*result, *result);
      }
    }
  }
}

// Legacy kernels for backward compatibility (kept for reference, but not used
// in new implementation) Template kernel: Compute scalar[i] * points[i] with
// 64-bit scalars
template <typename PointType>
__global__ void
kernel_scalar_mul_u64_array(PointType *results, const PointType *points,
                            const uint64_t *scalars, uint32_t n) {
  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    point_scalar_mul(results[idx], points[idx], &scalars[idx], 1);
  }
}

// Template kernel: Compute scalar[i] * points[i] with multi-limb scalars
template <typename PointType>
__global__ void kernel_scalar_mul_array(PointType *results,
                                        const PointType *points,
                                        const uint64_t *scalars,
                                        uint32_t scalar_limbs, uint32_t n) {
  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    point_scalar_mul(results[idx], points[idx], scalars + idx * scalar_limbs,
                     scalar_limbs);
  }
}

// Template kernel: Reduce array of points by addition
template <typename PointType>
__global__ void kernel_reduce_sum(PointType *result, const PointType *points,
                                  uint32_t n) {
  using AffinePoint = Affine<PointType>;
  if (threadIdx.x == 0 && blockIdx.x == 0) {
    AffinePoint::point_at_infinity(*result);
    for (uint32_t i = 0; i < n; i++) {
      PointType temp;
      point_add(temp, *result, points[i]);
      *result = temp;
    }
  }
}

// Template kernels for array operations (replacing legacy g1_* and g2_*
// kernels)

// Template kernel: Compute scalar[i] * points[i] with 64-bit scalars
template <typename PointType>
__global__ void
kernel_point_scalar_mul_u64_array(PointType *results, const PointType *points,
                                  const uint64_t *scalars, uint32_t n) {
  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    point_scalar_mul(results[idx], points[idx], &scalars[idx], 1);
  }
}

// Template kernel: Compute scalar[i] * points[i] with multi-limb scalars
template <typename PointType>
__global__ void
kernel_point_scalar_mul_array(PointType *results, const PointType *points,
                              const uint64_t *scalars, uint32_t scalar_limbs,
                              uint32_t n) {
  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    point_scalar_mul(results[idx], points[idx], scalars + idx * scalar_limbs,
                     scalar_limbs);
  }
}

// Template kernel: Reduce array of points by addition
template <typename PointType>
__global__ void kernel_point_reduce_sum(PointType *result,
                                        const PointType *points, uint32_t n) {
  using AffinePoint = Affine<PointType>;
  if (threadIdx.x == 0 && blockIdx.x == 0) {
    AffinePoint::point_at_infinity(*result);
    for (int i = 0; i < n; i++) {
      PointType temp;
      point_add(temp, *result, points[i]);
      *result = temp;
    }
  }
}

// ============================================================================
// Template Kernels for async/sync API (work on device pointers)
// ============================================================================

// Template kernel: Affine addition
template <typename PointType>
__global__ void kernel_point_add(PointType *result, const PointType *p1,
                                 const PointType *p2) {
  point_add(*result, *p1, *p2);
}

// Template kernel: Affine doubling
template <typename PointType>
__global__ void kernel_point_double(PointType *result, const PointType *p) {
  point_double(*result, *p);
}

// Template kernel: Affine negation
template <typename PointType>
__global__ void kernel_point_neg(PointType *result, const PointType *p) {
  point_neg(*result, *p);
}

// Template kernel: Affine at infinity
template <typename PointType>
__global__ void kernel_point_at_infinity(PointType *result) {
  using AffinePoint = Affine<PointType>;
  AffinePoint::point_at_infinity(*result);
}

// Template kernel: Convert point to Montgomery form
template <typename PointType>
__global__ void kernel_point_to_montgomery(PointType *result,
                                           const PointType *point) {
  using AffinePoint = Affine<PointType>;
  if (point->infinity) {
    result->infinity = true;
    AffinePoint::field_zero(result->x);
    AffinePoint::field_zero(result->y);
  } else {
    AffinePoint::field_to_montgomery(result->x, point->x);
    AffinePoint::field_to_montgomery(result->y, point->y);
    result->infinity = false;
  }
}

// Template kernel: Convert point from Montgomery form
template <typename PointType>
__global__ void kernel_point_from_montgomery(PointType *result,
                                             const PointType *point) {
  using AffinePoint = Affine<PointType>;
  if (point->infinity) {
    result->infinity = true;
    AffinePoint::field_zero(result->x);
    AffinePoint::field_zero(result->y);
  } else {
    AffinePoint::field_from_montgomery(result->x, point->x);
    AffinePoint::field_from_montgomery(result->y, point->y);
    result->infinity = false;
  }
}

// Template kernel: Batch convert points to Montgomery form
template <typename PointType>
__global__ void kernel_point_to_montgomery_batch(PointType *points,
                                                 uint32_t n) {
  using AffinePoint = Affine<PointType>;
  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    if (!points[idx].infinity) {
      AffinePoint::field_to_montgomery(points[idx].x, points[idx].x);
      AffinePoint::field_to_montgomery(points[idx].y, points[idx].y);
    }
  }
}

// Template kernel: Batch convert points from Montgomery form
template <typename PointType>
__global__ void kernel_point_from_montgomery_batch(PointType *points,
                                                   uint32_t n) {
  using AffinePoint = Affine<PointType>;
  uint32_t idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx < n) {
    if (!points[idx].infinity) {
      AffinePoint::field_from_montgomery(points[idx].x, points[idx].x);
      AffinePoint::field_from_montgomery(points[idx].y, points[idx].y);
    }
  }
}

// Template kernel: Scalar multiplication with 64-bit scalar
template <typename PointType>
__global__ void kernel_point_scalar_mul_u64(PointType *result,
                                            const PointType *point,
                                            uint64_t scalar) {
  point_scalar_mul(*result, *point, &scalar, 1);
}

// Template kernel: Scalar multiplication with multi-limb scalar
template <typename PointType>
__global__ void
kernel_point_scalar_mul(PointType *result, const PointType *point,
                        const uint64_t *scalar, uint32_t scalar_limbs) {
  point_scalar_mul(*result, *point, scalar, scalar_limbs);
}

// ============================================================================
// Template Async/Sync API implementations
// ============================================================================

// Template function: Affine addition
template <typename PointType>
void point_add_async(cudaStream_t stream, uint32_t gpu_index,
                     PointType *d_result, const PointType *d_p1,
                     const PointType *d_p2) {
  PANIC_IF_FALSE(d_result != nullptr && d_p1 != nullptr && d_p2 != nullptr,
                 "point_add_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_add<PointType><<<1, 1, 0, stream>>>(d_result, d_p1, d_p2);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_add(cudaStream_t stream, uint32_t gpu_index, PointType *d_result,
               const PointType *d_p1, const PointType *d_p2) {
  point_add_async<PointType>(stream, gpu_index, d_result, d_p1, d_p2);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Affine doubling
template <typename PointType>
void point_double_async(cudaStream_t stream, uint32_t gpu_index,
                        PointType *d_result, const PointType *d_p) {
  PANIC_IF_FALSE(d_result != nullptr && d_p != nullptr,
                 "point_double_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_double<PointType><<<1, 1, 0, stream>>>(d_result, d_p);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_double(cudaStream_t stream, uint32_t gpu_index, PointType *d_result,
                  const PointType *d_p) {
  point_double_async<PointType>(stream, gpu_index, d_result, d_p);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Affine negation
template <typename PointType>
void point_neg_async(cudaStream_t stream, uint32_t gpu_index,
                     PointType *d_result, const PointType *d_p) {
  PANIC_IF_FALSE(d_result != nullptr && d_p != nullptr,
                 "point_neg_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_neg<PointType><<<1, 1, 0, stream>>>(d_result, d_p);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_neg(cudaStream_t stream, uint32_t gpu_index, PointType *d_result,
               const PointType *d_p) {
  point_neg_async<PointType>(stream, gpu_index, d_result, d_p);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Affine at infinity
template <typename PointType>
void point_at_infinity_async(cudaStream_t stream, uint32_t gpu_index,
                             PointType *d_result) {
  PANIC_IF_FALSE(d_result != nullptr,
                 "point_at_infinity_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_at_infinity<PointType><<<1, 1, 0, stream>>>(d_result);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_at_infinity(cudaStream_t stream, uint32_t gpu_index,
                       PointType *d_result) {
  point_at_infinity_async<PointType>(stream, gpu_index, d_result);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Convert point to Montgomery form
template <typename PointType>
void point_to_montgomery_async(cudaStream_t stream, uint32_t gpu_index,
                               PointType *d_result, const PointType *d_point) {
  PANIC_IF_FALSE(d_result != nullptr && d_point != nullptr,
                 "point_to_montgomery_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_to_montgomery<PointType><<<1, 1, 0, stream>>>(d_result, d_point);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_to_montgomery(cudaStream_t stream, uint32_t gpu_index,
                         PointType *d_result, const PointType *d_point) {
  point_to_montgomery_async<PointType>(stream, gpu_index, d_result, d_point);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Convert point from Montgomery form
template <typename PointType>
void point_from_montgomery_async(cudaStream_t stream, uint32_t gpu_index,
                                 PointType *d_result,
                                 const PointType *d_point) {
  PANIC_IF_FALSE(d_result != nullptr && d_point != nullptr,
                 "point_from_montgomery_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_from_montgomery<PointType>
      <<<1, 1, 0, stream>>>(d_result, d_point);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_from_montgomery(cudaStream_t stream, uint32_t gpu_index,
                           PointType *d_result, const PointType *d_point) {
  point_from_montgomery_async<PointType>(stream, gpu_index, d_result, d_point);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Scalar multiplication with 64-bit scalar
template <typename PointType>
void point_scalar_mul_u64_async(cudaStream_t stream, uint32_t gpu_index,
                                PointType *d_result, const PointType *d_point,
                                uint64_t scalar) {
  PANIC_IF_FALSE(d_result != nullptr && d_point != nullptr,
                 "point_scalar_mul_u64_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_scalar_mul_u64<PointType>
      <<<1, 1, 0, stream>>>(d_result, d_point, scalar);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_scalar_mul_u64(cudaStream_t stream, uint32_t gpu_index,
                          PointType *d_result, const PointType *d_point,
                          uint64_t scalar) {
  point_scalar_mul_u64_async<PointType>(stream, gpu_index, d_result, d_point,
                                        scalar);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Scalar multiplication with multi-limb scalar
template <typename PointType>
void point_scalar_mul_async(cudaStream_t stream, uint32_t gpu_index,
                            PointType *d_result, const PointType *d_point,
                            const uint64_t *d_scalar, uint32_t scalar_limbs) {
  PANIC_IF_FALSE(d_result != nullptr && d_point != nullptr &&
                     d_scalar != nullptr,
                 "point_scalar_mul_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_point_scalar_mul<PointType>
      <<<1, 1, 0, stream>>>(d_result, d_point, d_scalar, scalar_limbs);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_scalar_mul(cudaStream_t stream, uint32_t gpu_index,
                      PointType *d_result, const PointType *d_point,
                      const uint64_t *d_scalar, uint32_t scalar_limbs) {
  point_scalar_mul_async<PointType>(stream, gpu_index, d_result, d_point,
                                    d_scalar, scalar_limbs);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Batch convert points to Montgomery form
template <typename PointType>
void point_to_montgomery_batch_async(cudaStream_t stream, uint32_t gpu_index,
                                     PointType *d_points, uint32_t n) {
  PANIC_IF_FALSE(d_points != nullptr,
                 "point_to_montgomery_batch_async: null pointer argument");
  if (n == 0)
    return;

  cuda_set_device(gpu_index);
  uint32_t threadsPerBlock = 256;
  uint32_t blocks = CEIL_DIV(n, threadsPerBlock);
  kernel_point_to_montgomery_batch<PointType>
      <<<blocks, threadsPerBlock, 0, stream>>>(d_points, n);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void point_to_montgomery_batch(cudaStream_t stream, uint32_t gpu_index,
                               PointType *d_points, uint32_t n) {
  point_to_montgomery_batch_async<PointType>(stream, gpu_index, d_points, n);
  cuda_synchronize_stream(stream, gpu_index);
}

// ============================================================================
// Refactored MSM API (device pointers only, no allocations/copies/frees)
// ============================================================================

// ============================================================================
// Explicit template instantiations (needed for external linkage)
// ============================================================================

// Async/Sync API instantiations
template void point_add_async<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                        const G1Affine *, const G1Affine *);
template void point_add<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                  const G1Affine *, const G1Affine *);
template void point_double_async<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                           const G1Affine *);
template void point_double<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                     const G1Affine *);
template void point_neg_async<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                        const G1Affine *);
template void point_neg<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                  const G1Affine *);
template void point_at_infinity_async<G1Affine>(cudaStream_t, uint32_t,
                                                G1Affine *);
template void point_at_infinity<G1Affine>(cudaStream_t, uint32_t, G1Affine *);
template void point_to_montgomery_async<G1Affine>(cudaStream_t, uint32_t,
                                                  G1Affine *, const G1Affine *);
template void point_to_montgomery<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                            const G1Affine *);
template void point_from_montgomery_async<G1Affine>(cudaStream_t, uint32_t,
                                                    G1Affine *,
                                                    const G1Affine *);
template void point_from_montgomery<G1Affine>(cudaStream_t, uint32_t,
                                              G1Affine *, const G1Affine *);
template void point_scalar_mul_u64_async<G1Affine>(cudaStream_t, uint32_t,
                                                   G1Affine *, const G1Affine *,
                                                   uint64_t);
template void point_scalar_mul_u64<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                             const G1Affine *, uint64_t);
template void point_scalar_mul_async<G1Affine>(cudaStream_t, uint32_t,
                                               G1Affine *, const G1Affine *,
                                               const uint64_t *, uint32_t);
template void point_scalar_mul<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                         const G1Affine *, const uint64_t *,
                                         uint32_t);
template void point_to_montgomery_batch_async<G1Affine>(cudaStream_t, uint32_t,
                                                        G1Affine *, uint32_t);
template void point_to_montgomery_batch<G1Affine>(cudaStream_t, uint32_t,
                                                  G1Affine *, uint32_t);

template void point_add_async<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                        const G2Affine *, const G2Affine *);
template void point_add<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                  const G2Affine *, const G2Affine *);
template void point_double_async<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                           const G2Affine *);
template void point_double<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                     const G2Affine *);
template void point_neg_async<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                        const G2Affine *);
template void point_neg<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                  const G2Affine *);
template void point_at_infinity_async<G2Affine>(cudaStream_t, uint32_t,
                                                G2Affine *);
template void point_at_infinity<G2Affine>(cudaStream_t, uint32_t, G2Affine *);
template void point_to_montgomery_async<G2Affine>(cudaStream_t, uint32_t,
                                                  G2Affine *, const G2Affine *);
template void point_to_montgomery<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                            const G2Affine *);
template void point_from_montgomery_async<G2Affine>(cudaStream_t, uint32_t,
                                                    G2Affine *,
                                                    const G2Affine *);
template void point_from_montgomery<G2Affine>(cudaStream_t, uint32_t,
                                              G2Affine *, const G2Affine *);
template void point_scalar_mul_u64_async<G2Affine>(cudaStream_t, uint32_t,
                                                   G2Affine *, const G2Affine *,
                                                   uint64_t);
template void point_scalar_mul_u64<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                             const G2Affine *, uint64_t);
template void point_scalar_mul_async<G2Affine>(cudaStream_t, uint32_t,
                                               G2Affine *, const G2Affine *,
                                               const uint64_t *, uint32_t);
template void point_scalar_mul<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                         const G2Affine *, const uint64_t *,
                                         uint32_t);
template void point_to_montgomery_batch_async<G2Affine>(cudaStream_t, uint32_t,
                                                        G2Affine *, uint32_t);
template void point_to_montgomery_batch<G2Affine>(cudaStream_t, uint32_t,
                                                  G2Affine *, uint32_t);

// ============================================================================
// Projective Affine Operations
// ============================================================================

// Convert affine point to projective: (x, y) -> (x, y, 1)
__host__ __device__ void affine_to_projective(G1Projective &proj,
                                              const G1Affine &affine) {
  if (g1_is_infinity(affine)) {
    fp_zero(proj.X);
    fp_zero(proj.Y);
    fp_zero(proj.Z);
  } else {
    // Affine coordinates are already in Montgomery form (converted before MSM)
    proj.X = affine.x;
    proj.Y = affine.y;
    fp_one_montgomery(proj.Z); // Z = 1 in Montgomery form
  }
}

// Specialization for G2
__host__ __device__ void affine_to_projective(G2Projective &proj,
                                              const G2Affine &affine) {
  if (g2_is_infinity(affine)) {
    fp2_zero(proj.X);
    fp2_zero(proj.Y);
    fp2_zero(proj.Z);
  } else {
    // Affine coordinates are already in Montgomery form (converted before MSM)
    proj.X = affine.x;
    proj.Y = affine.y;
    // Z = 1 in Montgomery form for Fp2 (1 + 0*i)
    Fp one;
    fp_one_montgomery(one);
    proj.Z.c0 = one;
    fp_zero(proj.Z.c1);
  }
}

// Convert projective point to affine: (X, Y, Z) -> (X/Z, Y/Z)
__host__ __device__ void projective_to_affine_g1(G1Affine &affine,
                                                 const G1Projective &proj) {
  if (fp_is_zero(proj.Z)) {
    g1_point_at_infinity(affine);
    return;
  }
  // x = X * Z^(-1)
  Fp Z_inv;
  fp_mont_inv(Z_inv, proj.Z);
  fp_mont_mul(affine.x, proj.X, Z_inv);
  fp_mont_mul(affine.y, proj.Y, Z_inv);
  affine.infinity = false;
}

__host__ __device__ void projective_to_affine_g2(G2Affine &affine,
                                                 const G2Projective &proj) {
  if (fp2_is_zero(proj.Z)) {
    g2_point_at_infinity(affine);
    return;
  }
  // x = X * Z^(-1)
  Fp2 Z_inv;
  fp2_mont_inv(Z_inv, proj.Z);
  fp2_mont_mul(affine.x, proj.X, Z_inv);
  fp2_mont_mul(affine.y, proj.Y, Z_inv);
  affine.infinity = false;
}

// Create projective point at infinity: (0, 0, 0)
// Using Z=0 convention: a point is at infinity iff Z=0
__host__ __device__ void g1_projective_point_at_infinity(G1Projective &point) {
  fp_zero(point.X);
  fp_zero(point.Y);
  fp_zero(point.Z);
}

// Create projective point at infinity: (0, 0, 0) in Fq2
// Using Z=0 convention: a point is at infinity iff Z=0
__host__ __device__ void g2_projective_point_at_infinity(G2Projective &point) {
  fp2_zero(point.X);
  fp2_zero(point.Y);
  fp2_zero(point.Z);
}

// Convert point to Montgomery form in-place
// Single entry point that works for G1Affine, G2Affine, G1Projective, or
// G2Projective
__host__ void point_to_montgomery_inplace(G1Affine &point) {
  if (!point.infinity) {
    fp_to_montgomery(point.x, point.x);
    fp_to_montgomery(point.y, point.y);
  }
}

__host__ void point_to_montgomery_inplace(G2Affine &point) {
  if (!point.infinity) {
    fp_to_montgomery(point.x.c0, point.x.c0);
    fp_to_montgomery(point.x.c1, point.x.c1);
    fp_to_montgomery(point.y.c0, point.y.c0);
    fp_to_montgomery(point.y.c1, point.y.c1);
  }
}

__host__ void point_to_montgomery_inplace(G1Projective &point) {
  fp_to_montgomery(point.X, point.X);
  fp_to_montgomery(point.Y, point.Y);
  fp_to_montgomery(point.Z, point.Z);
}

__host__ void point_to_montgomery_inplace(G2Projective &point) {
  fp_to_montgomery(point.X.c0, point.X.c0);
  fp_to_montgomery(point.X.c1, point.X.c1);
  fp_to_montgomery(point.Y.c0, point.Y.c0);
  fp_to_montgomery(point.Y.c1, point.Y.c1);
  fp_to_montgomery(point.Z.c0, point.Z.c0);
  fp_to_montgomery(point.Z.c1, point.Z.c1);
}

// Convert projective point from Montgomery form in-place
__host__ void point_from_montgomery_inplace(G1Projective &point) {
  fp_from_montgomery(point.X, point.X);
  fp_from_montgomery(point.Y, point.Y);
  fp_from_montgomery(point.Z, point.Z);
}

__host__ void point_from_montgomery_inplace(G2Projective &point) {
  fp_from_montgomery(point.X.c0, point.X.c0);
  fp_from_montgomery(point.X.c1, point.X.c1);
  fp_from_montgomery(point.Y.c0, point.Y.c0);
  fp_from_montgomery(point.Y.c1, point.Y.c1);
  fp_from_montgomery(point.Z.c0, point.Z.c0);
  fp_from_montgomery(point.Z.c1, point.Z.c1);
}

// Normalize projective coordinates to Z=1
// Divides X and Y by Z, then sets Z=1
// Point at infinity (Z=0) is left unchanged
// Uses Montgomery form internally for efficient computation
__host__ void normalize_projective_g1(G1Projective &point) {
  // Check if point is at infinity (Z=0)
  if (fp_is_zero(point.Z)) {
    return;
  }

  // Convert X, Y, Z to Montgomery form
  Fp x_mont, y_mont, z_mont;
  fp_to_montgomery(x_mont, point.X);
  fp_to_montgomery(y_mont, point.Y);
  fp_to_montgomery(z_mont, point.Z);

  // Compute Z^-1 in Montgomery form
  Fp z_inv_mont;
  fp_mont_inv(z_inv_mont, z_mont);

  // Multiply X and Y by Z^-1 in Montgomery form
  Fp x_norm_mont, y_norm_mont;
  fp_mont_mul(x_norm_mont, x_mont, z_inv_mont);
  fp_mont_mul(y_norm_mont, y_mont, z_inv_mont);

  // Convert X and Y back from Montgomery form
  fp_from_montgomery(point.X, x_norm_mont);
  fp_from_montgomery(point.Y, y_norm_mont);

  // Set Z = 1 in normal form
  fp_one(point.Z);
}

// Normalize projective coordinates to Z=(1,0) for G2
// Divides X and Y by Z, then sets Z=(1,0)
// Point at infinity (Z=0) is left unchanged
// Uses Montgomery form internally for efficient computation
__host__ void normalize_projective_g2(G2Projective &point) {
  // Check if point is at infinity (Z=0)
  if (fp_is_zero(point.Z.c0) && fp_is_zero(point.Z.c1)) {
    return;
  }

  // Convert X, Y, Z components to Montgomery form
  Fp2 x_mont, y_mont, z_mont;
  fp_to_montgomery(x_mont.c0, point.X.c0);
  fp_to_montgomery(x_mont.c1, point.X.c1);
  fp_to_montgomery(y_mont.c0, point.Y.c0);
  fp_to_montgomery(y_mont.c1, point.Y.c1);
  fp_to_montgomery(z_mont.c0, point.Z.c0);
  fp_to_montgomery(z_mont.c1, point.Z.c1);

  // Compute Z^-1 in Montgomery form
  Fp2 z_inv_mont;
  fp2_mont_inv(z_inv_mont, z_mont);

  // Multiply X and Y by Z^-1 in Montgomery form
  Fp2 x_norm_mont, y_norm_mont;
  fp2_mont_mul(x_norm_mont, x_mont, z_inv_mont);
  fp2_mont_mul(y_norm_mont, y_mont, z_inv_mont);

  // Convert X and Y back from Montgomery form
  fp_from_montgomery(point.X.c0, x_norm_mont.c0);
  fp_from_montgomery(point.X.c1, x_norm_mont.c1);
  fp_from_montgomery(point.Y.c0, y_norm_mont.c0);
  fp_from_montgomery(point.Y.c1, y_norm_mont.c1);

  // Set Z = (1, 0) in normal form
  fp_one(point.Z.c0);
  fp_zero(point.Z.c1);
}

// Projective point addition: result = p1 + p2 (no inversions!) - G1
// specialization
__host__ __device__ void projective_point_add(G1Projective &result,
                                              const G1Projective &p1,
                                              const G1Projective &p2) {
  // Handle infinity cases
  if (fp_is_zero(p1.Z)) {
    result = p2;
    return;
  }
  if (fp_is_zero(p2.Z)) {
    result = p1;
    return;
  }

  // G1 projective addition using complete formulas
  Fp Y1Z2, X1Z2, Z1Z2, u, uu, v, vv, vvv, R, A;

  // Y1Z2 = Y1 * Z2
  fp_mont_mul(Y1Z2, p1.Y, p2.Z);
  // X1Z2 = X1 * Z2
  fp_mont_mul(X1Z2, p1.X, p2.Z);
  // Z1Z2 = Z1 * Z2
  fp_mont_mul(Z1Z2, p1.Z, p2.Z);

  // u = Y2 * Z1 - Y1 * Z2 = Y2*Z1 - Y1Z2
  Fp Y2Z1;
  fp_mont_mul(Y2Z1, p2.Y, p1.Z);
  u = Y2Z1 - Y1Z2;

  // uu = u^2
  fp_mont_mul(uu, u, u);

  // v = X2 * Z1 - X1 * Z2 = X2*Z1 - X1Z2
  Fp X2Z1;
  fp_mont_mul(X2Z1, p2.X, p1.Z);
  v = X2Z1 - X1Z2;

  // Check if this is actually a doubling case (p1 == p2)
  // When u == 0 and v == 0, the points are equal
  if (fp_is_zero(u) && fp_is_zero(v)) {
    projective_point_double(result, p1);
    return;
  }

  // vv = v^2
  fp_mont_mul(vv, v, v);
  // vvv = v * vv
  fp_mont_mul(vvv, v, vv);

  // R = vv * X1Z2
  fp_mont_mul(R, vv, X1Z2);

  // A = uu * Z1Z2 - vvv - 2*R
  Fp temp1, two_R;
  fp_mont_mul(temp1, uu, Z1Z2);
  Fp temp2 = temp1 - vvv;
  // Compute 2*R using cached Montgomery constant
  Fp two_mont;
#ifdef __CUDA_ARCH__
  fp_two_montgomery(two_mont);
#else
  two_mont = get_fp_mont_constants_host().two;
#endif
  fp_mont_mul(two_R, two_mont, R);
  A = temp2 - two_R;

  // X3 = v * A
  fp_mont_mul(result.X, v, A);

  // Y3 = u * (R - A) - vvv * Y1Z2
  Fp R_minus_A = R - A;
  Fp uR_minus_A;
  fp_mont_mul(uR_minus_A, u, R_minus_A);
  Fp vvvY1Z2;
  fp_mont_mul(vvvY1Z2, vvv, Y1Z2);
  result.Y = uR_minus_A - vvvY1Z2;

  // Z3 = vvv * Z1Z2
  fp_mont_mul(result.Z, vvv, Z1Z2);
}

// Projective point addition: result = p1 + p2 (no inversions!) - G2
// specialization
__host__ __device__ void projective_point_add(G2Projective &result,
                                              const G2Projective &p1,
                                              const G2Projective &p2) {
  // Handle infinity cases
  if (fp2_is_zero(p1.Z)) {
    result = p2;
    return;
  }
  if (fp2_is_zero(p2.Z)) {
    result = p1;
    return;
  }

  // G2 projective addition (same algorithm with Fp2)
  Fp2 Y1Z2, X1Z2, Z1Z2, u, uu, v, vv, vvv, R, A;

  fp2_mont_mul(Y1Z2, p1.Y, p2.Z);
  fp2_mont_mul(X1Z2, p1.X, p2.Z);
  fp2_mont_mul(Z1Z2, p1.Z, p2.Z);

  Fp2 Y2Z1;
  fp2_mont_mul(Y2Z1, p2.Y, p1.Z);
  u = Y2Z1 - Y1Z2;

  fp2_mont_mul(uu, u, u);

  Fp2 X2Z1;
  fp2_mont_mul(X2Z1, p2.X, p1.Z);
  v = X2Z1 - X1Z2;

  // Check if this is actually a doubling case (p1 == p2)
  if (fp2_is_zero(u) && fp2_is_zero(v)) {
    projective_point_double(result, p1);
    return;
  }

  fp2_mont_mul(vv, v, v);
  fp2_mont_mul(vvv, v, vv);

  fp2_mont_mul(R, vv, X1Z2);

  // A = uu * Z1Z2 - vvv - 2*R
  Fp2 temp1, two_R;
  fp2_mont_mul(temp1, uu, Z1Z2);
  Fp2 temp2 = temp1 - vvv;
  // Compute 2*R using cached Montgomery constant
  Fp2 two_mont;
#ifdef __CUDA_ARCH__
  fp2_two_montgomery(two_mont);
#else
  two_mont = get_fp2_mont_constants_host().two;
#endif
  fp2_mont_mul(two_R, two_mont, R);
  A = temp2 - two_R;

  fp2_mont_mul(result.X, v, A);

  Fp2 R_minus_A = R - A;
  Fp2 uR_minus_A;
  fp2_mont_mul(uR_minus_A, u, R_minus_A);
  Fp2 vvvY1Z2;
  fp2_mont_mul(vvvY1Z2, vvv, Y1Z2);
  result.Y = uR_minus_A - vvvY1Z2;

  fp2_mont_mul(result.Z, vvv, Z1Z2);
}

// Mixed addition: result = p1 (projective) + p2 (affine) - G1 specialization
// Optimized for when Z2=1: saves 3 field multiplications vs
// projective+projective This is ~25% faster than converting affine to
// projective then adding
__host__ __device__ void projective_mixed_add(G1Projective &result,
                                              const G1Projective &p1,
                                              const G1Affine &p2) {
  // Handle infinity cases
  // Note: All coordinates are in Montgomery form per convention
  if (fp_is_zero(p1.Z)) {
    // p1 is infinity, result = p2 (convert affine to projective)
    if (p2.infinity) {
      fp_zero(result.X);
      fp_one_montgomery(result.Y);
      fp_zero(result.Z);
    } else {
      result.X = p2.x;
      result.Y = p2.y;
      fp_one_montgomery(result.Z);
    }
    return;
  }
  if (p2.infinity) {
    result = p1;
    return;
  }

  // Mixed addition: p2.Z is implicitly 1
  // Simplified formulas when Z2=1:
  // Y1Z2 = Y1 (skip mul), X1Z2 = X1 (skip mul), Z1Z2 = Z1 (skip mul)
  Fp u, uu, v, vv, vvv, R, A;

  // u = Y2 * Z1 - Y1 (since Y1Z2 = Y1 when Z2=1)
  Fp Y2Z1;
  fp_mont_mul(Y2Z1, p2.y, p1.Z);
  u = Y2Z1 - p1.Y;

  // v = X2 * Z1 - X1 (since X1Z2 = X1 when Z2=1)
  Fp X2Z1;
  fp_mont_mul(X2Z1, p2.x, p1.Z);
  v = X2Z1 - p1.X;

  // Check if this is actually a doubling case (p1 == p2)
  if (fp_is_zero(u) && fp_is_zero(v)) {
    projective_point_double(result, p1);
    return;
  }

  // uu = u^2
  fp_mont_mul(uu, u, u);
  // vv = v^2
  fp_mont_mul(vv, v, v);
  // vvv = v * vv
  fp_mont_mul(vvv, v, vv);

  // R = vv * X1 (since X1Z2 = X1 when Z2=1)
  fp_mont_mul(R, vv, p1.X);

  // A = uu * Z1 - vvv - 2*R (since Z1Z2 = Z1 when Z2=1)
  Fp temp1, two_R;
  fp_mont_mul(temp1, uu, p1.Z);
  Fp temp2 = temp1 - vvv;
  // Compute 2*R
  Fp two_mont;
#ifdef __CUDA_ARCH__
  fp_two_montgomery(two_mont);
#else
  two_mont = get_fp_mont_constants_host().two;
#endif
  fp_mont_mul(two_R, two_mont, R);
  A = temp2 - two_R;

  // X3 = v * A
  fp_mont_mul(result.X, v, A);

  // Y3 = u * (R - A) - vvv * Y1 (since Y1Z2 = Y1 when Z2=1)
  Fp R_minus_A = R - A;
  Fp uR_minus_A;
  fp_mont_mul(uR_minus_A, u, R_minus_A);
  Fp vvvY1;
  fp_mont_mul(vvvY1, vvv, p1.Y);
  result.Y = uR_minus_A - vvvY1;

  // Z3 = vvv * Z1 (since Z1Z2 = Z1 when Z2=1)
  fp_mont_mul(result.Z, vvv, p1.Z);
}

// Mixed addition: result = p1 (projective) + p2 (affine) - G2 specialization
// Optimized for when Z2=1: saves 3 field multiplications vs
// projective+projective
__host__ __device__ void projective_mixed_add(G2Projective &result,
                                              const G2Projective &p1,
                                              const G2Affine &p2) {
  // Handle infinity cases
  if (fp2_is_zero(p1.Z)) {
    // p1 is infinity, result = p2 (convert affine to projective)
    if (p2.infinity) {
      fp2_zero(result.X);
      fp2_one(result.Y);
      fp2_zero(result.Z);
    } else {
      result.X = p2.x;
      result.Y = p2.y;
      fp2_one(result.Z);
    }
    return;
  }
  if (p2.infinity) {
    result = p1;
    return;
  }

  // Mixed addition: p2.Z is implicitly 1
  Fp2 u, uu, v, vv, vvv, R, A;

  // u = Y2 * Z1 - Y1
  Fp2 Y2Z1;
  fp2_mont_mul(Y2Z1, p2.y, p1.Z);
  u = Y2Z1 - p1.Y;

  // v = X2 * Z1 - X1
  Fp2 X2Z1;
  fp2_mont_mul(X2Z1, p2.x, p1.Z);
  v = X2Z1 - p1.X;

  // Check if this is actually a doubling case
  if (fp2_is_zero(u) && fp2_is_zero(v)) {
    projective_point_double(result, p1);
    return;
  }

  // uu = u^2, vv = v^2, vvv = v * vv
  fp2_mont_mul(uu, u, u);
  fp2_mont_mul(vv, v, v);
  fp2_mont_mul(vvv, v, vv);

  // R = vv * X1
  fp2_mont_mul(R, vv, p1.X);

  // A = uu * Z1 - vvv - 2*R
  Fp2 temp1, two_R;
  fp2_mont_mul(temp1, uu, p1.Z);
  Fp2 temp2 = temp1 - vvv;
  Fp2 two_mont;
#ifdef __CUDA_ARCH__
  fp2_two_montgomery(two_mont);
#else
  two_mont = get_fp2_mont_constants_host().two;
#endif
  fp2_mont_mul(two_R, two_mont, R);
  A = temp2 - two_R;

  // X3 = v * A
  fp2_mont_mul(result.X, v, A);

  // Y3 = u * (R - A) - vvv * Y1
  Fp2 R_minus_A = R - A;
  Fp2 uR_minus_A;
  fp2_mont_mul(uR_minus_A, u, R_minus_A);
  Fp2 vvvY1;
  fp2_mont_mul(vvvY1, vvv, p1.Y);
  result.Y = uR_minus_A - vvvY1;

  // Z3 = vvv * Z1
  fp2_mont_mul(result.Z, vvv, p1.Z);
}

// Projective point doubling: result = 2 * p (no inversions!) - G1
// specialization
// Optimized: uses cached Montgomery constants (host) or computes once (device)
__host__ __device__ void projective_point_double(G1Projective &result,
                                                 const G1Projective &p) {
  // Handle infinity
  if (fp_is_zero(p.Z)) {
    result = p;
    return;
  }

  // G1 projective doubling using hyperelliptic.org formula
  // For curves y^2 = x^3 + a_4*x + b with a_4 = 0

  // Get Montgomery constants (cached for host, computed once for device)
  Fp two_mont, three_mont, four_mont, eight_mont;
#ifdef __CUDA_ARCH__
  init_fp_mont_constants(two_mont, three_mont, four_mont, eight_mont);
#else
  const FpMontConstants &c = get_fp_mont_constants_host();
  two_mont = c.two;
  three_mont = c.three;
  four_mont = c.four;
  eight_mont = c.eight;
#endif

  // A = 3 * X^2
  Fp X_sq, A;
  fp_mont_mul(X_sq, p.X, p.X);
  fp_mont_mul(A, three_mont, X_sq);

  // B = Y * Z
  Fp B;
  fp_mont_mul(B, p.Y, p.Z);

  // C = X * Y * B
  Fp XY, C;
  fp_mont_mul(XY, p.X, p.Y);
  fp_mont_mul(C, XY, B);

  // D = A^2 - 8*C
  Fp A_sq, eight_C;
  fp_mont_mul(A_sq, A, A);
  fp_mont_mul(eight_C, eight_mont, C);
  Fp D = A_sq - eight_C;

  // X₃ = 2 * B * D
  Fp BD;
  fp_mont_mul(BD, B, D);
  fp_mont_mul(result.X, two_mont, BD);

  // Y₃ = A * (4*C - D) - 8 * Y^2 * B^2
  Fp four_C, A_times_diff;
  fp_mont_mul(four_C, four_mont, C);
  Fp four_C_minus_D = four_C - D;
  fp_mont_mul(A_times_diff, A, four_C_minus_D);

  Fp Y_sq, B_sq, Y_sq_B_sq, eight_Y_sq_B_sq;
  fp_mont_mul(Y_sq, p.Y, p.Y);
  fp_mont_mul(B_sq, B, B);
  fp_mont_mul(Y_sq_B_sq, Y_sq, B_sq);
  fp_mont_mul(eight_Y_sq_B_sq, eight_mont, Y_sq_B_sq);
  result.Y = A_times_diff - eight_Y_sq_B_sq;

  // Z₃ = 8 * B^3
  Fp B_cu;
  fp_mont_mul(B_cu, B_sq, B);
  fp_mont_mul(result.Z, eight_mont, B_cu);
}

// Projective point doubling: result = 2 * p (no inversions!) - G2
// specialization
// Optimized: uses cached Montgomery constants (host) or computes once (device)
__host__ __device__ void projective_point_double(G2Projective &result,
                                                 const G2Projective &p) {
  // Handle infinity
  if (fp2_is_zero(p.Z)) {
    result = p;
    return;
  }

  // G2 projective doubling (same as G1 but with Fp2)

  // Get Montgomery constants (cached for host, computed once for device)
  Fp2 two_mont, three_mont, four_mont, eight_mont;
#ifdef __CUDA_ARCH__
  init_fp2_mont_constants(two_mont, three_mont, four_mont, eight_mont);
#else
  const Fp2MontConstants &c = get_fp2_mont_constants_host();
  two_mont = c.two;
  three_mont = c.three;
  four_mont = c.four;
  eight_mont = c.eight;
#endif

  // A = 3 * X^2
  Fp2 X_sq, A;
  fp2_mont_mul(X_sq, p.X, p.X);
  fp2_mont_mul(A, three_mont, X_sq);

  // B = Y * Z
  Fp2 B;
  fp2_mont_mul(B, p.Y, p.Z);

  // C = X * Y * B
  Fp2 XY, C;
  fp2_mont_mul(XY, p.X, p.Y);
  fp2_mont_mul(C, XY, B);

  // D = A^2 - 8*C
  Fp2 A_sq, eight_C;
  fp2_mont_mul(A_sq, A, A);
  fp2_mont_mul(eight_C, eight_mont, C);
  Fp2 D = A_sq - eight_C;

  // X₃ = 2 * B * D
  Fp2 BD;
  fp2_mont_mul(BD, B, D);
  fp2_mont_mul(result.X, two_mont, BD);

  // Y₃ = A * (4*C - D) - 8 * Y^2 * B^2
  Fp2 four_C, A_times_diff;
  fp2_mont_mul(four_C, four_mont, C);
  Fp2 four_C_minus_D = four_C - D;
  fp2_mont_mul(A_times_diff, A, four_C_minus_D);

  Fp2 Y_sq, B_sq, Y_sq_B_sq, eight_Y_sq_B_sq;
  fp2_mont_mul(Y_sq, p.Y, p.Y);
  fp2_mont_mul(B_sq, B, B);
  fp2_mont_mul(Y_sq_B_sq, Y_sq, B_sq);
  fp2_mont_mul(eight_Y_sq_B_sq, eight_mont, Y_sq_B_sq);
  result.Y = A_times_diff - eight_Y_sq_B_sq;

  // Z₃ = 8 * B^3
  Fp2 B_cu;
  fp2_mont_mul(B_cu, B_sq, B);
  fp2_mont_mul(result.Z, eight_mont, B_cu);
}

// ============================================================================
// MSM functions have been moved to src/msm/ directory
// ============================================================================
// The MSM entry points (point_msm_async_g1, point_msm_async_g2, etc.) are now
// implemented in src/msm/msm.cu using the Pippenger algorithm.

// Helper function to extract a window from a BigInt5 scalar
__device__ __forceinline__ uint32_t extract_window_bigint5(
    const Scalar &scalar, uint32_t window_idx, uint32_t window_size) {
  return extract_window_multi_internal(scalar.limb, ZP_LIMBS, window_idx,
                                       window_size);
}

// ============================================================================
// Template MSM Kernel (works for both G1 and G2)
// ============================================================================

// Template kernel: Accumulate buckets for MSM (works for both G1 and G2)
template <typename AffineType, typename ProjectiveType>
__global__ void kernel_accumulate_buckets_bigint5_projective_template(
    ProjectiveType *block_buckets, const AffineType *points,
    const Scalar *scalars, uint32_t n, uint32_t window_idx,
    uint32_t window_size) {
  using ProjectivePoint = Projective<ProjectiveType>;
  using FieldType = typename ProjectivePoint::Field;

  // Shared memory layout
  extern __shared__ char shared_mem[];
  auto *shared_buckets = reinterpret_cast<ProjectiveType *>(shared_mem);
  auto *thread_points = reinterpret_cast<ProjectiveType *>(
      shared_mem + MSM_G1_BUCKET_COUNT * sizeof(ProjectiveType));
  auto *thread_buckets = reinterpret_cast<int *>(
      shared_mem + MSM_G1_BUCKET_COUNT * sizeof(ProjectiveType) +
      blockDim.x * sizeof(ProjectiveType));

  // Initialize shared memory buckets to infinity (Z = 0)
  for (uint32_t i = threadIdx.x; i < MSM_G1_BUCKET_COUNT; i += blockDim.x) {
    ProjectivePoint::point_at_infinity(shared_buckets[i]);
  }
  __syncthreads();

  uint32_t point_idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (point_idx < n) {
    uint32_t bucket_idx =
        extract_window_bigint5(scalars[point_idx], window_idx, window_size);
    // Convert affine to projective at INPUT (no inversions needed later!)
    ProjectivePoint::affine_to_projective(thread_points[threadIdx.x],
                                          points[point_idx]);
    thread_buckets[threadIdx.x] = bucket_idx;
  } else {
    // Affine at infinity in projective form (Z = 0)
    ProjectivePoint::point_at_infinity(thread_points[threadIdx.x]);
    thread_buckets[threadIdx.x] = 0;
  }
  __syncthreads();

  uint32_t num_warps = CEIL_DIV(blockDim.x, CUDA_WARP_SIZE);
  uint32_t warp_id = threadIdx.x / CUDA_WARP_SIZE;
  uint32_t lane_id = threadIdx.x % CUDA_WARP_SIZE;

  // Phase 1: Warp-level reduction (if more than 1 warp AND n > 1)
  if (num_warps > 1 && n > 1) {
    auto *warp_buckets = reinterpret_cast<ProjectiveType *>(
        shared_mem + MSM_G1_BUCKET_COUNT * sizeof(ProjectiveType) +
        blockDim.x * sizeof(ProjectiveType) + blockDim.x * sizeof(int));
    auto *my_warp_buckets = warp_buckets + warp_id * MSM_G1_BUCKET_COUNT;

    // Initialize warp buckets
    if (lane_id < MSM_G1_BUCKET_COUNT) {
      ProjectivePoint::point_at_infinity(my_warp_buckets[lane_id]);
    }
    __syncwarp();

    // FIXED: Proper reduction pattern - each thread processes assigned buckets
    for (uint32_t bucket = lane_id; bucket < MSM_G1_BUCKET_COUNT;
         bucket += CUDA_WARP_SIZE) {
      for (int t = 0; t < blockDim.x; t++) {
        uint32_t t_warp_id = t / CUDA_WARP_SIZE;
        if (t_warp_id == warp_id) {
          uint32_t t_bucket = thread_buckets[t];
          uint32_t t_point_idx = blockIdx.x * blockDim.x + t;
          if (t_bucket == bucket && t_point_idx < n && bucket > 0) {
            if (ProjectivePoint::field_is_zero(my_warp_buckets[bucket].Z)) {
              my_warp_buckets[bucket] = thread_points[t];
            } else {
              ProjectiveType temp;
              ProjectivePoint::projective_add(temp, my_warp_buckets[bucket],
                                              thread_points[t]);
              my_warp_buckets[bucket] = temp;
            }
          }
        }
      }
    }
    __syncwarp();

    // Phase 2: Reduce warp buckets to shared buckets
    for (uint32_t i = lane_id; i < MSM_G1_BUCKET_COUNT; i += CUDA_WARP_SIZE) {
      if (!ProjectivePoint::field_is_zero(my_warp_buckets[i].Z)) {
        if (ProjectivePoint::field_is_zero(shared_buckets[i].Z)) {
          shared_buckets[i] = my_warp_buckets[i];
        } else {
          ProjectiveType temp;
          ProjectivePoint::projective_add(temp, shared_buckets[i],
                                          my_warp_buckets[i]);
          shared_buckets[i] = temp;
        }
      }
    }
  } else {
    // Direct reduction to shared buckets (only for n=1, or single warp)
    for (uint32_t bucket = threadIdx.x; bucket < MSM_G1_BUCKET_COUNT;
         bucket += blockDim.x) {
      for (int t = 0; t < blockDim.x; t++) {
        uint32_t t_bucket = thread_buckets[t];
        uint32_t t_point_idx = blockIdx.x * blockDim.x + t;
        if (t_bucket == bucket && t_point_idx < n && bucket > 0) {
          if (ProjectivePoint::field_is_zero(shared_buckets[bucket].Z)) {
            shared_buckets[bucket] = thread_points[t];
          } else {
            ProjectiveType temp;
            ProjectivePoint::projective_add(temp, shared_buckets[bucket],
                                            thread_points[t]);
            shared_buckets[bucket] = temp;
          }
        }
      }
    }
  }
  __syncthreads();

  // Phase 3: Write shared buckets to block buckets (one thread per bucket)
  if (threadIdx.x < MSM_G1_BUCKET_COUNT) {
    uint32_t block_bucket_idx = blockIdx.x * MSM_G1_BUCKET_COUNT + threadIdx.x;
    block_buckets[block_bucket_idx] = shared_buckets[threadIdx.x];
  }
}

// Legacy kernels (kept for compatibility, now just call template version)
// Kernel: Accumulate buckets for G1 with BigInt5 scalars (projective
// coordinates)
__global__ void kernel_accumulate_buckets_bigint5_projective_g1(
    G1Projective *block_buckets, const G1Affine *points, const Scalar *scalars,
    int n, int window_idx, int window_size) {
  // Shared memory layout (same as u64 version)
  extern __shared__ char shared_mem[];
  auto *shared_buckets = reinterpret_cast<G1Projective *>(shared_mem);
  auto *thread_points = reinterpret_cast<G1Projective *>(
      shared_mem + MSM_G1_BUCKET_COUNT * sizeof(G1Projective));
  auto *thread_buckets = reinterpret_cast<int *>(
      shared_mem + MSM_G1_BUCKET_COUNT * sizeof(G1Projective) +
      blockDim.x * sizeof(G1Projective));

  // Initialize shared memory buckets to infinity (Z = 0)
  for (uint32_t i = threadIdx.x; i < MSM_G1_BUCKET_COUNT; i += blockDim.x) {
    g1_projective_point_at_infinity(shared_buckets[i]);
  }
  __syncthreads();

  uint32_t point_idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (point_idx < n) {
    uint32_t bucket_idx =
        extract_window_bigint5(scalars[point_idx], window_idx, window_size);
    // Convert affine to projective at INPUT (no inversions needed later!)
    affine_to_projective(thread_points[threadIdx.x], points[point_idx]);
    thread_buckets[threadIdx.x] = bucket_idx;
  } else {
    // Affine at infinity in projective form (Z = 0)
    g1_projective_point_at_infinity(thread_points[threadIdx.x]);
    thread_buckets[threadIdx.x] = 0;
  }
  __syncthreads();

  uint32_t num_warps = CEIL_DIV(blockDim.x, CUDA_WARP_SIZE);
  uint32_t warp_id = threadIdx.x / CUDA_WARP_SIZE;
  uint32_t lane_id = threadIdx.x % CUDA_WARP_SIZE;

  // Phase 1: Warp-level reduction (if more than 1 warp AND n > 1)
  // FIXED: Always use warp reduction when n > 1 to avoid race conditions in
  // direct reduction For n=1, use direct reduction to avoid potential warp
  // reduction issues
  if (num_warps > 1 && n > 1) {
    auto *warp_buckets = reinterpret_cast<G1Projective *>(
        shared_mem + MSM_G1_BUCKET_COUNT * sizeof(G1Projective) +
        blockDim.x * sizeof(G1Projective) + blockDim.x * sizeof(int));
    auto *my_warp_buckets = warp_buckets + warp_id * MSM_G1_BUCKET_COUNT;

    // Initialize warp buckets
    if (lane_id < MSM_G1_BUCKET_COUNT) {
      g1_projective_point_at_infinity(my_warp_buckets[lane_id]);
    }
    __syncwarp();

    // CORRECT REDUCTION PATTERN: Match the working template implementation
    // EXACTLY Iterate through all threads in block and filter by warp_id This
    // ensures correctness even when warps are partially filled
    for (uint32_t bucket = lane_id; bucket < MSM_G1_BUCKET_COUNT;
         bucket += CUDA_WARP_SIZE) {
      for (int t = 0; t < blockDim.x; t++) {
        uint32_t t_warp_id = t / CUDA_WARP_SIZE;
        // Only process threads in the same warp
        if (t_warp_id == warp_id) {
          uint32_t t_bucket = thread_buckets[t];
          uint32_t t_point_idx = blockIdx.x * blockDim.x + t;
          // Match template exactly: check all conditions together
          if (t_bucket == bucket && t_point_idx < n && bucket > 0) {
            // This thread's point belongs to this bucket
            if (fp_is_zero(my_warp_buckets[bucket].Z)) {
              // Bucket is empty, write directly
              my_warp_buckets[bucket] = thread_points[t];
            } else {
              // Bucket already has a point, add to it
              G1Projective temp;
              projective_point_add(temp, my_warp_buckets[bucket],
                                   thread_points[t]);
              my_warp_buckets[bucket] = temp;
            }
          }
        }
      }
    }
    __syncwarp();

    // Phase 2: Reduce warp buckets to shared buckets
    // Match template exactly
    for (uint32_t i = lane_id; i < MSM_G1_BUCKET_COUNT; i += CUDA_WARP_SIZE) {
      if (!fp_is_zero(my_warp_buckets[i].Z)) {
        if (fp_is_zero(shared_buckets[i].Z)) {
          shared_buckets[i] = my_warp_buckets[i];
        } else {
          G1Projective temp;
          projective_point_add(temp, shared_buckets[i], my_warp_buckets[i]);
          shared_buckets[i] = temp;
        }
      }
    }
  } else {
    // Direct reduction to shared buckets (only for n=1, or single warp)
    // FIXED: Proper reduction pattern - each thread processes assigned buckets
    // Each thread is responsible for accumulating points for specific buckets
    // This avoids race conditions by ensuring only one thread writes to each
    // bucket
    for (uint32_t bucket = threadIdx.x; bucket < MSM_G1_BUCKET_COUNT;
         bucket += blockDim.x) {
      // This thread is responsible for this bucket
      // Iterate through all threads and accumulate points for this bucket
      for (int t = 0; t < blockDim.x; t++) {
        uint32_t t_bucket = thread_buckets[t];
        uint32_t t_point_idx = blockIdx.x * blockDim.x + t;
        if (t_bucket == bucket && t_point_idx < n && bucket > 0) {
          // This thread's point belongs to this bucket
          if (fp_is_zero(shared_buckets[bucket].Z)) {
            // Bucket is empty, write directly (use structure copy for
            // atomicity)
            shared_buckets[bucket] = thread_points[t];
          } else {
            // Bucket already has a point, add to it
            G1Projective temp;
            projective_point_add(temp, shared_buckets[bucket],
                                 thread_points[t]);
            shared_buckets[bucket] = temp;
          }
        }
      }
    }
  }
  __syncthreads();

  // Phase 3: Write shared buckets to block buckets (one thread per bucket)
  if (threadIdx.x < MSM_G1_BUCKET_COUNT) {
    uint32_t block_bucket_idx = blockIdx.x * MSM_G1_BUCKET_COUNT + threadIdx.x;
    block_buckets[block_bucket_idx] = shared_buckets[threadIdx.x];
  }
}

// Kernel: Accumulate buckets for G2 with BigInt5 scalars (projective
// coordinates)
__global__ void kernel_accumulate_buckets_bigint5_projective_g2(
    G2Projective *block_buckets, const G2Affine *points, const Scalar *scalars,
    int n, int window_idx, int window_size) {
  extern __shared__ char shared_mem[];
  auto *shared_buckets = reinterpret_cast<G2Projective *>(shared_mem);
  auto *thread_points = reinterpret_cast<G2Projective *>(
      shared_mem + MSM_G2_BUCKET_COUNT * sizeof(G2Projective));
  auto *thread_buckets = reinterpret_cast<int *>(
      shared_mem + MSM_G2_BUCKET_COUNT * sizeof(G2Projective) +
      blockDim.x * sizeof(G2Projective));

  for (uint32_t i = threadIdx.x; i < MSM_G2_BUCKET_COUNT; i += blockDim.x) {
    g2_projective_point_at_infinity(shared_buckets[i]);
  }
  __syncthreads();

  uint32_t point_idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (point_idx < n) {
    uint32_t bucket_idx =
        extract_window_bigint5(scalars[point_idx], window_idx, window_size);
    // Convert affine to projective at INPUT (no inversions needed later!)
    affine_to_projective(thread_points[threadIdx.x], points[point_idx]);
    thread_buckets[threadIdx.x] = bucket_idx;
  } else {
    g2_projective_point_at_infinity(thread_points[threadIdx.x]);
    thread_buckets[threadIdx.x] = 0;
  }
  __syncthreads();

  uint32_t num_warps = CEIL_DIV(blockDim.x, CUDA_WARP_SIZE);
  uint32_t warp_id = threadIdx.x / CUDA_WARP_SIZE;
  uint32_t lane_id = threadIdx.x % CUDA_WARP_SIZE;

  // Phase 1: Warp-level reduction (if more than 1 warp AND n > 1)
  // FIXED: Always use warp reduction when n > 1 to avoid race conditions in
  // direct reduction
  if (num_warps > 1 && n > 1) {
    auto *warp_buckets = reinterpret_cast<G2Projective *>(
        shared_mem + MSM_G2_BUCKET_COUNT * sizeof(G2Projective) +
        blockDim.x * sizeof(G2Projective) + blockDim.x * sizeof(int));
    auto *my_warp_buckets = warp_buckets + warp_id * MSM_G2_BUCKET_COUNT;

    // Initialize warp buckets
    if (lane_id < MSM_G2_BUCKET_COUNT) {
      g2_projective_point_at_infinity(my_warp_buckets[lane_id]);
    }
    __syncwarp();

    // CORRECT REDUCTION PATTERN: Match the working template implementation
    // EXACTLY Iterate through all threads in block and filter by warp_id This
    // ensures correctness even when warps are partially filled
    for (uint32_t bucket = lane_id; bucket < MSM_G2_BUCKET_COUNT;
         bucket += CUDA_WARP_SIZE) {
      for (int t = 0; t < blockDim.x; t++) {
        uint32_t t_warp_id = t / CUDA_WARP_SIZE;
        // Only process threads in the same warp
        if (t_warp_id == warp_id) {
          uint32_t t_bucket = thread_buckets[t];
          uint32_t t_point_idx = blockIdx.x * blockDim.x + t;
          // Match template exactly: check all conditions together
          if (t_bucket == bucket && t_point_idx < n && bucket > 0) {
            // This thread's point belongs to this bucket
            if (fp2_is_zero(my_warp_buckets[bucket].Z)) {
              // Bucket is empty, write directly
              my_warp_buckets[bucket] = thread_points[t];
            } else {
              // Bucket already has a point, add to it
              G2Projective temp;
              projective_point_add(temp, my_warp_buckets[bucket],
                                   thread_points[t]);
              my_warp_buckets[bucket] = temp;
            }
          }
        }
      }
    }
    __syncwarp();

    // Phase 2: Reduce warp buckets to shared buckets
    // Match template exactly
    for (uint32_t i = lane_id; i < MSM_G2_BUCKET_COUNT; i += CUDA_WARP_SIZE) {
      if (!fp2_is_zero(my_warp_buckets[i].Z)) {
        if (fp2_is_zero(shared_buckets[i].Z)) {
          shared_buckets[i] = my_warp_buckets[i];
        } else {
          G2Projective temp;
          projective_point_add(temp, shared_buckets[i], my_warp_buckets[i]);
          shared_buckets[i] = temp;
        }
      }
    }
  } else {
    // Direct reduction to shared buckets (only for n=1, or single warp)
    // FIXED: Proper reduction pattern - each thread processes assigned buckets
    // Each thread is responsible for accumulating points for specific buckets
    // This avoids race conditions by ensuring only one thread writes to each
    // bucket
    for (uint32_t bucket = threadIdx.x; bucket < MSM_G2_BUCKET_COUNT;
         bucket += blockDim.x) {
      // This thread is responsible for this bucket
      // Iterate through all threads and accumulate points for this bucket
      for (int t = 0; t < blockDim.x; t++) {
        uint32_t t_bucket = thread_buckets[t];
        uint32_t t_point_idx = blockIdx.x * blockDim.x + t;
        if (t_bucket == bucket && t_point_idx < n && bucket > 0) {
          // This thread's point belongs to this bucket
          if (fp2_is_zero(shared_buckets[bucket].Z)) {
            // Bucket is empty, write directly (use structure copy for
            // atomicity)
            shared_buckets[bucket] = thread_points[t];
          } else {
            // Bucket already has a point, add to it
            G2Projective temp;
            projective_point_add(temp, shared_buckets[bucket],
                                 thread_points[t]);
            shared_buckets[bucket] = temp;
          }
        }
      }
    }
  }
  __syncthreads();

  // Phase 3: Write shared buckets to block buckets (one thread per bucket)
  if (threadIdx.x < MSM_G2_BUCKET_COUNT) {
    uint32_t block_bucket_idx = blockIdx.x * MSM_G2_BUCKET_COUNT + threadIdx.x;
    block_buckets[block_bucket_idx] = shared_buckets[threadIdx.x];
  }
}

// MSM with BigInt5 scalars for G1 (projective coordinates internally)

// MSM with BigInt5 scalars for G2 (projective coordinates internally)

// Synchronous wrappers

// Explicit template instantiations for projective_scalar_mul (needed by MSM)
template void projective_scalar_mul<G1Projective>(G1Projective &result,
                                                  const G1Projective &point,
                                                  const Scalar &scalar);
template void projective_scalar_mul<G2Projective>(G2Projective &result,
                                                  const G2Projective &point,
                                                  const Scalar &scalar);
