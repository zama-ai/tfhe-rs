#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include "point_traits.h"
#include <cstdio>
#include <cstring>

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
  using FieldType = typename AffinePoint::FieldType;

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
  using FieldType = typename AffinePoint::FieldType;

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
  FieldType neg_y2;
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
  FieldType dx, dy, lambda, lambda_squared, x_result;
  AffinePoint::field_sub(dx, p2.x, p1.x);
  AffinePoint::field_sub(dy, p2.y, p1.y);
  AffinePoint::field_inv(lambda, dx);         // 1 / (x2 - x1)
  AffinePoint::field_mul(lambda, lambda, dy); // (y2 - y1) / (x2 - x1)

  // x_result = lambda^2 - x1 - x2
  AffinePoint::field_mul(lambda_squared, lambda, lambda);
  AffinePoint::field_sub(x_result, lambda_squared, p1.x);
  AffinePoint::field_sub(x_result, x_result, p2.x);

  // y_result = lambda * (x1 - x_result) - y1
  FieldType x1_minus_xr, y_result;
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
                 const UNSIGNED_LIMB *scalar, uint32_t scalar_limbs) {
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
      // Skip the final doubling on the MSB -- the doubled value is never used
      if (limb != msb_limb || j != end_bit)
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
  fp2_mont_square(y_squared_mont, y_mont);

  // Compute x^3 in Montgomery form
  Fp2 x_squared_mont, x_cubed_mont;
  fp2_mont_square(x_squared_mont, x_mont);
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
// extract_window_multi_internal and extract_window_multi are defined in
// msm/pippenger/msm_pippenger.cu

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

// Template kernel: Scalar multiplication with a single-limb scalar
template <typename PointType>
__global__ void kernel_single_point_scalar_mul(PointType *result,
                                               const PointType *point,
                                               UNSIGNED_LIMB scalar) {
  point_scalar_mul(*result, *point, &scalar, 1);
}

// Template kernel: Scalar multiplication with multi-limb scalar
template <typename PointType>
__global__ void
kernel_point_scalar_mul(PointType *result, const PointType *point,
                        const UNSIGNED_LIMB *scalar, uint32_t scalar_limbs) {
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

// Template function: Scalar multiplication with a single-limb scalar
template <typename PointType>
void single_point_scalar_mul_async(cudaStream_t stream, uint32_t gpu_index,
                                   PointType *d_result,
                                   const PointType *d_point,
                                   UNSIGNED_LIMB scalar) {
  PANIC_IF_FALSE(d_result != nullptr && d_point != nullptr,
                 "single_point_scalar_mul_async: null pointer argument");
  cuda_set_device(gpu_index);
  kernel_single_point_scalar_mul<PointType>
      <<<1, 1, 0, stream>>>(d_result, d_point, scalar);
  check_cuda_error(cudaGetLastError());
}

template <typename PointType>
void single_point_scalar_mul(cudaStream_t stream, uint32_t gpu_index,
                             PointType *d_result, const PointType *d_point,
                             UNSIGNED_LIMB scalar) {
  single_point_scalar_mul_async<PointType>(stream, gpu_index, d_result, d_point,
                                           scalar);
  cuda_synchronize_stream(stream, gpu_index);
}

// Template function: Scalar multiplication with multi-limb scalar
template <typename PointType>
void point_scalar_mul_async(cudaStream_t stream, uint32_t gpu_index,
                            PointType *d_result, const PointType *d_point,
                            const UNSIGNED_LIMB *d_scalar,
                            uint32_t scalar_limbs) {
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
                      const UNSIGNED_LIMB *d_scalar, uint32_t scalar_limbs) {
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
template void single_point_scalar_mul_async<G1Affine>(cudaStream_t, uint32_t,
                                                      G1Affine *,
                                                      const G1Affine *,
                                                      UNSIGNED_LIMB);
template void single_point_scalar_mul<G1Affine>(cudaStream_t, uint32_t,
                                                G1Affine *, const G1Affine *,
                                                UNSIGNED_LIMB);
template void point_scalar_mul_async<G1Affine>(cudaStream_t, uint32_t,
                                               G1Affine *, const G1Affine *,
                                               const UNSIGNED_LIMB *, uint32_t);
template void point_scalar_mul<G1Affine>(cudaStream_t, uint32_t, G1Affine *,
                                         const G1Affine *,
                                         const UNSIGNED_LIMB *, uint32_t);
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
template void single_point_scalar_mul_async<G2Affine>(cudaStream_t, uint32_t,
                                                      G2Affine *,
                                                      const G2Affine *,
                                                      UNSIGNED_LIMB);
template void single_point_scalar_mul<G2Affine>(cudaStream_t, uint32_t,
                                                G2Affine *, const G2Affine *,
                                                UNSIGNED_LIMB);
template void point_scalar_mul_async<G2Affine>(cudaStream_t, uint32_t,
                                               G2Affine *, const G2Affine *,
                                               const UNSIGNED_LIMB *, uint32_t);
template void point_scalar_mul<G2Affine>(cudaStream_t, uint32_t, G2Affine *,
                                         const G2Affine *,
                                         const UNSIGNED_LIMB *, uint32_t);
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

// Convert from Montgomery form and normalize to Z=1 in one pass (G1).
// Operates directly on Montgomery-form coordinates, avoiding the redundant
// from_montgomery -> to_montgomery round-trip. Only converts to normal form
// once, at the end.
__host__ void normalize_from_montgomery_g1(G1Projective &point) {
  // Check if point is at infinity (Z=0 in Montgomery form)
  if (fp_is_zero(point.Z)) {
    // Convert remaining coordinates to normal form
    fp_from_montgomery(point.X, point.X);
    fp_from_montgomery(point.Y, point.Y);
    return;
  }

  // Compute Z^-1 directly in Montgomery form (no conversion needed)
  Fp z_inv_mont;
  fp_mont_inv(z_inv_mont, point.Z);

  // Normalize: X' = X * Z^-1, Y' = Y * Z^-1 (all in Montgomery form)
  Fp x_norm_mont, y_norm_mont;
  fp_mont_mul(x_norm_mont, point.X, z_inv_mont);
  fp_mont_mul(y_norm_mont, point.Y, z_inv_mont);

  // Single conversion from Montgomery to normal form
  fp_from_montgomery(point.X, x_norm_mont);
  fp_from_montgomery(point.Y, y_norm_mont);

  // Set Z = 1 in normal form
  fp_one(point.Z);
}

// Convert from Montgomery form and normalize to Z=(1,0) in one pass (G2).
// Same optimization as G1: works directly in Montgomery form and converts
// once at the end.
__host__ void normalize_from_montgomery_g2(G2Projective &point) {
  // Check if point is at infinity (Z=0 in Montgomery form)
  if (fp_is_zero(point.Z.c0) && fp_is_zero(point.Z.c1)) {
    // Convert remaining coordinates to normal form
    fp_from_montgomery(point.X.c0, point.X.c0);
    fp_from_montgomery(point.X.c1, point.X.c1);
    fp_from_montgomery(point.Y.c0, point.Y.c0);
    fp_from_montgomery(point.Y.c1, point.Y.c1);
    return;
  }

  // Compute Z^-1 directly in Montgomery form (no conversion needed)
  Fp2 z_inv_mont;
  fp2_mont_inv(z_inv_mont, point.Z);

  // Normalize: X' = X * Z^-1, Y' = Y * Z^-1 (all in Montgomery form)
  Fp2 x_norm_mont, y_norm_mont;
  fp2_mont_mul(x_norm_mont, point.X, z_inv_mont);
  fp2_mont_mul(y_norm_mont, point.Y, z_inv_mont);

  // Single conversion from Montgomery to normal form
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
  fp_double(two_R, R);
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

  fp2_mont_square(uu, u);

  Fp2 X2Z1;
  fp2_mont_mul(X2Z1, p2.X, p1.Z);
  v = X2Z1 - X1Z2;

  // Check if this is actually a doubling case (p1 == p2)
  if (fp2_is_zero(u) && fp2_is_zero(v)) {
    projective_point_double(result, p1);
    return;
  }

  fp2_mont_square(vv, v);
  fp2_mont_mul(vvv, v, vv);

  fp2_mont_mul(R, vv, X1Z2);

  // A = uu * Z1Z2 - vvv - 2*R
  Fp2 temp1, two_R;
  fp2_mont_mul(temp1, uu, Z1Z2);
  Fp2 temp2 = temp1 - vvv;
  fp2_double(two_R, R);
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
  fp_double(two_R, R);
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
  // Note: All coordinates are in Montgomery form per convention
  if (fp2_is_zero(p1.Z)) {
    // p1 is infinity, result = p2 (convert affine to projective)
    if (p2.infinity) {
      fp2_zero(result.X);
      fp_one_montgomery(result.Y.c0);
      fp_zero(result.Y.c1);
      fp2_zero(result.Z);
    } else {
      result.X = p2.x;
      result.Y = p2.y;
      fp_one_montgomery(result.Z.c0);
      fp_zero(result.Z.c1);
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
  fp2_mont_square(uu, u);
  fp2_mont_square(vv, v);
  fp2_mont_mul(vvv, v, vv);

  // R = vv * X1
  fp2_mont_mul(R, vv, p1.X);

  // A = uu * Z1 - vvv - 2*R
  Fp2 temp1, two_R;
  fp2_mont_mul(temp1, uu, p1.Z);
  Fp2 temp2 = temp1 - vvv;
  fp2_double(two_R, R);
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

  // A = 3 * X^2
  Fp X_sq, A;
  fp_mont_mul(X_sq, p.X, p.X);
  fp_mul3(A, X_sq);

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
  fp_mul8(eight_C, C);
  Fp D = A_sq - eight_C;

  // X3 = 2 * B * D
  Fp BD;
  fp_mont_mul(BD, B, D);
  fp_double(result.X, BD);

  // Y3 = A * (4*C - D) - 8 * Y^2 * B^2
  Fp four_C, A_times_diff;
  fp_mul4(four_C, C);
  Fp four_C_minus_D = four_C - D;
  fp_mont_mul(A_times_diff, A, four_C_minus_D);

  Fp Y_sq, B_sq, Y_sq_B_sq, eight_Y_sq_B_sq;
  fp_mont_mul(Y_sq, p.Y, p.Y);
  fp_mont_mul(B_sq, B, B);
  fp_mont_mul(Y_sq_B_sq, Y_sq, B_sq);
  fp_mul8(eight_Y_sq_B_sq, Y_sq_B_sq);
  result.Y = A_times_diff - eight_Y_sq_B_sq;

  // Z3 = 8 * B^3
  Fp B_cu;
  fp_mont_mul(B_cu, B_sq, B);
  fp_mul8(result.Z, B_cu);
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

  // A = 3 * X^2
  Fp2 X_sq, A;
  fp2_mont_square(X_sq, p.X);
  fp2_mul3(A, X_sq);

  // B = Y * Z
  Fp2 B;
  fp2_mont_mul(B, p.Y, p.Z);

  // C = X * Y * B
  Fp2 XY, C;
  fp2_mont_mul(XY, p.X, p.Y);
  fp2_mont_mul(C, XY, B);

  // D = A^2 - 8*C
  Fp2 A_sq, eight_C;
  fp2_mont_square(A_sq, A);
  fp2_mul8(eight_C, C);
  Fp2 D = A_sq - eight_C;

  // X3 = 2 * B * D
  Fp2 BD;
  fp2_mont_mul(BD, B, D);
  fp2_double(result.X, BD);

  // Y3 = A * (4*C - D) - 8 * Y^2 * B^2
  Fp2 four_C, A_times_diff;
  fp2_mul4(four_C, C);
  Fp2 four_C_minus_D = four_C - D;
  fp2_mont_mul(A_times_diff, A, four_C_minus_D);

  Fp2 Y_sq, B_sq, Y_sq_B_sq, eight_Y_sq_B_sq;
  fp2_mont_square(Y_sq, p.Y);
  fp2_mont_square(B_sq, B);
  fp2_mont_mul(Y_sq_B_sq, Y_sq, B_sq);
  fp2_mul8(eight_Y_sq_B_sq, Y_sq_B_sq);
  result.Y = A_times_diff - eight_Y_sq_B_sq;

  // Z3 = 8 * B^3
  Fp2 B_cu;
  fp2_mont_mul(B_cu, B_sq, B);
  fp2_mul8(result.Z, B_cu);
}

// Explicit template instantiations for projective_scalar_mul (needed by MSM)
template void projective_scalar_mul<G1Projective>(G1Projective &result,
                                                  const G1Projective &point,
                                                  const Scalar &scalar);
template void projective_scalar_mul<G2Projective>(G2Projective &result,
                                                  const G2Projective &point,
                                                  const Scalar &scalar);
