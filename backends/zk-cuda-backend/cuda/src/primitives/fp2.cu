#include "device.h"
#include "fp2.h"
#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>

// Comparison: compares c0 first, then c1
// NOTE: This comparison has a timing side-channel (reveals which component
// differs first). This is acceptable in current usage but should be addressed
// if constant-time comparisons become necessary.
__host__ __device__ ComparisonType fp2_cmp(const Fp2 &a, const Fp2 &b) {
  ComparisonType cmp0 = fp_cmp(a.c0, b.c0);
  if (cmp0 != ComparisonType::Equal)
    return cmp0;
  return fp_cmp(a.c1, b.c1);
}

__host__ __device__ bool fp2_is_zero(const Fp2 &a) {
  return fp_is_zero(a.c0) && fp_is_zero(a.c1);
}

__host__ __device__ bool fp2_is_one(const Fp2 &a) {
  return fp_is_one(a.c0) && fp_is_zero(a.c1);
}

// Set to zero
__host__ __device__ void fp2_zero(Fp2 &a) {
  fp_zero(a.c0);
  fp_zero(a.c1);
}

// Set to one (1 + 0*i)
__host__ __device__ void fp2_one(Fp2 &a) {
  fp_one(a.c0);
  fp_zero(a.c1);
}

// Helper functions to get small integers in Montgomery form for Fp2
// These are real numbers (c1 = 0) in Montgomery form
// Note: Zero is identical in both normal and Montgomery form
__host__ __device__ void fp2_two_montgomery(Fp2 &a) {
  fp_two_montgomery(a.c0);
  fp_zero(a.c1);
}

__host__ __device__ void fp2_three_montgomery(Fp2 &a) {
  fp_three_montgomery(a.c0);
  fp_zero(a.c1);
}

__host__ __device__ void fp2_four_montgomery(Fp2 &a) {
  fp_four_montgomery(a.c0);
  fp_zero(a.c1);
}

__host__ __device__ void fp2_eight_montgomery(Fp2 &a) {
  fp_eight_montgomery(a.c0);
  fp_zero(a.c1);
}

// Copy: dst = src
__host__ __device__ void fp2_copy(Fp2 &dst, const Fp2 &src) {
  fp_copy(dst.c0, src.c0);
  fp_copy(dst.c1, src.c1);
}

__host__ __device__ void fp2_add(Fp2 &c, const Fp2 &a, const Fp2 &b) {
  fp_add(c.c0, a.c0, b.c0);
  fp_add(c.c1, a.c1, b.c1);
}

__host__ __device__ void fp2_sub(Fp2 &c, const Fp2 &a, const Fp2 &b) {
  fp_sub(c.c0, a.c0, b.c0);
  fp_sub(c.c1, a.c1, b.c1);
}

// Multiplication: c = a * b
// (a0 + a1*i) * (b0 + b1*i) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*i
// Optimized: converts to Montgomery once at start, operates, converts back at
// end (6 conversions instead of 9)
__host__ __device__ void fp2_mul(Fp2 &c, const Fp2 &a, const Fp2 &b) {
  // Special case: multiply by 1
  if (fp2_is_one(b)) {
    fp2_copy(c, a);
    return;
  }
  // Special case: multiply by 0
  if (fp2_is_zero(b)) {
    fp2_zero(c);
    return;
  }
  // Special case: 1 * b = b
  if (fp2_is_one(a)) {
    fp2_copy(c, b);
    return;
  }
  // Special case: 0 * b = 0
  if (fp2_is_zero(a)) {
    fp2_zero(c);
    return;
  }

  // Convert all inputs to Montgomery form once
  Fp a0_m{}, a1_m{}, b0_m, b1_m;
  fp_to_montgomery(a0_m, a.c0);
  fp_to_montgomery(a1_m, a.c1);
  fp_to_montgomery(b0_m, b.c0);
  fp_to_montgomery(b1_m, b.c1);

  // Operate in Montgomery form
  Fp t0, t1, t2, t3;
  fp_mont_mul(t0, a0_m, b0_m); // t0 = a0 * b0
  fp_mont_mul(t1, a1_m, b1_m); // t1 = a1 * b1
  fp_add(t2, a0_m, a1_m);      // t2 = a0 + a1
  fp_add(t3, b0_m, b1_m);      // t3 = b0 + b1
  fp_mont_mul(t2, t2, t3);     // t2 = (a0 + a1) * (b0 + b1)

  Fp c0_m, c1_m;
  fp_sub(c0_m, t0, t1);   // c0 = t0 - t1 = a0*b0 - a1*b1
  fp_sub(c1_m, t2, t0);   // c1 = t2 - t0
  fp_sub(c1_m, c1_m, t1); // c1 = t2 - t0 - t1 = a0*b1 + a1*b0

  // Convert outputs back from Montgomery form
  fp_from_montgomery(c.c0, c0_m);
  fp_from_montgomery(c.c1, c1_m);
}

// Montgomery multiplication: c = a * b (all in Montgomery form)
// (a0 + a1*i) * (b0 + b1*i) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*i
// Uses Karatsuba-like optimization
// NOTE: All inputs and outputs are in Montgomery form
__host__ __device__ void fp2_mont_mul(Fp2 &c, const Fp2 &a, const Fp2 &b) {
  Fp t0, t1, t2, t3;

  fp_mont_mul(t0, a.c0, b.c0);
  fp_mont_mul(t1, a.c1, b.c1);
  fp_add(t2, a.c0, a.c1);
  fp_add(t3, b.c0, b.c1);
  fp_mont_mul(t2, t2, t3);
  fp_sub(c.c0, t0, t1);
  fp_sub(c.c1, t2, t0);
  fp_sub(c.c1, c.c1, t1);
}

// Optimized: converts to Montgomery once at start, operates, converts back at
// end (4 conversions instead of 9)
__host__ __device__ void fp2_square(Fp2 &c, const Fp2 &a) {
  // Convert inputs to Montgomery form once
  Fp a0_m, a1_m;
  fp_to_montgomery(a0_m, a.c0);
  fp_to_montgomery(a1_m, a.c1);

  // Operate in Montgomery form
  Fp t0, t1, t2;
  fp_mont_mul(t0, a0_m, a0_m); // t0 = a0^2
  fp_mont_mul(t1, a1_m, a1_m); // t1 = a1^2
  fp_add(t2, a0_m, a1_m);      // t2 = a0 + a1
  fp_mont_mul(t2, t2, t2);     // t2 = (a0 + a1)^2

  Fp c0_m, c1_m;
  fp_sub(c0_m, t0, t1);   // c0 = a0^2 - a1^2
  fp_sub(c1_m, t2, t0);   // c1 = (a0+a1)^2 - a0^2
  fp_sub(c1_m, c1_m, t1); // c1 = (a0+a1)^2 - a0^2 - a1^2 = 2*a0*a1

  // Convert outputs back from Montgomery form
  fp_from_montgomery(c.c0, c0_m);
  fp_from_montgomery(c.c1, c1_m);
}

__host__ __device__ void fp2_neg(Fp2 &c, const Fp2 &a) {
  fp_neg(c.c0, a.c0);
  fp_neg(c.c1, a.c1);
}

__host__ __device__ void fp2_conjugate(Fp2 &c, const Fp2 &a) {
  fp_copy(c.c0, a.c0);
  fp_neg(c.c1, a.c1);
}

// Attention: we don't want to use #pragma unroll here because
// it causes "code explosion" during compilation
__host__ __device__ void fp_inv_fermat(Fp &result, const Fp &a) {
  if (fp_is_zero(a)) {
    fp_zero(result);
    return;
  }

  Fp p_minus_2;
  Fp one, two;
  fp_one(one);
  fp_one(two);
  two.limb[0] = 2;
  const Fp &p = fp_modulus();
  fp_sub(p_minus_2, p, two);

  // Convert base to Montgomery form once
  Fp base_mont;
  fp_to_montgomery(base_mont, a);

  // Start result as 1 in Montgomery form
  Fp result_mont;
  fp_one_montgomery(result_mont);

  bool found_first_bit = false;
  for (int limb = FP_LIMBS - 1; limb >= 0; limb--) {
    for (int bit = LIMB_BITS - 1; bit >= 0; bit--) {
      if (found_first_bit || ((p_minus_2.limb[limb] >> bit) & 1)) {
        found_first_bit = true;
        Fp temp;
        fp_mont_mul(temp, result_mont, result_mont);
        fp_copy(result_mont, temp);

        if ((p_minus_2.limb[limb] >> bit) & 1) {
          fp_mont_mul(temp, result_mont, base_mont);
          fp_copy(result_mont, temp);
        }
      }
    }
  }

  // Convert result back from Montgomery form
  fp_from_montgomery(result, result_mont);
}

// NOTE: Caller must ensure a != 0 (division by zero check must be done at host
// side)
__host__ __device__ void fp2_inv(Fp2 &c, const Fp2 &a) {
  // Convert inputs to Montgomery form
  Fp a0_m, a1_m;
  fp_to_montgomery(a0_m, a.c0);
  fp_to_montgomery(a1_m, a.c1);

  // Compute norm = a0^2 + a1^2 in Montgomery form
  Fp t0, t1, norm_m;
  fp_mont_mul(t0, a0_m, a0_m);
  fp_mont_mul(t1, a1_m, a1_m);
  fp_add(norm_m, t0, t1);

  // Convert norm to normal form for inversion, then back to Montgomery
  Fp norm, norm_inv, norm_inv_m;
  fp_from_montgomery(norm, norm_m);
  fp_inv_fermat(norm_inv, norm);
  fp_to_montgomery(norm_inv_m, norm_inv);

  // Final multiplications in Montgomery form
  Fp c0_m, c1_m;
  fp_mont_mul(c0_m, a0_m, norm_inv_m);
  fp_neg(c1_m, a1_m); // negation preserves Montgomery form
  fp_mont_mul(c1_m, c1_m, norm_inv_m);

  // Convert outputs back from Montgomery form
  fp_from_montgomery(c.c0, c0_m);
  fp_from_montgomery(c.c1, c1_m);
}

// Montgomery inversion: c = a^(-1) (all in Montgomery form)
// NOTE: All inputs and outputs are in Montgomery form
// NOTE: Caller must ensure a != 0 (division by zero check must be done at host
// side)
__host__ __device__ void fp2_mont_inv(Fp2 &c, const Fp2 &a) {
  Fp t0, t1, norm, norm_inv;

  fp_mont_mul(t0, a.c0, a.c0);
  fp_mont_mul(t1, a.c1, a.c1);
  fp_add(norm, t0, t1);
  fp_mont_inv(norm_inv, norm);
  fp_mont_mul(c.c0, a.c0, norm_inv);
  fp_neg(c.c1, a.c1);
  fp_mont_mul(c.c1, c.c1, norm_inv);
}

__host__ __device__ void fp2_div(Fp2 &c, const Fp2 &a, const Fp2 &b) {
  Fp2 b_inv;
  fp2_inv(b_inv, b);
  fp2_mul(c, a, b_inv);
}

__host__ __device__ void fp2_cmov(Fp2 &dst, const Fp2 &src,
                                  uint64_t condition) {
  fp_cmov(dst.c0, src.c0, condition);
  fp_cmov(dst.c1, src.c1, condition);
}

// Frobenius map: c = a^p
// For Fp2, the Frobenius map is: (a0 + a1*i)^p = a0 - a1*i = conjugate
// This is because i^p = i^(p mod 4) = i^(-1) = -i (since p ≡ 3 mod 4 for BLS12
// curves)
__host__ __device__ void fp2_frobenius(Fp2 &c, const Fp2 &a) {
  fp2_conjugate(c, a);
}

__host__ __device__ void fp2_mul_by_i(Fp2 &c, const Fp2 &a) {
  Fp temp;
  fp_copy(temp, a.c0);
  fp_neg(c.c0, a.c1);
  fp_copy(c.c1, temp);
}

// ============================================================================
// Operator Overloading Implementations
// ============================================================================

__host__ __device__ Fp2 operator+(const Fp2 &a, const Fp2 &b) {
  Fp2 c;
  fp2_add(c, a, b);
  return c;
}

__host__ __device__ Fp2 operator-(const Fp2 &a, const Fp2 &b) {
  Fp2 c;
  fp2_sub(c, a, b);
  return c;
}

__host__ __device__ Fp2 operator*(const Fp2 &a, const Fp2 &b) {
  Fp2 c;
  fp2_mul(c, a, b);
  return c;
}

__host__ __device__ Fp2 operator/(const Fp2 &a, const Fp2 &b) {
  Fp2 c;
  fp2_div(c, a, b);
  return c;
}

__host__ __device__ Fp2 operator-(const Fp2 &a) {
  Fp2 c;
  fp2_neg(c, a);
  return c;
}

__host__ __device__ bool operator==(const Fp2 &a, const Fp2 &b) {
  return fp2_cmp(a, b) == ComparisonType::Equal;
}

__host__ __device__ bool operator!=(const Fp2 &a, const Fp2 &b) {
  return fp2_cmp(a, b) != ComparisonType::Equal;
}

__host__ __device__ Fp2 &operator+=(Fp2 &a, const Fp2 &b) {
  fp2_add(a, a, b);
  return a;
}

__host__ __device__ Fp2 &operator-=(Fp2 &a, const Fp2 &b) {
  fp2_sub(a, a, b);
  return a;
}

__host__ __device__ Fp2 &operator*=(Fp2 &a, const Fp2 &b) {
  Fp2 temp;
  fp2_mul(temp, a, b);
  fp2_copy(a, temp);
  return a;
}

__host__ __device__ Fp2 &operator/=(Fp2 &a, const Fp2 &b) {
  Fp2 temp;
  fp2_div(temp, a, b);
  fp2_copy(a, temp);
  return a;
}
