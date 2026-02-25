#pragma once

#include "fp.h"
#include <cstdint>
#include <cuda_runtime.h>

// Fp2: Quadratic extension field Fp[i] where i^2 = -1
// An Fp2 element is represented as a + b*i where a, b ∈ Fp
// This is a POD type for CUDA compatibility
//
// IMPORTANT: Do not add constructors to this struct. Adding constructors would
// make it non-POD, which would break:
// 1. CUDA __constant__ memory aggregate initialization (DEVICE_CURVE_B_G2,
// etc.)
// 2. Rust FFI bindings that expect POD layout (#[repr(C)])
// Use helper functions like fp2_zero() for initialization instead.
struct Fp2 {
  Fp c0; // Real part (coefficient of 1)
  Fp c1; // Imaginary part (coefficient of i)
};

// ============================================================================
// Operator Overloading for Fp2
// ============================================================================
// These operators provide a cleaner syntax for extension field arithmetic.
// They call the underlying fp2_* functions and return by value.

// Binary arithmetic operators
__host__ __device__ Fp2 operator+(const Fp2 &a, const Fp2 &b);
__host__ __device__ Fp2 operator-(const Fp2 &a, const Fp2 &b);
__host__ __device__ Fp2 operator*(const Fp2 &a, const Fp2 &b);
__host__ __device__ Fp2 operator/(const Fp2 &a, const Fp2 &b);

// Unary negation operator
__host__ __device__ Fp2 operator-(const Fp2 &a);

// Comparison operators
__host__ __device__ bool operator==(const Fp2 &a, const Fp2 &b);
__host__ __device__ bool operator!=(const Fp2 &a, const Fp2 &b);

// Compound assignment operators
__host__ __device__ Fp2 &operator+=(Fp2 &a, const Fp2 &b);
__host__ __device__ Fp2 &operator-=(Fp2 &a, const Fp2 &b);
__host__ __device__ Fp2 &operator*=(Fp2 &a, const Fp2 &b);
__host__ __device__ Fp2 &operator/=(Fp2 &a, const Fp2 &b);

// Multi-precision arithmetic operations for Fp2
// All operations are CUDA-compatible (can be called from host or device)

__host__ __device__ ComparisonType fp2_cmp(const Fp2 &a, const Fp2 &b);

__host__ __device__ bool fp2_is_zero(const Fp2 &a);

__host__ __device__ bool fp2_is_one(const Fp2 &a);

__host__ __device__ void fp2_zero(Fp2 &a);

// Set to one (1 + 0*i)
__host__ __device__ void fp2_one(Fp2 &a);

// Set small integers in Montgomery form for Fp2 (real numbers, c1 = 0)
__host__ __device__ void fp2_two_montgomery(Fp2 &a);
__host__ __device__ void fp2_three_montgomery(Fp2 &a);
__host__ __device__ void fp2_four_montgomery(Fp2 &a);
__host__ __device__ void fp2_eight_montgomery(Fp2 &a);

__host__ __device__ void fp2_copy(Fp2 &dst, const Fp2 &src);

// Addition: c = a + b
__host__ __device__ void fp2_add(Fp2 &c, const Fp2 &a, const Fp2 &b);

// Subtraction: c = a - b
__host__ __device__ void fp2_sub(Fp2 &c, const Fp2 &a, const Fp2 &b);

// Multiplication: c = a * b
// (a0 + a1*i) * (b0 + b1*i) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*i
// NOTE: Assumes inputs are in normal form and converts to/from Montgomery
__host__ __device__ void fp2_mul(Fp2 &c, const Fp2 &a, const Fp2 &b);

// Montgomery multiplication: c = a * b (all in Montgomery form)
// NOTE: All inputs and outputs are in Montgomery form (no conversions)
__host__ __device__ void fp2_mont_mul(Fp2 &c, const Fp2 &a, const Fp2 &b);

// Montgomery squaring: c = a^2 (all in Montgomery form)
// Uses the complex-squaring identity: c0 = (a0+a1)(a0-a1), c1 = 2*a0*a1
// Only 2 Fp multiplications vs 3 for fp2_mont_mul(c, a, a).
// NOTE: All inputs and outputs are in Montgomery form (no conversions)
__host__ __device__ void fp2_mont_square(Fp2 &c, const Fp2 &a);

// Squaring: c = a^2
// (a0 + a1*i)^2 = (a0^2 - a1^2) + 2*a0*a1*i
// Optimized version that uses fewer multiplications
__host__ __device__ void fp2_square(Fp2 &c, const Fp2 &a);

__host__ __device__ void fp2_neg(Fp2 &c, const Fp2 &a);

// Conjugation: c = a.conjugate() = a0 - a1*i
__host__ __device__ void fp2_conjugate(Fp2 &c, const Fp2 &a);

// Inversion: c = a^(-1)
// Uses the formula: (a0 + a1*i)^(-1) = (a0 - a1*i) / (a0^2 + a1^2)
// NOTE: Assumes inputs are in normal form and converts to/from Montgomery
__host__ __device__ void fp2_inv(Fp2 &c, const Fp2 &a);

// Montgomery inversion: c = a^(-1) (all in Montgomery form)
// NOTE: All inputs and outputs are in Montgomery form (no conversions)
__host__ __device__ void fp2_mont_inv(Fp2 &c, const Fp2 &a);

// Division: c = a / b = a * b^(-1)
__host__ __device__ void fp2_div(Fp2 &c, const Fp2 &a, const Fp2 &b);

// Small-constant multiplication via addition chains (much cheaper than
// fp2_mont_mul). MONTGOMERY: input and output must be in Montgomery form.
__host__ __device__ void fp2_double(Fp2 &c, const Fp2 &a);
__host__ __device__ void fp2_mul3(Fp2 &c, const Fp2 &a);
__host__ __device__ void fp2_mul4(Fp2 &c, const Fp2 &a);
__host__ __device__ void fp2_mul8(Fp2 &c, const Fp2 &a);

__host__ __device__ void fp2_cmov(Fp2 &dst, const Fp2 &src, uint64_t condition);

// Frobenius map: c = a^p
// For Fp2, the Frobenius map is: (a0 + a1*i)^p = a0 - a1*i = conjugate
// This is because i^p = i^(p mod 4) = i^(-1) = -i (since p ≡ 3 mod 4 for BLS12
// curves)
__host__ __device__ void fp2_frobenius(Fp2 &c, const Fp2 &a);

// Multiply by i: c = a * i
// (a0 + a1*i) * i = -a1 + a0*i
__host__ __device__ void fp2_mul_by_i(Fp2 &c, const Fp2 &a);

// ============================================================================
// Note: Async/Sync host wrappers have been removed. Test-only wrappers are
// available in tests/primitives/fp2_helpers.cu
// ============================================================================
