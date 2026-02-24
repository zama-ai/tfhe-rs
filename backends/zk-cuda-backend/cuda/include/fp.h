#pragma once

#include <cstdint>
#include <cuda_runtime.h>

// Ceiling division: computes (M + N - 1) / N
#define CEIL_DIV(M, N) (((M) + (N)-1) / (N))

// CUDA architecture constant
#define CUDA_WARP_SIZE 32 // NVIDIA warp size (threads per warp)

// ============================================================================
// LIMB SIZE CONFIGURATION
// ============================================================================
// Define LIMB_BITS_CONFIG before including this header to change limb size.
// Default: 64-bit limbs.
//
// Supported values: 32, 64.
// ============================================================================
#ifndef LIMB_BITS_CONFIG
#define LIMB_BITS_CONFIG 64
#endif

#if LIMB_BITS_CONFIG == 64
using UNSIGNED_LIMB = uint64_t;
#define ZP_LIMBS 5
#elif LIMB_BITS_CONFIG == 32
using UNSIGNED_LIMB = uint32_t;
#define ZP_LIMBS 10
#else
#error "Unsupported LIMB_BITS_CONFIG value. Only 32 and 64 are supported."
#endif

// BLS12-446: 446-bit prime field
// For 64-bit limbs: ceil(446 / 64) = 7 limbs (448 bits total)
// For 32-bit limbs: ceil(446 / 32) = 14 limbs (448 bits total)
#if LIMB_BITS_CONFIG == 64
#define FP_LIMBS 7
#elif LIMB_BITS_CONFIG == 32
#define FP_LIMBS 14
#endif
#define FP_BITS 446

// Bits per limb (derived from configuration, also available as constexpr)
#define LIMB_BITS LIMB_BITS_CONFIG
constexpr int LIMB_BITS_CONSTEXPR = LIMB_BITS;

// Maximum value for a limb
#if LIMB_BITS_CONFIG == 64
#define LIMB_MAX UINT64_MAX
#elif LIMB_BITS_CONFIG == 32
#define LIMB_MAX UINT32_MAX
#endif

static_assert(LIMB_BITS == 32 || LIMB_BITS == 64,
              "LIMB_BITS_CONFIG must be 32 or 64");

// Generic BigInt template for N limbs
// Represents a big integer as N limbs of LIMB_BITS bits each
// Little-endian: limb[0] is least significant word
// Note: This is a POD (Plain Old Data) type for CUDA __constant__ compatibility
template <int N> struct BigInt {
  UNSIGNED_LIMB limb[N];

  // Total bits in this BigInt
  static constexpr int NUM_BITS = N * LIMB_BITS;
};

// ============================================================================
// MONTGOMERY FORM CONVENTION
// ============================================================================
// All Fp values in internal computations MUST be in Montgomery form.
//
// Entry points (normal -> Montgomery):
//   - fp_to_montgomery(c, a): Convert normal form 'a' to Montgomery form 'c'
//   - Input data from external sources must be converted before use
//
// Exit points (Montgomery -> normal):
//   - fp_from_montgomery(c, a): Convert Montgomery form 'a' to normal form 'c'
//   - Output data to external consumers must be converted after computation
//
// Functions expecting Montgomery form inputs (all internal operations):
//   - fp_add(), fp_sub(): Both inputs must be Montgomery, result is Montgomery
//   - fp_mont_mul(): Both inputs must be Montgomery, result is Montgomery
//   - fp_mont_inv(): Input and output are Montgomery
//   - fp_neg(): Input must be Montgomery, result is Montgomery
//   - All point/curve operations: Coordinates must be Montgomery
//
// Functions producing normal form (for conversions only):
//   - fp_one(): Returns 1 in normal form (used internally by
//   fp_from_montgomery)
//   - fp_zero(): Returns 0 (same in both forms)
//
// Functions producing Montgomery form:
//   - fp_one_montgomery(): Returns 1 in Montgomery form (R mod p)
//   - fp_two_montgomery(), fp_three_montgomery(), etc.
//
// EXTERNAL API functions (accept normal form, return normal form):
//   - fp_inv(): Input normal -> output normal (converts internally)
//   - fp_div(): Inputs normal -> output normal (converts internally)
//   - fp_pow(): Input normal -> output normal (converts internally)
//   - fp_sqrt(): Input normal -> output normal (converts internally)
// These are convenience APIs; prefer fp_mont_inv() for hot paths.
// ============================================================================
//
// IMPORTANT: Do not add constructors to this struct. Adding constructors would
// make it non-POD, which would break:
// 1. CUDA __constant__ memory aggregate initialization (DEVICE_MODULUS, etc.)
// 2. Rust FFI bindings that expect POD layout (#[repr(C)])
// Use helper functions like fp_zero() for initialization instead.
struct Fp : BigInt<FP_LIMBS> {};

// 64-bit: 7 limbs * 8 bytes = 56 bytes
// 32-bit: 14 limbs * 4 bytes = 56 bytes
static_assert(sizeof(Fp) == FP_LIMBS * sizeof(UNSIGNED_LIMB),
              "Fp size mismatch");

// ============================================================================
// Operator Overloading for Fp
// ============================================================================
// These operators provide a cleaner syntax for field arithmetic.
// They call the underlying fp_* functions and return by value.

// Binary arithmetic operators
__host__ __device__ Fp operator+(const Fp &a, const Fp &b);
__host__ __device__ Fp operator-(const Fp &a, const Fp &b);
// MONTGOMERY: Both inputs must be in Montgomery form, result is in Montgomery
// form.
__host__ __device__ Fp operator*(const Fp &a, const Fp &b);
// MONTGOMERY: Both inputs must be in Montgomery form, result is in Montgomery
// form. Computes a * b^{-1} in Montgomery representation.
__host__ __device__ Fp operator/(const Fp &a, const Fp &b);

// Unary negation operator
__host__ __device__ Fp operator-(const Fp &a);

// Comparison operators
__host__ __device__ bool operator==(const Fp &a, const Fp &b);
__host__ __device__ bool operator!=(const Fp &a, const Fp &b);

// Compound assignment operators (declared as member-like free functions)
__host__ __device__ Fp &operator+=(Fp &a, const Fp &b);
__host__ __device__ Fp &operator-=(Fp &a, const Fp &b);
__host__ __device__ Fp &operator*=(Fp &a, const Fp &b);
// MONTGOMERY: Both inputs must be in Montgomery form.
__host__ __device__ Fp &operator/=(Fp &a, const Fp &b);

// Prime modulus p for BLS12-446
// Device-side constant (hardcoded in fp.cu at compile time)
extern __constant__ const Fp DEVICE_MODULUS;

// Montgomery constants
// R = 2^448 (for 7 limbs of 64 bits, or 14 limbs of 32 bits)
// R^2 mod p and p' = -p^(-1) mod 2^LIMB_BITS
// All hardcoded at compile time
extern __constant__ const Fp DEVICE_R2;
extern __constant__ const UNSIGNED_LIMB DEVICE_P_PRIME;

// Multi-precision arithmetic operations
// All operations are CUDA-compatible (can be called from host or device)

// Comparison result enum
enum class ComparisonType : int {
  Less = -1,  // a < b
  Equal = 0,  // a == b
  Greater = 1 // a > b
};

__host__ __device__ ComparisonType fp_cmp(const Fp &a, const Fp &b);

__host__ __device__ bool fp_is_zero(const Fp &a);

__host__ __device__ bool fp_is_one(const Fp &a);

// NORMAL: Returns 0 (identical in both forms)
__host__ __device__ void fp_zero(Fp &a);

// NORMAL: Returns 1 in normal form (used internally by fp_from_montgomery)
__host__ __device__ void fp_one(Fp &a);

// Set to one in Montgomery form (R mod p)
__host__ __device__ void fp_one_montgomery(Fp &a);

// Set small integers in Montgomery form (used by curve operations)
__host__ __device__ void fp_two_montgomery(Fp &a);
__host__ __device__ void fp_three_montgomery(Fp &a);
__host__ __device__ void fp_four_montgomery(Fp &a);
__host__ __device__ void fp_eight_montgomery(Fp &a);

__host__ __device__ void fp_copy(Fp &dst, const Fp &src);

// Addition: c = a + b (without reduction)
// "Raw" means the operation is performed without modular reduction modulo p.
// The result may be >= p or may overflow (indicated by carry).
// Returns carry out (1 if result >= 2^448, 0 otherwise)
__host__ __device__ UNSIGNED_LIMB fp_add_raw(Fp &c, const Fp &a, const Fp &b);

// Subtraction: c = a - b (without reduction)
// "Raw" means the operation is performed without modular reduction modulo p.
// The result may be negative (indicated by borrow).
// Returns borrow (1 if a < b, 0 otherwise)
__host__ __device__ UNSIGNED_LIMB fp_sub_raw(Fp &c, const Fp &a, const Fp &b);

// Addition with modular reduction: c = (a + b) mod p
// MONTGOMERY: Both inputs and output must be in Montgomery form
__host__ __device__ void fp_add(Fp &c, const Fp &a, const Fp &b);

// Subtraction with modular reduction: c = (a - b) mod p
// MONTGOMERY: Both inputs and output must be in Montgomery form
__host__ __device__ void fp_sub(Fp &c, const Fp &a, const Fp &b);

// Multiplication: c = a * b (without reduction)
// "Raw" means the operation is performed without modular reduction modulo p.
// The result is stored in double-width (2*FP_LIMBS limbs) and may be >= p.
// Result stored in c[0..2*FP_LIMBS-1] (little-endian)
__host__ __device__ void fp_mul_schoolbook_raw(UNSIGNED_LIMB *c, const Fp &a,
                                               const Fp &b);

// Montgomery reduction: c = (a * R_INV) mod p
// Input a is 2*FP_LIMBS limbs (result of multiplication)
// Output c is FP_LIMBS limbs in Montgomery form
__host__ __device__ void fp_mont_reduce(Fp &c, const UNSIGNED_LIMB *a);

// Montgomery multiplication: c = (a * b * R_INV) mod p
// Both a and b are in Montgomery form, result is in Montgomery form
__host__ __device__ void fp_mont_mul(Fp &c, const Fp &a, const Fp &b);

// CONVERSION: Input is normal form, output is Montgomery form
__host__ __device__ void fp_to_montgomery(Fp &c, const Fp &a);

// CONVERSION: Input is Montgomery form, output is normal form
__host__ __device__ void fp_from_montgomery(Fp &c, const Fp &a);

// MONTGOMERY: Input and output in Montgomery form
__host__ __device__ void fp_neg(Fp &c, const Fp &a);

// Inversion: c = a^(-1) mod p
// Uses Fermat's little theorem: a^(p-2) = a^(-1) mod p
// Returns c = 0 if a = 0 (division by zero)
// NOTE: Assumes input is in normal form and converts to/from Montgomery
__host__ __device__ void fp_inv(Fp &c, const Fp &a);

// Montgomery inversion: c = a^(-1) mod p (all in Montgomery form)
// NOTE: Input and output are in Montgomery form (no conversions)
__host__ __device__ void fp_mont_inv(Fp &c, const Fp &a);

// Division: c = a / b mod p = a * b^(-1) mod p
// Returns c = 0 if b = 0 (division by zero)
__host__ __device__ void fp_div(Fp &c, const Fp &a, const Fp &b);

// Exponentiation: c = a^e mod p
// e is represented as a big integer in little-endian format (limb[0] is LSB)
// e_limbs is the number of UNSIGNED_LIMB limbs in the exponent
// For exponents larger than FP_BITS, only the lower FP_BITS bits are used
__host__ __device__ void fp_pow(Fp &c, const Fp &a, const UNSIGNED_LIMB *e,
                                int e_limbs);

// Exponentiation with 64-bit exponent: c = a^e mod p
__host__ __device__ void fp_pow_u64(Fp &c, const Fp &a, uint64_t e);

// Square root: c = sqrt(a) mod p if a is a quadratic residue
// Returns true if a is a quadratic residue (square root exists), false
// otherwise If false, c is set to 0 For primes p ≡ 3 (mod 4): sqrt(a) =
// a^((p+1)/4) mod p For other primes, uses Tonelli-Shanks algorithm
__host__ __device__ bool fp_sqrt(Fp &c, const Fp &a);

// Check if a is a quadratic residue (has a square root)
// Returns true if a is a quadratic residue, false otherwise
// Uses Euler's criterion: a is a quadratic residue if a^((p-1)/2) = 1 mod p
__host__ __device__ bool fp_is_quadratic_residue(const Fp &a);

// Small-constant multiplication via addition chains (much cheaper than
// fp_mont_mul). MONTGOMERY: input and output must be in Montgomery form.
__host__ __device__ void fp_double(Fp &c, const Fp &a);
__host__ __device__ void fp_mul3(Fp &c, const Fp &a);
__host__ __device__ void fp_mul4(Fp &c, const Fp &a);
__host__ __device__ void fp_mul8(Fp &c, const Fp &a);

// Conditional assignment: if condition, dst = src, else dst unchanged
__host__ __device__ void fp_cmov(Fp &dst, const Fp &src, uint64_t condition);

// Helper functions to access constants
// Get modulus reference (device: from constant memory, host: static copy)
__host__ __device__ const Fp &fp_modulus();

// ============================================================================
// Async/Sync API for device memory operations
// ============================================================================
// All pointers in these functions point to device memory (already allocated)
// _async versions: Launch kernels asynchronously, return immediately (no sync)
// Note: Async/Sync host wrappers have been removed. Test-only wrappers are
// available in tests/primitives/fp_helpers.cu
