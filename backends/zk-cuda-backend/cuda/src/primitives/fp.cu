#include "bls12_446_params.h"
#include "device.h"
#include "fp.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>

// For CUDA device code, we use __constant__ memory
// Constants are hardcoded at compile time (like sppark) to avoid
// cudaMemcpyToSymbol
// Note: DEVICE_MODULUS is in normal form (not Montgomery)
__constant__ const Fp DEVICE_MODULUS = {BLS12_446_MODULUS_LIMBS};

// Note: DEVICE_R2 is in normal form (used for conversion to Montgomery)
__constant__ const Fp DEVICE_R2 = {BLS12_446_R2_LIMBS};

__constant__ const UNSIGNED_LIMB DEVICE_P_PRIME = BLS12_446_P_PRIME;

// Precomputed Montgomery form constants for small integers
// These avoid recomputing 2*R, 3*R, 4*R, 8*R mod p on every point operation
// Note: These are in Montgomery form
__constant__ const Fp DEVICE_TWO_MONT = {BLS12_446_TWO_MONT_LIMBS};
__constant__ const Fp DEVICE_THREE_MONT = {BLS12_446_THREE_MONT_LIMBS};
__constant__ const Fp DEVICE_FOUR_MONT = {BLS12_446_FOUR_MONT_LIMBS};
__constant__ const Fp DEVICE_EIGHT_MONT = {BLS12_446_EIGHT_MONT_LIMBS};

// Getter functions for precomputed Montgomery constants
__host__ __device__ const Fp &fp_two_mont() {
#ifdef __CUDA_ARCH__
  return DEVICE_TWO_MONT;
#else
  static const Fp host_two = {BLS12_446_TWO_MONT_LIMBS};
  return host_two;
#endif
}

__host__ __device__ const Fp &fp_three_mont() {
#ifdef __CUDA_ARCH__
  return DEVICE_THREE_MONT;
#else
  static const Fp host_three = {BLS12_446_THREE_MONT_LIMBS};
  return host_three;
#endif
}

__host__ __device__ const Fp &fp_four_mont() {
#ifdef __CUDA_ARCH__
  return DEVICE_FOUR_MONT;
#else
  static const Fp host_four = {BLS12_446_FOUR_MONT_LIMBS};
  return host_four;
#endif
}

__host__ __device__ const Fp &fp_eight_mont() {
#ifdef __CUDA_ARCH__
  return DEVICE_EIGHT_MONT;
#else
  static const Fp host_eight = {BLS12_446_EIGHT_MONT_LIMBS};
  return host_eight;
#endif
}

__host__ __device__ const Fp &fp_modulus() {
#ifdef __CUDA_ARCH__
  return DEVICE_MODULUS;
#else
  // Note: modulus is in normal form (not Montgomery)
  static const Fp host_mod = {BLS12_446_MODULUS_LIMBS};
  return host_mod;
#endif
}

__host__ __device__ const Fp &fp_r2() {
#ifdef __CUDA_ARCH__
  return DEVICE_R2;
#else
  // Note: R^2 is in normal form (used for conversion to Montgomery)
  static const Fp host_r2 = {BLS12_446_R2_LIMBS};
  return host_r2;
#endif
}

__host__ __device__ UNSIGNED_LIMB fp_p_prime() {
#ifdef __CUDA_ARCH__
  return DEVICE_P_PRIME;
#else
  return BLS12_446_P_PRIME;
#endif
}

// Comparison: returns ComparisonType::Less if a < b, ComparisonType::Equal if a
// == b, ComparisonType::Greater if a > b
__host__ __device__ ComparisonType fp_cmp(const Fp &a, const Fp &b) {
  for (int i = FP_LIMBS - 1; i >= 0; i--) {
    if (a.limb[i] > b.limb[i])
      return ComparisonType::Greater;
    if (a.limb[i] < b.limb[i])
      return ComparisonType::Less;
  }
  return ComparisonType::Equal;
}

__host__ __device__ bool fp_is_zero(const Fp &a) {
  // By doing this way we avoid branching
  uint64_t acc = 0;
  for (int i = 0; i < FP_LIMBS; i++) {
    acc |= a.limb[i];
  }
  return acc == 0;
}

__host__ __device__ bool fp_is_one(const Fp &a) {
  if (a.limb[0] != 1)
    return false;
  // By doing this way we avoid branching
  uint64_t acc = 0;
  for (int i = 1; i < FP_LIMBS; i++) {
    acc |= a.limb[i];
  }
  return acc == 0;
}

__host__ __device__ void fp_zero(Fp &a) {
#ifdef __CUDA_ARCH__
  for (int i = 0; i < FP_LIMBS; i++) {
    a.limb[i] = 0;
  }
#else
  // Host code: use memset for better performance
  memset(&a.limb[0], 0, FP_LIMBS * sizeof(UNSIGNED_LIMB));
#endif
  // Note: Zero is zero in both normal and Montgomery forms
}

__host__ __device__ void fp_one(Fp &a) {
  // NORMAL: Returns 1 in normal form (used internally by fp_from_montgomery)
  a.limb[0] = 1;
#ifdef __CUDA_ARCH__
  for (int i = 1; i < FP_LIMBS; i++) {
    a.limb[i] = 0;
  }
#else
  // Host code: use memset for better performance
  if (FP_LIMBS > 1) {
    memset(&a.limb[1], 0, (FP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
  }
#endif
}

__host__ __device__ void fp_one_montgomery(Fp &a) {
  Fp one;
  fp_one(one);
  fp_to_montgomery(a, one);
}

// Helper functions to get small integers in Montgomery form
// These now use precomputed constants instead of recomputing each time
__host__ __device__ void fp_two_montgomery(Fp &a) { fp_copy(a, fp_two_mont()); }

__host__ __device__ void fp_three_montgomery(Fp &a) {
  fp_copy(a, fp_three_mont());
}

__host__ __device__ void fp_four_montgomery(Fp &a) {
  fp_copy(a, fp_four_mont());
}

__host__ __device__ void fp_eight_montgomery(Fp &a) {
  fp_copy(a, fp_eight_mont());
}

__host__ __device__ void fp_copy(Fp &dst, const Fp &src) {
#ifdef __CUDA_ARCH__
  // Device code: use loop for better performance with small fixed-size arrays
  for (int i = 0; i < FP_LIMBS; i++) {
    dst.limb[i] = src.limb[i];
  }
#else
  // Host code: use memcpy for better performance
  memcpy(&dst.limb[0], &src.limb[0], FP_LIMBS * sizeof(UNSIGNED_LIMB));
#endif
}

// Addition with carry propagation
// "Raw" means without modular reduction - performs a + b and returns carry.
// This is an internal helper used by fp_add() which handles reduction.
__host__ __device__ UNSIGNED_LIMB fp_add_raw(Fp &c, const Fp &a, const Fp &b) {
  UNSIGNED_LIMB carry = 0;

  for (int i = 0; i < FP_LIMBS; i++) {
    // Add with carry: c = a + b + carry
    UNSIGNED_LIMB sum = a.limb[i] + carry;
    carry = (sum < a.limb[i]) ? 1 : 0; // Check for overflow
    sum += b.limb[i];
    carry += (sum < b.limb[i]) ? 1 : 0; // Check for overflow
    c.limb[i] = sum;
  }

  return carry;
}

// Subtraction with borrow propagation
// "Raw" means without modular reduction - performs a - b and returns borrow.
// This is an internal helper used by fp_sub() which handles reduction.
__host__ __device__ UNSIGNED_LIMB fp_sub_raw(Fp &c, const Fp &a, const Fp &b) {
  UNSIGNED_LIMB borrow = 0;

  for (int i = 0; i < FP_LIMBS; i++) {
    // Subtract with borrow: c = a - b - borrow
    UNSIGNED_LIMB diff = a.limb[i] - borrow;
    borrow = (diff > a.limb[i]) ? 1 : 0; // Check for underflow
    UNSIGNED_LIMB old_diff = diff;
    diff -= b.limb[i];
    borrow += (diff > old_diff) ? 1 : 0; // Check for underflow
    c.limb[i] = diff;
  }

  return borrow;
}

// Addition with modular reduction: c = (a + b) mod p
// MONTGOMERY: Both inputs and output must be in Montgomery form
__host__ __device__ void fp_add(Fp &c, const Fp &a, const Fp &b) {
  Fp sum;
  UNSIGNED_LIMB carry = fp_add_raw(sum, a, b);

  // If there's a carry or sum >= MODULUS, we need to reduce
  const Fp &p = fp_modulus();
  if (carry || fp_cmp(sum, p) != ComparisonType::Less) {
    Fp reduced;
    fp_sub_raw(reduced, sum, p);
    fp_copy(c, reduced);
  } else {
    fp_copy(c, sum);
  }
}

// Subtraction with modular reduction: c = (a - b) mod p
// MONTGOMERY: Both inputs and output must be in Montgomery form
__host__ __device__ void fp_sub(Fp &c, const Fp &a, const Fp &b) {
  Fp diff;
  UNSIGNED_LIMB borrow = fp_sub_raw(diff, a, b);

  // If there was a borrow, we need to add MODULUS
  const Fp &p = fp_modulus();
  if (borrow) {
    fp_add_raw(c, diff, p);
  } else {
    fp_copy(c, diff);
  }
}

// Small-constant multiplication via addition chains.
// These replace full Montgomery multiplications by 2, 3, 4, 8 with a few
// modular additions, each ~25 instructions vs ~200+ for CIOS Montgomery mul.

__host__ __device__ void fp_double(Fp &c, const Fp &a) { fp_add(c, a, a); }

__host__ __device__ void fp_mul3(Fp &c, const Fp &a) {
  Fp t;
  fp_add(t, a, a);
  fp_add(c, t, a);
}

__host__ __device__ void fp_mul4(Fp &c, const Fp &a) {
  Fp t;
  fp_add(t, a, a);
  fp_add(c, t, t);
}

__host__ __device__ void fp_mul8(Fp &c, const Fp &a) {
  Fp t;
  fp_mul4(t, a);
  fp_add(c, t, t);
}

// Helper function for limb multiplication: LIMB_BITS x LIMB_BITS -> 2*LIMB_BITS
// Returns (hi, lo) via output parameters
__host__ __device__ inline void mul_limbs(UNSIGNED_LIMB a, UNSIGNED_LIMB b,
                                          UNSIGNED_LIMB &hi,
                                          UNSIGNED_LIMB &lo) {
#if LIMB_BITS_CONFIG == 64
#ifdef __CUDA_ARCH__
  // Use CUDA intrinsics for device code
  lo = a * b;
  hi = __umul64hi(a, b);
#else
  // Host code: use __uint128_t if available, otherwise manual implementation
#ifdef __SIZEOF_INT128__
  __uint128_t product =
      static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
  lo = static_cast<uint64_t>(product);
  hi = static_cast<uint64_t>(product >> 64);
#else
  // Fallback for systems without __uint128_t
  uint64_t a_lo = a & 0xFFFFFFFFULL;
  uint64_t a_hi = a >> 32;
  uint64_t b_lo = b & 0xFFFFFFFFULL;
  uint64_t b_hi = b >> 32;

  uint64_t p0 = a_lo * b_lo;
  uint64_t p1 = a_lo * b_hi;
  uint64_t p2 = a_hi * b_lo;
  uint64_t p3 = a_hi * b_hi;

  uint64_t mid1 = p1 + (p0 >> 32);
  uint64_t carry1 = (mid1 < p1) ? 1 : 0;

  uint64_t mid2 = mid1 + p2;
  uint64_t carry2 = (mid2 < mid1) ? 1 : 0;

  lo = (p0 & 0xFFFFFFFFULL) | (mid2 << 32);
  hi = p3 + (mid2 >> 32) + (carry1 << 32) + (carry2 << 32);
#endif
#endif
#elif LIMB_BITS_CONFIG == 32
  // 32x32 -> 64 bit multiplication, then split
  uint64_t product = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
  lo = static_cast<uint32_t>(product);
  hi = static_cast<uint32_t>(product >> 32);
#endif
}

// Multiplication using schoolbook method
// "Raw" means without modular reduction - performs a * b and stores result in
// double-width. This is an internal helper used by fp_mont_mul() which handles
// reduction. Result is stored in c[0..2*FP_LIMBS-1] (little-endian)
__host__ __device__ void fp_mul_schoolbook_raw(UNSIGNED_LIMB *c, const Fp &a,
                                               const Fp &b) {
  // Initialize result to zero
#ifdef __CUDA_ARCH__
  for (int i = 0; i < 2 * FP_LIMBS; i++) {
    c[i] = 0;
  }
#else
  // Host code: use memset for better performance
  memset(c, 0, 2 * FP_LIMBS * sizeof(UNSIGNED_LIMB));
#endif

  // Schoolbook multiplication: c[i+j] += a[i] * b[j]
  for (int i = 0; i < FP_LIMBS; i++) {
    UNSIGNED_LIMB carry = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      // Multiply a[i] * b[j] to get double-width result
      UNSIGNED_LIMB lo, hi;
      mul_limbs(a.limb[i], b.limb[j], hi, lo);

      // Add lo to c[i+j]
      UNSIGNED_LIMB sum_lo = c[i + j] + lo;
      UNSIGNED_LIMB carry_lo = (sum_lo < c[i + j]) ? 1 : 0;
      c[i + j] = sum_lo;

      // Add hi + carry + carry_lo to c[i + j + 1]
      UNSIGNED_LIMB old_val = c[i + j + 1];
      UNSIGNED_LIMB sum1 = old_val + hi;
      UNSIGNED_LIMB carry1 = (sum1 < old_val) ? 1 : 0;

      UNSIGNED_LIMB sum2 = sum1 + carry;
      UNSIGNED_LIMB carry2 = (sum2 < sum1) ? 1 : 0;

      UNSIGNED_LIMB sum3 = sum2 + carry_lo;
      UNSIGNED_LIMB carry3 = (sum3 < sum2) ? 1 : 0;

      c[i + j + 1] = sum3;
      carry = carry1 + carry2 + carry3;
    }

    // Propagate remaining carry through higher limbs
    int idx = i + FP_LIMBS;
    while (carry && idx < 2 * FP_LIMBS) {
      UNSIGNED_LIMB sum = c[idx] + carry;
      carry = (sum < c[idx]) ? 1 : 0;
      c[idx] = sum;
      idx++;
    }
  }
}

// Montgomery reduction: c = (a * R_INV) mod p
// Input a is 2*FP_LIMBS limbs (result of multiplication)
// Output c is FP_LIMBS limbs in Montgomery form
// Algorithm: Standard Montgomery reduction for R = 2^448
__host__ __device__ void fp_mont_reduce(Fp &c, const UNSIGNED_LIMB *a) {
  const Fp &p = fp_modulus();
  UNSIGNED_LIMB p_prime = fp_p_prime();

  // Working array: copy input
  UNSIGNED_LIMB t[2 * FP_LIMBS + 1];
#ifdef __CUDA_ARCH__
  for (int i = 0; i < 2 * FP_LIMBS; i++) {
    t[i] = a[i];
  }
#else
  memcpy(t, a, 2 * FP_LIMBS * sizeof(UNSIGNED_LIMB));
#endif
  t[2 * FP_LIMBS] = 0;

  // Montgomery reduction: for each limb, compute u = t[i] * p' mod 2^LIMB_BITS
  // then add u * p to t, which zeros out t[i]
  for (int i = 0; i < FP_LIMBS; i++) {
    UNSIGNED_LIMB u = t[i] * p_prime; // u = t[i] * p' mod 2^LIMB_BITS

    // Add u * p to t, starting at position i
    UNSIGNED_LIMB carry = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      UNSIGNED_LIMB hi, lo;
      mul_limbs(u, p.limb[j], hi, lo);

      // Three-way addition: t[i+j] + lo + carry
      // Do it in two steps to handle carries properly
      UNSIGNED_LIMB temp = t[i + j] + lo;
      UNSIGNED_LIMB carry1 = (temp < t[i + j]) ? 1 : 0;

      UNSIGNED_LIMB sum = temp + carry;
      UNSIGNED_LIMB carry2 = (sum < temp) ? 1 : 0;

      t[i + j] = sum;

      // Next carry is hi + carry1 + carry2
      carry = hi + carry1 + carry2;
    }

    // Propagate remaining carry
    int idx = i + FP_LIMBS;
    while (carry != 0 && idx <= 2 * FP_LIMBS) {
      UNSIGNED_LIMB sum = t[idx] + carry;
      carry = (sum < t[idx]) ? 1 : 0;
      t[idx] = sum;
      idx++;
    }
  }

  // Result is in t[FP_LIMBS..2*FP_LIMBS-1] (high half)
  // But we also need to check if there's a carry into t[2*FP_LIMBS]
  // Copy to output
#ifdef __CUDA_ARCH__
  for (int i = 0; i < FP_LIMBS; i++) {
    c.limb[i] = t[i + FP_LIMBS];
  }
#else
  // Host code: use memcpy for better performance
  memcpy(&c.limb[0], &t[FP_LIMBS], FP_LIMBS * sizeof(UNSIGNED_LIMB));
#endif

  // Final reduction: if c >= p, subtract p
  // Also handle any carry that might have gone into t[2*FP_LIMBS]
  if (t[2 * FP_LIMBS] != 0 || fp_cmp(c, p) != ComparisonType::Less) {
    Fp reduced;
    fp_sub_raw(reduced, c, p);
    fp_copy(c, reduced);
  }
}

// ============================================================================
// PTX-accelerated CIOS Montgomery multiplication (device path)
// ============================================================================
// The CIOS algorithm for 7 x 64-bit limbs executes 98 multiply-accumulate
// steps across 7 outer iterations. Each step computes:
//   (carry, t[j]) = t[j] + a[j] * b_i + carry
// which is a 64x64->128 multiply plus a three-operand addition with carry.
//
// The C++ path uses software carry detection: carry = (sum < old) ? 1 : 0,
// which compiles to SETP + SELP (2-3 extra instructions per carry). The PTX
// path below uses hardware carry flags via the .cc suffix:
//   - mul.lo.u64 / mul.hi.u64 : 64x64->128 wide multiply
//   - add.cc.u64 / addc.u64   : addition chain with hardware carry flag
//
// Each multiply-accumulate step uses 6 PTX instructions instead of ~10+ in
// the software-carry version. The 7 outer iterations are fully unrolled, and
// the limb-shift loop (t[j] = t[j+1]) is eliminated by register renaming.
//
// REGISTER ALIASING NOTE: All PTX temporaries (_lo, _hi) are declared as
// .reg inside the asm block. This prevents nvcc's register allocator from
// aliasing them with C operands (t_j, carry), which was the root cause of
// previous correctness bugs where "+l" outputs could share registers with
// "l" inputs in the same asm statement.
// ============================================================================

#ifdef __CUDA_ARCH__
#if LIMB_BITS_CONFIG == 64

// Multiply-accumulate one limb: (carry_out, t_j) = t_j + a_j * b_i + carry_in
//
// All intermediates (_lo, _hi) are PTX .reg temporaries inside a { } scope
// block to avoid: (1) nvcc register aliasing between C operands, and (2)
// duplicate .reg definitions when the macro is expanded multiple times.
// The 6-instruction sequence:
//   mul.lo.u64  _lo, a_j, b_i      -- low 64 bits of product
//   mul.hi.u64  _hi, a_j, b_i      -- high 64 bits of product
//   add.cc.u64  t_j, t_j, _lo      -- t_j += _lo, set CF
//   addc.u64    _hi, _hi, 0        -- _hi += CF
//   add.cc.u64  t_j, t_j, carry    -- t_j += carry_in, set CF
//   addc.u64    carry, _hi, 0      -- carry_out = _hi + CF
#define LIMB_MACC(t_j, carry, a_j, b_i)                                       \
  asm volatile("{\n\t"                                                         \
               ".reg .u64 _lo, _hi;\n\t"                                       \
               "mul.lo.u64  _lo, %2, %3;\n\t"                                 \
               "mul.hi.u64  _hi, %2, %3;\n\t"                                 \
               "add.cc.u64  %0, %0, _lo;\n\t"                                 \
               "addc.u64    _hi, _hi, 0;\n\t"                                 \
               "add.cc.u64  %0, %0, %1;\n\t"                                  \
               "addc.u64    %1, _hi, 0;\n\t"                                  \
               "}\n\t"                                                         \
               : "+&l"(t_j), "+&l"(carry) : "l"(a_j), "l"(b_i))

// Single CIOS iteration: multiply-accumulate, reduce, and shift.
//
// Computes:
//   1. t += a * b_i  (7 limb multiply-accumulate with carry chain)
//   2. m = t[0] * p_prime  (Montgomery reduction factor)
//   3. t += m * p  (reduction, zeros out t[0])
//   4. Shift t right by one limb (via register renaming into r0..r7)
//
// The macro lets the compiler allocate registers across all 7 unrolled
// iterations, avoiding spills to local memory.
#define CIOS_ITERATION_PTX(                                                    \
    t0, t1, t2, t3, t4, t5, t6, t7,                                           \
    a0, a1, a2, a3, a4, a5, a6,                                               \
    b_i,                                                                       \
    p0, p1, p2, p3, p4, p5, p6,                                               \
    p_prime,                                                                   \
    r0, r1, r2, r3, r4, r5, r6, r7)                                           \
  do {                                                                         \
    uint64_t _carry = 0;                                                       \
    /* Step 1: t += a * b_i */                                                 \
    LIMB_MACC(t0, _carry, a0, b_i);                                            \
    LIMB_MACC(t1, _carry, a1, b_i);                                            \
    LIMB_MACC(t2, _carry, a2, b_i);                                            \
    LIMB_MACC(t3, _carry, a3, b_i);                                            \
    LIMB_MACC(t4, _carry, a4, b_i);                                            \
    LIMB_MACC(t5, _carry, a5, b_i);                                            \
    LIMB_MACC(t6, _carry, a6, b_i);                                            \
    /* Accumulate final carry into overflow limb t7 */                         \
    uint64_t _overflow;                                                        \
    asm("add.cc.u64  %0, %0, %2;\n\t"                                         \
        "addc.u64    %1, 0, 0;\n\t"                                            \
        : "+l"(t7), "=l"(_overflow)                                            \
        : "l"(_carry));                                                        \
                                                                               \
    /* Step 2: m = t0 * p_prime mod 2^64 */                                    \
    uint64_t _m = t0 * p_prime;                                                \
                                                                               \
    /* Step 3: t += m * p (zeros out t0) */                                    \
    _carry = 0;                                                                \
    LIMB_MACC(t0, _carry, _m, p0);                                             \
    LIMB_MACC(t1, _carry, _m, p1);                                             \
    LIMB_MACC(t2, _carry, _m, p2);                                             \
    LIMB_MACC(t3, _carry, _m, p3);                                             \
    LIMB_MACC(t4, _carry, _m, p4);                                             \
    LIMB_MACC(t5, _carry, _m, p5);                                             \
    LIMB_MACC(t6, _carry, _m, p6);                                             \
    /* Finalize overflow: t7 = t7 + _carry + _overflow                       */ \
    /* Plain adds (no carry chain) -- the CIOS invariant guarantees this     */ \
    /* sum fits in 64 bits so intermediate overflow does not matter.         */ \
    t7 += _carry;                                                              \
    t7 += _overflow;                                                          \
                                                                               \
    /* Step 4: Shift right by one limb via register renaming */                \
    /* t0 is now zero (by construction of m), discard it */                    \
    r0 = t1; r1 = t2; r2 = t3; r3 = t4;                                       \
    r4 = t5; r5 = t6; r6 = t7; r7 = 0;                                        \
  } while (0)

__device__ __noinline__ void fp_mont_mul_cios_ptx(Fp &c, const Fp &a, const Fp &b) {
  const uint64_t p0 = DEVICE_MODULUS.limb[0];
  const uint64_t p1 = DEVICE_MODULUS.limb[1];
  const uint64_t p2 = DEVICE_MODULUS.limb[2];
  const uint64_t p3 = DEVICE_MODULUS.limb[3];
  const uint64_t p4 = DEVICE_MODULUS.limb[4];
  const uint64_t p5 = DEVICE_MODULUS.limb[5];
  const uint64_t p6 = DEVICE_MODULUS.limb[6];
  const uint64_t pp = DEVICE_P_PRIME;

  const uint64_t a0 = a.limb[0], a1 = a.limb[1], a2 = a.limb[2];
  const uint64_t a3 = a.limb[3], a4 = a.limb[4], a5 = a.limb[5];
  const uint64_t a6 = a.limb[6];

  // Accumulator: 7 limbs + 1 overflow, initialized to zero
  uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
  uint64_t t4 = 0, t5 = 0, t6 = 0, t7 = 0;

  // 7 fully-unrolled CIOS iterations with register renaming for the shift.
  // Each iteration processes one limb of b, accumulates a*b[i], reduces,
  // and shifts. The output registers become the input for the next iteration.

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7,
                     a0, a1, a2, a3, a4, a5, a6, b.limb[0],
                     p0, p1, p2, p3, p4, p5, p6, pp,
                     t0, t1, t2, t3, t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7,
                     a0, a1, a2, a3, a4, a5, a6, b.limb[1],
                     p0, p1, p2, p3, p4, p5, p6, pp,
                     t0, t1, t2, t3, t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7,
                     a0, a1, a2, a3, a4, a5, a6, b.limb[2],
                     p0, p1, p2, p3, p4, p5, p6, pp,
                     t0, t1, t2, t3, t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7,
                     a0, a1, a2, a3, a4, a5, a6, b.limb[3],
                     p0, p1, p2, p3, p4, p5, p6, pp,
                     t0, t1, t2, t3, t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7,
                     a0, a1, a2, a3, a4, a5, a6, b.limb[4],
                     p0, p1, p2, p3, p4, p5, p6, pp,
                     t0, t1, t2, t3, t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7,
                     a0, a1, a2, a3, a4, a5, a6, b.limb[5],
                     p0, p1, p2, p3, p4, p5, p6, pp,
                     t0, t1, t2, t3, t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7,
                     a0, a1, a2, a3, a4, a5, a6, b.limb[6],
                     p0, p1, p2, p3, p4, p5, p6, pp,
                     t0, t1, t2, t3, t4, t5, t6, t7);

  // Final reduction: if t[0..7] >= p (extended to 8 limbs), subtract p.
  // Compute (t[0..6] - p[0..6]) with borrow, then subtract borrow from t7.
  // If t7 after subtraction is non-negative, the reduced result is valid;
  // otherwise the original t[0..6] is already in [0, p).
  uint64_t r0, r1, r2, r3, r4, r5, r6, mask;
  asm("sub.cc.u64   %0, %8,  %15;\n\t"  // r0 = t0 - p0
      "subc.cc.u64  %1, %9,  %16;\n\t"  // r1 = t1 - p1 - borrow
      "subc.cc.u64  %2, %10, %17;\n\t"  // r2 = t2 - p2 - borrow
      "subc.cc.u64  %3, %11, %18;\n\t"  // r3 = t3 - p3 - borrow
      "subc.cc.u64  %4, %12, %19;\n\t"  // r4 = t4 - p4 - borrow
      "subc.cc.u64  %5, %13, %20;\n\t"  // r5 = t5 - p5 - borrow
      "subc.cc.u64  %6, %14, %21;\n\t"  // r6 = t6 - p6 - borrow
      "subc.u64     %7, %22, 0;\n\t"    // mask_src = t7 - 0 - borrow
      "shr.s64      %7, %7, 63;\n\t"    // mask = sign-extend: -1 if negative, 0 if >= 0
      : "=l"(r0), "=l"(r1), "=l"(r2), "=l"(r3),
        "=l"(r4), "=l"(r5), "=l"(r6), "=l"(mask)
      : "l"(t0), "l"(t1), "l"(t2), "l"(t3),
        "l"(t4), "l"(t5), "l"(t6),
        "l"(p0), "l"(p1), "l"(p2), "l"(p3),
        "l"(p4), "l"(p5), "l"(p6), "l"(t7));

  // Branchless selection:
  //   mask = 0  -> t >= p (use reduced r[0..6])
  //   mask = -1 -> t < p  (keep original t[0..6])
  c.limb[0] = (t0 & mask) | (r0 & ~mask);
  c.limb[1] = (t1 & mask) | (r1 & ~mask);
  c.limb[2] = (t2 & mask) | (r2 & ~mask);
  c.limb[3] = (t3 & mask) | (r3 & ~mask);
  c.limb[4] = (t4 & mask) | (r4 & ~mask);
  c.limb[5] = (t5 & mask) | (r5 & ~mask);
  c.limb[6] = (t6 & mask) | (r6 & ~mask);
}

#undef LIMB_MACC
#undef CIOS_ITERATION_PTX

#endif // LIMB_BITS_CONFIG == 64
#endif // __CUDA_ARCH__

// CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication
// Fuses multiplication and reduction in a single pass for better efficiency.
// Uses only FP_LIMBS+1 limbs of working space instead of 2*FP_LIMBS.
// Both a and b are in Montgomery form, result is in Montgomery form.
__host__ __device__ void fp_mont_mul_cios(Fp &c, const Fp &a, const Fp &b) {
#if defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 64
  // Device path: fully unrolled PTX with hardware carry flags
  fp_mont_mul_cios_ptx(c, a, b);
#else
  // Host path: portable C++ implementation
  const Fp &p = fp_modulus();
  UNSIGNED_LIMB p_prime = fp_p_prime();

  // Working array: only n+1 limbs needed (vs 2n for separate mul+reduce)
  UNSIGNED_LIMB t[FP_LIMBS + 1];
  memset(t, 0, (FP_LIMBS + 1) * sizeof(UNSIGNED_LIMB));

  // Main CIOS loop: for each limb of b
  for (int i = 0; i < FP_LIMBS; i++) {
    // Step 1: Multiply-accumulate t += a * b[i]
    UNSIGNED_LIMB carry = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      UNSIGNED_LIMB hi, lo;
      mul_limbs(a.limb[j], b.limb[i], hi, lo);

      // t[j] = t[j] + lo + carry
      UNSIGNED_LIMB sum1 = t[j] + lo;
      UNSIGNED_LIMB c1 = (sum1 < t[j]) ? 1 : 0;
      UNSIGNED_LIMB sum2 = sum1 + carry;
      UNSIGNED_LIMB c2 = (sum2 < sum1) ? 1 : 0;
      t[j] = sum2;

      // carry = hi + c1 + c2
      carry = hi + c1 + c2;
    }
    // Add carry to t[n]
    UNSIGNED_LIMB sum = t[FP_LIMBS] + carry;
    UNSIGNED_LIMB overflow = (sum < t[FP_LIMBS]) ? 1 : 0;
    t[FP_LIMBS] = sum;

    // Step 2: Reduction - compute m = t[0] * p' mod 2^LIMB_BITS
    UNSIGNED_LIMB m = t[0] * p_prime;

    // Add m * p to t (this zeros out t[0])
    carry = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      UNSIGNED_LIMB hi, lo;
      mul_limbs(m, p.limb[j], hi, lo);

      // t[j] = t[j] + lo + carry
      UNSIGNED_LIMB s1 = t[j] + lo;
      UNSIGNED_LIMB c1 = (s1 < t[j]) ? 1 : 0;
      UNSIGNED_LIMB s2 = s1 + carry;
      UNSIGNED_LIMB c2 = (s2 < s1) ? 1 : 0;
      t[j] = s2;

      carry = hi + c1 + c2;
    }
    // Add carry + overflow to t[n]
    UNSIGNED_LIMB s1 = t[FP_LIMBS] + carry;
    UNSIGNED_LIMB c1 = (s1 < t[FP_LIMBS]) ? 1 : 0;
    UNSIGNED_LIMB s2 = s1 + overflow;
    UNSIGNED_LIMB c2 = (s2 < s1) ? 1 : 0;
    t[FP_LIMBS] = s2;
    overflow = c1 + c2; // Track overflow for final reduction

    // Step 3: Shift right by one limb (divide by 2^LIMB_BITS)
    // t[0..n-1] = t[1..n], t[n] = overflow
    for (int j = 0; j < FP_LIMBS; j++) {
      t[j] = t[j + 1];
    }
    t[FP_LIMBS] = overflow;
  }

  // Copy result to output
  memcpy(&c.limb[0], t, FP_LIMBS * sizeof(UNSIGNED_LIMB));

  // Final reduction: if result >= p or there's overflow, subtract p
  if (t[FP_LIMBS] != 0 || fp_cmp(c, p) != ComparisonType::Less) {
    Fp reduced;
    fp_sub_raw(reduced, c, p);
    fp_copy(c, reduced);
  }
  // Result is in Montgomery form
#endif
}

// Montgomery multiplication: c = (a * b * R_INV) mod p
// Both a and b are in Montgomery form, result is in Montgomery form
// Uses CIOS algorithm for fused multiply-reduce
__host__ __device__ void fp_mont_mul(Fp &c, const Fp &a, const Fp &b) {
  fp_mont_mul_cios(c, a, b);
}

// CONVERSION: Convert from normal form to Montgomery form
// Input a is in normal form, output c is in Montgomery form
// Uses CIOS: c = a * R^2 * R^-1 mod p = a * R mod p
__host__ __device__ void fp_to_montgomery(Fp &c, const Fp &a) {
  // c = a * R mod p = a * R^2 * R^-1 mod p
  // Use CIOS to compute a * R^2 with integrated reduction
  const Fp &r2 = fp_r2();
  fp_mont_mul_cios(c, a, r2);
}

// CONVERSION: Convert from Montgomery form to normal form
// Input a is in Montgomery form, output c is in normal form
// Uses CIOS: c = a * 1 * R^-1 mod p = a * R^-1 mod p
__host__ __device__ void fp_from_montgomery(Fp &c, const Fp &a) {
  // c = a * R^-1 mod p = a * 1 * R^-1 mod p
  // Use CIOS to compute a * 1 with integrated reduction
  Fp one;
  fp_one(one);
  fp_mont_mul_cios(c, a, one);
}

// Negation: c = -a mod p = p - a
// Works in both Montgomery and normal form: fp_sub computes (p - a) mod p.
// Although p is stored in normal form, fp_sub(c, p, a) is correct because
// (p mod p) == 0 in either representation, so the result is -a mod p.
__host__ __device__ void fp_neg(Fp &c, const Fp &a) {
  if (fp_is_zero(a)) {
    fp_zero(c);
  } else {
    const Fp &p = fp_modulus();
    fp_sub(c, p, a);
  }
}

// Exponentiation by squaring - Montgomery form version (no conversions)
// Computes base_mont^exp mod p where base_mont is already in Montgomery form
// Result is returned in Montgomery form
// NOTE: All inputs and outputs are in Montgomery form
__host__ __device__ static void fp_pow_internal_mont(Fp &result,
                                                     const Fp &base_mont,
                                                     const UNSIGNED_LIMB *exp,
                                                     int exp_limbs) {
  // Result starts as 1 in Montgomery form
  fp_one_montgomery(result);

  // Find the most significant bit
  int msb_idx = exp_limbs - 1;
  while (msb_idx >= 0 && exp[msb_idx] == 0) {
    // TODO: Possible branching?
    msb_idx--;
  }

  if (msb_idx < 0) {
    // Exponent is zero, result is 1 in Montgomery form
    fp_one_montgomery(result);
    return;
  }

  // Find the most significant bit in the highest non-zero limb
  UNSIGNED_LIMB msb_val = exp[msb_idx];
  int bit_pos = LIMB_BITS - 1;
  while (bit_pos >= 0 && ((msb_val >> bit_pos) & 1) == 0) {
    // TODO: Possible branching?
    bit_pos--;
  }

  // Square-and-multiply algorithm (all in Montgomery form)
  for (int limb_idx = msb_idx; limb_idx >= 0; limb_idx--) {
    int start_bit = (limb_idx == msb_idx) ? bit_pos : LIMB_BITS - 1;

    for (int bit = start_bit; bit >= 0; bit--) {
      // Square result
      Fp temp;
      fp_mont_mul(temp, result, result);
      fp_copy(result, temp);

      // Multiply by base if current bit is set
      if ((exp[limb_idx] >> bit) & 1) {
        fp_mont_mul(temp, result, base_mont);
        fp_copy(result, temp);
      }
    }
  }
}

// Exponentiation by squaring (helper for inversion and pow)
// Computes base^exp mod p where exp is a big integer
// Uses Montgomery form internally for efficiency
__host__ __device__ static void fp_pow_internal(Fp &result, const Fp &base,
                                                const UNSIGNED_LIMB *exp,
                                                int exp_limbs) {
  // Convert base to Montgomery form
  Fp base_mont;
  fp_to_montgomery(base_mont, base);

  // Do exponentiation in Montgomery form
  Fp result_mont;
  fp_pow_internal_mont(result_mont, base_mont, exp, exp_limbs);

  // Convert result back from Montgomery form
  fp_from_montgomery(result, result_mont);
}

// Exponentiation with 64-bit exponent
__host__ __device__ void fp_pow_u64(Fp &c, const Fp &a, uint64_t e) {
#if LIMB_BITS_CONFIG == 64
  UNSIGNED_LIMB exp_array[1] = {e};
  fp_pow_internal(c, a, exp_array, 1);
#elif LIMB_BITS_CONFIG == 32
  // Split 64-bit exponent into two 32-bit limbs (little-endian)
  UNSIGNED_LIMB exp_array[2] = {static_cast<UNSIGNED_LIMB>(e & 0xFFFFFFFF),
                                static_cast<UNSIGNED_LIMB>(e >> 32)};
  int exp_limbs = (exp_array[1] == 0) ? 1 : 2;
  fp_pow_internal(c, a, exp_array, exp_limbs);
#endif
}

// Exponentiation with big integer exponent (native limb type)
__host__ __device__ void fp_pow(Fp &c, const Fp &a, const UNSIGNED_LIMB *e,
                                int e_limbs) {
  int actual_limbs = (e_limbs > FP_LIMBS) ? FP_LIMBS : e_limbs;
  fp_pow_internal(c, a, e, actual_limbs);
}

// Inversion: c = a^(-1) mod p
// Uses Fermat's little theorem: a^(p-2) = a^(-1) mod p
// NOTE: Assumes input is in normal form and converts to/from Montgomery
// NOTE: Caller must ensure a != 0 (division by zero check must be done at host
// side)
__host__ __device__ void fp_inv(Fp &c, const Fp &a) {
  // Compute a^(p-2) mod p
  const Fp &p = fp_modulus();

  Fp p_minus_2;
  Fp two;
  fp_one(two);
  two.limb[0] = 2;
  fp_sub(p_minus_2, p, two);
  fp_pow_internal(c, a, p_minus_2.limb, FP_LIMBS);
}

// Montgomery inversion: c = a^(-1) mod p (all in Montgomery form)
// Optimized: uses fp_pow_internal_mont directly, no conversions needed
// NOTE: Input and output are in Montgomery form
// NOTE: Caller must ensure a != 0 (division by zero check must be done at host
// side)
__host__ __device__ void fp_mont_inv(Fp &c, const Fp &a) {
  const Fp &p = fp_modulus();
  Fp p_minus_2;
  Fp two;
  fp_one(two);
  two.limb[0] = 2;
  fp_sub(p_minus_2, p, two);

  // Compute a^(p-2) directly in Montgomery form - no conversions needed
  fp_pow_internal_mont(c, a, p_minus_2.limb, FP_LIMBS);
}

// Optimized: stays in Montgomery form throughout
// (3 conversions instead of 5)
// NOTE: Caller must ensure b != 0 (division by zero check must be done at host
// side)
__host__ __device__ void fp_div(Fp &c, const Fp &a, const Fp &b) {
  // Convert inputs to Montgomery form
  Fp a_mont, b_mont;
  fp_to_montgomery(a_mont, a);
  fp_to_montgomery(b_mont, b);

  // Invert b in Montgomery form (no conversions)
  Fp b_inv_mont;
  fp_mont_inv(b_inv_mont, b_mont);

  // Multiply in Montgomery form
  Fp c_mont;
  fp_mont_mul(c_mont, a_mont, b_inv_mont);

  // Convert result back
  fp_from_montgomery(c, c_mont);
}

__host__ __device__ static void fp_div_by_2(Fp &result, const Fp &a) {
  UNSIGNED_LIMB carry = 0;
  for (int i = FP_LIMBS - 1; i >= 0; i--) {
    UNSIGNED_LIMB new_val = (a.limb[i] >> 1) | (carry << (LIMB_BITS - 1));
    carry = a.limb[i] & 1;
    result.limb[i] = new_val;
  }
}

__host__ __device__ static void fp_div_by_4(Fp &result, const Fp &a) {
  Fp temp;
  fp_div_by_2(temp, a);
  fp_div_by_2(result, temp);
}

__host__ __device__ bool fp_is_quadratic_residue(const Fp &a) {
  if (fp_is_zero(a)) {
    return true;
  }

  const Fp &p = fp_modulus();

  // Compute (p-1)/2
  Fp p_minus_1;
  Fp one;
  fp_one(one);
  fp_sub(p_minus_1, p, one);

  // Divide by 2 using helper
  Fp exp_direct;
  fp_div_by_2(exp_direct, p_minus_1);

  // Compute a^((p-1)/2) mod p
  Fp result;
  fp_pow_internal(result, a, exp_direct.limb, FP_LIMBS);

  // If result == 1, a is a quadratic residue
  return fp_is_one(result);
}

// Optimized: verification uses Montgomery form
// (2-4 conversions instead of 9)
__host__ __device__ bool fp_sqrt(Fp &c, const Fp &a) {
  if (fp_is_zero(a)) {
    fp_zero(c);
    return true;
  }

  if (!fp_is_quadratic_residue(a)) {
    fp_zero(c);
    return false;
  }

  const Fp &p = fp_modulus();
  Fp three, p_minus_3, exp;
  fp_zero(three);
  three.limb[0] = 3;
  fp_sub(p_minus_3, p, three);
  fp_div_by_4(exp, p_minus_3);
  Fp one;
  fp_one(one);
  fp_add(exp, exp, one);

  fp_pow_internal(c, a, exp.limb, FP_LIMBS);

  // Convert a to Montgomery form once for all verifications
  Fp a_mont;
  fp_to_montgomery(a_mont, a);

  // Verify: c^2 should equal a (mod p) - using Montgomery form
  Fp c_mont, c_squared_mont;
  fp_to_montgomery(c_mont, c);
  fp_mont_mul(c_squared_mont, c_mont, c_mont);

  if (fp_cmp(c_squared_mont, a_mont) == ComparisonType::Equal) {
    return true;
  }

  // Try the other square root: p - c
  Fp alt_c, alt_c_mont;
  fp_sub(alt_c, p, c);
  fp_to_montgomery(alt_c_mont, alt_c);
  fp_mont_mul(c_squared_mont, alt_c_mont, alt_c_mont);
  if (fp_cmp(c_squared_mont, a_mont) == ComparisonType::Equal) {
    fp_copy(c, alt_c);
    return true;
  }

  // Final reduction check
  if (fp_cmp(c, p) != ComparisonType::Less) {
    Fp reduced_c, reduced_c_mont;
    fp_sub(reduced_c, c, p);
    fp_copy(c, reduced_c);
    fp_to_montgomery(reduced_c_mont, reduced_c);
    fp_mont_mul(c_squared_mont, reduced_c_mont, reduced_c_mont);
    if (fp_cmp(c_squared_mont, a_mont) == ComparisonType::Equal) {
      return true;
    }
  }

  return false;
}

// Conditional assignment: if condition, dst = src, else dst unchanged
__host__ __device__ void fp_cmov(Fp &dst, const Fp &src, uint64_t condition) {
  UNSIGNED_LIMB mask = -static_cast<UNSIGNED_LIMB>(condition & 1);

  for (int i = 0; i < FP_LIMBS; i++) {
    dst.limb[i] = (dst.limb[i] & ~mask) | (src.limb[i] & mask);
  }
}

// ============================================================================
// Operator Overloading Implementations
// ============================================================================

// Binary addition: a + b
__host__ __device__ Fp operator+(const Fp &a, const Fp &b) {
  Fp c;
  fp_add(c, a, b);
  return c;
}

// Binary subtraction: a - b
__host__ __device__ Fp operator-(const Fp &a, const Fp &b) {
  Fp c;
  fp_sub(c, a, b);
  return c;
}

// Binary multiplication: a * b
// MONTGOMERY: Both inputs must be in Montgomery form, result is in Montgomery
// form. This is consistent with operator+ and operator- which also require
// Montgomery-form inputs.
__host__ __device__ Fp operator*(const Fp &a, const Fp &b) {
  Fp result;
  fp_mont_mul(result, a, b);
  return result;
}

// Binary division: a / b
// MONTGOMERY: Both inputs must be in Montgomery form, result is in Montgomery
// form. Computes a * b^{-1} entirely in Montgomery representation.
__host__ __device__ Fp operator/(const Fp &a, const Fp &b) {
  Fp b_inv;
  fp_mont_inv(b_inv, b);
  Fp c;
  fp_mont_mul(c, a, b_inv);
  return c;
}

// Unary negation: -a
__host__ __device__ Fp operator-(const Fp &a) {
  Fp c;
  fp_neg(c, a);
  return c;
}

// Equality comparison: a == b
__host__ __device__ bool operator==(const Fp &a, const Fp &b) {
  return fp_cmp(a, b) == ComparisonType::Equal;
}

// Inequality comparison: a != b
__host__ __device__ bool operator!=(const Fp &a, const Fp &b) {
  return fp_cmp(a, b) != ComparisonType::Equal;
}

// Compound addition: a += b
__host__ __device__ Fp &operator+=(Fp &a, const Fp &b) {
  fp_add(a, a, b);
  return a;
}

// Compound subtraction: a -= b
__host__ __device__ Fp &operator-=(Fp &a, const Fp &b) {
  fp_sub(a, a, b);
  return a;
}

// Compound multiplication: a *= b
// MONTGOMERY: Both inputs must be in Montgomery form, result is in Montgomery
// form.
__host__ __device__ Fp &operator*=(Fp &a, const Fp &b) {
  Fp temp;
  fp_mont_mul(temp, a, b);
  fp_copy(a, temp);
  return a;
}

// Compound division: a /= b
// MONTGOMERY: Both inputs must be in Montgomery form, result is in Montgomery
// form.
__host__ __device__ Fp &operator/=(Fp &a, const Fp &b) {
  Fp b_inv;
  fp_mont_inv(b_inv, b);
  Fp temp;
  fp_mont_mul(temp, a, b_inv);
  fp_copy(a, temp);
  return a;
}
