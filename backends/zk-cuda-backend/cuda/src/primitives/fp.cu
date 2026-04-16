#include "bls12_446_params.h"
#include "device.h"
#include "fp.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>

// For CUDA device code, we use __constant__ memory
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
  UNSIGNED_LIMB acc = 0;
  for (int i = 0; i < FP_LIMBS; i++) {
    acc |= a.limb[i];
  }
  return acc == 0;
}

__host__ __device__ bool fp_is_one(const Fp &a) {
  if (a.limb[0] != 1)
    return false;
  // All higher limbs must be zero.
  UNSIGNED_LIMB acc = 0;
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
#if defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 64
  // PTX carry-chain: add.cc sets the hardware carry flag, addc.cc propagates
  // it. This replaces 2 software carry-detect comparisons per limb (~14 extra
  // instructions across 7 limbs) with zero-cost hardware flag propagation.
  uint64_t carry_out;
  asm("add.cc.u64   %0,  %8,  %15;\n\t" // c[0] = a[0] + b[0], set CF
      "addc.cc.u64  %1,  %9,  %16;\n\t" // c[1] = a[1] + b[1] + CF
      "addc.cc.u64  %2,  %10, %17;\n\t" // c[2] = a[2] + b[2] + CF
      "addc.cc.u64  %3,  %11, %18;\n\t" // c[3] = a[3] + b[3] + CF
      "addc.cc.u64  %4,  %12, %19;\n\t" // c[4] = a[4] + b[4] + CF
      "addc.cc.u64  %5,  %13, %20;\n\t" // c[5] = a[5] + b[5] + CF
      "addc.cc.u64  %6,  %14, %21;\n\t" // c[6] = a[6] + b[6] + CF
      "addc.u64     %7,  0,   0;\n\t"   // carry_out = 0 + 0 + CF
      : "=l"(c.limb[0]), "=l"(c.limb[1]), "=l"(c.limb[2]), "=l"(c.limb[3]),
        "=l"(c.limb[4]), "=l"(c.limb[5]), "=l"(c.limb[6]), "=l"(carry_out)
      : "l"(a.limb[0]), "l"(a.limb[1]), "l"(a.limb[2]), "l"(a.limb[3]),
        "l"(a.limb[4]), "l"(a.limb[5]), "l"(a.limb[6]), "l"(b.limb[0]),
        "l"(b.limb[1]), "l"(b.limb[2]), "l"(b.limb[3]), "l"(b.limb[4]),
        "l"(b.limb[5]), "l"(b.limb[6]));
  return carry_out;
#elif defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 32
  // 32-bit PTX carry chain: add.cc.u32 sets the hardware carry flag,
  // addc.cc.u32 propagates it. Eliminates software carry-detect comparisons
  // across all 14 limbs.
  // Operand map: %0..%13 = c[0..13], %14 = carry_out,
  //              %15..%28 = a[0..13], %29..%42 = b[0..13].
  uint32_t carry_out;
  asm("add.cc.u32   %0,  %15, %29;\n\t" // c[0]  = a[0]  + b[0],  set CF
      "addc.cc.u32  %1,  %16, %30;\n\t" // c[1]  = a[1]  + b[1]  + CF
      "addc.cc.u32  %2,  %17, %31;\n\t" // c[2]  = a[2]  + b[2]  + CF
      "addc.cc.u32  %3,  %18, %32;\n\t" // c[3]  = a[3]  + b[3]  + CF
      "addc.cc.u32  %4,  %19, %33;\n\t" // c[4]  = a[4]  + b[4]  + CF
      "addc.cc.u32  %5,  %20, %34;\n\t" // c[5]  = a[5]  + b[5]  + CF
      "addc.cc.u32  %6,  %21, %35;\n\t" // c[6]  = a[6]  + b[6]  + CF
      "addc.cc.u32  %7,  %22, %36;\n\t" // c[7]  = a[7]  + b[7]  + CF
      "addc.cc.u32  %8,  %23, %37;\n\t" // c[8]  = a[8]  + b[8]  + CF
      "addc.cc.u32  %9,  %24, %38;\n\t" // c[9]  = a[9]  + b[9]  + CF
      "addc.cc.u32  %10, %25, %39;\n\t" // c[10] = a[10] + b[10] + CF
      "addc.cc.u32  %11, %26, %40;\n\t" // c[11] = a[11] + b[11] + CF
      "addc.cc.u32  %12, %27, %41;\n\t" // c[12] = a[12] + b[12] + CF
      "addc.cc.u32  %13, %28, %42;\n\t" // c[13] = a[13] + b[13] + CF
      "addc.u32     %14, 0,   0;\n\t"   // carry_out = 0 + 0 + CF (0 or 1)
      : "=r"(c.limb[0]), "=r"(c.limb[1]), "=r"(c.limb[2]), "=r"(c.limb[3]),
        "=r"(c.limb[4]), "=r"(c.limb[5]), "=r"(c.limb[6]), "=r"(c.limb[7]),
        "=r"(c.limb[8]), "=r"(c.limb[9]), "=r"(c.limb[10]), "=r"(c.limb[11]),
        "=r"(c.limb[12]), "=r"(c.limb[13]), "=r"(carry_out)
      : "r"(a.limb[0]), "r"(a.limb[1]), "r"(a.limb[2]), "r"(a.limb[3]),
        "r"(a.limb[4]), "r"(a.limb[5]), "r"(a.limb[6]), "r"(a.limb[7]),
        "r"(a.limb[8]), "r"(a.limb[9]), "r"(a.limb[10]), "r"(a.limb[11]),
        "r"(a.limb[12]), "r"(a.limb[13]), "r"(b.limb[0]), "r"(b.limb[1]),
        "r"(b.limb[2]), "r"(b.limb[3]), "r"(b.limb[4]), "r"(b.limb[5]),
        "r"(b.limb[6]), "r"(b.limb[7]), "r"(b.limb[8]), "r"(b.limb[9]),
        "r"(b.limb[10]), "r"(b.limb[11]), "r"(b.limb[12]), "r"(b.limb[13]));
  return static_cast<UNSIGNED_LIMB>(carry_out);
#else
  // Host path: portable software carry detection
  UNSIGNED_LIMB carry = 0;

  for (int i = 0; i < FP_LIMBS; i++) {
    UNSIGNED_LIMB sum = a.limb[i] + carry;
    carry = (sum < a.limb[i]) ? 1 : 0;
    sum += b.limb[i];
    carry += (sum < b.limb[i]) ? 1 : 0;
    c.limb[i] = sum;
  }

  return carry;
#endif
}

// Subtraction with borrow propagation
// "Raw" means without modular reduction - performs a - b and returns borrow.
// This is an internal helper used by fp_sub() which handles reduction.
__host__ __device__ UNSIGNED_LIMB fp_sub_raw(Fp &c, const Fp &a, const Fp &b) {
#if defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 64
  // PTX borrow-chain: sub.cc sets the hardware borrow flag, subc.cc propagates
  // it. Same benefit as fp_add_raw -- eliminates 2 comparisons per limb.
  uint64_t borrow_out;
  asm("sub.cc.u64   %0,  %8,  %15;\n\t" // c[0] = a[0] - b[0], set CF
      "subc.cc.u64  %1,  %9,  %16;\n\t" // c[1] = a[1] - b[1] - CF
      "subc.cc.u64  %2,  %10, %17;\n\t" // c[2] = a[2] - b[2] - CF
      "subc.cc.u64  %3,  %11, %18;\n\t" // c[3] = a[3] - b[3] - CF
      "subc.cc.u64  %4,  %12, %19;\n\t" // c[4] = a[4] - b[4] - CF
      "subc.cc.u64  %5,  %13, %20;\n\t" // c[5] = a[5] - b[5] - CF
      "subc.cc.u64  %6,  %14, %21;\n\t" // c[6] = a[6] - b[6] - CF
      "subc.u64     %7,  0,   0;\n\t"   // borrow_out = 0 - 0 - CF
      : "=l"(c.limb[0]), "=l"(c.limb[1]), "=l"(c.limb[2]), "=l"(c.limb[3]),
        "=l"(c.limb[4]), "=l"(c.limb[5]), "=l"(c.limb[6]), "=l"(borrow_out)
      : "l"(a.limb[0]), "l"(a.limb[1]), "l"(a.limb[2]), "l"(a.limb[3]),
        "l"(a.limb[4]), "l"(a.limb[5]), "l"(a.limb[6]), "l"(b.limb[0]),
        "l"(b.limb[1]), "l"(b.limb[2]), "l"(b.limb[3]), "l"(b.limb[4]),
        "l"(b.limb[5]), "l"(b.limb[6]));
  // subc.u64 with 0-0-CF produces 0 if no borrow, or 0xFFFFFFFFFFFFFFFF if
  // borrow. Normalize to 0/1 for callers that check (borrow != 0) or add it.
  return borrow_out & 1;
#elif defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 32
  // 32-bit PTX borrow chain: sub.cc.u32 sets the hardware borrow flag,
  // subc.cc.u32 propagates it across all 14 limbs.
  // subc.u32 with 0-0-BF gives 0xFFFFFFFF on borrow; normalize to 0/1.
  // Operand map: %0..%13 = c[0..13], %14 = borrow_out,
  //              %15..%28 = a[0..13], %29..%42 = b[0..13].
  uint32_t borrow_out;
  asm("sub.cc.u32   %0,  %15, %29;\n\t" // c[0]  = a[0]  - b[0],  set BF
      "subc.cc.u32  %1,  %16, %30;\n\t" // c[1]  = a[1]  - b[1]  - BF
      "subc.cc.u32  %2,  %17, %31;\n\t" // c[2]  = a[2]  - b[2]  - BF
      "subc.cc.u32  %3,  %18, %32;\n\t" // c[3]  = a[3]  - b[3]  - BF
      "subc.cc.u32  %4,  %19, %33;\n\t" // c[4]  = a[4]  - b[4]  - BF
      "subc.cc.u32  %5,  %20, %34;\n\t" // c[5]  = a[5]  - b[5]  - BF
      "subc.cc.u32  %6,  %21, %35;\n\t" // c[6]  = a[6]  - b[6]  - BF
      "subc.cc.u32  %7,  %22, %36;\n\t" // c[7]  = a[7]  - b[7]  - BF
      "subc.cc.u32  %8,  %23, %37;\n\t" // c[8]  = a[8]  - b[8]  - BF
      "subc.cc.u32  %9,  %24, %38;\n\t" // c[9]  = a[9]  - b[9]  - BF
      "subc.cc.u32  %10, %25, %39;\n\t" // c[10] = a[10] - b[10] - BF
      "subc.cc.u32  %11, %26, %40;\n\t" // c[11] = a[11] - b[11] - BF
      "subc.cc.u32  %12, %27, %41;\n\t" // c[12] = a[12] - b[12] - BF
      "subc.cc.u32  %13, %28, %42;\n\t" // c[13] = a[13] - b[13] - BF
      "subc.u32     %14, 0,   0;\n\t"   // borrow_out = 0 - 0 - BF (0 or
                                        // 0xFFFFFFFF)
      : "=r"(c.limb[0]), "=r"(c.limb[1]), "=r"(c.limb[2]), "=r"(c.limb[3]),
        "=r"(c.limb[4]), "=r"(c.limb[5]), "=r"(c.limb[6]), "=r"(c.limb[7]),
        "=r"(c.limb[8]), "=r"(c.limb[9]), "=r"(c.limb[10]), "=r"(c.limb[11]),
        "=r"(c.limb[12]), "=r"(c.limb[13]), "=r"(borrow_out)
      : "r"(a.limb[0]), "r"(a.limb[1]), "r"(a.limb[2]), "r"(a.limb[3]),
        "r"(a.limb[4]), "r"(a.limb[5]), "r"(a.limb[6]), "r"(a.limb[7]),
        "r"(a.limb[8]), "r"(a.limb[9]), "r"(a.limb[10]), "r"(a.limb[11]),
        "r"(a.limb[12]), "r"(a.limb[13]), "r"(b.limb[0]), "r"(b.limb[1]),
        "r"(b.limb[2]), "r"(b.limb[3]), "r"(b.limb[4]), "r"(b.limb[5]),
        "r"(b.limb[6]), "r"(b.limb[7]), "r"(b.limb[8]), "r"(b.limb[9]),
        "r"(b.limb[10]), "r"(b.limb[11]), "r"(b.limb[12]), "r"(b.limb[13]));
  return static_cast<UNSIGNED_LIMB>(borrow_out & 1u);
#else
  // Host path: portable software borrow detection
  UNSIGNED_LIMB borrow = 0;

  for (int i = 0; i < FP_LIMBS; i++) {
    UNSIGNED_LIMB diff = a.limb[i] - borrow;
    borrow = (diff > a.limb[i]) ? 1 : 0;
    UNSIGNED_LIMB old_diff = diff;
    diff -= b.limb[i];
    borrow += (diff > old_diff) ? 1 : 0;
    c.limb[i] = diff;
  }

  return borrow;
#endif
}

// Addition with modular reduction: c = (a + b) mod p
// MONTGOMERY: Both inputs and output must be in Montgomery form
__host__ __device__ void fp_add(Fp &c, const Fp &a, const Fp &b) {
  Fp sum;
  UNSIGNED_LIMB carry = fp_add_raw(sum, a, b);

#if defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 64
  // Branchless reduction: always compute sum - p, then select based on
  // whether reduction was needed. This avoids divergent branches that stall
  // warps when some threads need reduction and others don't.
  //
  // Decision logic:
  //   carry=1 -> sum overflowed 448 bits, definitely >= p -> use reduced
  //   carry=0, borrow=0 -> sum >= p in 448 bits -> use reduced
  //   carry=0, borrow=1 -> sum < p -> use original sum
  // So: use_original = (!carry) & borrow
  Fp reduced;
  UNSIGNED_LIMB borrow = fp_sub_raw(reduced, sum, fp_modulus());
  UNSIGNED_LIMB use_original = ((carry ^ 1) & borrow);
  UNSIGNED_LIMB mask =
      -use_original; // all-ones if keep sum, all-zeros if keep reduced

  for (int i = 0; i < FP_LIMBS; i++) {
    c.limb[i] = (sum.limb[i] & mask) | (reduced.limb[i] & ~mask);
  }
#elif defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 32
  // Same branchless logic as the 64-bit path; mask arithmetic is identical
  // since UNSIGNED_LIMB is uint32_t: -1u == 0xFFFFFFFF (all-ones).
  Fp reduced;
  UNSIGNED_LIMB borrow = fp_sub_raw(reduced, sum, fp_modulus());
  UNSIGNED_LIMB use_original = ((carry ^ 1u) & borrow);
  UNSIGNED_LIMB mask = -use_original;

  for (int i = 0; i < FP_LIMBS; i++) {
    c.limb[i] = (sum.limb[i] & mask) | (reduced.limb[i] & ~mask);
  }
#else
  // Host path: branching is fine on CPU (branch predictor handles it well)
  const Fp &p = fp_modulus();
  if (carry || fp_cmp(sum, p) != ComparisonType::Less) {
    Fp reduced;
    fp_sub_raw(reduced, sum, p);
    fp_copy(c, reduced);
  } else {
    fp_copy(c, sum);
  }
#endif
}

// Subtraction with modular reduction: c = (a - b) mod p
// MONTGOMERY: Both inputs and output must be in Montgomery form
__host__ __device__ void fp_sub(Fp &c, const Fp &a, const Fp &b) {
  Fp diff;
  UNSIGNED_LIMB borrow = fp_sub_raw(diff, a, b);

#if defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 64
  // Branchless correction: always compute diff + p, select based on borrow.
  // Same rationale as fp_add -- avoids warp divergence.
  //   borrow=1 -> a < b, need to add p -> use corrected
  //   borrow=0 -> a >= b, result is valid -> use diff
  Fp corrected;
  fp_add_raw(corrected, diff, fp_modulus());
  UNSIGNED_LIMB mask =
      -borrow; // all-ones if borrow (use corrected), all-zeros if not

  for (int i = 0; i < FP_LIMBS; i++) {
    c.limb[i] = (corrected.limb[i] & mask) | (diff.limb[i] & ~mask);
  }
#elif defined(__CUDA_ARCH__) && LIMB_BITS_CONFIG == 32
  // Same branchless logic as the 64-bit path; -1u == 0xFFFFFFFF for uint32_t.
  Fp corrected;
  fp_add_raw(corrected, diff, fp_modulus());
  UNSIGNED_LIMB mask = -borrow;

  for (int i = 0; i < FP_LIMBS; i++) {
    c.limb[i] = (corrected.limb[i] & mask) | (diff.limb[i] & ~mask);
  }
#else
  // Host path: branching is fine on CPU
  const Fp &p = fp_modulus();
  if (borrow) {
    fp_add_raw(c, diff, p);
  } else {
    fp_copy(c, diff);
  }
#endif
}

// Lazy addition: c = a + b, result in [0, 2p) for inputs in [0, p).
// Skips the conditional subtraction of fp_add; valid as input to fp_mont_mul
// since CIOS accepts operands in [0, 2p).
__host__ __device__ void fp_add_lazy(Fp &c, const Fp &a, const Fp &b) {
  fp_add_raw(c, a, b);
}

// Lazy subtraction: c ≡ a - b (mod p), result in [0, 2p) for inputs in [0, p).
// Adds p unconditionally (no borrow-select), saving one conditional branch.
// Valid as input to fp_mont_mul; must NOT be used where [0, p) is
// required (e.g. final results, inputs to fp_sub/fp_neg).
__host__ __device__ void fp_sub_lazy(Fp &c, const Fp &a, const Fp &b) {
  Fp diff;
  fp_sub_raw(diff, a, b);            // a - b, borrow absorbed into bit pattern
  fp_add_raw(c, diff, fp_modulus()); // always add p; carry discarded
  // For a >= b (no borrow): diff = a-b ∈ [0,p), result = a-b+p ∈ [p,2p)  ✓
  // For a < b  (borrow=1):  diff wraps, result = a-b+2^N+p mod 2^N = a-b+p ∈
  // [0,p) ✓
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

    // Add u * p to t, starting at position i.
    // Use uint64_t accumulator in 32-bit mode to avoid carry overflow:
    // hi + carry1 + carry2 can reach 2^32 which overflows uint32_t.
#if LIMB_BITS_CONFIG == 32
    uint64_t carry = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      uint64_t acc =
          (uint64_t)t[i + j] + (uint64_t)u * (uint64_t)p.limb[j] + carry;
      t[i + j] = (UNSIGNED_LIMB)acc;
      carry = acc >> LIMB_BITS;
    }
    // Propagate remaining carry (carry ≤ 2^32-1 at this point)
    int idx = i + FP_LIMBS;
    while (carry != 0 && idx <= 2 * FP_LIMBS) {
      uint64_t acc = (uint64_t)t[idx] + carry;
      t[idx] = (UNSIGNED_LIMB)acc;
      carry = acc >> LIMB_BITS;
      idx++;
    }
#else
    UNSIGNED_LIMB carry = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      UNSIGNED_LIMB hi, lo;
      mul_limbs(u, p.limb[j], hi, lo);

      // Three-way addition: t[i+j] + lo + carry
      UNSIGNED_LIMB temp = t[i + j] + lo;
      UNSIGNED_LIMB carry1 = (temp < t[i + j]) ? 1 : 0;

      UNSIGNED_LIMB sum = temp + carry;
      UNSIGNED_LIMB carry2 = (sum < temp) ? 1 : 0;

      t[i + j] = sum;

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
#endif
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

// PTX-accelerated CIOS Montgomery multiplication (device path)

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
#define LIMB_MACC(t_j, carry, a_j, b_i)                                        \
  asm volatile("{\n\t"                                                         \
               ".reg .u64 _lo, _hi;\n\t"                                       \
               "mul.lo.u64  _lo, %2, %3;\n\t"                                  \
               "mul.hi.u64  _hi, %2, %3;\n\t"                                  \
               "add.cc.u64  %0, %0, _lo;\n\t"                                  \
               "addc.u64    _hi, _hi, 0;\n\t"                                  \
               "add.cc.u64  %0, %0, %1;\n\t"                                   \
               "addc.u64    %1, _hi, 0;\n\t"                                   \
               "}\n\t"                                                         \
               : "+l"(t_j), "+l"(carry)                                        \
               : "l"(a_j), "l"(b_i))

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
#define CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, \
                           a5, a6, b_i, p0, p1, p2, p3, p4, p5, p6, p_prime,   \
                           r0, r1, r2, r3, r4, r5, r6, r7)                     \
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
    asm("add.cc.u64  %0, %0, %2;\n\t"                                          \
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
    /* Finalize overflow: t7 = t7 + _carry + _overflow */                      \
    /* Plain adds (no carry chain) -- the CIOS invariant guarantees this */    \
    /* sum fits in 64 bits so intermediate overflow does not matter. */        \
    t7 += _carry;                                                              \
    t7 += _overflow;                                                           \
                                                                               \
    /* Step 4: Shift right by one limb via register renaming */                \
    /* t0 is now zero (by construction of m), discard it */                    \
    r0 = t1;                                                                   \
    r1 = t2;                                                                   \
    r2 = t3;                                                                   \
    r3 = t4;                                                                   \
    r4 = t5;                                                                   \
    r5 = t6;                                                                   \
    r6 = t7;                                                                   \
    r7 = 0;                                                                    \
  } while (0)

__device__ __noinline__ void fp_mont_mul_cios_ptx(Fp &c, const Fp &a,
                                                  const Fp &b) {
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

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6,
                     b.limb[0], p0, p1, p2, p3, p4, p5, p6, pp, t0, t1, t2, t3,
                     t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6,
                     b.limb[1], p0, p1, p2, p3, p4, p5, p6, pp, t0, t1, t2, t3,
                     t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6,
                     b.limb[2], p0, p1, p2, p3, p4, p5, p6, pp, t0, t1, t2, t3,
                     t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6,
                     b.limb[3], p0, p1, p2, p3, p4, p5, p6, pp, t0, t1, t2, t3,
                     t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6,
                     b.limb[4], p0, p1, p2, p3, p4, p5, p6, pp, t0, t1, t2, t3,
                     t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6,
                     b.limb[5], p0, p1, p2, p3, p4, p5, p6, pp, t0, t1, t2, t3,
                     t4, t5, t6, t7);

  CIOS_ITERATION_PTX(t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6,
                     b.limb[6], p0, p1, p2, p3, p4, p5, p6, pp, t0, t1, t2, t3,
                     t4, t5, t6, t7);

  // Final reduction: if t[0..7] >= p (extended to 8 limbs), subtract p.
  // Compute (t[0..6] - p[0..6]) with borrow, then subtract borrow from t7.
  // If t7 after subtraction is non-negative, the reduced result is valid;
  // otherwise the original t[0..6] is already in [0, p).
  uint64_t r0, r1, r2, r3, r4, r5, r6, mask;
  asm("sub.cc.u64   %0, %8,  %15;\n\t" // r0 = t0 - p0
      "subc.cc.u64  %1, %9,  %16;\n\t" // r1 = t1 - p1 - borrow
      "subc.cc.u64  %2, %10, %17;\n\t" // r2 = t2 - p2 - borrow
      "subc.cc.u64  %3, %11, %18;\n\t" // r3 = t3 - p3 - borrow
      "subc.cc.u64  %4, %12, %19;\n\t" // r4 = t4 - p4 - borrow
      "subc.cc.u64  %5, %13, %20;\n\t" // r5 = t5 - p5 - borrow
      "subc.cc.u64  %6, %14, %21;\n\t" // r6 = t6 - p6 - borrow
      "subc.u64     %7, %22, 0;\n\t"   // mask_src = t7 - 0 - borrow
      "shr.s64      %7, %7, 63;\n\t" // mask = sign-extend: -1 if negative, 0 if
                                     // >= 0
      : "=l"(r0), "=l"(r1), "=l"(r2), "=l"(r3), "=l"(r4), "=l"(r5), "=l"(r6),
        "=l"(mask)
      : "l"(t0), "l"(t1), "l"(t2), "l"(t3), "l"(t4), "l"(t5), "l"(t6), "l"(p0),
        "l"(p1), "l"(p2), "l"(p3), "l"(p4), "l"(p5), "l"(p6), "l"(t7));

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

// 32-bit dual MAD-chain Montgomery multiplication (device path)

#ifdef __CUDA_ARCH__

// PTX carry-chain primitives for 32-bit Montgomery arithmetic.
//
// These are macros rather than __forceinline__ functions because the hardware
// carry flag (CC register) does not survive a function-call boundary
// (lo, hi) = a * b : 64-bit product, no carry in or out.
// Initialises a fresh wide accumulator slot.
#define FP_MUL_WIDE_32(lo, hi, a, b)                                           \
  asm("mul.lo.u32 %0, %2, %3; mul.hi.u32 %1, %2, %3;"                          \
      : "=r"(lo), "=r"(hi)                                                     \
      : "r"(a), "r"(b))

// lo += lo(a*b); hi += hi(a*b) + CC.  Sets CC.
// Opens a carry chain (mad.lo.cc / madc.hi.cc).
#define FP_MAD_WIDE_CC_32(lo, hi, a, b)                                        \
  asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.cc.u32 %1, %2, %3, %1;"           \
      : "+r"(lo), "+r"(hi)                                                     \
      : "r"(a), "r"(b))

// lo += lo(a*b) + CC; hi += hi(a*b) + CC.  Sets CC.
// Continues a carry chain (madc.lo.cc / madc.hi.cc).
#define FP_MADC_WIDE_CC_32(lo, hi, a, b)                                       \
  asm("madc.lo.cc.u32 %0, %2, %3, %0; madc.hi.cc.u32 %1, %2, %3, %1;"          \
      : "+r"(lo), "+r"(hi)                                                     \
      : "r"(a), "r"(b))

// r += CC.  No carry out terminates a carry chain.
#define FP_ADDC_32(r) asm("addc.u32 %0, %0, 0;" : "+r"(r))

// dst = src + CC.  No carry out
#define FP_ADDC_INTO_32(dst, src)                                              \
  asm("addc.u32 %0, %1, 0;" : "=r"(dst) : "r"(src))

// r = CC (capture carry flag as 0 or 1).  No carry out.
#define FP_CARRY_32(r) asm("addc.u32 %0, 0, 0;" : "=r"(r))

// dst = src + src.  Sets CC opens a left-shift doubling chain.
#define FP_DBL_CC_32(dst, src)                                                 \
  asm("add.cc.u32 %0, %1, %1;" : "=r"(dst) : "r"(src))

// r = r + r + CC.  Sets CC continues a left-shift doubling chain.
#define FP_DBLC_CC_32(r) asm("addc.cc.u32 %0, %0, %0;" : "+r"(r))

/// dst = lo32 | (hi32 << 32): pack two 32-bit halves into one 64-bit register.
#define FP_PACK_U64(dst, lo32, hi32)                                           \
  asm("mov.b64 %0, {%1, %2};" : "=l"(dst) : "r"(lo32), "r"(hi32))

// Initialize acc[0..n-1] with products of every other element of a and bi.
// For each j (step 2): acc[j] = lo(a[j]*bi), acc[j+1] = hi(a[j]*bi).
static __device__ __forceinline__ void
fp_mul_n_32(uint32_t *acc, const uint32_t *a, uint32_t bi, int n) {
#pragma unroll
  for (int j = 0; j < n; j += 2) {
    asm("mul.lo.u32 %0, %1, %2;" : "=r"(acc[j]) : "r"(a[j]), "r"(bi));
    asm("mul.hi.u32 %0, %1, %2;" : "=r"(acc[j + 1]) : "r"(a[j]), "r"(bi));
  }
}

// Multiply-accumulate across n limbs with a hardware carry chain.
// First pair uses mad.lo.cc + madc.hi.cc (initiates the chain).
// Remaining pairs continue with madc.lo.cc + madc.hi.cc.
// Carry flag exits in CC on return; caller must consume it.
static __device__ __forceinline__ void
fp_cmad_n_32(uint32_t *acc, const uint32_t *a, uint32_t bi, int n) {
  asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.cc.u32 %1, %2, %3, %1;"
      : "+r"(acc[0]), "+r"(acc[1])
      : "r"(a[0]), "r"(bi));
#pragma unroll
  for (int j = 2; j < n; j += 2)
    asm("madc.lo.cc.u32 %0, %2, %3, %0; madc.hi.cc.u32 %1, %2, %3, %1;"
        : "+r"(acc[j]), "+r"(acc[j + 1])
        : "r"(a[j]), "r"(bi));
  // CC holds the final carry on return
}

// Multiply-accumulate with implicit right-shift of odd by two positions.
// Each pair: odd[j] = lo/hi(a[j]*bi) + old_odd[j+2] + CC.
// Reads are always two positions ahead of writes so forward iteration is safe.
// Final pair terminates the chain with addend=0 and no carry-out (.hi only).
static __device__ __forceinline__ void
fp_madc_n_rshift_32(uint32_t *odd, const uint32_t *a, uint32_t bi, int n) {
#pragma unroll
  for (int j = 0; j < n - 2; j += 2)
    asm("madc.lo.cc.u32 %0, %2, %3, %4; madc.hi.cc.u32 %1, %2, %3, %5;"
        : "=r"(odd[j]), "=r"(odd[j + 1])
        : "r"(a[j]), "r"(bi), "r"(odd[j + 2]), "r"(odd[j + 3]));
  asm("madc.lo.cc.u32 %0, %2, %3, 0; madc.hi.u32 %1, %2, %3, 0;"
      : "=r"(odd[n - 2]), "=r"(odd[n - 1])
      : "r"(a[n - 2]), "r"(bi));
  // Note: final madc.hi.u32 has no .cc so CC is clear on return
}

// After the call even[0] == 0 (by the Montgomery invariant), so the next
// iteration's right-shift effectively advances the window by one limb.
static __device__ __forceinline__ void
fp_mad_n_redc_32(uint32_t *even, uint32_t *odd, const uint32_t *a,
                 const uint32_t *p, uint32_t bi, uint32_t M0, bool first) {
  constexpr int n = 14; // 32-bit limbs for BLS12-446 (446 bits → 14 × 32-bit)

  if (first) {
    // Fresh initialization: no carry from previous iteration.
    // even[2j]   = lo(a[2j]   * bi),  even[2j+1] = hi(a[2j]   * bi)
    // odd[2j]    = lo(a[2j+1] * bi),  odd[2j+1]  = hi(a[2j+1] * bi)
    fp_mul_n_32(even, a, bi, n);
    fp_mul_n_32(odd, a + 1, bi, n);
  } else {
    // Merge carry from previous iteration and advance both accumulators.
    asm("add.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(odd[1]));
    fp_madc_n_rshift_32(odd, a + 1, bi, n);
    fp_cmad_n_32(even, a, bi, n);
    asm("addc.u32 %0, %0, 0;" : "+r"(odd[n - 1]));
  }

  // Montgomery reduction: choose mi so that even[0] + lo(p[0]*mi) = 0 mod 2^32
  uint32_t mi = even[0] * M0;
  fp_cmad_n_32(odd, p + 1, mi, n);
  fp_cmad_n_32(even, p, mi, n);
  asm("addc.u32 %0, %0, 0;" : "+r"(odd[n - 1]));
}

// Carry-add: acc[i] += a[i] for i = 0..n-1 with PTX carry chain.
// Starts with add.cc (initiates chain); all subsequent adds use addc.cc.
// Carry flag is left set in CC on return for the caller to consume.
static __device__ __forceinline__ void fp_cadd_n_32(uint32_t *acc,
                                                    const uint32_t *a, int n) {
  asm("add.cc.u32 %0, %0, %1;" : "+r"(acc[0]) : "r"(a[0]));
#pragma unroll
  for (int i = 1; i < n; i++)
    asm("addc.cc.u32 %0, %0, %1;" : "+r"(acc[i]) : "r"(a[i]));
}

// Even row of the upper-triangle squaring pass.
// Adds a[1..n-2]*bi into odd[0..n-3] (cmad chain), places a[n-1]*bi into
// odd[n-2..n-1] fresh (terminates carry), then adds a[0..n-1]*bi into
// even[0..n-1] (independent cmad chain), folding the even carry into odd[n-1].
static __device__ __forceinline__ void fp_mad_row_32(uint32_t *odd,
                                                     uint32_t *even,
                                                     const uint32_t *a,
                                                     uint32_t bi, int n) {
  fp_cmad_n_32(odd, a + 1, bi, n - 2);
  asm("madc.lo.cc.u32 %0, %2, %3, 0; madc.hi.u32 %1, %2, %3, 0;"
      : "=r"(odd[n - 2]), "=r"(odd[n - 1])
      : "r"(a[n - 1]), "r"(bi));
  fp_cmad_n_32(even, a, bi, n);
  asm("addc.u32 %0, %0, 0;" : "+r"(odd[n - 1]));
}

// Odd row of the upper-triangle squaring pass.
// Adds a[0..n-3]*bi into odd[0..n-3] (cmad chain), places a[n-2]*bi into
// odd[n-2..n-1] fresh, then adds a[1..n-2]*bi into even[0..n-3] (n-2 terms),
// folding the even carry into odd[n-1].
static __device__ __forceinline__ void fp_qad_row_32(uint32_t *odd,
                                                     uint32_t *even,
                                                     const uint32_t *a,
                                                     uint32_t bi, int n) {
  fp_cmad_n_32(odd, a, bi, n - 2);
  asm("madc.lo.cc.u32 %0, %2, %3, 0; madc.hi.u32 %1, %2, %3, 0;"
      : "=r"(odd[n - 2]), "=r"(odd[n - 1])
      : "r"(a[n - 2]), "r"(bi));
  fp_cmad_n_32(even, a + 1, bi, n - 2);
  asm("addc.u32 %0, %0, 0;" : "+r"(odd[n - 1]));
}

// One Montgomery-reduction row without a multiply step (b_i = 0).
// Used by fp_mont_sqr_mad32 to reduce the lower n words of the wide product.
// Mirrors fp_mad_n_redc_32 but omits the initial product accumulation, leaving
// only the annihilation step that drives even[0] to zero.
static __device__ __forceinline__ void
fp_mul_by_1_row_32(uint32_t *even, uint32_t *odd, const uint32_t *p,
                   uint32_t M0, bool first) {
  constexpr int n = 14;
  // mi removes even[0]: even[0] + lo(p[0]*mi) == 0 mod 2^32.
  // IMPORTANT: mi must be computed from even[0] *after* any add.cc that
  // modifies it. Plain integer multiply does not touch CC.
  uint32_t mi;
  if (first) {
    mi = even[0] * M0;
    fp_mul_n_32(odd, p + 1, mi, n);
    fp_cmad_n_32(even, p, mi, n);
    asm("addc.u32 %0, %0, 0;" : "+r"(odd[n - 1]));
  } else {
    // Absorb the shifted carry word from the previous step, then reduce.
    asm("add.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(odd[1]));
    // Use PTX mul explicitly: a plain C multiply after add.cc could in theory
    // let the compiler insert an instruction that clobbers CC before
    // madc_n_rshift.
    asm("mul.lo.u32 %0, %1, %2;" : "=r"(mi) : "r"(even[0]), "r"(M0));
    fp_madc_n_rshift_32(odd, p + 1, mi, n);
    fp_cmad_n_32(even, p, mi, n);
    asm("addc.u32 %0, %0, 0;" : "+r"(odd[n - 1]));
  }
}

// Montgomery squaring using CIOS with triangular 32-bit MAD chains.
// See fp_mont_mul_mad32 for the algorithm reference (Koç et al., 1996).
//
// Computes c = a^2 * R^{-1} mod p (input and output in Montgomery form).
__device__ __noinline__ void fp_mont_sqr_mad32(Fp &c, const Fp &a) {
  constexpr int n = 14;

  const uint32_t *a32 = reinterpret_cast<const uint32_t *>(a.limb);
  const uint32_t *p32 = reinterpret_cast<const uint32_t *>(DEVICE_MODULUS.limb);
  const uint32_t M0 = static_cast<uint32_t>(DEVICE_P_PRIME);

  uint32_t wide[2 * n], wtemp[2 * n - 2];
  // Phase 1: upper triangle a[i]*a[j] for j > i
  fp_mul_n_32(wtemp, a32 + 1, a32[0], n);
  fp_mul_n_32(wide + 2, a32 + 2, a32[0], n - 2);

#pragma unroll
  for (int i = 2; i <= n - 4; i += 2) {
    fp_mad_row_32(&wide[2 * i], &wtemp[2 * i - 2], &a32[i], a32[i - 1], n - i);
    fp_qad_row_32(&wtemp[2 * i], &wide[2 * i + 2], &a32[i + 1], a32[i], n - i);
  }

  FP_MUL_WIDE_32(wide[2 * n - 4], wide[2 * n - 3], a32[n - 1], a32[n - 3]);
  FP_MAD_WIDE_CC_32(wtemp[2 * n - 6], wtemp[2 * n - 5], a32[n - 2], a32[n - 3]);
  FP_ADDC_32(wide[2 * n - 3]);
  FP_MUL_WIDE_32(wtemp[2 * n - 4], wtemp[2 * n - 3], a32[n - 1], a32[n - 2]);

  fp_cadd_n_32(&wide[2], &wtemp[1], 2 * n - 4);
  FP_ADDC_INTO_32(wide[2 * n - 2], wtemp[2 * n - 3]);

  // Phase 2: double the upper-triangle sum (left-shift the 2n-bit value by 1)
  wide[0] = 0;
  FP_DBL_CC_32(wide[1], wtemp[0]);
#pragma unroll
  for (int j = 2; j < 2 * n - 1; j++)
    FP_DBLC_CC_32(wide[j]);
  FP_CARRY_32(wide[2 * n - 1]);

  // Phase 3: add diagonal a[i]^2 terms (squares of each limb)
  FP_MAD_WIDE_CC_32(wide[0], wide[1], a32[0], a32[0]);
#pragma unroll
  for (int i = 1; i < n; i++)
    FP_MADC_WIDE_CC_32(wide[2 * i], wide[2 * i + 1], a32[i], a32[i]);

  // Phase 4: Montgomery reduction
  uint32_t red_odd[n];
#pragma unroll
  for (int i = 0; i < n; i += 2) {
    fp_mul_by_1_row_32(&wide[0], &red_odd[0], p32, M0, i == 0);
    fp_mul_by_1_row_32(&red_odd[0], &wide[0], p32, M0, false);
  }
  // Merge the final red_odd word into wide[0..n-1].
  fp_cadd_n_32(&wide[0], &red_odd[1], n - 1);
  FP_ADDC_32(wide[n - 1]);

  // Add reduced lower half into upper half wide[n..2n-1]; the result lives
  // in wide[n..2n-1] and is in [0, 2p).
  fp_cadd_n_32(&wide[n], &wide[0], n);
  FP_CARRY_32(wide[0]); // discard overflow (always 0 for p<2^446)

#if LIMB_BITS_CONFIG == 64
  // Pack uint32_t pairs back into uint64_t limbs.
#pragma unroll
  for (int j = 0; j < 7; j++)
    FP_PACK_U64(c.limb[j], wide[n + 2 * j], wide[n + 2 * j + 1]);

  const uint64_t p0 = DEVICE_MODULUS.limb[0], p1 = DEVICE_MODULUS.limb[1],
                 p2 = DEVICE_MODULUS.limb[2], p3 = DEVICE_MODULUS.limb[3],
                 p4 = DEVICE_MODULUS.limb[4], p5 = DEVICE_MODULUS.limb[5],
                 p6 = DEVICE_MODULUS.limb[6];
  uint64_t r0, r1, r2, r3, r4, r5, r6, mask64;
  asm("sub.cc.u64   %0, %8,  %15;\n\t"
      "subc.cc.u64  %1, %9,  %16;\n\t"
      "subc.cc.u64  %2, %10, %17;\n\t"
      "subc.cc.u64  %3, %11, %18;\n\t"
      "subc.cc.u64  %4, %12, %19;\n\t"
      "subc.cc.u64  %5, %13, %20;\n\t"
      "subc.cc.u64  %6, %14, %21;\n\t"
      "subc.u64     %7, 0,   0;\n\t"
      "shr.s64      %7, %7,  63;\n\t"
      : "=l"(r0), "=l"(r1), "=l"(r2), "=l"(r3), "=l"(r4), "=l"(r5), "=l"(r6),
        "=l"(mask64)
      : "l"(c.limb[0]), "l"(c.limb[1]), "l"(c.limb[2]), "l"(c.limb[3]),
        "l"(c.limb[4]), "l"(c.limb[5]), "l"(c.limb[6]), "l"(p0), "l"(p1),
        "l"(p2), "l"(p3), "l"(p4), "l"(p5), "l"(p6));
  c.limb[0] = (c.limb[0] & mask64) | (r0 & ~mask64);
  c.limb[1] = (c.limb[1] & mask64) | (r1 & ~mask64);
  c.limb[2] = (c.limb[2] & mask64) | (r2 & ~mask64);
  c.limb[3] = (c.limb[3] & mask64) | (r3 & ~mask64);
  c.limb[4] = (c.limb[4] & mask64) | (r4 & ~mask64);
  c.limb[5] = (c.limb[5] & mask64) | (r5 & ~mask64);
  c.limb[6] = (c.limb[6] & mask64) | (r6 & ~mask64);
#else
#pragma unroll
  for (int j = 0; j < n; j++)
    c.limb[j] = wide[n + j];
  Fp reduced;
  UNSIGNED_LIMB borrow = fp_sub_raw(reduced, c, fp_modulus());
  UNSIGNED_LIMB mask32 = -borrow;
#pragma unroll
  for (int j = 0; j < n; j++)
    c.limb[j] = (c.limb[j] & mask32) | (reduced.limb[j] & ~mask32);
#endif
}

// Montgomery multiplication using CIOS (Coarsely Integrated Operand Scanning):
// Computes c = a * b * R^{-1} mod p (all operands in Montgomery form).
// Inputs are stored as uint64_t[7]; they are reinterpreted as uint32_t[14]
// (little-endian: a64[j] == a32[2j] | (a32[2j+1] << 32)).
__device__ __noinline__ void fp_mont_mul_mad32(Fp &c, const Fp &a,
                                               const Fp &b) {
  constexpr int n = 14;

  // Reinterpret 64-bit limb arrays as 32-bit on little-endian hardware.
  const uint32_t *a32 = reinterpret_cast<const uint32_t *>(a.limb);
  const uint32_t *b32 = reinterpret_cast<const uint32_t *>(b.limb);
  const uint32_t *p32 = reinterpret_cast<const uint32_t *>(DEVICE_MODULUS.limb);

  // 32-bit Montgomery constant: low 32 bits of DEVICE_P_PRIME.
  // Correct because -p^{-1} mod 2^32 == (-p^{-1} mod 2^64) mod 2^32.
  const uint32_t M0 = static_cast<uint32_t>(DEVICE_P_PRIME);

  uint32_t even[n], odd[n];

  // Process every 32-bit limb of b in pairs, alternating primary accumulator.
#pragma unroll
  for (int i = 0; i < n; i += 2) {
    fp_mad_n_redc_32(even, odd, a32, p32, b32[i], M0, i == 0);
    fp_mad_n_redc_32(odd, even, a32, p32, b32[i + 1], M0, false);
  }

  // Merge: even[0..n-2] += odd[1..n-1], propagate final carry into even[n-1].
  fp_cadd_n_32(even, odd + 1, n - 1);
  FP_ADDC_32(even[n - 1]);

  // Pack and final reduction layout depends on LIMB_BITS_CONFIG.
  // In both cases UNSIGNED_LIMB* and uint32_t* point to the same 56-byte block.
#if LIMB_BITS_CONFIG == 64
  // 64-bit limbs: pack pairs into uint64_t with PTX mov.b64, then do a
  // branchless 7-limb 64-bit conditional subtraction.
#pragma unroll
  for (int j = 0; j < 7; j++)
    FP_PACK_U64(c.limb[j], even[2 * j], even[2 * j + 1]);

  // subc.u64 0-0-borrow gives 0xFFFF... when c<p (keep), 0 when c>=p (reduce).
  // shr.s64 sign-extends to a per-bit selection mask.
  const uint64_t p0 = DEVICE_MODULUS.limb[0], p1 = DEVICE_MODULUS.limb[1],
                 p2 = DEVICE_MODULUS.limb[2], p3 = DEVICE_MODULUS.limb[3],
                 p4 = DEVICE_MODULUS.limb[4], p5 = DEVICE_MODULUS.limb[5],
                 p6 = DEVICE_MODULUS.limb[6];
  uint64_t r0, r1, r2, r3, r4, r5, r6, mask64;
  asm("sub.cc.u64   %0, %8,  %15;\n\t"
      "subc.cc.u64  %1, %9,  %16;\n\t"
      "subc.cc.u64  %2, %10, %17;\n\t"
      "subc.cc.u64  %3, %11, %18;\n\t"
      "subc.cc.u64  %4, %12, %19;\n\t"
      "subc.cc.u64  %5, %13, %20;\n\t"
      "subc.cc.u64  %6, %14, %21;\n\t"
      "subc.u64     %7, 0,   0;\n\t"
      "shr.s64      %7, %7,  63;\n\t"
      : "=l"(r0), "=l"(r1), "=l"(r2), "=l"(r3), "=l"(r4), "=l"(r5), "=l"(r6),
        "=l"(mask64)
      : "l"(c.limb[0]), "l"(c.limb[1]), "l"(c.limb[2]), "l"(c.limb[3]),
        "l"(c.limb[4]), "l"(c.limb[5]), "l"(c.limb[6]), "l"(p0), "l"(p1),
        "l"(p2), "l"(p3), "l"(p4), "l"(p5), "l"(p6));
  c.limb[0] = (c.limb[0] & mask64) | (r0 & ~mask64);
  c.limb[1] = (c.limb[1] & mask64) | (r1 & ~mask64);
  c.limb[2] = (c.limb[2] & mask64) | (r2 & ~mask64);
  c.limb[3] = (c.limb[3] & mask64) | (r3 & ~mask64);
  c.limb[4] = (c.limb[4] & mask64) | (r4 & ~mask64);
  c.limb[5] = (c.limb[5] & mask64) | (r5 & ~mask64);
  c.limb[6] = (c.limb[6] & mask64) | (r6 & ~mask64);
#else
#pragma unroll
  for (int j = 0; j < n; j++)
    c.limb[j] = even[j];

  Fp reduced;
  UNSIGNED_LIMB borrow = fp_sub_raw(reduced, c, fp_modulus());
  UNSIGNED_LIMB mask32 = -borrow; // all-ones if c<p (keep), all-zeros if c>=p
#pragma unroll
  for (int j = 0; j < n; j++)
    c.limb[j] = (c.limb[j] & mask32) | (reduced.limb[j] & ~mask32);
#endif
}

#undef FP_MUL_WIDE_32
#undef FP_MAD_WIDE_CC_32
#undef FP_MADC_WIDE_CC_32
#undef FP_ADDC_32
#undef FP_ADDC_INTO_32
#undef FP_CARRY_32
#undef FP_DBL_CC_32
#undef FP_DBLC_CC_32
#undef FP_PACK_U64

#endif // __CUDA_ARCH__

// CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication
// Fuses multiplication and reduction in a single pass for better efficiency.
// Uses only FP_LIMBS+1 limbs of working space instead of 2*FP_LIMBS.
// Both a and b are in Montgomery form, result is in Montgomery form.
__host__ __device__ void fp_mont_mul_cios(Fp &c, const Fp &a, const Fp &b) {
#ifdef __CUDA_ARCH__
  // Device path: 32-bit dual MAD chain
  fp_mont_mul_mad32(c, a, b);
#else
  // Host path: portable C++ implementation
  const Fp &p = fp_modulus();
  UNSIGNED_LIMB p_prime = fp_p_prime();

  // Working array: only n+1 limbs needed (vs 2n for separate mul+reduce)
  UNSIGNED_LIMB t[FP_LIMBS + 1];
  // memset is not guaranteed available in all device compilation contexts;
  // use an explicit loop which the compiler will unroll anyway.
#ifdef __CUDA_ARCH__
  for (int i = 0; i <= FP_LIMBS; i++) {
    t[i] = 0;
  }
#else
  memset(t, 0, (FP_LIMBS + 1) * sizeof(UNSIGNED_LIMB));
#endif

  // Main CIOS loop: for each limb of b
  for (int i = 0; i < FP_LIMBS; i++) {
    // Step 1: Multiply-accumulate t += a * b[i]
#if LIMB_BITS_CONFIG == 32
    uint64_t carry64 = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      uint64_t acc =
          (uint64_t)t[j] + (uint64_t)a.limb[j] * (uint64_t)b.limb[i] + carry64;
      t[j] = (UNSIGNED_LIMB)acc;
      carry64 = acc >> LIMB_BITS;
    }
    uint64_t sum64 = (uint64_t)t[FP_LIMBS] + carry64;
    UNSIGNED_LIMB overflow = (UNSIGNED_LIMB)(sum64 >> LIMB_BITS);
    t[FP_LIMBS] = (UNSIGNED_LIMB)sum64;
#else
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

      carry = hi + c1 + c2;
    }
    UNSIGNED_LIMB sum = t[FP_LIMBS] + carry;
    UNSIGNED_LIMB overflow = (sum < t[FP_LIMBS]) ? 1 : 0;
    t[FP_LIMBS] = sum;
#endif

    // Step 2: Reduction - compute m = t[0] * p' mod 2^LIMB_BITS
    UNSIGNED_LIMB m = t[0] * p_prime;

    // Add m * p to t (this zeros out t[0])
#if LIMB_BITS_CONFIG == 32
    carry64 = 0;
    for (int j = 0; j < FP_LIMBS; j++) {
      uint64_t acc =
          (uint64_t)t[j] + (uint64_t)m * (uint64_t)p.limb[j] + carry64;
      t[j] = (UNSIGNED_LIMB)acc;
      carry64 = acc >> LIMB_BITS;
    }
    // Merge carry from reduction with the overflow from step 1.
    // sum64 ≤ (2^32-1) + (2^32-1) + 1 = 2^33-1, so the new overflow is 0 or 1.
    uint64_t s64 = (uint64_t)t[FP_LIMBS] + carry64 + (uint64_t)overflow;
    t[FP_LIMBS] = (UNSIGNED_LIMB)s64;
    overflow = (UNSIGNED_LIMB)(s64 >> LIMB_BITS);
#else
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
#endif

    // Step 3: Shift right by one limb (divide by 2^LIMB_BITS)
    // t[0..n-1] = t[1..n], t[n] = overflow
    for (int j = 0; j < FP_LIMBS; j++) {
      t[j] = t[j + 1];
    }
    t[FP_LIMBS] = overflow;
  }

  // Copy result to output
#ifdef __CUDA_ARCH__
  for (int i = 0; i < FP_LIMBS; i++) {
    c.limb[i] = t[i];
  }
#else
  memcpy(&c.limb[0], t, FP_LIMBS * sizeof(UNSIGNED_LIMB));
#endif

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

// Montgomery squaring: c = (a^2 * R_INV) mod p
// Input and output in Montgomery form.
// On device: uses fp_mont_sqr_mad32 (triangular MAD chain, ~30-40% fewer
// multiplications than fp_mont_mul(c, a, a)).
// On host: delegates to fp_mont_mul_cios(c, a, a).
__host__ __device__ void fp_mont_sqr(Fp &c, const Fp &a) {
#ifdef __CUDA_ARCH__
  fp_mont_sqr_mad32(c, a);
#else
  fp_mont_mul_cios(c, a, a);
#endif
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
      // Square result using the optimised squaring path
      Fp temp;
      fp_mont_sqr(temp, result);
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
  fp_mont_sqr(c_squared_mont, c_mont);

  if (fp_cmp(c_squared_mont, a_mont) == ComparisonType::Equal) {
    return true;
  }

  // Try the other square root: p - c
  Fp alt_c, alt_c_mont;
  fp_sub(alt_c, p, c);
  fp_to_montgomery(alt_c_mont, alt_c);
  fp_mont_sqr(c_squared_mont, alt_c_mont);
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
    fp_mont_sqr(c_squared_mont, reduced_c_mont);
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
