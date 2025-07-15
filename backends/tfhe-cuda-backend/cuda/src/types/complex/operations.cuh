#ifndef GPU_BOOTSTRAP_COMMON_CUH
#define GPU_BOOTSTRAP_COMMON_CUH

#include <cstdint>
#include <cstdio>

using sTorus = int32_t;
using u32 = uint32_t;
using i32 = int32_t;

//--------------------------------------------------
// Basic double2 operations

__device__ inline double2 conjugate(const double2 num) {
  return {num.x, -num.y};
}

__device__ inline void operator+=(double2 &lh, const double2 rh) {
  lh.x = __dadd_rn(lh.x, rh.x);
  lh.y = __dadd_rn(lh.y, rh.y);
}

__device__ inline void operator-=(double2 &lh, const double2 rh) {
  lh.x = __dsub_rn(lh.x, rh.x);
  lh.y = __dsub_rn(lh.y, rh.y);
}

__device__ inline double2 operator+(const double2 a, const double2 b) {
  return {__dadd_rn(a.x, b.x), __dadd_rn(a.y, b.y)};
}

__device__ inline double2 operator-(const double2 a, const double2 b) {
  return {__dsub_rn(a.x, b.x), __dsub_rn(a.y, b.y)};
}

// Fused multiply-add/subtract for complex multiplication
__device__ inline double2 operator*(const double2 a, const double2 b) {
  return {
      __fma_rn(a.x, b.x,
               -__dmul_rn(a.y, b.y)), // Real part: a.x * b.x - a.y * b.y
      __fma_rn(a.x, b.y,
               __dmul_rn(a.y, b.x)) // Imaginary part: a.x * b.y + a.y * b.x
  };
}

// Fused complex multiplication assignment (avoiding temporary storage)
__device__ inline void operator*=(double2 &a, const double2 b) {
  double real = __fma_rn(a.x, b.x, -__dmul_rn(a.y, b.y));
  a.y = __fma_rn(
      a.x, b.y,
      __dmul_rn(a.y,
                b.x)); // Update imag first to prevent register reuse issues
  a.x = real;
}

__device__ inline double2 operator*(const double2 a, double b) {
  return {__dmul_rn(a.x, b), __dmul_rn(a.y, b)};
}

// Direct multiplication with scalar
__device__ inline void operator*=(double2 &a, const double b) {
  a.x = __dmul_rn(a.x, b);
  a.y = __dmul_rn(a.y, b);
}

// Fused division (could be improved with reciprocal if division is frequent)
__device__ inline void operator/=(double2 &a, const double b) {
  double inv_b = __drcp_rn(b); // Use reciprocal for faster division
  a.x = __dmul_rn(a.x, inv_b);
  a.y = __dmul_rn(a.y, inv_b);
}

__device__ inline double2 operator*(double a, double2 b) {
  return {__dmul_rn(b.x, a), __dmul_rn(b.y, a)};
}

__device__ inline double2 shfl_xor_double2(double2 val, int laneMask,
                                           unsigned mask = 0xFFFFFFFF) {
  double lo = __shfl_xor_sync(mask, val.x, laneMask);
  double hi = __shfl_xor_sync(mask, val.y, laneMask);

  return make_double2(lo, hi);
}
#endif
