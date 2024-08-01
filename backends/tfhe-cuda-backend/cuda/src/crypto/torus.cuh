#ifndef CNCRT_TORUS_CUH
#define CNCRT_TORUS_CUH

#include "types/int128.cuh"
#include <limits>

template <typename T>
__device__ inline void typecast_double_to_torus(double x, T &r) {
  r = T(x);
}

template <>
__device__ inline void typecast_double_to_torus<uint32_t>(double x,
                                                          uint32_t &r) {
  r = __double2uint_rn(x);
}

template <>
__device__ inline void typecast_double_to_torus<uint64_t>(double x,
                                                          uint64_t &r) {
  uint64_t x_bits = *((uint64_t const *)(&x));

  uint64_t biased_exp = (x_bits >> 52) & 0x7FF;

  int exp = int(biased_exp) - 1023;
  int shift = exp - 52;

  uint64_t mantissa = x_bits & ((uint64_t(1) << 52) - 1);
  mantissa |= (uint64_t(1) << 52);

  shift = shift < -63 ? -63 : shift;
  shift = shift > 63 ? 63 : shift;
  bool positive = shift >= 0;
  shift = positive ? shift : (-1 - shift);

  uint64_t left_shift = mantissa << shift;
  uint64_t right_shift = mantissa >> shift;
  right_shift += right_shift & 1;
  right_shift >>= 1;

  mantissa = positive ? left_shift : right_shift;
  r = mantissa;
}

template <typename T>
__device__ inline void typecast_double_round_to_torus(double x, T &r) {
  double mx = (sizeof(T) == 4) ? 4294967296.0 : 18446744073709551616.0;
  double frac = x - floor(x);
  frac *= mx;
  typecast_double_to_torus(frac, r);
}

template <>
__device__ inline void typecast_double_round_to_torus<uint64_t>(double x,
                                                                uint64_t &r) {
  uint64_t x_bits = *((uint64_t const *)(&x));

  uint64_t biased_exp = (x_bits >> 52) & 0x7FF;
  bool sign = x_bits >> 63 != 0;

  int exp = int(biased_exp) + (64 - 1023);
  int shift = exp - 52;

  uint64_t mantissa = x_bits & ((uint64_t(1) << 52) - 1);
  mantissa |= (uint64_t(1) << 52);

  shift = shift < -63 ? -63 : shift;
  shift = shift > 63 ? 63 : shift;
  bool positive = shift >= 0;
  shift = positive ? shift : (-1 - shift);

  uint64_t left_shift = mantissa << shift;
  uint64_t right_shift = mantissa >> shift;
  right_shift += right_shift & 1;
  right_shift >>= 1;

  mantissa = positive ? left_shift : right_shift;
  r = sign ? -mantissa : mantissa;
}

template <typename T>
__device__ inline T round_to_closest_multiple(T x, uint32_t base_log,
                                              uint32_t level_count) {
  T shift = sizeof(T) * 8 - level_count * base_log;
  T mask = 1ll << (shift - 1);
  T b = (x & mask) >> (shift - 1);
  T res = x >> shift;
  res += b;
  res <<= shift;
  return res;
}

template <typename T>
__device__ __forceinline__ void modulus_switch(T input, T &output,
                                               uint32_t log_modulus) {
  constexpr uint32_t BITS = sizeof(T) * 8;

  output = input + (((T)1) << (BITS - log_modulus - 1));
  output >>= (BITS - log_modulus);
}

template <typename T>
__device__ __forceinline__ T modulus_switch(T input, uint32_t log_modulus) {
  T output;
  modulus_switch(input, output, log_modulus);
  return output;
}

#endif // CNCRT_TORUS_H
