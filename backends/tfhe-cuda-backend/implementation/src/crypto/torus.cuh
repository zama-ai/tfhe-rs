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
  // The ull intrinsic does not behave in the same way on all architectures and
  // on some platforms this causes the cmux tree test to fail
  // Hence the intrinsic is not used here
  uint128 nnnn = make_uint128_from_float(x);
  uint64_t lll = nnnn.lo_;
  r = lll;
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
__device__ __forceinline__ void rescale_torus_element(T element, T &output,
                                                      uint32_t log_shift) {
  output =
      round((double)element / (double(std::numeric_limits<T>::max()) + 1.0) *
            (double)log_shift);
}

template <typename T>
__device__ __forceinline__ T rescale_torus_element(T element,
                                                   uint32_t log_shift) {
  return round((double)element / (double(std::numeric_limits<T>::max()) + 1.0) *
               (double)log_shift);
}

template <>
__device__ __forceinline__ void
rescale_torus_element<uint32_t>(uint32_t element, uint32_t &output,
                                uint32_t log_shift) {
  output =
      round(__uint2double_rn(element) /
            (__uint2double_rn(std::numeric_limits<uint32_t>::max()) + 1.0) *
            __uint2double_rn(log_shift));
}

template <>
__device__ __forceinline__ void
rescale_torus_element<uint64_t>(uint64_t element, uint64_t &output,
                                uint32_t log_shift) {
  output = round(__ull2double_rn(element) /
                 (__ull2double_rn(std::numeric_limits<uint64_t>::max()) + 1.0) *
                 __uint2double_rn(log_shift));
}
#endif // CNCRT_TORUS_H
