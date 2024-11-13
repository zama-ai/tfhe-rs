#ifndef CNCRT_TORUS_CUH
#define CNCRT_TORUS_CUH

#include "device.h"
#include "polynomial/parameters.cuh"
#include "types/int128.cuh"
#include "utils/kernel_dimensions.cuh"
#include <limits>

template <typename T>
__host__ __device__ __forceinline__ constexpr double get_two_pow_torus_bits() {
  return (sizeof(T) == 4) ? 4294967296.0 : 18446744073709551616.0;
}

template <typename T>
__host__ __device__ __forceinline__ constexpr T scalar_max() {
  return std::numeric_limits<T>::max();
}

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
__device__ inline void typecast_double_round_to_torus(double x, T &r) {
  constexpr double mx = get_two_pow_torus_bits<T>();
  // floor must be used here because round has an issue with rounding .5,
  // as it rounds away from zero.
  double frac = x - floor(x);
  frac *= mx;
  typecast_double_to_torus(round(frac), r);
}

template <typename T>
__device__ inline void typecast_torus_to_double(T x, double &r);

template <>
__device__ inline void typecast_torus_to_double<uint32_t>(uint32_t x,
                                                          double &r) {
  r = __int2double_rn(x);
}

template <>
__device__ inline void typecast_torus_to_double<uint64_t>(uint64_t x,
                                                          double &r) {
  r = __ll2double_rn(x);
}

template <typename T>
__device__ inline T init_decomposer_state(T input, uint32_t base_log,
                                          uint32_t level_count) {
  const T rep_bit_count = level_count * base_log;
  const T non_rep_bit_count = sizeof(T) * 8 - rep_bit_count;
  T res = input >> (non_rep_bit_count - 1);
  T rounding_bit = res & (T)(1);
  res++;
  res >>= 1;
  T torus_max = scalar_max<T>();
  T mod_mask = torus_max >> non_rep_bit_count;
  res &= mod_mask;
  T shifted_random = rounding_bit << (rep_bit_count - 1);
  T need_balance =
      (((res - (T)(1)) | shifted_random) & res) >> (rep_bit_count - 1);
  return res - (need_balance << rep_bit_count);
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

template <typename Torus>
__global__ void modulus_switch_inplace(Torus *array, int size,
                                       uint32_t log_modulus) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  if (tid < size) {
    array[tid] = modulus_switch(array[tid], log_modulus);
  }
}

template <typename Torus>
__host__ void host_modulus_switch_inplace(cudaStream_t stream,
                                          uint32_t gpu_index, Torus *array,
                                          int size, uint32_t log_modulus) {
  cudaSetDevice(gpu_index);

  int num_threads = 0, num_blocks = 0;
  getNumBlocksAndThreads(size, 1024, num_blocks, num_threads);

  modulus_switch_inplace<<<num_blocks, num_threads, 0, stream>>>(array, size,
                                                                 log_modulus);
  check_cuda_error(cudaGetLastError());
}

#endif // CNCRT_TORUS_H
