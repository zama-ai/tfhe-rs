#ifndef CNCRT_TORUS_CUH
#define CNCRT_TORUS_CUH

#include "types/int128.cuh"
#include "utils/kernel_dimensions.cuh"
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
  uint128 nnnn = make_uint128_from_float(x);
  uint64_t lll = nnnn.lo_;
  r = lll;
}

template <typename T>
__device__ inline void typecast_double_round_to_torus(double x, T &r) {
  double mx = (sizeof(T) == 4) ? 4294967296.0 : 18446744073709551616.0;
  double frac = x - floor(x);
  frac *= mx;
  typecast_double_to_torus(frac, r);
}

template <typename T>
__device__ inline T round_to_closest_multiple(T x, uint32_t base_log,
                                              uint32_t level_count) {
  const T non_rep_bit_count = sizeof(T) * 8 - level_count * base_log;
  const T shift = non_rep_bit_count - 1;
  T res = x >> shift;
  res += 1;
  res &= (T)(-2);
  return res << shift;
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
