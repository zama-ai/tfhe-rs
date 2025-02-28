#ifndef CNCRT_TORUS_CUH
#define CNCRT_TORUS_CUH

#include "ciphertext.h"
#include "device.h"
#include "helper_multi_gpu.h"
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
  cuda_set_device(gpu_index);

  int num_threads = 0, num_blocks = 0;
  getNumBlocksAndThreads(size, 1024, num_blocks, num_threads);

  modulus_switch_inplace<Torus>
      <<<num_blocks, num_threads, 0, stream>>>(array, size, log_modulus);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__device__ __forceinline__ double round_error_double(T input,
                                                     uint32_t log_modulus) {
  T rounded;
  constexpr uint32_t BITS = sizeof(T) * 8;
  modulus_switch<T>(input, rounded, log_modulus);
  rounded <<= (BITS - log_modulus);
  rounded -= input;
  return __ll2double_rn((int64_t)rounded);
}

template <typename T>
__device__ __forceinline__ double measure_modulus_switch_noise(
    T input1, T input2, uint32_t log_modulus, uint32_t lwe_size,
    double *sum_mask_errors, double *sum_squared_mask_errors, double *body,
    double input_variance, double r_sigma, double bound) {

  double input_double1 = round_error_double<T>(input1, log_modulus);
  double input_double2 = round_error_double<T>(input2, log_modulus);

  if (threadIdx.x + blockDim.x == lwe_size - 1) {
    body[0] = input_double2;
  }
  // Here we are assuming that lwe is at least 512 so all threads will work
  sum_mask_errors[threadIdx.x] = input_double1;
  sum_squared_mask_errors[threadIdx.x] = input_double1 * input_double1;

  if (threadIdx.x + blockDim.x < lwe_size - 1) {
    sum_mask_errors[threadIdx.x] += input_double2;
    sum_squared_mask_errors[threadIdx.x] += input_double2 * input_double2;
  }

  // We need to perform a reduction to get the expectancy and variance
  for (int offset = blockDim.x / 2; offset > 0; offset /= 2) {
    __syncthreads();
    if (threadIdx.x < offset) {
      sum_mask_errors[threadIdx.x] += sum_mask_errors[threadIdx.x + offset];
      sum_squared_mask_errors[threadIdx.x] +=
          sum_squared_mask_errors[threadIdx.x + offset];
    }
  }

  // Thread 0 has the sum of the mask errors and calculates the noise
  double noise = 0;
  if (threadIdx.x == 0) {
    double expectancy = body[threadIdx.x] - sum_mask_errors[threadIdx.x] / 2.0f;
    double variance = sum_squared_mask_errors[threadIdx.x] / 4.0f;
    double std_dev = sqrt(variance + input_variance);
    noise = abs(expectancy) + std_dev * r_sigma;
  }
  __syncthreads();
  return noise; // only thread 0 will return the correct noise
}

// Each thread processes two elements of the lwe array
template <typename Torus>
__global__ void
improve_noise_modulus_switch(Torus *array_out, const Torus *array_in,
                             const Torus *zeros, int lwe_size, int num_zeros,
                             double input_variance, double r_sigma,
                             double bound, uint32_t log_modulus) {

  // First we will assume size is less than the number of threads per block
  // I should switch this to dynamic shared memory
  __shared__ double sum_mask_errors[512];
  __shared__ double sum_squared_mask_errors[512];
  __shared__ double body[1];
  __shared__ bool found;

  // We need to initialize the shared memory
  if (threadIdx.x == 0)
    found = false;
  __syncthreads();
  // This probably are not needed cause we are setting the values
  sum_mask_errors[threadIdx.x] = 0.f;
  sum_squared_mask_errors[threadIdx.x] = 0.f;

  Torus input_element1 = array_in[threadIdx.x + blockIdx.x * lwe_size];

  Torus input_element2 =
      threadIdx.x + blockDim.x < lwe_size
          ? array_in[threadIdx.x + blockDim.x + blockIdx.x * lwe_size]
          : 0;

  // Base noise is only handled by thread 0
  double base_noise = measure_modulus_switch_noise<Torus>(
      input_element1, input_element2, log_modulus, lwe_size, sum_mask_errors,
      sum_squared_mask_errors, body, input_variance, r_sigma, bound);

  // If the noise is less than the bound we can just copy the input
  if (base_noise <= bound && threadIdx.x == 0) {
    found = true;
  }
  __syncthreads();

  if (found)
    array_out[threadIdx.x + blockIdx.x * lwe_size] = input_element1;

  if (found && (threadIdx.x + blockDim.x) < lwe_size)
    array_out[threadIdx.x + blockDim.x + blockIdx.x * lwe_size] =
        input_element2;

  __syncthreads();
  // If we found a zero element we stop iterating (in avg 20 times are
  // required)
  if (found)
    return;

  // Now we need to start testing the other zero_elements
  for (int index = 0; index < num_zeros; index++) {

    Torus zero_element1 =
        zeros[threadIdx.x + index * lwe_size] + input_element1;
    Torus zero_element2 =
        threadIdx.x + blockDim.x < lwe_size
            ? zeros[threadIdx.x + blockDim.x + index * lwe_size] +
                  input_element2
            : 0;
    // Index noise is only handled by thread 0
    // Measuring the potential noise is costly cause requires a reduction
    double index_noise = measure_modulus_switch_noise<Torus>(
        zero_element1, zero_element2, log_modulus, lwe_size, sum_mask_errors,
        sum_squared_mask_errors, body, input_variance, r_sigma, bound);

    if (index_noise <= bound && threadIdx.x == 0) {
      found = true;
    }
    __syncthreads();
    // Assumption we always have at least 512 elements
    // If we find a useful zero encryption we replace the lwe by lwe + zero
    if (found)
      array_out[threadIdx.x + blockIdx.x * lwe_size] = zero_element1;

    if (found && (threadIdx.x + blockDim.x) < lwe_size)
      array_out[threadIdx.x + blockDim.x + blockIdx.x * lwe_size] =
          zero_element2;

    __syncthreads();
    // If we found a zero element we stop iterating (in avg 20 times are
    // required)
    if (found)
      return;
  }
}

template <typename Torus>
__host__ void host_improve_noise_modulus_switch(
    cudaStream_t stream, uint32_t gpu_index, Torus *array_out,
    Torus const *array_in, const Torus *zeros, uint32_t lwe_size,
    uint32_t num_lwes, const uint32_t num_zeros, const double input_variance,
    const double r_sigma, const double bound, uint32_t log_modulus) {

  if (lwe_size < 512) {
    PANIC("The lwe_size is less than 512, this is not supported\n");
    return;
  }

  if (lwe_size > 1024) {
    PANIC("The lwe_size is greater than 1024, this is not supported\n");
    return;
  }
  cuda_set_device(gpu_index);

  // This reduction requires a power of two num of threads
  int num_threads = 512, num_blocks = num_lwes;

  improve_noise_modulus_switch<Torus><<<num_blocks, num_threads, 0, stream>>>(
      array_out, array_in, zeros, lwe_size, num_zeros, input_variance, r_sigma,
      bound, log_modulus);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, class params>
__device__ uint32_t calculates_monomial_degree(const Torus *lwe_array_group,
                                               uint32_t ggsw_idx,
                                               uint32_t grouping_factor) {
  Torus x = 0;
  for (int i = 0; i < grouping_factor; i++) {
    uint32_t mask_position = grouping_factor - (i + 1);
    int selection_bit = (ggsw_idx >> mask_position) & 1;
    x += selection_bit * lwe_array_group[i];
  }

  return modulus_switch(x, params::log2_degree + 1);
}

template <typename Torus, class params>
__global__ void
modulus_switch_multi_bit(Torus *array_out, const Torus *array_in, int size,
                         uint32_t log_modulus, uint32_t grouping_factor) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  if (tid < size) {
    int num_monomials = 1 << grouping_factor;
    int input_offset = tid * grouping_factor;
    int output_offset = tid * (num_monomials - 1); // First monomial is skipped
    for (int ggsw_idx = 1; ggsw_idx < num_monomials; ggsw_idx++) {
      array_out[ggsw_idx - 1 + output_offset] =
          calculates_monomial_degree<Torus, params>(&array_in[input_offset],
                                                    ggsw_idx, grouping_factor);
    }
  }
}

template <typename Torus>
__host__ void host_modulus_switch_multi_bit(
    cudaStream_t stream, uint32_t gpu_index, Torus *array_out, Torus *array_in,
    int size, uint32_t log_modulus, uint32_t degree, uint32_t grouping_factor) {
  cudaSetDevice(gpu_index);
  int multibit_size = size / grouping_factor;
  int num_threads = 0, num_blocks = 0;
  getNumBlocksAndThreads(multibit_size, 1024, num_blocks, num_threads);
  switch (degree) {
  case 256:
    modulus_switch_multi_bit<Torus, Degree<256>>
        <<<num_blocks, num_threads, 0, stream>>>(
            array_out, array_in, multibit_size, log_modulus, grouping_factor);
    break;
  case 512:
    modulus_switch_multi_bit<Torus, Degree<512>>
        <<<num_blocks, num_threads, 0, stream>>>(
            array_out, array_in, multibit_size, log_modulus, grouping_factor);
    break;
  case 1024:
    modulus_switch_multi_bit<Torus, Degree<1024>>
        <<<num_blocks, num_threads, 0, stream>>>(
            array_out, array_in, multibit_size, log_modulus, grouping_factor);
    break;
  case 2048:
    modulus_switch_multi_bit<Torus, Degree<2048>>
        <<<num_blocks, num_threads, 0, stream>>>(
            array_out, array_in, multibit_size, log_modulus, grouping_factor);
    break;
  case 4096:
    modulus_switch_multi_bit<Torus, Degree<4096>>
        <<<num_blocks, num_threads, 0, stream>>>(
            array_out, array_in, multibit_size, log_modulus, grouping_factor);
    break;
  case 8192:
    modulus_switch_multi_bit<Torus, Degree<8192>>
        <<<num_blocks, num_threads, 0, stream>>>(
            array_out, array_in, multibit_size, log_modulus, grouping_factor);
    break;
  case 16384:
    modulus_switch_multi_bit<Torus, Degree<16384>>
        <<<num_blocks, num_threads, 0, stream>>>(
            array_out, array_in, multibit_size, log_modulus, grouping_factor);
    break;
  default:
    PANIC("Cuda error: unsupported polynomial size. Supported "
          "N's are powers of two in the interval [256..16384].")
  };

  check_cuda_error(cudaGetLastError());
}

#endif // CNCRT_TORUS_H
