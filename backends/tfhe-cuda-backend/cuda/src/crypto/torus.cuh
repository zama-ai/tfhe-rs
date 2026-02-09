#ifndef CNCRT_TORUS_CUH
#define CNCRT_TORUS_CUH

#include "ciphertext.h"
#include "device.h"
#include "helper_multi_gpu.h"
#include "polynomial/parameters.cuh"
#include "types/int128.cuh"
#include "utils/helper.cuh"
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

template <>
__device__ inline void typecast_torus_to_double<__uint128_t>(__uint128_t x,
                                                             double &r) {
  // We truncate x
  r = __ll2double_rn(static_cast<uint64_t>(x));
}

// Helper to get signed integer type corresponding to Torus type at compile time
template <typename Torus> struct signed_torus_type {
  using clean_t = std::remove_cv_t<Torus>;

  // Compile time check:
  static_assert(std::is_same<clean_t, uint32_t>::value ||
                    std::is_same<clean_t, uint64_t>::value ||
                    std::is_same<clean_t, __uint128_t>::value,
                "Torus must be uint32_t, uint64_t, or __uint128_t");

  // Type alias (only one will activate)
  using type = typename std::conditional<
      std::is_same<clean_t, uint32_t>::value, int32_t,
      typename std::conditional<std::is_same<clean_t, uint64_t>::value, int64_t,
                                __int128_t // fallback: we're assuming
                                           // __uint128_t -> __int128_t
                                >::type>::type;
};
template <typename Torus>
using signed_torus_t = typename signed_torus_type<Torus>::type;

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

template <typename T, uint32_t base_log, uint32_t level_count>
__device__ inline T init_decomposer_state_2_2_params(T input) {
  constexpr T rep_bit_count = level_count * base_log;
  constexpr T non_rep_bit_count = sizeof(T) * 8 - rep_bit_count;
  T res = input >> (non_rep_bit_count - 1);
  T rounding_bit = res & (T)(1);
  res++;
  res >>= 1;
  constexpr T torus_max = scalar_max<T>();
  constexpr T mod_mask = torus_max >> non_rep_bit_count;
  res &= mod_mask;
  T shifted_random = rounding_bit << (rep_bit_count - 1);
  T need_balance =
      (((res - (T)(1)) | shifted_random) & res) >> (rep_bit_count - 1);
  return res - (need_balance << rep_bit_count);
}

template <typename T>
__device__ __forceinline__ void modulus_switch(const T input, T &output,
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

template <typename Torus>
__global__ void modulus_switch_inplace(Torus *array, uint32_t size,
                                       uint32_t log_modulus) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  if (tid < size) {
    array[tid] = modulus_switch(array[tid], log_modulus);
  }
}
// Applies the modulus switch on a single LWE
template <typename Torus>
__host__ void host_modulus_switch_inplace(cudaStream_t stream,
                                          uint32_t gpu_index, Torus *array,
                                          uint32_t size, uint32_t log_modulus) {
  cuda_set_device(gpu_index);

  int num_threads = 0, num_blocks = 0;
  getNumBlocksAndThreads(size, 1024, num_blocks, num_threads);
  modulus_switch_inplace<Torus>
      <<<num_blocks, num_threads, 0, stream>>>(array, size, log_modulus);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__global__ void modulus_switch(Torus *output, const Torus *input, uint32_t size,
                               uint32_t log_modulus) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  if (tid < size) {
    output[tid] = modulus_switch(input[tid], log_modulus);
  }
}
// Applies the modulus switch on a single LWE
template <typename Torus>
__host__ void host_modulus_switch(cudaStream_t stream, uint32_t gpu_index,
                                  Torus *output, const Torus *input,
                                  uint32_t size, uint32_t log_modulus) {
  cuda_set_device(gpu_index);

  int num_threads = 0, num_blocks = 0;
  getNumBlocksAndThreads(size, 1024, num_blocks, num_threads);

  modulus_switch<Torus><<<num_blocks, num_threads, 0, stream>>>(
      output, input, size, log_modulus);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__device__ __forceinline__ T round_error(T input, uint32_t log_modulus) {
  T rounded;
  constexpr uint32_t BITS = sizeof(T) * 8;
  modulus_switch<T>(input, rounded, log_modulus);
  rounded <<= (BITS - log_modulus);
  rounded -= input;
  return rounded;
}

// This method is based on rust's
// core_crypto::centered_binary_ms_body_correction_to_add()
template <typename T>
__device__ T centered_binary_modulus_switch_body_correction_to_add(
    const T *lwe, const uint32_t lwe_dimension, const uint32_t log_modulus) {
  T sum_half_mask_round_errors = 0;
  signed_torus_t<T> sum_halving_errors_doubled = 0;
  constexpr auto TWO = static_cast<signed_torus_t<T>>(2);

  for (auto i = 0; i < lwe_dimension; i++) {
    auto error = round_error(lwe[i], log_modulus);
    auto signed_error = static_cast<signed_torus_t<T>>(error);
    auto half_error = signed_error / TWO;

    // Dividing by 2 can add an error where |error| <= 1/2 in each run of the
    // loop. Combined, they can add up to more than 1 (in the mod 2^64 torus)
    // Thus we compute this combined error to reduce it to less than 1/2
    // half_error = half_error_theoretical + halving_error_doubled/2
    // where half_error_theoretical * 2 = signed_error
    auto halving_error_doubled = (half_error * TWO) - signed_error;

    sum_half_mask_round_errors += static_cast<T>(half_error);
    sum_halving_errors_doubled += halving_error_doubled;
  }

  auto sum_halving_errors = static_cast<T>(sum_halving_errors_doubled / TWO);

  // sum(half_error_theoretical) = sum(half_error) -
  // sum(halving_error_doubled)/2
  sum_half_mask_round_errors -= sum_halving_errors;

  constexpr uint32_t BITS = sizeof(T) * 8;
  auto half_case = static_cast<T>(1) << (BITS - log_modulus - 1);

  // E(e_MMS) = - sum(mask_round_error / 2)
  // body_centered = body_input - E(e_MMS) - half_case
  // body_centered = body_input + sum(mask_round_error / 2) - half_case
  // body_correction_to_add = sum(mask_round_error / 2) - half_case
  return sum_half_mask_round_errors - half_case;
}

template <typename Torus>
__global__ void centered_modulus_switch(Torus *output, const Torus *input,
                                        uint32_t lwe_dimension,
                                        uint32_t log_modulus) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;

  if (tid == lwe_dimension) {
    auto correction = centered_binary_modulus_switch_body_correction_to_add(
        input, lwe_dimension, log_modulus);

    auto body = input[lwe_dimension];
    output[lwe_dimension] = modulus_switch(body + correction, log_modulus);
  } else {
    output[tid] = modulus_switch(input[tid], log_modulus);
  }
}

// Applies the centered modulus switch on a single LWE
template <typename Torus>
__host__ void host_centered_modulus_switch_inplace(
    cudaStream_t stream, uint32_t gpu_index, Torus *output, const Torus *input,
    uint32_t lwe_dimension, uint32_t log_modulus) {
  cuda_set_device(gpu_index);
  if (input == output)
    PANIC("Input and Output arrays should be different")

  // Get device properties to check max threads per block
  cudaDeviceProp deviceProp;
  check_cuda_error(cudaGetDeviceProperties(&deviceProp, gpu_index));

  // Check if lwe_dimension+1 exceeds maximum threads per block
  if (lwe_dimension + 1 > deviceProp.maxThreadsPerBlock)
    PANIC("lwe_dimension+1 exceeds maximum number of threads per block")

  // We assume
  int num_threads = lwe_dimension + 1, num_blocks = 1;
  centered_modulus_switch<<<num_blocks, num_threads, 0, stream>>>(
      output, input, lwe_dimension, log_modulus);
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
__global__ void __launch_bounds__(512)
    improve_noise_modulus_switch(Torus *array_out, const Torus *array_in,
                                 const uint64_t *indexes, const Torus *zeros,
                                 int lwe_size, int num_zeros,
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
  auto this_block_lwe_in = array_in + indexes[blockIdx.x] * lwe_size;
  // We use modulus switch to gather the output in trivial order
  auto this_block_lwe_out = array_out + blockIdx.x * lwe_size;
  Torus input_element1 = this_block_lwe_in[threadIdx.x];

  Torus input_element2 = threadIdx.x + blockDim.x < lwe_size
                             ? this_block_lwe_in[threadIdx.x + blockDim.x]
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
    this_block_lwe_out[threadIdx.x] = input_element1;

  if (found && (threadIdx.x + blockDim.x) < lwe_size)
    this_block_lwe_out[threadIdx.x + blockDim.x] = input_element2;

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
      this_block_lwe_out[threadIdx.x] = zero_element1;

    if (found && (threadIdx.x + blockDim.x) < lwe_size)
      this_block_lwe_out[threadIdx.x + blockDim.x] = zero_element2;

    __syncthreads();
    // If we found a zero element we stop iterating (in avg 20 times are
    // required)
    if (found)
      return;
  }
}

#endif // CNCRT_TORUS_H
