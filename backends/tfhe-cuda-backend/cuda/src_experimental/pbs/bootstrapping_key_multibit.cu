#include "bootstrapping_key_multibit.cuh"
#include "checked_arithmetic.h"
#include "pbs/programmable_bootstrap_multibit.h"

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    CudaLweBootstrapKeyParamsFFI bsk_params) {
  if (bsk_params.pbs_type != PBS_TYPE::MULTI_BIT)
    PANIC("Cuda error (multi-bit PBS): the bootstrap key parameters are not "
          "multi-bit (pbs_type %u).",
          bsk_params.pbs_type)
  uint32_t grouping_factor = bsk_params.pbs_params.multi_bit.grouping_factor;
  size_t total_polynomials = safe_mul((size_t)bsk_params.input_lwe_dimension,
                                      (size_t)(bsk_params.glwe_dimension + 1),
                                      (size_t)(bsk_params.glwe_dimension + 1),
                                      (size_t)bsk_params.level_count);
  total_polynomials =
      safe_mul(total_polynomials, (size_t)(1 << grouping_factor)) /
      grouping_factor;
  size_t buffer_size = safe_mul_sizeof<uint64_t>(
      total_polynomials, (size_t)bsk_params.polynomial_size);

  cuda_memcpy_async_to_gpu((uint64_t *)dest, (uint64_t *)src, buffer_size,
                           static_cast<cudaStream_t>(stream), gpu_index);
}

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_128_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    CudaLweBootstrapKeyParamsFFI bsk_params) {
  if (bsk_params.pbs_type != PBS_TYPE::MULTI_BIT)
    PANIC("Cuda error (multi-bit PBS): the bootstrap key parameters are not "
          "multi-bit (pbs_type %u).",
          bsk_params.pbs_type)
  uint32_t grouping_factor = bsk_params.pbs_params.multi_bit.grouping_factor;
  size_t total_polynomials = safe_mul((size_t)bsk_params.input_lwe_dimension,
                                      (size_t)(bsk_params.glwe_dimension + 1),
                                      (size_t)(bsk_params.glwe_dimension + 1),
                                      (size_t)bsk_params.level_count);
  total_polynomials =
      safe_mul(total_polynomials, (size_t)(1 << grouping_factor)) /
      grouping_factor;
  size_t buffer_size = safe_mul_sizeof<__uint128_t>(
      total_polynomials, (size_t)bsk_params.polynomial_size);

  cuda_memcpy_async_to_gpu((__uint128_t *)dest, (__uint128_t *)src, buffer_size,
                           static_cast<cudaStream_t>(stream), gpu_index);
}

// We need these lines so the compiler knows how to specialize these functions
template __device__ const __uint128_t *
get_multi_bit_ith_lwe_gth_group_kth_block(const __uint128_t *ptr, int g, int i,
                                          int k, int level,
                                          uint32_t grouping_factor,
                                          uint32_t polynomial_size,
                                          uint32_t glwe_dimension,
                                          uint32_t level_count);

template __device__ const uint64_t *get_multi_bit_ith_lwe_gth_group_kth_block(
    const uint64_t *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);

template __device__ const double2 *get_multi_bit_ith_lwe_gth_group_kth_block(
    const double2 *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);

bool cuda_multi_bit_pbs_golden_is_supported_async(uint32_t gpu_index) {
  cudaDeviceProp prop{};
  cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
  // sm_90 (Hopper) or newer: the multi-bit golden data is captured on H100 and
  // only validated there.
  return err == cudaSuccess && prop.major >= 9;
}
