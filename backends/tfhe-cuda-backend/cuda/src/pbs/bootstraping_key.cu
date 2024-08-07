#include "bootstrapping_key.cuh"

void cuda_convert_lwe_programmable_bootstrap_key_32(
    void *stream, uint32_t gpu_index, void *dest, void *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  uint32_t total_polynomials =
      input_lwe_dim * (glwe_dim + 1) * (glwe_dim + 1) * level_count;
  cuda_convert_lwe_programmable_bootstrap_key<uint32_t, int32_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (int32_t *)src, polynomial_size, total_polynomials);
}

void cuda_convert_lwe_programmable_bootstrap_key_64(
    void *stream, uint32_t gpu_index, void *dest, void *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  uint32_t total_polynomials =
      input_lwe_dim * (glwe_dim + 1) * (glwe_dim + 1) * level_count;
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (int64_t *)src, polynomial_size, total_polynomials);
}

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
    void *stream, uint32_t gpu_index, void *dest, void *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size, uint32_t grouping_factor) {
  uint32_t total_polynomials = input_lwe_dim * (glwe_dim + 1) * (glwe_dim + 1) *
                               level_count * (1 << grouping_factor) /
                               grouping_factor;
  size_t buffer_size = total_polynomials * polynomial_size * sizeof(uint64_t);

  cuda_memcpy_async_to_gpu((uint64_t *)dest, (uint64_t *)src, buffer_size,
                           static_cast<cudaStream_t>(stream), gpu_index);
}

// We need these lines so the compiler knows how to specialize these functions
template __device__ const uint64_t *
get_ith_mask_kth_block(const uint64_t *ptr, int i, int k, int level,
                       uint32_t polynomial_size, int glwe_dimension,
                       uint32_t level_count);
template __device__ const uint32_t *
get_ith_mask_kth_block(const uint32_t *ptr, int i, int k, int level,
                       uint32_t polynomial_size, int glwe_dimension,
                       uint32_t level_count);
template __device__ const double2 *
get_ith_mask_kth_block(const double2 *ptr, int i, int k, int level,
                       uint32_t polynomial_size, int glwe_dimension,
                       uint32_t level_count);
template __device__ uint64_t *get_ith_mask_kth_block(uint64_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ uint32_t *get_ith_mask_kth_block(uint32_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ double2 *get_ith_mask_kth_block(double2 *ptr, int i, int k,
                                                    int level,
                                                    uint32_t polynomial_size,
                                                    int glwe_dimension,
                                                    uint32_t level_count);

template __device__ uint64_t *get_ith_body_kth_block(uint64_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ uint32_t *get_ith_body_kth_block(uint32_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ double2 *get_ith_body_kth_block(double2 *ptr, int i, int k,
                                                    int level,
                                                    uint32_t polynomial_size,
                                                    int glwe_dimension,
                                                    uint32_t level_count);

template __device__ const uint64_t *get_multi_bit_ith_lwe_gth_group_kth_block(
    const uint64_t *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);

template __device__ const double2 *get_multi_bit_ith_lwe_gth_group_kth_block(
    const double2 *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);
