#ifndef CUDA_BSK_MULTIBIT_CUH
#define CUDA_BSK_MULTIBIT_CUH

#include "bootstrapping_key.cuh"

__device__ inline int get_start_ith_lwe(uint32_t i, uint32_t grouping_factor,
                                        uint32_t polynomial_size,
                                        uint32_t glwe_dimension,
                                        uint32_t level_count) {
  return i * (1 << grouping_factor) * polynomial_size / 2 *
         (glwe_dimension + 1) * (glwe_dimension + 1) * level_count;
}

template <typename T>
__device__ const T *get_multi_bit_ith_lwe_gth_group_kth_block(
    const T *ptr, int g, int i, int k, int level, uint32_t grouping_factor,
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count) {
  const T *ptr_group =
      ptr + get_start_ith_lwe(i, grouping_factor, polynomial_size,
                              glwe_dimension, level_count);
  return get_ith_mask_kth_block(ptr_group, g, k, level, polynomial_size,
                                glwe_dimension, level_count);
}

#endif // CUDA_BSK_MULTIBIT_CUH
