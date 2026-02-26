#include "programmable_bootstrap.cuh"

template <>
__device__ int get_this_block_rank(grid_group &group, bool support_dsm) {
  return blockIdx.y;
}

template <>
__device__ double2 *
get_join_buffer_element(int level_id, int glwe_id, grid_group &group,
                        double2 *global_memory_buffer, uint32_t polynomial_size,
                        uint32_t glwe_dimension, bool support_dsm) {
  double2 *buffer_slice =
      global_memory_buffer +
      (glwe_id + level_id * (glwe_dimension + 1)) * polynomial_size / 2;
  return buffer_slice;
}

template <>
__device__ double *get_join_buffer_element_128(
    int level_id, int glwe_id, grid_group &group, double *global_memory_buffer,
    uint32_t polynomial_size, uint32_t glwe_dimension, bool support_dsm) {
  double *buffer_slice =
      global_memory_buffer +
      (glwe_id + level_id * (glwe_dimension + 1)) * polynomial_size / 2 * 4;
  return buffer_slice;
}
#if CUDA_ARCH >= 900
template <>
__device__ int get_this_block_rank(cluster_group &cluster, bool support_dsm) {
  if (support_dsm)
    return cluster.block_index().y;
  else
    return blockIdx.y;
}
template <>
__device__ double2 *
get_join_buffer_element(int level_id, int glwe_id, cluster_group &cluster,
                        double2 *global_memory_buffer, uint32_t polynomial_size,
                        uint32_t glwe_dimension, bool support_dsm) {
  double2 *buffer_slice;
  if (support_dsm) {
    extern __shared__ double2 smem[];
    buffer_slice = cluster.map_shared_rank(
        smem, glwe_id + level_id * (glwe_dimension + 1));
  } else {
    buffer_slice =
        global_memory_buffer +
        (glwe_id + level_id * (glwe_dimension + 1)) * polynomial_size / 2;
  }
  return buffer_slice;
}

template <>
__device__ double *get_join_buffer_element_128_tbc(int level_id, int glwe_id,
                                                   cluster_group &cluster,
                                                   double *shared_memory_buffer,
                                                   uint32_t polynomial_size,
                                                   uint32_t glwe_dimension) {
  double *buffer_slice;

  buffer_slice = cluster.map_shared_rank(
      shared_memory_buffer, glwe_id + level_id * (glwe_dimension + 1));
  return buffer_slice;
}
#endif
