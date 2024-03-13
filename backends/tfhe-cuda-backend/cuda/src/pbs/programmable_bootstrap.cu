#include "programmable_bootstrap.cuh"


template <> __device__ int get_this_block_rank(grid_group &group, bool support_dsm) {
  return blockIdx.y;
}

template <> __device__ int get_this_block_rank(cluster_group &cluster, bool support_dsm) {
  if (support_dsm)
    return cluster.block_rank();
  else
    return blockIdx.y;
}

template<> __device__ double2 *get_join_buffer_element(int i, grid_group &group,
                                            bool support_dsm,
                                            double2 *global_memory_buffer, uint32_t
                                            polynomial_size) {
  double2 *buffer_slice = global_memory_buffer + i * polynomial_size / 2;
  return buffer_slice;
}

template<> __device__ double2 *get_join_buffer_element(int i, cluster_group &cluster,
                                            bool support_dsm,
                                            double2 *global_memory_buffer, uint32_t
                                            polynomial_size) {
#if CUDA_ARCH < 900
  double2 *buffer_slice =
      global_memory_buffer + blockIdx.y * polynomial_size / 2;
#else
  double2 *buffer_slice;
  if (support_dsm) {
    extern __shared__ double2 smem[];
    buffer_slice = cluster.map_shared_rank(smem, i);
  } else {
    buffer_slice = global_memory_buffer + i * polynomial_size / 2;
  }
#endif
  return buffer_slice;
}