#ifndef CUDA_PROGRAMMABLE_BOOTSTRAP_CUH
#define CUDA_PROGRAMMABLE_BOOTSTRAP_CUH

#include "device.h"
#include "fft/bnsmfft.cuh"
#include "programmable_bootstrap.h"
#include "programmable_bootstrap_multibit.h"

#include "cooperative_groups.h"
#include "helper_multi_gpu.h"

using namespace cooperative_groups;
namespace cg = cooperative_groups;

template <typename G>
__device__ int get_this_block_rank(G &group, bool support_dsm);

template <typename G>
__device__ double2 *
get_join_buffer_element(int level_id, int glwe_id, G &group,
                        double2 *global_memory_buffer, uint32_t polynomial_size,
                        uint32_t glwe_dimension, bool support_dsm);

template <typename Torus, typename G, class params>
__device__ void mul_ggsw_glwe(Torus *accumulator, double2 *fft,
                              double2 *join_buffer, double2 *bootstrapping_key,
                              int polynomial_size, uint32_t glwe_dimension,
                              int level_count, int iteration, G &group,
                              bool support_dsm = false) {

  // Switch to the FFT space
  NSMFFT_direct<HalfDegree<params>>(fft);
  synchronize_threads_in_block();

  // Get the pieces of the bootstrapping key that will be needed for the
  // external product; blockIdx.x is the ID of the block that's executing
  // this function, so we end up getting the lines of the bootstrapping key
  // needed to perform the external product in this block (corresponding to
  // the same decomposition level)
  auto bsk_slice = get_ith_mask_kth_block(
      bootstrapping_key, iteration, blockIdx.y, blockIdx.x, polynomial_size,
      glwe_dimension, level_count);

  // Perform the matrix multiplication between the GGSW and the GLWE,
  // each block operating on a single level for mask and body

  // The first product is used to initialize level_join_buffer
  auto bsk_poly = bsk_slice + blockIdx.y * params::degree / 2;
  auto this_block_rank = get_this_block_rank<G>(group, support_dsm);
  auto buffer_slice =
      get_join_buffer_element<G>(blockIdx.x, blockIdx.y, group, join_buffer,
                                 polynomial_size, glwe_dimension, support_dsm);

  int tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    buffer_slice[tid] = fft[tid] * bsk_poly[tid];
    tid += params::degree / params::opt;
  }

  group.sync();

  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  for (int j = 1; j < (glwe_dimension + 1); j++) {
    int idx = (j + this_block_rank) % (glwe_dimension + 1);

    auto bsk_poly = bsk_slice + idx * params::degree / 2;
    auto buffer_slice = get_join_buffer_element<G>(blockIdx.x, idx, group,
                                                   join_buffer, polynomial_size,
                                                   glwe_dimension, support_dsm);

    int tid = threadIdx.x;
    for (int i = 0; i < params::opt / 2; i++) {
      buffer_slice[tid] += fft[tid] * bsk_poly[tid];
      tid += params::degree / params::opt;
    }
    group.sync();
  }

  // -----------------------------------------------------------------
  // All blocks are synchronized here; after this sync, level_join_buffer has
  // the values needed from every other block

  auto src_acc =
      get_join_buffer_element<G>(0, blockIdx.y, group, join_buffer,
                                 polynomial_size, glwe_dimension, support_dsm);

  // copy first product into fft buffer
  tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] = src_acc[tid];
    tid += params::degree / params::opt;
  }
  synchronize_threads_in_block();

  // accumulate rest of the products into fft buffer
  for (int l = 1; l < gridDim.x; l++) {
    auto cur_src_acc = get_join_buffer_element<G>(l, blockIdx.y, group,
                                                  join_buffer, polynomial_size,
                                                  glwe_dimension, support_dsm);
    tid = threadIdx.x;
    for (int i = 0; i < params::opt / 2; i++) {
      fft[tid] += cur_src_acc[tid];
      tid += params::degree / params::opt;
    }
  }

  synchronize_threads_in_block();

  // Perform the inverse FFT on the result of the GGSW x GLWE and add to the
  // accumulator
  NSMFFT_inverse<HalfDegree<params>>(fft);
  synchronize_threads_in_block();

  add_to_torus<Torus, params>(fft, accumulator);

  __syncthreads();
}

template <typename Torus>
void execute_pbs(cudaStream_t *streams, uint32_t *gpu_indexes,
                 uint32_t gpu_count, Torus *lwe_array_out,
                 Torus *lwe_output_indexes, std::vector<Torus *> lut_vec,
                 std::vector<Torus *> lut_indexes_vec, Torus *lwe_array_in,
                 Torus *lwe_input_indexes, void **bootstrapping_keys,
                 std::vector<int8_t *> pbs_buffer, uint32_t glwe_dimension,
                 uint32_t lwe_dimension, uint32_t polynomial_size,
                 uint32_t base_log, uint32_t level_count,
                 uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
                 uint32_t num_luts, uint32_t lwe_idx,
                 uint32_t max_shared_memory, PBS_TYPE pbs_type,
                 bool sync_streams = true) {
  auto active_gpu_count =
      get_active_gpu_count(input_lwe_ciphertext_count, gpu_count);
  if (sync_streams)
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case CLASSICAL:
#pragma omp parallel for num_threads(active_gpu_count)
      for (uint i = 0; i < active_gpu_count; i++) {
        int num_inputs_on_gpu =
            get_num_inputs_on_gpu(input_lwe_ciphertext_count, i, gpu_count);
        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, gpu_count);
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);
        cuda_programmable_bootstrap_lwe_ciphertext_vector_32(
            streams[i], gpu_indexes[i], lwe_array_out, lwe_output_indexes,
            lut_vec[i], d_lut_vector_indexes, lwe_array_in, lwe_input_indexes,
            bootstrapping_keys[i], pbs_buffer[i], lwe_dimension, glwe_dimension,
            polynomial_size, base_log, level_count, num_inputs_on_gpu, num_luts,
            lwe_idx, max_shared_memory, gpu_offset);
      }
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
      break;
    }
    break;
  case sizeof(uint64_t):
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      if (grouping_factor == 0)
        PANIC("Multi-bit PBS error: grouping factor should be > 0.")
#pragma omp parallel for num_threads(active_gpu_count)
      for (uint i = 0; i < active_gpu_count; i++) {
        int num_inputs_on_gpu =
            get_num_inputs_on_gpu(input_lwe_ciphertext_count, i, gpu_count);
        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, gpu_count);
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
            streams[i], gpu_indexes[i], lwe_array_out, lwe_output_indexes,
            lut_vec[i], d_lut_vector_indexes, lwe_array_in, lwe_input_indexes,
            bootstrapping_keys[i], pbs_buffer[i], lwe_dimension, glwe_dimension,
            polynomial_size, grouping_factor, base_log, level_count,
            num_inputs_on_gpu, num_luts, lwe_idx, max_shared_memory,
            gpu_offset);
      }
      break;
    case CLASSICAL:
#pragma omp parallel for num_threads(active_gpu_count)
      for (uint i = 0; i < active_gpu_count; i++) {
        int num_inputs_on_gpu =
            get_num_inputs_on_gpu(input_lwe_ciphertext_count, i, gpu_count);
        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, gpu_count);
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);
        cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
            streams[i], gpu_indexes[i], lwe_array_out, lwe_output_indexes,
            lut_vec[i], d_lut_vector_indexes, lwe_array_in, lwe_input_indexes,
            bootstrapping_keys[i], pbs_buffer[i], lwe_dimension, glwe_dimension,
            polynomial_size, base_log, level_count, num_inputs_on_gpu, num_luts,
            lwe_idx, max_shared_memory, gpu_offset);
      }
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
    break;
  default:
    PANIC("Cuda error: unsupported modulus size: only 32 and 64 bit integer "
          "moduli are supported.")
  }

  if (sync_streams)
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
}

template <typename Torus>
void execute_scratch_pbs(cudaStream_t stream, uint32_t gpu_index,
                         int8_t **pbs_buffer, uint32_t glwe_dimension,
                         uint32_t lwe_dimension, uint32_t polynomial_size,
                         uint32_t level_count, uint32_t grouping_factor,
                         uint32_t input_lwe_ciphertext_count,
                         uint32_t max_shared_memory, PBS_TYPE pbs_type,
                         bool allocate_gpu_memory) {
  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case CLASSICAL:
      scratch_cuda_programmable_bootstrap_32(
          stream, gpu_index, pbs_buffer, glwe_dimension, polynomial_size,
          level_count, input_lwe_ciphertext_count, max_shared_memory,
          allocate_gpu_memory);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
    break;
  case sizeof(uint64_t):
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      if (grouping_factor == 0)
        PANIC("Multi-bit PBS error: grouping factor should be > 0.")
      scratch_cuda_multi_bit_programmable_bootstrap_64(
          stream, gpu_index, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, level_count, grouping_factor,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    case CLASSICAL:
      scratch_cuda_programmable_bootstrap_64(
          stream, gpu_index, pbs_buffer, glwe_dimension, polynomial_size,
          level_count, input_lwe_ciphertext_count, max_shared_memory,
          allocate_gpu_memory);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
    break;
  default:
    PANIC("Cuda error: unsupported modulus size: only 32 and 64 bit integer "
          "moduli are supported.")
  }
}

#endif
