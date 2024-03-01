#ifndef BOOTSTRAP_CUH
#define BOOTSTRAP_CUH

#include "bootstrap.h"
#include "bootstrap_multibit.h"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"

#include "cooperative_groups.h"

using namespace cooperative_groups;
namespace cg = cooperative_groups;

template <typename Torus, typename G, class params>
__device__ void mul_ggsw_glwe(Torus *accumulator, double2 *fft,
                              double2 *join_buffer, double2 *bootstrapping_key,
                              int polynomial_size, uint32_t glwe_dimension,
                              int level_count, int iteration, G &grid) {

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

  // Selects all GLWEs in a particular decomposition level
  auto level_join_buffer =
      join_buffer + blockIdx.x * (glwe_dimension + 1) * params::degree / 2;

  // Perform the matrix multiplication between the GGSW and the GLWE,
  // each block operating on a single level for mask and body

  // The first product is used to initialize level_join_buffer
  auto bsk_poly = bsk_slice + blockIdx.y * params::degree / 2;
  auto buffer_slice = level_join_buffer + blockIdx.y * params::degree / 2;

  int tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    buffer_slice[tid] = fft[tid] * bsk_poly[tid];
    tid += params::degree / params::opt;
  }

  grid.sync();

  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  for (int j = 1; j < (glwe_dimension + 1); j++) {
    int idx = (j + blockIdx.y) % (glwe_dimension + 1);

    auto bsk_poly = bsk_slice + idx * params::degree / 2;
    auto buffer_slice = level_join_buffer + idx * params::degree / 2;

    int tid = threadIdx.x;
    for (int i = 0; i < params::opt / 2; i++) {
      buffer_slice[tid] += fft[tid] * bsk_poly[tid];
      tid += params::degree / params::opt;
    }
    grid.sync();
  }

  // -----------------------------------------------------------------
  // All blocks are synchronized here; after this sync, level_join_buffer has
  // the values needed from every other block

  auto src_acc = join_buffer + blockIdx.y * params::degree / 2;

  // copy first product into fft buffer
  tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] = src_acc[tid];
    tid += params::degree / params::opt;
  }
  synchronize_threads_in_block();

  // accumulate rest of the products into fft buffer
  for (int l = 1; l < gridDim.x; l++) {
    auto cur_src_acc = &src_acc[l * (glwe_dimension + 1) * params::degree / 2];
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

// mul_ggsw_glwe that uses distributed shared memory
template <typename Torus, class params>
__device__ void mul_ggsw_glwe_dsm(Torus *accumulator, double2 *fft,
                                  double2 *bootstrapping_key,
                                  int polynomial_size, uint32_t glwe_dimension,
                                  int level_count, int iteration) {

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
  auto bsk_poly = bsk_slice + blockIdx.y * params::degree / 2;

  extern __shared__ double2 smem[];
  auto cluster = this_cluster();
  unsigned int this_cluster_block_rank = cluster.block_rank();

  double2 *buffer_slice =
      cluster.map_shared_rank(smem, this_cluster_block_rank);

  // The first product is used to initialize level_join_buffer
  int tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    buffer_slice[tid] = fft[tid] * bsk_poly[tid];
    tid += params::degree / params::opt;
  }

  cluster.sync();

  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  for (int j = 1; j < (glwe_dimension + 1); j++) {
    int idx = (j + this_cluster_block_rank) % (glwe_dimension + 1);

    auto bsk_poly = bsk_slice + idx * params::degree / 2;
    double2 *buffer_slice = cluster.map_shared_rank(smem, idx);

    int tid = threadIdx.x;
    for (int i = 0; i < params::opt / 2; i++) {
      buffer_slice[tid] += fft[tid] * bsk_poly[tid];
      tid += params::degree / params::opt;
    }
    cluster.sync();
  }

  // -----------------------------------------------------------------
  // All blocks are synchronized here; after this sync, level_join_buffer has
  // the values needed from every other block

  double2 *src_acc = cluster.map_shared_rank(smem, this_cluster_block_rank);

  // copy first product into fft buffer
  tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] = src_acc[tid];
    tid += params::degree / params::opt;
  }
  synchronize_threads_in_block();

  // accumulate rest of the products into fft buffer
  for (int l = 1; l < gridDim.x; l++) {
    auto cur_src_acc = &src_acc[l * (glwe_dimension + 1) * params::degree / 2];
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
void execute_pbs(cuda_stream_t *stream, Torus *lwe_array_out,
                 Torus *lwe_output_indexes, Torus *lut_vector,
                 Torus *lut_vector_indexes, Torus *lwe_array_in,
                 Torus *lwe_input_indexes, void *bootstrapping_key,
                 int8_t *pbs_buffer, uint32_t glwe_dimension,
                 uint32_t lwe_dimension, uint32_t polynomial_size,
                 uint32_t base_log, uint32_t level_count,
                 uint32_t grouping_factor, uint32_t input_lwe_ciphertext_count,
                 uint32_t num_luts, uint32_t lwe_idx,
                 uint32_t max_shared_memory, PBS_TYPE pbs_type) {
  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case LOW_LAT:
      cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
      break;
    case AMORTIZED:
      cuda_bootstrap_amortized_lwe_ciphertext_vector_32(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
      break;
    default:
      break;
    }
    break;
  case sizeof(uint64_t):
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      cuda_multi_bit_pbs_lwe_ciphertext_vector_64(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, grouping_factor, base_log, level_count,
          input_lwe_ciphertext_count, num_luts, lwe_idx, max_shared_memory);
      break;
    case LOW_LAT:
      cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
      break;
    case AMORTIZED:
      cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
          stream, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, input_lwe_ciphertext_count,
          num_luts, lwe_idx, max_shared_memory);
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

template <typename Torus>
void execute_scratch_pbs(cuda_stream_t *stream, int8_t **pbs_buffer,
                         uint32_t glwe_dimension, uint32_t lwe_dimension,
                         uint32_t polynomial_size, uint32_t level_count,
                         uint32_t grouping_factor,
                         uint32_t input_lwe_ciphertext_count,
                         uint32_t max_shared_memory, PBS_TYPE pbs_type,
                         bool allocate_gpu_memory) {
  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case LOW_LAT:
      scratch_cuda_bootstrap_low_latency_32(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    case AMORTIZED:
      scratch_cuda_bootstrap_amortized_32(
          stream, pbs_buffer, glwe_dimension, polynomial_size,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
    break;
  case sizeof(uint64_t):
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      scratch_cuda_multi_bit_pbs_64(
          stream, pbs_buffer, lwe_dimension, glwe_dimension, polynomial_size,
          level_count, grouping_factor, input_lwe_ciphertext_count,
          max_shared_memory, allocate_gpu_memory);
      break;
    case LOW_LAT:
      scratch_cuda_bootstrap_low_latency_64(
          stream, pbs_buffer, glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
      break;
    case AMORTIZED:
      scratch_cuda_bootstrap_amortized_64(
          stream, pbs_buffer, glwe_dimension, polynomial_size,
          input_lwe_ciphertext_count, max_shared_memory, allocate_gpu_memory);
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
