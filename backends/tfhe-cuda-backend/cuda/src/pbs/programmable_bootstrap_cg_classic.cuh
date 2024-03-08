#ifndef CUDA_CG_PBS_CUH
#define CUDA_CG_PBS_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "cooperative_groups.h"

#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "programmable_bootstrap.h"
#include "types/complex/operations.cuh"

// Cooperative groups are used for this implementation
using namespace cooperative_groups;
namespace cg = cooperative_groups;

template <typename Torus, class params>
__device__ void mul_ggsw_glwe(Torus *accumulator, double2 *fft,
                              double2 *join_buffer, double2 *bootstrapping_key,
                              int polynomial_size, uint32_t glwe_dimension,
                              int level_count, int iteration,
                              grid_group &grid) {

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

/*
 * Kernel that computes the classical PBS using cooperative groups
 *
 * - lwe_array_out: vector of output lwe s, with length
 * (glwe_dimension * polynomial_size+1)*num_samples
 * - lut_vector: vector of look up tables with
 * length  (glwe_dimension+1) * polynomial_size * num_samples
 * - lut_vector_indexes: mapping between lwe_array_in and lut_vector
 * lwe_array_in: vector of lwe inputs with length (lwe_dimension + 1) *
 * num_samples
 *
 * Each y-block computes one element of the lwe_array_out.
 */
template <typename Torus, class params, sharedMemDegree SMD>
__global__ void device_programmable_bootstrap_cg(
    Torus *lwe_array_out, Torus *lwe_output_indexes, Torus *lut_vector,
    Torus *lut_vector_indexes, Torus *lwe_array_in, Torus *lwe_input_indexes,
    double2 *bootstrapping_key, double2 *join_buffer, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    int8_t *device_mem, uint64_t device_memory_size_per_block) {

  grid_group grid = this_grid();

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;
  uint32_t glwe_dimension = gridDim.y - 1;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.x + blockIdx.y * gridDim.x +
                      blockIdx.z * gridDim.x * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  // We always compute the pointer with most restrictive alignment to avoid
  // alignment issues
  double2 *accumulator_fft = (double2 *)selected_memory;
  Torus *accumulator =
      (Torus *)accumulator_fft +
      (ptrdiff_t)(sizeof(double2) * polynomial_size / 2 / sizeof(Torus));
  Torus *accumulator_rotated =
      (Torus *)accumulator + (ptrdiff_t)polynomial_size;

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double2 *)sharedmem;

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.z] * (lwe_dimension + 1)];

  Torus *block_lut_vector = &lut_vector[lut_vector_indexes[blockIdx.z] *
                                        params::degree * (glwe_dimension + 1)];

  double2 *block_join_buffer =
      &join_buffer[blockIdx.z * level_count * (glwe_dimension + 1) *
                   params::degree / 2];
  // Since the space is L1 cache is small, we use the same memory location for
  // the rotated accumulator and the fft accumulator, since we know that the
  // rotated array is not in use anymore by the time we perform the fft

  // Put "b" in [0, 2N[
  Torus b_hat = 0;
  rescale_torus_element(block_lwe_array_in[lwe_dimension], b_hat,
                        2 * params::degree);

  divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                        params::degree / params::opt>(
      accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
      false);

  for (int i = 0; i < lwe_dimension; i++) {
    synchronize_threads_in_block();

    // Put "a" in [0, 2N[
    Torus a_hat = 0;
    rescale_torus_element(block_lwe_array_in[i], a_hat,
                          2 * params::degree); // 2 * params::log2_degree + 1);

    // Perform ACC * (X^ä - 1)
    multiply_by_monomial_negacyclic_and_sub_polynomial<
        Torus, params::opt, params::degree / params::opt>(
        accumulator, accumulator_rotated, a_hat);

    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    round_to_closest_multiple_inplace<Torus, params::opt,
                                      params::degree / params::opt>(
        accumulator_rotated, base_log, level_count);

    synchronize_threads_in_block();

    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<Torus, params> gadget_acc(base_log, level_count,
                                           accumulator_rotated);
    gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.x);

    // We are using the same memory space for accumulator_fft and
    // accumulator_rotated, so we need to synchronize here to make sure they
    // don't modify the same memory space at the same time
    synchronize_threads_in_block();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe<Torus, params>(
        accumulator, accumulator_fft, block_join_buffer, bootstrapping_key,
        polynomial_size, glwe_dimension, level_count, i, grid);

    synchronize_threads_in_block();
  }

  auto block_lwe_array_out =
      &lwe_array_out[lwe_output_indexes[blockIdx.z] *
                         (glwe_dimension * polynomial_size + 1) +
                     blockIdx.y * polynomial_size];

  if (blockIdx.x == 0 && blockIdx.y < glwe_dimension) {
    // Perform a sample extract. At this point, all blocks have the result, but
    // we do the computation at block 0 to avoid waiting for extra blocks, in
    // case they're not synchronized
    sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
  } else if (blockIdx.x == 0 && blockIdx.y == glwe_dimension) {
    sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
  }
}

template <typename Torus, typename STorus, typename params>
__host__ void scratch_programmable_bootstrap_cg(
    cuda_stream_t *stream, pbs_buffer<Torus, CLASSICAL> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {
  cudaSetDevice(stream->gpu_index);

  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
          polynomial_size);
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg<Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg<Torus, params, FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  *buffer = new pbs_buffer<Torus, CLASSICAL>(
      stream, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, PBS_VARIANT::CG, allocate_gpu_memory);
}

/*
 * Host wrapper
 */
template <typename Torus, class params>
__host__ void host_programmable_bootstrap_cg(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, double2 *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t num_luts, uint32_t max_shared_memory) {
  cudaSetDevice(stream->gpu_index);

  // With SM each block corresponds to either the mask or body, no need to
  // duplicate data for each
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(polynomial_size);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
          polynomial_size);

  uint64_t full_dm = full_sm;

  uint64_t partial_dm = full_dm - partial_sm;

  int8_t *d_mem = buffer->d_mem;
  double2 *buffer_fft = buffer->global_accumulator_fft;

  int thds = polynomial_size / params::opt;
  dim3 grid(level_count, glwe_dimension + 1, input_lwe_ciphertext_count);

  void *kernel_args[14];
  kernel_args[0] = &lwe_array_out;
  kernel_args[1] = &lwe_output_indexes;
  kernel_args[2] = &lut_vector;
  kernel_args[3] = &lut_vector_indexes;
  kernel_args[4] = &lwe_array_in;
  kernel_args[5] = &lwe_input_indexes;
  kernel_args[6] = &bootstrapping_key;
  kernel_args[7] = &buffer_fft;
  kernel_args[8] = &lwe_dimension;
  kernel_args[9] = &polynomial_size;
  kernel_args[10] = &base_log;
  kernel_args[11] = &level_count;
  kernel_args[12] = &d_mem;

  if (max_shared_memory < partial_sm) {
    kernel_args[13] = &full_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_programmable_bootstrap_cg<Torus, params, NOSM>, grid,
        thds, (void **)kernel_args, 0, stream->stream));
  } else if (max_shared_memory < full_sm) {
    kernel_args[13] = &partial_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        grid, thds, (void **)kernel_args, partial_sm, stream->stream));
  } else {
    int no_dm = 0;
    kernel_args[13] = &no_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_programmable_bootstrap_cg<Torus, params, FULLSM>, grid,
        thds, (void **)kernel_args, full_sm, stream->stream));
  }

  check_cuda_error(cudaGetLastError());
}

// Verify if the grid size satisfies the cooperative group constraints
template <typename Torus, class params>
__host__ bool verify_cuda_programmable_bootstrap_cg_grid_size(
    int glwe_dimension, int level_count, int num_samples,
    uint32_t max_shared_memory) {

  // If Cooperative Groups is not supported, no need to check anything else
  if (!cuda_check_support_cooperative_groups())
    return false;

  // Calculate the dimension of the kernel
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(params::degree);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
          params::degree);

  int thds = params::degree / params::opt;

  // Get the maximum number of active blocks per streaming multiprocessors
  int number_of_blocks = level_count * (glwe_dimension + 1) * num_samples;
  int max_active_blocks_per_sm;

  if (max_shared_memory < partial_sm) {
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg<Torus, params, NOSM>, thds, 0);
  } else if (max_shared_memory < full_sm) {
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        thds, partial_sm);
  } else {
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg<Torus, params, FULLSM>, thds,
        full_sm);
  }

  // Get the number of streaming multiprocessors
  int number_of_sm = 0;
  cudaDeviceGetAttribute(&number_of_sm, cudaDevAttrMultiProcessorCount, 0);
  return number_of_blocks <= max_active_blocks_per_sm * number_of_sm;
}

// Verify if the grid size satisfies the cooperative group constraints
template <typename Torus>
__host__ bool supports_cooperative_groups_on_programmable_bootstrap(
    int glwe_dimension, int polynomial_size, int level_count, int num_samples,
    uint32_t max_shared_memory) {
  switch (polynomial_size) {
  case 256:
    return verify_cuda_programmable_bootstrap_cg_grid_size<
        Torus, AmortizedDegree<256>>(glwe_dimension, level_count, num_samples,
                                     max_shared_memory);
  case 512:
    return verify_cuda_programmable_bootstrap_cg_grid_size<
        Torus, AmortizedDegree<512>>(glwe_dimension, level_count, num_samples,
                                     max_shared_memory);
  case 1024:
    return verify_cuda_programmable_bootstrap_cg_grid_size<
        Torus, AmortizedDegree<1024>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 2048:
    return verify_cuda_programmable_bootstrap_cg_grid_size<
        Torus, AmortizedDegree<2048>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 4096:
    return verify_cuda_programmable_bootstrap_cg_grid_size<
        Torus, AmortizedDegree<4096>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 8192:
    return verify_cuda_programmable_bootstrap_cg_grid_size<
        Torus, AmortizedDegree<8192>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 16384:
    return verify_cuda_programmable_bootstrap_cg_grid_size<
        Torus, AmortizedDegree<16384>>(glwe_dimension, level_count, num_samples,
                                       max_shared_memory);
  default:
    PANIC("Cuda error (classical PBS): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..16384].")
  }
}

#endif // CG_PBS_H
