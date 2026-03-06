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
#include "pbs/pbs_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "programmable_bootstrap.cuh"
#include "programmable_bootstrap_classic.cuh"
#include "types/complex/operations.cuh"

using namespace cooperative_groups;
namespace cg = cooperative_groups;

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
    Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
    const Torus *__restrict__ lut_vector,
    const Torus *__restrict__ lut_vector_indexes,
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes,
    const double2 *__restrict__ bootstrapping_key, double2 *join_buffer,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, int8_t *device_mem,
    uint64_t device_memory_size_per_block, uint32_t num_many_lut,
    uint32_t lut_stride, PBS_MS_REDUCTION_T noise_reduction_type) {

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
    int block_index = blockIdx.z + blockIdx.y * gridDim.z +
                      blockIdx.x * gridDim.z * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  // We always compute the pointer with most restrictive alignment to avoid
  // alignment issues
  Torus *accumulator = (Torus *)selected_memory;
  Torus *accumulator_rotated =
      (Torus *)accumulator + (ptrdiff_t)(polynomial_size);
  double2 *accumulator_fft =
      (double2 *)(accumulator_rotated) +
      (ptrdiff_t)(polynomial_size * sizeof(Torus) / sizeof(double2));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double2 *)sharedmem;

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  double2 *block_join_buffer =
      &join_buffer[blockIdx.x * level_count * (glwe_dimension + 1) *
                   params::degree / 2];
  // Since the space is L1 cache is small, we use the same memory location for
  // the rotated accumulator and the fft accumulator, since we know that the
  // rotated array is not in use anymore by the time we perform the fft

  // Put "b" in [0, 2N[
  constexpr auto log_modulus = params::log2_degree + 1;
  Torus b_hat = 0;
  Torus correction = 0;
  if (noise_reduction_type == PBS_MS_REDUCTION_T::CENTERED) {
    correction = centered_binary_modulus_switch_body_correction_to_add(
        block_lwe_array_in, lwe_dimension, log_modulus);
  }
  modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                 log_modulus);

  divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                        params::degree / params::opt>(
      accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
      false);

  for (int i = 0; i < lwe_dimension; i++) {
    __syncthreads();

    // Put "a" in [0, 2N[
    Torus a_hat = 0;
    modulus_switch(block_lwe_array_in[i], a_hat, params::log2_degree + 1);

    // Perform ACC * (X^ä - 1)
    multiply_by_monomial_negacyclic_and_sub_polynomial<
        Torus, params::opt, params::degree / params::opt>(
        accumulator, accumulator_rotated, a_hat);

    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace<Torus, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, base_log, level_count);

    __syncthreads();

    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<Torus, params> gadget_acc(base_log, level_count,
                                           accumulator_rotated);
    gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.z);
    NSMFFT_direct<HalfDegree<params>>(accumulator_fft);
    __syncthreads();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_in_fourier_domain<grid_group, params>(
        accumulator_fft, block_join_buffer, bootstrapping_key, i, grid);
    NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
    __syncthreads();

    add_to_torus<Torus, params>(accumulator_fft, accumulator);
  }

  auto block_lwe_array_out =
      &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                         (glwe_dimension * polynomial_size + 1) +
                     blockIdx.y * polynomial_size];

  if (blockIdx.z == 0) {
    if (blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra blocks,
      // in case they're not synchronized
      sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
      if (num_many_lut > 1) {
        for (int i = 1; i < num_many_lut; i++) {
          auto next_lwe_array_out =
              lwe_array_out +
              (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  blockIdx.y * polynomial_size];

          sample_extract_mask<Torus, params>(next_block_lwe_array_out,
                                             accumulator, 1, i * lut_stride);
        }
      }
    } else if (blockIdx.y == glwe_dimension) {
      __syncthreads();
      sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
      if (num_many_lut > 1) {
        for (int i = 1; i < num_many_lut; i++) {

          auto next_lwe_array_out =
              lwe_array_out +
              (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  blockIdx.y * polynomial_size];
          // No need to sync, it is already synchronized before the first
          // sample_extract_body call
          sample_extract_body<Torus, params>(next_block_lwe_array_out,
                                             accumulator, 0, i * lut_stride);
        }
      }
    }
  }
}

template <typename Torus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_cg(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer<Torus, CLASSICAL> **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  cuda_set_device(gpu_index);

  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
          polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg<Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg<Torus, params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<Torus, CLASSICAL>(
      stream, gpu_index, lwe_dimension, glwe_dimension, polynomial_size,
      level_count, input_lwe_ciphertext_count, PBS_VARIANT::CG,
      allocate_gpu_memory, noise_reduction_type, size_tracker);
  return size_tracker;
}

/*
 * Host wrapper
 */
template <typename Torus, class params>
__host__ void host_programmable_bootstrap_cg(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t num_many_lut, uint32_t lut_stride) {
  PANIC_IF_FALSE(sizeof(Torus) == 8,
                 "Error: Programmable bootstrap cg only supports 64-bit "
                 "Torus type.");
  // With SM each block corresponds to either the mask or body, no need to
  // duplicate data for each
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<Torus>(polynomial_size);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<Torus>(
          polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);

  uint64_t full_dm = full_sm;

  uint64_t partial_dm = full_dm - partial_sm;

  int8_t *d_mem = buffer->d_mem;
  double2 *buffer_fft = buffer->global_join_buffer;

  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1, level_count);

  auto noise_reduction_type = buffer->noise_reduction_type;

  void *kernel_args[17];
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
  kernel_args[14] = &num_many_lut;
  kernel_args[15] = &lut_stride;
  kernel_args[16] = &noise_reduction_type;

  if (max_shared_memory < partial_sm) {
    kernel_args[13] = &full_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_programmable_bootstrap_cg<Torus, params, NOSM>, grid,
        thds, (void **)kernel_args, 0, stream));
  } else if (max_shared_memory < full_sm) {
    kernel_args[13] = &partial_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        grid, thds, (void **)kernel_args, partial_sm, stream));
  } else {
    int no_dm = 0;
    kernel_args[13] = &no_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_programmable_bootstrap_cg<Torus, params, FULLSM>, grid,
        thds, (void **)kernel_args, full_sm, stream));
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
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg<Torus, params, NOSM>, thds,
        0));
  } else if (max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg<Torus, params, PARTIALSM>,
        thds, partial_sm));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg<Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg<Torus, params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg<Torus, params, FULLSM>, thds,
        full_sm));
    check_cuda_error(cudaGetLastError());
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
  // If specialized 2_2_params conditions are met, don't use CG (use classic
  // with specialized kernel, less restrictive and better performance)
  bool use_specialized_2_2_params = supports_specialized_2_2_params<Torus>(
      polynomial_size, glwe_dimension, level_count, max_shared_memory);
  if (use_specialized_2_2_params) {
    return false;
  }

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
