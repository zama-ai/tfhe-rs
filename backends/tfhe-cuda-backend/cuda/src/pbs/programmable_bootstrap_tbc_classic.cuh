#ifndef CUDA_TBC_PBS_CUH
#define CUDA_TBC_PBS_CUH

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
__global__ void device_programmable_bootstrap_tbc(
    Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
    const Torus *__restrict__ lut_vector,
    const Torus *__restrict__ lut_vector_indexes,
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes,
    const double2 *__restrict__ bootstrapping_key, double2 *join_buffer,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, int8_t *device_mem,
    uint64_t device_memory_size_per_block, bool support_dsm,
    uint32_t num_many_lut, uint32_t lut_stride, bool uses_noise_reduction) {

  cluster_group cluster = this_cluster();

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;
  uint32_t glwe_dimension = gridDim.y - 1;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
    if (support_dsm)
      selected_memory += sizeof(Torus) * polynomial_size;
  } else {
    int block_index = blockIdx.z + blockIdx.y * gridDim.z +
                      blockIdx.x * gridDim.z * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  Torus *accumulator = (Torus *)selected_memory;
  Torus *accumulator_rotated =
      (Torus *)accumulator + (ptrdiff_t)polynomial_size;
  double2 *accumulator_fft =
      (double2 *)accumulator_rotated +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  if constexpr (SMD == PARTIALSM) {
    accumulator_fft = (double2 *)sharedmem;
    if (support_dsm)
      accumulator_fft += (ptrdiff_t)(polynomial_size / 2);
  }

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const Torus *block_lwe_array_in =
      uses_noise_reduction
          ? &lwe_array_in[blockIdx.x * (lwe_dimension + 1)]
          : &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

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
  uint32_t log_modulus = params::log2_degree + 1;
  Torus b_hat = 0;
  Torus e_mms = centered_binary_modulus_switch_body_correction_to_add(
      block_lwe_array_in, lwe_dimension, log_modulus);
  modulus_switch(block_lwe_array_in[lwe_dimension] + e_mms, b_hat, log_modulus);

  divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                        params::degree / params::opt>(
      accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
      false);

  for (int i = 0; i < lwe_dimension; i++) {
    __syncthreads();

    // Put "a" in [0, 2N[
    Torus a_hat = 0;
    modulus_switch(block_lwe_array_in[i], a_hat,
                   params::log2_degree + 1); // 2 * params::log2_degree + 1);

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
    mul_ggsw_glwe_in_fourier_domain<cluster_group, params>(
        accumulator_fft, block_join_buffer, bootstrapping_key, i, cluster,
        support_dsm);
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

          sample_extract_body<Torus, params>(next_block_lwe_array_out,
                                             accumulator, 0, i * lut_stride);
        }
      }
    }
  }
}

template <typename Torus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_tbc(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer<Torus, CLASSICAL> **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    bool allocate_ms_array) {

  cuda_set_device(gpu_index);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  bool supports_dsm =
      supports_distributed_shared_memory_on_classic_programmable_bootstrap<
          Torus>(polynomial_size, max_shared_memory);

  uint64_t full_sm = get_buffer_size_full_sm_programmable_bootstrap_tbc<Torus>(
      polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_tbc<Torus>(
          polynomial_size);
  uint64_t minimum_sm_tbc = 0;
  if (supports_dsm)
    minimum_sm_tbc =
        get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap<Torus>(
            polynomial_size);

  if (max_shared_memory >= full_sm + minimum_sm_tbc) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_tbc<Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm + minimum_sm_tbc));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_tbc<Torus, params, FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm + minimum_sm_tbc) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_tbc<Torus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        partial_sm + minimum_sm_tbc));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_tbc<Torus, params, PARTIALSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_tbc<Torus, params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, minimum_sm_tbc));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_tbc<Torus, params, NOSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<Torus, CLASSICAL>(
      stream, gpu_index, lwe_dimension, glwe_dimension, polynomial_size,
      level_count, input_lwe_ciphertext_count, PBS_VARIANT::TBC,
      allocate_gpu_memory, allocate_ms_array, size_tracker);
  return size_tracker;
}

/*
 * Host wrapper
 */
template <typename Torus, class params>
__host__ void host_programmable_bootstrap_tbc(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t num_many_lut, uint32_t lut_stride) {
  cuda_set_device(gpu_index);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  auto supports_dsm =
      supports_distributed_shared_memory_on_classic_programmable_bootstrap<
          Torus>(polynomial_size, max_shared_memory);

  // With SM each block corresponds to either the mask or body, no need to
  // duplicate data for each
  uint64_t full_sm = get_buffer_size_full_sm_programmable_bootstrap_tbc<Torus>(
      polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_tbc<Torus>(
          polynomial_size);
  uint64_t minimum_sm_tbc = 0;
  if (supports_dsm)
    minimum_sm_tbc =
        get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap<Torus>(
            polynomial_size);

  uint64_t full_dm = full_sm;

  uint64_t partial_dm = full_dm - partial_sm;

  int8_t *d_mem = buffer->d_mem;
  double2 *buffer_fft = buffer->global_join_buffer;
  bool uses_noise_reduction = buffer->uses_noise_reduction;
  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1, level_count);

  cudaLaunchConfig_t config = {0};
  // The grid dimension is not affected by cluster launch, and is still
  // enumerated using number of blocks. The grid dimension should be a multiple
  // of cluster size.
  config.gridDim = grid;
  config.blockDim = thds;

  cudaLaunchAttribute attribute[1];
  attribute[0].id = cudaLaunchAttributeClusterDimension;
  attribute[0].val.clusterDim.x = 1;
  attribute[0].val.clusterDim.y = (glwe_dimension + 1);
  attribute[0].val.clusterDim.z = level_count; // Cluster size in Z-dimension
  config.attrs = attribute;
  config.numAttrs = 1;
  config.stream = stream;

  if (max_shared_memory < partial_sm + minimum_sm_tbc) {
    config.dynamicSmemBytes = minimum_sm_tbc;

    check_cuda_error(cudaLaunchKernelEx(
        &config, device_programmable_bootstrap_tbc<Torus, params, NOSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, bootstrapping_key, buffer_fft,
        lwe_dimension, polynomial_size, base_log, level_count, d_mem, full_dm,
        supports_dsm, num_many_lut, lut_stride, uses_noise_reduction));
  } else if (max_shared_memory < full_sm + minimum_sm_tbc) {
    config.dynamicSmemBytes = partial_sm + minimum_sm_tbc;

    check_cuda_error(cudaLaunchKernelEx(
        &config, device_programmable_bootstrap_tbc<Torus, params, PARTIALSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, bootstrapping_key, buffer_fft,
        lwe_dimension, polynomial_size, base_log, level_count, d_mem,
        partial_dm, supports_dsm, num_many_lut, lut_stride,
        uses_noise_reduction));
  } else {
    config.dynamicSmemBytes = full_sm + minimum_sm_tbc;

    check_cuda_error(cudaLaunchKernelEx(
        &config, device_programmable_bootstrap_tbc<Torus, params, FULLSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, bootstrapping_key, buffer_fft,
        lwe_dimension, polynomial_size, base_log, level_count, d_mem, 0,
        supports_dsm, num_many_lut, lut_stride, buffer->uses_noise_reduction));
  }
}

// Verify if the grid size satisfies the cooperative group constraints
template <typename Torus, class params>
__host__ bool verify_cuda_programmable_bootstrap_tbc_grid_size(
    int glwe_dimension, int level_count, int num_samples,
    uint32_t max_shared_memory) {

  // If Cooperative Groups is not supported, no need to check anything else
  if (!cuda_check_support_cooperative_groups())
    return false;

  // Calculate the dimension of the kernel
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_tbc<Torus>(params::degree);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_tbc<Torus>(
          params::degree);

  int thds = params::degree / params::opt;

  // Get the maximum number of active blocks per streaming multiprocessors
  int number_of_blocks = level_count * (glwe_dimension + 1) * num_samples;
  int max_active_blocks_per_sm;
  if (max_shared_memory < partial_sm) {
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_tbc<Torus, params, NOSM>, thds,
        0);
  } else if (max_shared_memory < full_sm) {
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_tbc<Torus, params, PARTIALSM>,
        thds, partial_sm);
  } else {
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_tbc<Torus, params, FULLSM>, thds,
        full_sm);
  }

  // Get the number of streaming multiprocessors
  int number_of_sm = 0;
  cudaDeviceGetAttribute(&number_of_sm, cudaDevAttrMultiProcessorCount, 0);
  return number_of_blocks <= max_active_blocks_per_sm * number_of_sm;
}

template <typename Torus>
bool supports_distributed_shared_memory_on_classic_programmable_bootstrap(
    uint32_t polynomial_size, uint32_t max_shared_memory) {
  uint64_t minimum_sm =
      get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap<Torus>(
          polynomial_size);

  if (max_shared_memory < minimum_sm) {
    // If we cannot store a single polynomial in a block shared memory we cannot
    // use TBC
    return false;
  } else {
    return cuda_check_support_thread_block_clusters();
  }
}

template <typename Torus, class params>
__host__ bool supports_thread_block_clusters_on_classic_programmable_bootstrap(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory) {

  if (!cuda_check_support_thread_block_clusters() || num_samples > 128)
    return false;

  uint64_t full_sm = get_buffer_size_full_sm_programmable_bootstrap_tbc<Torus>(
      polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_tbc<Torus>(
          polynomial_size);
  uint64_t minimum_sm_tbc = 0;
  if (supports_distributed_shared_memory_on_classic_programmable_bootstrap<
          Torus>(polynomial_size, max_shared_memory))
    minimum_sm_tbc =
        get_buffer_size_sm_dsm_plus_tbc_classic_programmable_bootstrap<Torus>(
            polynomial_size);

  int cluster_size;

  dim3 grid_accumulate(num_samples, glwe_dimension + 1, level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  cudaLaunchConfig_t config = {0};
  // The grid dimension is not affected by cluster launch, and is still
  // enumerated using number of blocks. The grid dimension should be a multiple
  // of cluster size.
  config.gridDim = grid_accumulate;
  config.blockDim = thds;
  config.numAttrs = 0;

  /* Despite the documentation stating that we could have cluster sizes up to 16
   * on H100s if we enable non-portable cluster sizes, this doesn't seem the
   * case and it will fail if we try. Thus, since level_count *
   * (glwe_dimension+1) is usually smaller than 8 at this moment, we will
   * disable cudaFuncAttributeNonPortableClusterSizeAllowed */
  if (max_shared_memory < partial_sm + minimum_sm_tbc) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_tbc<Torus, params, NOSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size, device_programmable_bootstrap_tbc<Torus, params, NOSM>,
        &config));
  } else if (max_shared_memory < full_sm + minimum_sm_tbc) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_tbc<Torus, params, PARTIALSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size,
        device_programmable_bootstrap_tbc<Torus, params, PARTIALSM>, &config));
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_tbc<Torus, params, FULLSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size, device_programmable_bootstrap_tbc<Torus, params, FULLSM>,
        &config));
  }

  return cluster_size >= level_count * (glwe_dimension + 1);
}

#endif // CG_PBS_H
