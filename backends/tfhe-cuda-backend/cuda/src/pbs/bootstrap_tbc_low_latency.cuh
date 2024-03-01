#ifndef CUDA_TBC_LOWLAT_PBS_CUH
#define CUDA_TBC_LOWLAT_PBS_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "bootstrap.cuh"
#include "bootstrap.h"
#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "types/complex/operations.cuh"

#include "cooperative_groups.h"

using namespace cooperative_groups;
namespace cg = cooperative_groups;

/*
 * Kernel launched by the low latency version of the
 * bootstrapping, that uses cooperative groups
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
__global__ void device_bootstrap_tbc_low_latency(
    Torus *lwe_array_out, Torus *lwe_output_indexes, Torus *lut_vector,
    Torus *lut_vector_indexes, Torus *lwe_array_in, Torus *lwe_input_indexes,
    double2 *bootstrapping_key, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    int8_t *device_mem, uint64_t device_memory_size_per_block) {
#if __CUDA_ARCH__ >= 900
  cluster_group grid = this_cluster();

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
  // The first (polynomial_size/2) * sizeof(double2) bytes are reserved for
  // external product using distributed shared memory
  double2 *accumulator_fft = (double2 *)selected_memory + polynomial_size / 2;
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
    mul_ggsw_glwe_dsm<Torus, params>(accumulator, accumulator_fft,
                                     bootstrapping_key, polynomial_size,
                                     glwe_dimension, level_count, i);

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
#else
  printf("PANIC: CUDA Architecture must be greater or equal 900\n");
#endif
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_bootstrap_tbc_low_latency(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size +      // accumulator_rotated
         sizeof(Torus) * polynomial_size +      // accumulator
         sizeof(Torus) * polynomial_size +      // mul_glwe_ggsw_dsm
         sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_bootstrap_tbc_low_latency(uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2 // accumulator fft mask & body
         + sizeof(Torus) * polynomial_size;    // mul_glwe_ggsw_dsm
}

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_bootstrap_tbc_low_latency(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {

  uint64_t full_sm =
      get_buffer_size_full_sm_bootstrap_tbc_low_latency<Torus>(polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_bootstrap_tbc_low_latency<Torus>(
          polynomial_size);
  uint64_t partial_dm = full_sm - partial_sm;
  uint64_t full_dm = full_sm;
  uint64_t device_mem = 0;
  if (max_shared_memory < partial_sm) {
    device_mem = full_dm * input_lwe_ciphertext_count * level_count *
                 (glwe_dimension + 1);
  } else if (max_shared_memory < full_sm) {
    device_mem = partial_dm * input_lwe_ciphertext_count * level_count *
                 (glwe_dimension + 1);
  }
  uint64_t buffer_size = device_mem + (glwe_dimension + 1) * level_count *
                                          input_lwe_ciphertext_count *
                                          polynomial_size / 2 * sizeof(double2);
  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus, typename STorus, typename params>
__host__ void scratch_bootstrap_tbc_low_latency(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {
  cudaSetDevice(stream->gpu_index);

  uint64_t full_sm =
      get_buffer_size_full_sm_bootstrap_tbc_low_latency<Torus>(polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_bootstrap_tbc_low_latency<Torus>(
          polynomial_size);
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_bootstrap_tbc_low_latency<Torus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    cudaFuncSetCacheConfig(
        device_bootstrap_tbc_low_latency<Torus, params, PARTIALSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_bootstrap_tbc_low_latency<Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    cudaFuncSetCacheConfig(
        device_bootstrap_tbc_low_latency<Torus, params, FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else {
    uint64_t no_sm = sizeof(Torus) * polynomial_size;
    check_cuda_error(cudaFuncSetAttribute(
        device_bootstrap_tbc_low_latency<Torus, params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, no_sm));
    cudaFuncSetCacheConfig(
        device_bootstrap_tbc_low_latency<Torus, params, NOSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  if (allocate_gpu_memory) {
    uint64_t buffer_size = get_buffer_size_bootstrap_tbc_low_latency<Torus>(
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, max_shared_memory);
    *pbs_buffer = (int8_t *)cuda_malloc_async(buffer_size, stream);
    check_cuda_error(cudaGetLastError());
  }
}

/*
 * Host wrapper to the low latency version
 * of bootstrapping
 */
template <typename Torus, class params>
__host__ void host_bootstrap_tbc_low_latency(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, double2 *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t glwe_dimension, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t num_luts,
    uint32_t max_shared_memory) {
  cudaSetDevice(stream->gpu_index);

  // With SM each block corresponds to either the mask or body, no need to
  // duplicate data for each
  uint64_t full_sm =
      get_buffer_size_full_sm_bootstrap_tbc_low_latency<Torus>(polynomial_size);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_bootstrap_tbc_low_latency<Torus>(
          polynomial_size);

  uint64_t full_dm = full_sm;
  uint64_t partial_dm = full_dm - partial_sm;

  int8_t *d_mem = pbs_buffer;

  int thds = polynomial_size / params::opt;
  dim3 grid(level_count, glwe_dimension + 1, input_lwe_ciphertext_count);

  cudaLaunchConfig_t config = {0};
  // The grid dimension is not affected by cluster launch, and is still
  // enumerated using number of blocks. The grid dimension should be a multiple
  // of cluster size.
  config.gridDim = grid;
  config.blockDim = thds;

  cudaLaunchAttribute attribute[1];
  attribute[0].id = cudaLaunchAttributeClusterDimension;
  attribute[0].val.clusterDim.x = 1; // Cluster size in X-dimension
  attribute[0].val.clusterDim.y = (glwe_dimension + 1);
  attribute[0].val.clusterDim.z = 1;
  config.attrs = attribute;
  config.numAttrs = 1;
  config.stream = stream->stream;

  if (max_shared_memory < partial_sm) {
    config.dynamicSmemBytes = sizeof(Torus) * polynomial_size;

    check_cuda_error(cudaLaunchKernelEx(
        &config, device_bootstrap_tbc_low_latency<Torus, params, NOSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
        polynomial_size, base_log, level_count, d_mem, full_dm));

  } else if (max_shared_memory < full_sm) {
    config.dynamicSmemBytes = partial_sm;

    check_cuda_error(cudaLaunchKernelEx(
        &config, device_bootstrap_tbc_low_latency<Torus, params, PARTIALSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
        polynomial_size, base_log, level_count, d_mem, partial_dm));
  } else {
    config.dynamicSmemBytes = full_sm;

    check_cuda_error(cudaLaunchKernelEx(
        &config, device_bootstrap_tbc_low_latency<Torus, params, FULLSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
        polynomial_size, base_log, level_count, d_mem, 0));
  }

  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ bool supports_thread_block_clusters_on_lowlat_pbs(uint32_t polynomial_size, uint32_t max_shared_memory) {
    uint64_t no_sm = sizeof(Torus) * polynomial_size;

    if (max_shared_memory <= no_sm) {
        // If we cannot store a single polynomial in a block shared memory we cannot use TBC
        return false;
    } else {
        return cuda_check_support_thread_block_clusters();
    }

}

#endif // LOWLAT_TBC_PBS_H
