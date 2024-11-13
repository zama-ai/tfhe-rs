#ifndef CUDA_TBC_MULTIBIT_PBS_CUH
#define CUDA_TBC_MULTIBIT_PBS_CUH

#include "cooperative_groups.h"
#include "crypto/gadget.cuh"
#include "crypto/ggsw.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "pbs/pbs_multibit_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "programmable_bootstrap.cuh"
#include "types/complex/operations.cuh"
#include <vector>

template <typename Torus, class params, sharedMemDegree SMD>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_tbc_accumulate(
        Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
        const Torus *__restrict__ lut_vector,
        const Torus *__restrict__ lut_vector_indexes,
        const Torus *__restrict__ lwe_array_in,
        const Torus *__restrict__ lwe_input_indexes,
        const double2 *__restrict__ keybundle_array, double2 *join_buffer,
        Torus *global_accumulator, uint32_t lwe_dimension,
        uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
        uint32_t level_count, uint32_t grouping_factor, uint32_t lwe_offset,
        uint32_t lwe_chunk_size, uint32_t keybundle_size_per_input,
        int8_t *device_mem, uint64_t device_memory_size_per_block,
        bool support_dsm, uint32_t lut_count, uint32_t lut_stride) {

  cluster_group cluster = this_cluster();

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  if constexpr (SMD == FULLSM) {
    // The first (polynomial_size/2) * sizeof(double2) bytes are reserved for
    // external product using distributed shared memory
    selected_memory = sharedmem;
    if (support_dsm)
      selected_memory += sizeof(Torus) * polynomial_size;
  } else {
    int block_index = blockIdx.x + blockIdx.y * gridDim.x +
                      blockIdx.z * gridDim.x * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  Torus *accumulator_rotated = (Torus *)selected_memory;
  double2 *accumulator_fft =
      (double2 *)accumulator_rotated +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  if constexpr (SMD == PARTIALSM) {
    accumulator_fft = (double2 *)sharedmem;
    if (support_dsm)
      accumulator_fft += sizeof(double2) * (polynomial_size / 2);
  }

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.z] * (lwe_dimension + 1)];

  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.z] * params::degree *
                  (glwe_dimension + 1)];

  double2 *block_join_buffer =
      &join_buffer[blockIdx.z * level_count * (glwe_dimension + 1) *
                   params::degree / 2];

  Torus *global_accumulator_slice =
      &global_accumulator[(blockIdx.y + blockIdx.z * (glwe_dimension + 1)) *
                          params::degree];

  const double2 *keybundle =
      &keybundle_array[blockIdx.z * keybundle_size_per_input];

  if (lwe_offset == 0) {
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                   params::log2_degree + 1);

    divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                          params::degree / params::opt>(
        accumulator_rotated, &block_lut_vector[blockIdx.y * params::degree],
        b_hat, false);
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        global_accumulator_slice, accumulator_rotated);
  }

  for (int i = 0; (i + lwe_offset) < lwe_dimension && i < lwe_chunk_size; i++) {
    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace<Torus, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, base_log, level_count);

    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<Torus, params> gadget_acc(base_log, level_count,
                                           accumulator_rotated);
    gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.x);
    NSMFFT_direct<HalfDegree<params>>(accumulator_fft);
    synchronize_threads_in_block();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_in_fourier_domain<cluster_group, params>(
        accumulator_fft, block_join_buffer, keybundle, i, cluster, support_dsm);
    NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
    synchronize_threads_in_block();

    add_to_torus<Torus, params>(accumulator_fft, accumulator_rotated, true);
  }

  auto accumulator = accumulator_rotated;

  if (blockIdx.x == 0) {
    if (lwe_offset + lwe_chunk_size >= (lwe_dimension / grouping_factor)) {
      auto block_lwe_array_out =
          &lwe_array_out[lwe_output_indexes[blockIdx.z] *
                             (glwe_dimension * polynomial_size + 1) +
                         blockIdx.y * polynomial_size];

      if (blockIdx.y < glwe_dimension) {
        // Perform a sample extract. At this point, all blocks have the result,
        // but we do the computation at block 0 to avoid waiting for extra
        // blocks, in case they're not synchronized
        sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);

        if (lut_count > 1) {
          for (int i = 1; i < lut_count; i++) {
            auto next_lwe_array_out =
                lwe_array_out +
                (i * gridDim.z * (glwe_dimension * polynomial_size + 1));
            auto next_block_lwe_array_out =
                &next_lwe_array_out[lwe_output_indexes[blockIdx.z] *
                                        (glwe_dimension * polynomial_size + 1) +
                                    blockIdx.y * polynomial_size];

            sample_extract_mask<Torus, params>(next_block_lwe_array_out,
                                               accumulator, 1, i * lut_stride);
          }
        }
      } else if (blockIdx.y == glwe_dimension) {
        sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
        if (lut_count > 1) {
          for (int i = 1; i < lut_count; i++) {

            auto next_lwe_array_out =
                lwe_array_out +
                (i * gridDim.z * (glwe_dimension * polynomial_size + 1));
            auto next_block_lwe_array_out =
                &next_lwe_array_out[lwe_output_indexes[blockIdx.z] *
                                        (glwe_dimension * polynomial_size + 1) +
                                    blockIdx.y * polynomial_size];

            sample_extract_body<Torus, params>(next_block_lwe_array_out,
                                               accumulator, 0, i * lut_stride);
          }
        }
      }
    } else {
      // Load the accumulator calculated in previous iterations
      copy_polynomial<Torus, params::opt, params::degree / params::opt>(
          accumulator, global_accumulator_slice);
    }
  }
}

template <typename Torus>
uint64_t get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size; // distributed shared memory
}

template <typename Torus>
uint64_t get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size; // accumulator
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size * 2; // accumulator
}

template <typename Torus, typename params>
__host__ void scratch_tbc_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  bool supports_dsm =
      supports_distributed_shared_memory_on_multibit_programmable_bootstrap<
          Torus>(polynomial_size);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_tbc_accumulate =
      get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_sm_tbc_accumulate =
      get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t minimum_sm_tbc_accumulate = 0;
  if (supports_dsm)
    minimum_sm_tbc_accumulate =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

  int max_shared_memory = cuda_get_max_shared_memory(0);

  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  if (max_shared_memory <
      partial_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        minimum_sm_tbc_accumulate));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory <
             full_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        partial_sm_tbc_accumulate + minimum_sm_tbc_accumulate));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_tbc_accumulate + minimum_sm_tbc_accumulate));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  auto lwe_chunk_size = get_lwe_chunk_size<Torus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size);
  *buffer = new pbs_buffer<uint64_t, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, lwe_chunk_size, PBS_VARIANT::TBC,
      allocate_gpu_memory);
}

template <typename Torus, class params>
__host__ void execute_tbc_external_product_loop(
    cudaStream_t stream, uint32_t gpu_index, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, pbs_buffer<Torus, MULTI_BIT> *buffer,
    uint32_t num_samples, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t lwe_offset, uint32_t lut_count,
    uint32_t lut_stride) {

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  auto supports_dsm =
      supports_distributed_shared_memory_on_multibit_programmable_bootstrap<
          Torus>(polynomial_size);

  uint64_t full_dm =
      get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_dm =
      get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t minimum_dm = 0;
  if (supports_dsm)
    minimum_dm =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

  int max_shared_memory = cuda_get_max_shared_memory(0);
  cudaSetDevice(gpu_index);

  uint32_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2);

  uint32_t chunk_size =
      std::min(lwe_chunk_size, (lwe_dimension / grouping_factor) - lwe_offset);

  auto d_mem = buffer->d_mem_acc_tbc;
  auto keybundle_fft = buffer->keybundle_fft;
  auto global_accumulator = buffer->global_accumulator;
  auto buffer_fft = buffer->global_join_buffer;

  dim3 grid_accumulate(level_count, glwe_dimension + 1, num_samples);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  cudaLaunchConfig_t config = {0};
  // The grid dimension is not affected by cluster launch, and is still
  // enumerated using number of blocks. The grid dimension should be a multiple
  // of cluster size.
  config.gridDim = grid_accumulate;
  config.blockDim = thds;

  cudaLaunchAttribute attribute[1];
  attribute[0].id = cudaLaunchAttributeClusterDimension;
  attribute[0].val.clusterDim.x = level_count; // Cluster size in X-dimension
  attribute[0].val.clusterDim.y = (glwe_dimension + 1);
  attribute[0].val.clusterDim.z = 1;
  config.attrs = attribute;
  config.numAttrs = 1;
  config.stream = stream;

  if (max_shared_memory < partial_dm + minimum_dm) {
    config.dynamicSmemBytes = minimum_dm;
    check_cuda_error(cudaLaunchKernelEx(
        &config,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, keybundle_fft, buffer_fft,
        global_accumulator, lwe_dimension, glwe_dimension, polynomial_size,
        base_log, level_count, grouping_factor, lwe_offset, chunk_size,
        keybundle_size_per_input, d_mem, full_dm, supports_dsm, lut_count,
        lut_stride));
  } else if (max_shared_memory < full_dm + minimum_dm) {
    config.dynamicSmemBytes = partial_dm + minimum_dm;
    check_cuda_error(cudaLaunchKernelEx(
        &config,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, keybundle_fft, buffer_fft,
        global_accumulator, lwe_dimension, glwe_dimension, polynomial_size,
        base_log, level_count, grouping_factor, lwe_offset, chunk_size,
        keybundle_size_per_input, d_mem, partial_dm, supports_dsm, lut_count,
        lut_stride));
  } else {
    config.dynamicSmemBytes = full_dm + minimum_dm;
    check_cuda_error(cudaLaunchKernelEx(
        &config,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               FULLSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, keybundle_fft, buffer_fft,
        global_accumulator, lwe_dimension, glwe_dimension, polynomial_size,
        base_log, level_count, grouping_factor, lwe_offset, chunk_size,
        keybundle_size_per_input, d_mem, 0, supports_dsm, lut_count,
        lut_stride));
  }
}

template <typename Torus, class params>
__host__ void host_tbc_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t lut_count, uint32_t lut_stride) {
  cudaSetDevice(gpu_index);

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  for (uint32_t lwe_offset = 0; lwe_offset < (lwe_dimension / grouping_factor);
       lwe_offset += lwe_chunk_size) {

    // Compute a keybundle
    execute_compute_keybundle<Torus, params>(
        stream, gpu_index, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        buffer, num_samples, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, level_count, lwe_offset);

    // Accumulate
    execute_tbc_external_product_loop<Torus, params>(
        stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, lwe_array_out, lwe_output_indexes, buffer,
        num_samples, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, lwe_offset, lut_count,
        lut_stride);
  }
}

template <typename Torus>
bool supports_distributed_shared_memory_on_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  uint64_t minimum_sm =
      get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);

  int max_shared_memory = cuda_get_max_shared_memory(0);
  if (max_shared_memory <= minimum_sm) {
    // If we cannot store a single polynomial in a block shared memory we
    // cannot use TBC
    return false;
  } else {
    return cuda_check_support_thread_block_clusters();
  }
}

template <typename Torus, class params>
__host__ bool supports_thread_block_clusters_on_multibit_programmable_bootstrap(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count) {

  if (!cuda_check_support_thread_block_clusters())
    return false;

  uint64_t full_sm_tbc_accumulate =
      get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_sm_tbc_accumulate =
      get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t minimum_sm_tbc_accumulate = 0;
  if (supports_distributed_shared_memory_on_multibit_programmable_bootstrap<
          Torus>(polynomial_size))
    minimum_sm_tbc_accumulate =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

  int cluster_size;

  dim3 grid_accumulate(level_count, glwe_dimension + 1, num_samples);
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
  int max_shared_memory = cuda_get_max_shared_memory(0);
  if (max_shared_memory <
      partial_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        &config));
  } else if (max_shared_memory <
             full_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        &config));
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               FULLSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               FULLSM>,
        &config));
  }

  return cluster_size >= level_count * (glwe_dimension + 1);
}

template bool
supports_distributed_shared_memory_on_multibit_programmable_bootstrap<uint64_t>(
    uint32_t polynomial_size);
#endif // FASTMULTIBIT_PBS_H
