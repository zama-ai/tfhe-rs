#ifndef CUDA_TBC_MULTIBIT_PBS_CUH
#define CUDA_TBC_MULTIBIT_PBS_CUH

#include "bootstrap.h"
#include "bootstrap_multibit.cuh"
#include "crypto/gadget.cuh"
#include "crypto/ggsw.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "types/complex/operations.cuh"
#include <vector>

#include "cooperative_groups.h"

using namespace cooperative_groups;
namespace cg = cooperative_groups;

template <typename Torus, class params>
__global__ void device_multi_bit_bootstrap_tbc_accumulate(
    Torus *lwe_array_out, Torus *lwe_output_indexes, Torus *lut_vector,
    Torus *lut_vector_indexes, Torus *lwe_array_in, Torus *lwe_input_indexes,
    double2 *keybundle_array, Torus *global_accumulator, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t grouping_factor, uint32_t lwe_offset,
    uint32_t lwe_chunk_size, uint32_t keybundle_size_per_input) {
#if __CUDA_ARCH__ >= 900
  cluster_group cluster = this_cluster();

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much tbder than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  selected_memory = sharedmem;

  // We always compute the pointer with most restrictive alignment to avoid
  // alignment issues
  // The first (polynomial_size/2) * sizeof(double2) bytes are reserved for
  // external product using distributed shared memory
  Torus *accumulator = (Torus *)selected_memory + polynomial_size;
  double2 *accumulator_fft =
      (double2 *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.z] * (lwe_dimension + 1)];

  Torus *block_lut_vector = &lut_vector[lut_vector_indexes[blockIdx.z] *
                                        params::degree * (glwe_dimension + 1)];

  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.z * (glwe_dimension + 1)) * params::degree;

  double2 *keybundle = keybundle_array +
                       // select the input
                       blockIdx.z * keybundle_size_per_input;

  if (lwe_offset == 0) {
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    rescale_torus_element(block_lwe_array_in[lwe_dimension], b_hat,
                          2 * params::degree);

    divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                          params::degree / params::opt>(
        accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
        false);
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        global_slice, accumulator);
  }

  for (int i = 0; (i + lwe_offset) < lwe_dimension && i < lwe_chunk_size; i++) {
    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    round_to_closest_multiple_inplace<Torus, params::opt,
                                      params::degree / params::opt>(
        accumulator, base_log, level_count);

    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<Torus, params> gadget_acc(base_log, level_count, accumulator);
    gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.x);

    // We are using the same memory space for accumulator_fft and
    // accumulator_rotated, so we need to synchronize here to make sure they
    // don't modify the same memory space at the same time
    synchronize_threads_in_block();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_dsm<Torus, params>(accumulator, accumulator_fft, keybundle,
                                     polynomial_size, glwe_dimension,
                                     level_count, i);

    synchronize_threads_in_block();
  }

  if (lwe_offset + lwe_chunk_size >= (lwe_dimension / grouping_factor)) {
    auto block_lwe_array_out =
        &lwe_array_out[lwe_output_indexes[blockIdx.z] *
                           (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.x == 0 && blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra blocks,
      // in case they're not synchronized
      sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
    } else if (blockIdx.x == 0 && blockIdx.y == glwe_dimension) {
      sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
    }
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        accumulator, global_slice);
  }
#else
  printf("PANIC: CUDA Architecture must be greater or equal 900\n");
#endif
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_tbc_multibit_bootstrap(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size * 3; // accumulator
}

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_tbc_multibit_bootstrap(
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t grouping_factor, uint32_t lwe_chunk_size,
    uint32_t max_shared_memory) {

  uint64_t buffer_size = 0;
  buffer_size += input_lwe_ciphertext_count * lwe_chunk_size * level_count *
                 (glwe_dimension + 1) * (glwe_dimension + 1) *
                 (polynomial_size / 2) * sizeof(double2); // keybundle fft
  buffer_size += input_lwe_ciphertext_count * (glwe_dimension + 1) *
                 polynomial_size * sizeof(Torus); // global_accumulator

  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus, typename STorus, typename params>
__host__ void scratch_tbc_multi_bit_pbs(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t grouping_factor,
    uint32_t max_shared_memory, bool allocate_gpu_memory,
    uint32_t lwe_chunk_size = 0) {

  cudaSetDevice(stream->gpu_index);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate =
      get_buffer_size_full_sm_tbc_multibit_bootstrap<Torus>(polynomial_size);

  check_cuda_error(cudaFuncSetAttribute(
      device_multi_bit_bootstrap_keybundle<Torus, params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
  cudaFuncSetCacheConfig(device_multi_bit_bootstrap_keybundle<Torus, params>,
                         cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  check_cuda_error(cudaFuncSetAttribute(
      device_multi_bit_bootstrap_tbc_accumulate<Torus, params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_accumulate));
  cudaFuncSetCacheConfig(
      device_multi_bit_bootstrap_tbc_accumulate<Torus, params>,
      cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  if (allocate_gpu_memory) {
    if (!lwe_chunk_size)
      lwe_chunk_size =
          get_average_lwe_chunk_size(lwe_dimension, level_count, glwe_dimension,
                                     input_lwe_ciphertext_count);

    uint64_t buffer_size = get_buffer_size_tbc_multibit_bootstrap<Torus>(
        lwe_dimension, glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, grouping_factor, lwe_chunk_size,
        max_shared_memory);
    *pbs_buffer = (int8_t *)cuda_malloc_async(buffer_size, stream);
    check_cuda_error(cudaGetLastError());
  }
}

template <typename Torus, typename STorus, class params>
__host__ void host_tbc_multi_bit_pbs(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, uint64_t *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t glwe_dimension, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0) {
  cudaSetDevice(stream->gpu_index);

  if (!lwe_chunk_size)
    lwe_chunk_size = get_average_lwe_chunk_size(lwe_dimension, level_count,
                                                glwe_dimension, num_samples);

  //
  double2 *keybundle_fft = (double2 *)pbs_buffer;
  Torus *global_accumulator =
      (Torus *)keybundle_fft +
      (ptrdiff_t)(sizeof(double2) * num_samples * lwe_chunk_size * level_count *
                  (glwe_dimension + 1) * (glwe_dimension + 1) *
                  (polynomial_size / 2) / sizeof(Torus));

  //
  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate =
      get_buffer_size_full_sm_tbc_multibit_bootstrap<Torus>(polynomial_size);

  uint32_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2);

  //
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
  attribute[0].val.clusterDim.x = 1; // Cluster size in X-dimension
  attribute[0].val.clusterDim.y = (glwe_dimension + 1);
  attribute[0].val.clusterDim.z = 1;
  config.attrs = attribute;
  config.numAttrs = 1;
  config.dynamicSmemBytes = full_sm_accumulate;
  config.stream = stream->stream;

  for (uint32_t lwe_offset = 0; lwe_offset < (lwe_dimension / grouping_factor);
       lwe_offset += lwe_chunk_size) {

    uint32_t chunk_size = std::min(
        lwe_chunk_size, (lwe_dimension / grouping_factor) - lwe_offset);

    // Compute a keybundle
    dim3 grid_keybundle(num_samples * chunk_size,
                        (glwe_dimension + 1) * (glwe_dimension + 1),
                        level_count);
    device_multi_bit_bootstrap_keybundle<Torus, params>
        <<<grid_keybundle, thds, full_sm_keybundle, stream->stream>>>(
            lwe_array_in, lwe_input_indexes, keybundle_fft, bootstrapping_key,
            lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
            base_log, level_count, lwe_offset, chunk_size,
            keybundle_size_per_input);
    check_cuda_error(cudaGetLastError());

    check_cuda_error(cudaLaunchKernelEx(
        &config, device_multi_bit_bootstrap_tbc_accumulate<Torus, params>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, keybundle_fft, global_accumulator,
        lwe_dimension, glwe_dimension, polynomial_size, base_log, level_count,
        grouping_factor, lwe_offset, chunk_size, keybundle_size_per_input));
  }
}

template <typename Torus>
__host__ bool supports_thread_block_clusters_on_multibit_pbs(uint32_t polynomial_size, uint32_t max_shared_memory) {
    uint64_t no_sm = sizeof(Torus) * polynomial_size;

    if (max_shared_memory <= no_sm) {
        // If we cannot store a single polynomial in a block shared memory we cannot use TBC
        return false;
    } else {
        return cuda_check_support_thread_block_clusters();
    }
}
#endif // TBDMULTIBIT_PBS_H
