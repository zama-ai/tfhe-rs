#ifndef CUDA_PROGRAMMABLE_BOOTSTRAP_CUH
#define CUDA_PROGRAMMABLE_BOOTSTRAP_CUH

#include "bootstrapping_key.cuh"
#include "ciphertext.h"
#include "cooperative_groups.h"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "helper_multi_gpu.h"
#include "pbs/programmable_bootstrap_multibit.h"
#include "polynomial/polynomial_math.cuh"

using namespace cooperative_groups;
namespace cg = cooperative_groups;

template <typename G>
__device__ int get_this_block_rank(G &group, bool support_dsm);

template <typename G>
__device__ double2 *
get_join_buffer_element(int level_id, int glwe_id, G &group,
                        double2 *global_memory_buffer, uint32_t polynomial_size,
                        uint32_t glwe_dimension, bool support_dsm);

template <typename G, uint32_t level_id, uint32_t glwe_dimension>
__device__ __forceinline__ double2 *
get_join_buffer_element_tbc(int glwe_id, G &cluster,
                            double2 *shared_memory_buffer) {
  double2 *buffer_slice;
  buffer_slice = cluster.map_shared_rank(
      shared_memory_buffer, glwe_id + level_id * (glwe_dimension + 1));
  return buffer_slice;
}

template <typename G>
__device__ double *get_join_buffer_element_128(
    int level_id, int glwe_id, G &group, double *global_memory_buffer,
    uint32_t polynomial_size, uint32_t glwe_dimension, bool support_dsm);

/** Perform the matrix multiplication between the GGSW and the GLWE,
 * each block operating on a single level for mask and body.
 * Both operands should be at fourier domain
 *
 * This function assumes:
 *  - Thread blocks at dimension z relates to the decomposition level.
 *  - Thread blocks at dimension y relates to the glwe dimension.
 *  - polynomial_size / params::opt threads are available per block
 */
template <typename G, class params>
__device__ void
mul_ggsw_glwe_in_fourier_domain(double2 *fft, double2 *join_buffer,
                                const double2 *__restrict__ bootstrapping_key,
                                int iteration, G &group,
                                bool support_dsm = false) {
  const uint32_t polynomial_size = params::degree;
  const uint32_t glwe_dimension = gridDim.y - 1;
  const uint32_t level_count = gridDim.z;

  // The first product is used to initialize level_join_buffer
  auto this_block_rank = get_this_block_rank<G>(group, support_dsm);

  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  auto bsk_slice = get_ith_mask_kth_block(
      bootstrapping_key, iteration, blockIdx.y, blockIdx.z, polynomial_size,
      glwe_dimension, level_count);
  for (int j = 0; j < glwe_dimension + 1; j++) {
    int idx = (j + this_block_rank) % (glwe_dimension + 1);

    auto bsk_poly = bsk_slice + idx * polynomial_size / 2;
    auto buffer_slice = get_join_buffer_element<G>(blockIdx.z, idx, group,
                                                   join_buffer, polynomial_size,
                                                   glwe_dimension, support_dsm);

    polynomial_product_accumulate_in_fourier_domain<params, double2>(
        buffer_slice, fft, bsk_poly, j == 0);
    group.sync();
  }

  // -----------------------------------------------------------------
  // All blocks are synchronized here; after this sync, level_join_buffer has
  // the values needed from every other block

  // accumulate rest of the products into fft buffer
  for (int l = 0; l < level_count; l++) {
    auto cur_src_acc = get_join_buffer_element<G>(l, blockIdx.y, group,
                                                  join_buffer, polynomial_size,
                                                  glwe_dimension, support_dsm);

    polynomial_accumulate_in_fourier_domain<params>(fft, cur_src_acc, l == 0);
  }

  __syncthreads();
}

/** Perform the matrix multiplication between the GGSW and the GLWE,
 * each block operating on a single level for mask and body.
 * Both operands should be at fourier domain
 *
 * This function assumes:
 *  - Thread blocks at dimension z relates to the decomposition level.
 *  - Thread blocks at dimension y relates to the glwe dimension.
 *  - polynomial_size / params::opt threads are available per block
 */
template <typename G, class params>
__device__ void mul_ggsw_glwe_in_fourier_domain_128(
    double *fft, double *join_buffer,
    const double *__restrict__ bootstrapping_key, int iteration, G &group,
    bool support_dsm = false) {
  const uint32_t polynomial_size = params::degree;
  const uint32_t glwe_dimension = gridDim.y - 1;
  const uint32_t level_count = gridDim.z;

  // The first product is used to initialize level_join_buffer
  auto this_block_rank = get_this_block_rank<G>(group, support_dsm);

  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  auto bsk_slice = get_ith_mask_kth_block_128(
      bootstrapping_key, iteration, blockIdx.y, blockIdx.z, polynomial_size,
      glwe_dimension, level_count);
  for (int j = 0; j < glwe_dimension + 1; j++) {
    int idx = (j + this_block_rank) % (glwe_dimension + 1);

    auto bsk_poly = bsk_slice + idx * polynomial_size / 2 * 4;
    auto buffer_slice = get_join_buffer_element_128<G>(
        blockIdx.z, idx, group, join_buffer, polynomial_size, glwe_dimension,
        support_dsm);

    polynomial_product_accumulate_in_fourier_domain_128<params>(
        buffer_slice, fft, bsk_poly, j == 0);
    group.sync();
  }

  // -----------------------------------------------------------------
  // All blocks are synchronized here; after this sync, level_join_buffer has
  // the values needed from every other block

  // accumulate rest of the products into fft buffer
  for (int l = 0; l < level_count; l++) {
    auto cur_src_acc = get_join_buffer_element_128<G>(
        l, blockIdx.y, group, join_buffer, polynomial_size, glwe_dimension,
        support_dsm);

    polynomial_accumulate_in_fourier_domain_128<params>(fft, cur_src_acc,
                                                        l == 0);
  }

  __syncthreads();
}

/** Perform the matrix multiplication between the GGSW and the GLWE,
 * each block operating on a single level for mask and body.
 * Both operands should be at fourier domain
 *
 * This function assumes that 2_2 params are used:
 *  - Thread blocks at dimension z relates to the decomposition level.
 *  - Thread blocks at dimension y relates to the glwe dimension.
 *  - polynomial_size / params::opt threads are available per block
 */
template <typename G, class params, uint32_t polynomial_size,
          uint32_t glwe_dimension, uint32_t level_count>
__device__ void mul_ggsw_glwe_in_fourier_domain_2_2_params(
    double2 *fft, double2 *join_buffer,
    const double2 *__restrict__ bootstrapping_key, int iteration, G &group,
    int this_block_rank) {
  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  // We accumulate in registers to free shared memory
  double2 buffer_regs[params::opt / 2];
  // In 2_2 params we only have one level
  constexpr uint32_t level_id = 0;
  // The first product doesn't need using dsm
  auto bsk_slice =
      get_ith_mask_kth_block_2_2_params<double2, polynomial_size,
                                        glwe_dimension, level_count, level_id>(
          bootstrapping_key, iteration, this_block_rank);
  auto bsk_poly = bsk_slice + blockIdx.y * polynomial_size / 2;
  polynomial_product_accumulate_in_fourier_domain_2_2_params<params, double2,
                                                             true>(
      buffer_regs, fft, bsk_poly);

  // Synchronize to ensure all blocks have written its fft result
  group.sync();
  constexpr uint32_t glwe_id = 1;
  int idx = (glwe_id + this_block_rank) % (glwe_dimension + 1);
  bsk_slice =
      get_ith_mask_kth_block_2_2_params<double2, polynomial_size,
                                        glwe_dimension, level_count, level_id>(
          bootstrapping_key, iteration, idx);
  bsk_poly = bsk_slice + blockIdx.y * polynomial_size / 2;
  auto fft_slice =
      get_join_buffer_element_tbc<G, level_id, glwe_dimension>(idx, group, fft);
  polynomial_product_accumulate_in_fourier_domain_2_2_params<params, double2,
                                                             false>(
      buffer_regs, fft_slice, bsk_poly);

  // Synchronize to ensure all blocks have used the fft already
  group.sync();

  // In 2_2 params, level_count=1 so we can just copy the result from the
  // registers into shared without needing to accumulate
  int tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] = buffer_regs[i];
    tid += params::degree / params::opt;
  }
  __syncthreads();
}

template <typename Torus>
void execute_pbs_async(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, const LweArrayVariant<Torus> &lwe_array_out,
    const LweArrayVariant<Torus> &lwe_output_indexes,
    const std::vector<Torus *> lut_vec,
    const std::vector<Torus *> lut_indexes_vec,
    const LweArrayVariant<Torus> &lwe_array_in,
    const LweArrayVariant<Torus> &lwe_input_indexes,
    void *const *bootstrapping_keys,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    std::vector<int8_t *> pbs_buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t grouping_factor,
    uint32_t input_lwe_ciphertext_count, PBS_TYPE pbs_type,
    uint32_t num_many_lut, uint32_t lut_stride) {

  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case CLASSICAL:
      for (uint i = 0; i < gpu_count; i++) {
        int num_inputs_on_gpu =
            get_num_inputs_on_gpu(input_lwe_ciphertext_count, i, gpu_count);

        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, gpu_count);
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        Torus *current_lwe_array_out = GET_VARIANT_ELEMENT(lwe_array_out, i);
        Torus *current_lwe_output_indexes =
            GET_VARIANT_ELEMENT(lwe_output_indexes, i);
        Torus *current_lwe_array_in = GET_VARIANT_ELEMENT(lwe_array_in, i);
        Torus *current_lwe_input_indexes =
            GET_VARIANT_ELEMENT(lwe_input_indexes, i);

        cuda_programmable_bootstrap_lwe_ciphertext_vector_32(
            streams[i], gpu_indexes[i], current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], d_lut_vector_indexes,
            current_lwe_array_in, current_lwe_input_indexes,
            bootstrapping_keys[i], pbs_buffer[i], lwe_dimension, glwe_dimension,
            polynomial_size, base_log, level_count, num_inputs_on_gpu,
            num_many_lut, lut_stride);
      }
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
      for (uint i = 0; i < gpu_count; i++) {
        int num_inputs_on_gpu =
            get_num_inputs_on_gpu(input_lwe_ciphertext_count, i, gpu_count);

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        Torus *current_lwe_array_out = GET_VARIANT_ELEMENT(lwe_array_out, i);
        Torus *current_lwe_output_indexes =
            GET_VARIANT_ELEMENT(lwe_output_indexes, i);
        Torus *current_lwe_array_in = GET_VARIANT_ELEMENT(lwe_array_in, i);
        Torus *current_lwe_input_indexes =
            GET_VARIANT_ELEMENT(lwe_input_indexes, i);

        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, gpu_count);
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);

        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
            streams[i], gpu_indexes[i], current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], d_lut_vector_indexes,
            current_lwe_array_in, current_lwe_input_indexes,
            bootstrapping_keys[i], pbs_buffer[i], lwe_dimension, glwe_dimension,
            polynomial_size, grouping_factor, base_log, level_count,
            num_inputs_on_gpu, num_many_lut, lut_stride);
      }
      break;
    case CLASSICAL:
      for (uint i = 0; i < gpu_count; i++) {
        int num_inputs_on_gpu =
            get_num_inputs_on_gpu(input_lwe_ciphertext_count, i, gpu_count);

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        Torus *current_lwe_array_out = GET_VARIANT_ELEMENT(lwe_array_out, i);
        Torus *current_lwe_output_indexes =
            GET_VARIANT_ELEMENT(lwe_output_indexes, i);
        Torus *current_lwe_array_in = GET_VARIANT_ELEMENT(lwe_array_in, i);
        Torus *current_lwe_input_indexes =
            GET_VARIANT_ELEMENT(lwe_input_indexes, i);

        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, gpu_count);
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);

        void *zeros = nullptr;
        if (ms_noise_reduction_key != nullptr &&
            ms_noise_reduction_key->ptr != nullptr)
          zeros = ms_noise_reduction_key->ptr[i];
        cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
            streams[i], gpu_indexes[i], current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], d_lut_vector_indexes,
            current_lwe_array_in, current_lwe_input_indexes,
            bootstrapping_keys[i], ms_noise_reduction_key, zeros, pbs_buffer[i],
            lwe_dimension, glwe_dimension, polynomial_size, base_log,
            level_count, num_inputs_on_gpu, num_many_lut, lut_stride);
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
}

template <typename Torus>
void execute_scratch_pbs(cudaStream_t stream, uint32_t gpu_index,
                         int8_t **pbs_buffer, uint32_t glwe_dimension,
                         uint32_t lwe_dimension, uint32_t polynomial_size,
                         uint32_t level_count, uint32_t grouping_factor,
                         uint32_t input_lwe_ciphertext_count, PBS_TYPE pbs_type,
                         bool allocate_gpu_memory, bool allocate_ms_array,
                         uint64_t &size_tracker) {
  switch (sizeof(Torus)) {
  case sizeof(uint32_t):
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case CLASSICAL:
      size_tracker = scratch_cuda_programmable_bootstrap_32(
          stream, gpu_index, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, level_count, input_lwe_ciphertext_count,
          allocate_gpu_memory, allocate_ms_array);
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
      size_tracker = scratch_cuda_multi_bit_programmable_bootstrap_64(
          stream, gpu_index, pbs_buffer, glwe_dimension, polynomial_size,
          level_count, input_lwe_ciphertext_count, allocate_gpu_memory);
      break;
    case CLASSICAL:
      size_tracker = scratch_cuda_programmable_bootstrap_64(
          stream, gpu_index, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, level_count, input_lwe_ciphertext_count,
          allocate_gpu_memory, allocate_ms_array);
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
