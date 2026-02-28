#ifndef CUDA_PROGRAMMABLE_BOOTSTRAP_CUH
#define CUDA_PROGRAMMABLE_BOOTSTRAP_CUH

#include "bootstrapping_key.cuh"
#include "ciphertext.h"
#include "cooperative_groups.h"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "helper_multi_gpu.h"
#include "pbs/pbs_128_utilities.h"
#include "pbs/pbs_utilities.h"
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

template <typename G>
__device__ double *get_join_buffer_element_128_tbc(int level_id, int glwe_id,
                                                   G &group,
                                                   double *shared_memory_buffer,
                                                   uint32_t polynomial_size,
                                                   uint32_t glwe_dimension);

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

template <typename G, class params>
__device__ void mul_ggsw_glwe_in_fourier_domain_128_tbc(
    double *fft, double *join_buffer,
    const double *__restrict__ bootstrapping_key, int iteration, G &group,
    int this_block_rank) {
  const uint32_t polynomial_size = params::degree;
  const uint32_t glwe_dimension = gridDim.y - 1;
  const uint32_t level_count = gridDim.z;

  // We apply the same idea than in 64-bit specialized pbs, Each cuda thread
  // block from the cluster calculates its fft, and then is placed in dsm. Here
  // we synchronize the cluster to ensure every block has written its fft. Then
  // each block can perform its accumulation reading others fft without further
  // synchronizations.
  group.sync();
  for (int j = 0; j < glwe_dimension + 1; j++) {
    int idx = (j + this_block_rank) % (glwe_dimension + 1);

    auto bsk_slice = get_ith_mask_kth_block_128(
        bootstrapping_key, iteration, idx, blockIdx.z, polynomial_size,
        glwe_dimension, level_count);

    auto bsk_poly = bsk_slice + blockIdx.y * polynomial_size / 2 * 4;
    auto fft_slice = get_join_buffer_element_128_tbc<G>(
        blockIdx.z, idx, group, join_buffer, polynomial_size, glwe_dimension);

    polynomial_product_accumulate_in_fourier_domain_128<params>(
        join_buffer, fft_slice + 4096, bsk_poly, j == 0);
  }

  // -----------------------------------------------------------------
  // All blocks are synchronized here; after this sync, Join buffer lives
  // in shared memory and has the values needed from every other block
  // that's why we need to synchronize the cluster before reading from it.
  group.sync();
  // At this point we no longer need the fft buffer so we can accumulate
  // the results in that buffer and thus save some shared memory.
  for (int l = 0; l < level_count; l++) {
    auto cur_src_acc = get_join_buffer_element_128_tbc<G>(
        l, blockIdx.y, group, join_buffer, polynomial_size, glwe_dimension);

    polynomial_accumulate_in_fourier_domain_128<params>(fft, cur_src_acc,
                                                        l == 0);
  }

  // We only need to synchronize threads within the block, no need to sync
  //  the cluster because it will be synced in the next iteration,or at exit.
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
 *  - local fft is read from registers
 * To avoid a cluster synchronization the accumulator output is different than
 * the input, and next iteration are switched to act as a ping pong buffer.
 */
template <typename G, class params, uint32_t polynomial_size,
          uint32_t glwe_dimension, uint32_t level_count>
__device__ void mul_ggsw_glwe_in_fourier_domain_2_2_params(
    double2 *fft, double2 *fft_regs, double2 *buffer_regs,
    const double2 *__restrict__ bootstrapping_key, int iteration, G &group,
    int this_block_rank) {
  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  // We accumulate in registers to free shared memory
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
      buffer_regs, fft_regs, bsk_poly);

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

  // We don't need to synchronize here, cause we are going to use a buffer
  // different than the input In 2_2 params, level_count=1 so we can just return
  // the buffer in registers to avoid synchronizations and shared memory usage
}

// We need a different version for classical accumulation because the
// bootstrapping key is not stored in the same way than the keybundles. This is
// a suboptimal version cause global reads are not coalesced, but the bsk key is
// small and hopefully it will be stored in cache. We can optimize this later.
template <typename G, class params, uint32_t polynomial_size,
          uint32_t glwe_dimension, uint32_t level_count>
__device__ void mul_ggsw_glwe_in_fourier_domain_2_2_params_classical(
    double2 *fft, double2 *fft_regs, double2 *buffer_regs,
    const double2 *__restrict__ bootstrapping_key, int iteration, G &group,
    int this_block_rank) {
  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  // We accumulate in registers to free shared memory
  // In 2_2 params we only have one level
  constexpr uint32_t level_id = 0;
  // The first product doesn't need using dsm
  auto bsk_slice =
      get_ith_mask_kth_block_2_2_params<double2, polynomial_size,
                                        glwe_dimension, level_count, level_id>(
          bootstrapping_key, iteration, this_block_rank);
  auto bsk_poly = bsk_slice + blockIdx.y * polynomial_size / 2;
  polynomial_product_accumulate_in_fourier_domain_2_2_params_classical<
      params, double2, true>(buffer_regs, fft_regs, bsk_poly);

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
  polynomial_product_accumulate_in_fourier_domain_2_2_params_classical<
      params, double2, false>(buffer_regs, fft_slice, bsk_poly);

  // We don't need to synchronize here, cause we are going to use a buffer
  // different than the input In 2_2 params, level_count=1 so we can just return
  // the buffer in registers to avoid synchronizations and shared memory usage
}

template <typename InputTorus, typename OutputTorus>
void execute_pbs_async(CudaStreams streams,
                       const LweArrayVariant<OutputTorus> &lwe_array_out,
                       const LweArrayVariant<InputTorus> &lwe_output_indexes,
                       const std::vector<OutputTorus *> lut_vec,
                       const std::vector<InputTorus *> lut_indexes_vec,
                       const LweArrayVariant<InputTorus> &lwe_array_in,
                       const LweArrayVariant<InputTorus> &lwe_input_indexes,
                       void *const *bootstrapping_keys,
                       std::vector<pbs_buffer_base *> pbs_buffer,
                       uint32_t glwe_dimension, uint32_t lwe_dimension,
                       uint32_t polynomial_size, uint32_t base_log,
                       uint32_t level_count, uint32_t grouping_factor,
                       uint32_t input_lwe_ciphertext_count, PBS_TYPE pbs_type,
                       uint32_t num_many_lut, uint32_t lut_stride) {

  if constexpr (std::is_same_v<OutputTorus, uint32_t>) {
    // 32 bits
    switch (pbs_type) {
    case MULTI_BIT:
      PANIC("Error: 32-bit multibit PBS is not supported.\n")
    case CLASSICAL:
      for (uint i = 0; i < streams.count(); i++) {
        int num_inputs_on_gpu = get_num_inputs_on_gpu(
            input_lwe_ciphertext_count, i, streams.count());

        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, streams.count());
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        auto current_lwe_array_out = get_variant_element(lwe_array_out, i);
        auto current_lwe_output_indexes =
            get_variant_element(lwe_output_indexes, i);
        auto current_lwe_array_in = get_variant_element(lwe_array_in, i);
        auto current_lwe_input_indexes =
            get_variant_element(lwe_input_indexes, i);

        cuda_programmable_bootstrap_lwe_ciphertext_vector_32_async(
            streams.stream(i), streams.gpu_index(i), current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], d_lut_vector_indexes,
            current_lwe_array_in, current_lwe_input_indexes,
            bootstrapping_keys[i], reinterpret_cast<int8_t *>(pbs_buffer[i]),
            lwe_dimension, glwe_dimension, polynomial_size, base_log,
            level_count, num_inputs_on_gpu, num_many_lut, lut_stride);
      }
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
  } else if constexpr (std::is_same_v<OutputTorus, uint64_t>) {
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      if (grouping_factor == 0)
        PANIC("Multi-bit PBS error: grouping factor should be > 0.")
      for (uint i = 0; i < streams.count(); i++) {
        int num_inputs_on_gpu = get_num_inputs_on_gpu(
            input_lwe_ciphertext_count, i, streams.count());

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        auto current_lwe_array_out = get_variant_element(lwe_array_out, i);
        auto current_lwe_output_indexes =
            get_variant_element(lwe_output_indexes, i);
        auto current_lwe_array_in = get_variant_element(lwe_array_in, i);
        auto current_lwe_input_indexes =
            get_variant_element(lwe_input_indexes, i);

        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, streams.count());
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);

        cuda_multi_bit_programmable_bootstrap_64_async(
            streams.stream(i), streams.gpu_index(i), current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], d_lut_vector_indexes,
            current_lwe_array_in, current_lwe_input_indexes,
            bootstrapping_keys[i], reinterpret_cast<int8_t *>(pbs_buffer[i]),
            lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
            base_log, level_count, num_inputs_on_gpu, num_many_lut, lut_stride);
      }
      break;
    case CLASSICAL:
      for (uint i = 0; i < streams.count(); i++) {
        int num_inputs_on_gpu = get_num_inputs_on_gpu(
            input_lwe_ciphertext_count, i, streams.count());

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        auto current_lwe_array_out = get_variant_element(lwe_array_out, i);
        auto current_lwe_output_indexes =
            get_variant_element(lwe_output_indexes, i);
        auto current_lwe_array_in = get_variant_element(lwe_array_in, i);
        auto current_lwe_input_indexes =
            get_variant_element(lwe_input_indexes, i);

        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, streams.count());
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);

        cuda_programmable_bootstrap_64_async(
            streams.stream(i), streams.gpu_index(i), current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], d_lut_vector_indexes,
            current_lwe_array_in, current_lwe_input_indexes,
            bootstrapping_keys[i], reinterpret_cast<int8_t *>(pbs_buffer[i]),
            lwe_dimension, glwe_dimension, polynomial_size, base_log,
            level_count, num_inputs_on_gpu, num_many_lut, lut_stride);
      }
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
  } else if constexpr (std::is_same_v<OutputTorus, __uint128_t>) {
    // 128 bits
    switch (pbs_type) {
    case MULTI_BIT:
      if (grouping_factor == 0)
        PANIC("Multi-bit PBS error: grouping factor should be > 0.")
      for (uint i = 0; i < streams.count(); i++) {
        int num_inputs_on_gpu = get_num_inputs_on_gpu(
            input_lwe_ciphertext_count, i, streams.count());

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        auto current_lwe_array_out = get_variant_element(lwe_array_out, i);
        auto current_lwe_output_indexes =
            get_variant_element(lwe_output_indexes, i);
        auto current_lwe_array_in = get_variant_element(lwe_array_in, i);
        auto current_lwe_input_indexes =
            get_variant_element(lwe_input_indexes, i);

        cuda_multi_bit_programmable_bootstrap_128_async(
            streams.stream(i), streams.gpu_index(i), current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], current_lwe_array_in,
            current_lwe_input_indexes, bootstrapping_keys[i],
            reinterpret_cast<int8_t *>(pbs_buffer[i]), lwe_dimension,
            glwe_dimension, polynomial_size, grouping_factor, base_log,
            level_count, num_inputs_on_gpu, num_many_lut, lut_stride);
      }
      break;
    case CLASSICAL:
      for (uint i = 0; i < streams.count(); i++) {
        int num_inputs_on_gpu = get_num_inputs_on_gpu(
            input_lwe_ciphertext_count, i, streams.count());

        // Use the macro to get the correct elements for the current iteration
        // Handles the case when the input/output are scattered through
        // different gpus and when it is not
        auto current_lwe_array_out = get_variant_element(lwe_array_out, i);
        auto current_lwe_output_indexes =
            get_variant_element(lwe_output_indexes, i);
        auto current_lwe_array_in = get_variant_element(lwe_array_in, i);
        auto current_lwe_input_indexes =
            get_variant_element(lwe_input_indexes, i);

        int gpu_offset =
            get_gpu_offset(input_lwe_ciphertext_count, i, streams.count());
        auto d_lut_vector_indexes =
            lut_indexes_vec[i] + (ptrdiff_t)(gpu_offset);

        cuda_programmable_bootstrap_128_async(
            streams.stream(i), streams.gpu_index(i), current_lwe_array_out,
            lut_vec[i], current_lwe_array_in, bootstrapping_keys[i],
            reinterpret_cast<int8_t *>(pbs_buffer[i]), lwe_dimension,
            glwe_dimension, polynomial_size, base_log, level_count,
            num_inputs_on_gpu);
      }
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
  } else {
    static_assert(
        std::is_same_v<OutputTorus, uint32_t> ||
            std::is_same_v<OutputTorus, uint64_t> ||
            std::is_same_v<OutputTorus, __uint128_t>,
        "Cuda error: unsupported modulus size: only 32, 64, or 128-bit integer "
        "moduli are supported.");
  }
}

template <typename Torus>
void execute_scratch_pbs(cudaStream_t stream, uint32_t gpu_index,
                         int8_t **pbs_buffer, uint32_t glwe_dimension,
                         uint32_t lwe_dimension, uint32_t polynomial_size,
                         uint32_t level_count, uint32_t base_log,
                         uint32_t grouping_factor,
                         uint32_t input_lwe_ciphertext_count, PBS_TYPE pbs_type,
                         bool allocate_gpu_memory,
                         PBS_MS_REDUCTION_T noise_reduction_type,
                         uint64_t &size_tracker) {
  static_assert(
      std::is_same_v<Torus, uint64_t> || std::is_same_v<Torus, __uint128_t>,
      "Cuda error: unsupported modulus size: only 64, or 128-bit integer "
      "moduli are supported.");
  if constexpr (std::is_same_v<Torus, uint64_t>) {
    // 64 bits
    switch (pbs_type) {
    case MULTI_BIT:
      if (grouping_factor == 0)
        PANIC("Multi-bit PBS error: grouping factor should be > 0.")
      size_tracker = scratch_cuda_multi_bit_programmable_bootstrap_64_async(
          stream, gpu_index, pbs_buffer, glwe_dimension, polynomial_size,
          level_count, input_lwe_ciphertext_count, allocate_gpu_memory);
      break;
    case CLASSICAL:
      size_tracker = scratch_cuda_programmable_bootstrap_64_async(
          stream, gpu_index, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, level_count, input_lwe_ciphertext_count,
          allocate_gpu_memory, noise_reduction_type);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
  } else if constexpr (std::is_same_v<Torus, __uint128_t>) {
    // 128 bits
    switch (pbs_type) {
    case MULTI_BIT:
      if (grouping_factor == 0)
        PANIC("Multi-bit PBS error: grouping factor should be > 0.")
      size_tracker = scratch_cuda_multi_bit_programmable_bootstrap_128_async(
          stream, gpu_index, pbs_buffer, glwe_dimension, polynomial_size,
          level_count, input_lwe_ciphertext_count, allocate_gpu_memory);
      break;
    case CLASSICAL:
      size_tracker = scratch_cuda_programmable_bootstrap_128_async(
          stream, gpu_index, pbs_buffer, lwe_dimension, glwe_dimension,
          polynomial_size, level_count, base_log, input_lwe_ciphertext_count,
          allocate_gpu_memory, noise_reduction_type);
      break;
    default:
      PANIC("Error: unsupported cuda PBS type.")
    }
  } else {
    PANIC("Error: unsupported cuda PBS modulus size.")
  }
}

#endif
