#ifndef CUDA_PROGRAMMABLE_BOOTSTRAP_CUH
#define CUDA_PROGRAMMABLE_BOOTSTRAP_CUH

#include "bootstrapping_key.cuh"
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

/** Perform the matrix multiplication between the GGSW and the GLWE,
 * each block operating on a single level for mask and body.
 * Both operands should be at fourier domain
 *
 * This function assumes:
 *  - Thread blocks at dimension x relates to the decomposition level.
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
  const uint32_t level_count = gridDim.x;

  // The first product is used to initialize level_join_buffer
  auto this_block_rank = get_this_block_rank<G>(group, support_dsm);

  // Continues multiplying fft by every polynomial in that particular bsk level
  // Each y-block accumulates in a different polynomial at each iteration
  auto bsk_slice = get_ith_mask_kth_block(
      bootstrapping_key, iteration, blockIdx.y, blockIdx.x, polynomial_size,
      glwe_dimension, level_count);
  for (int j = 0; j < glwe_dimension + 1; j++) {
    int idx = (j + this_block_rank) % (glwe_dimension + 1);

    auto bsk_poly = bsk_slice + idx * polynomial_size / 2;
    auto buffer_slice = get_join_buffer_element<G>(blockIdx.x, idx, group,
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

  synchronize_threads_in_block();
}

template <typename Torus>
void execute_pbs_async(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                       uint32_t gpu_count,
                       const LweArrayVariant<Torus> &lwe_array_out,
                       const LweArrayVariant<Torus> &lwe_output_indexes,
                       const std::vector<Torus *> lut_vec,
                       const std::vector<Torus *> lut_indexes_vec,
                       const LweArrayVariant<Torus> &lwe_array_in,
                       const LweArrayVariant<Torus> &lwe_input_indexes,
                       void *const *bootstrapping_keys,
                       std::vector<int8_t *> pbs_buffer,
                       uint32_t glwe_dimension, uint32_t lwe_dimension,
                       uint32_t polynomial_size, uint32_t base_log,
                       uint32_t level_count, uint32_t grouping_factor,
                       uint32_t input_lwe_ciphertext_count, PBS_TYPE pbs_type,
                       uint32_t lut_count, uint32_t lut_stride) {

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
            lut_count, lut_stride);
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
            num_inputs_on_gpu, lut_count, lut_stride);
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

        cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
            streams[i], gpu_indexes[i], current_lwe_array_out,
            current_lwe_output_indexes, lut_vec[i], d_lut_vector_indexes,
            current_lwe_array_in, current_lwe_input_indexes,
            bootstrapping_keys[i], pbs_buffer[i], lwe_dimension, glwe_dimension,
            polynomial_size, base_log, level_count, num_inputs_on_gpu,
            lut_count, lut_stride);
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
          level_count, input_lwe_ciphertext_count, allocate_gpu_memory);
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
          stream, gpu_index, pbs_buffer, glwe_dimension, polynomial_size,
          level_count, input_lwe_ciphertext_count, allocate_gpu_memory);
      break;
    case CLASSICAL:
      scratch_cuda_programmable_bootstrap_64(
          stream, gpu_index, pbs_buffer, glwe_dimension, polynomial_size,
          level_count, input_lwe_ciphertext_count, allocate_gpu_memory);
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
