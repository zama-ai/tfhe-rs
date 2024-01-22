#ifndef CUDA_MULTIBIT_PBS_CUH
#define CUDA_MULTIBIT_PBS_CUH

#include "bootstrap.h"
#include "bootstrap_fast_low_latency.cuh"
#include "bootstrap_multibit.h"
#include "cooperative_groups.h"
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

template <typename Torus, class params>
__device__ Torus calculates_monomial_degree(Torus *lwe_array_group,
                                            uint32_t ggsw_idx,
                                            uint32_t grouping_factor) {
  Torus x = 0;
  for (int i = 0; i < grouping_factor; i++) {
    uint32_t mask_position = grouping_factor - (i + 1);
    int selection_bit = (ggsw_idx >> mask_position) & 1;
    x += selection_bit * lwe_array_group[i];
  }

  return rescale_torus_element(
      x, 2 * params::degree); // 2 * params::log2_degree + 1);
}

template <typename Torus, class params>
__global__ void device_multi_bit_bootstrap_keybundle(
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *keybundle_array,
    Torus *bootstrapping_key, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t lwe_offset, uint32_t lwe_chunk_size,
    uint32_t keybundle_size_per_input) {

  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory = sharedmem;

  // Ids
  uint32_t level_id = blockIdx.z;
  uint32_t glwe_id = blockIdx.y / (glwe_dimension + 1);
  uint32_t poly_id = blockIdx.y % (glwe_dimension + 1);
  uint32_t lwe_iteration = (blockIdx.x % lwe_chunk_size + lwe_offset);
  uint32_t input_idx = blockIdx.x / lwe_chunk_size;

  if (lwe_iteration < (lwe_dimension / grouping_factor)) {
    //
    Torus *accumulator = (Torus *)selected_memory;

    Torus *block_lwe_array_in =
        &lwe_array_in[lwe_input_indexes[input_idx] * (lwe_dimension + 1)];

    double2 *keybundle = keybundle_array +
                         // select the input
                         input_idx * keybundle_size_per_input;

    ////////////////////////////////////////////////////////////
    // Computes all keybundles
    uint32_t rev_lwe_iteration =
        ((lwe_dimension / grouping_factor) - lwe_iteration - 1);

    // ////////////////////////////////
    // Keygen guarantees the first term is a constant term of the polynomial, no
    // polynomial multiplication required
    Torus *bsk_slice = get_multi_bit_ith_lwe_gth_group_kth_block(
        bootstrapping_key, 0, rev_lwe_iteration, glwe_id, level_id,
        grouping_factor, 2 * polynomial_size, glwe_dimension, level_count);
    Torus *bsk_poly = bsk_slice + poly_id * params::degree;

    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        bsk_poly, accumulator);

    // Accumulate the other terms
    for (int g = 1; g < (1 << grouping_factor); g++) {

      Torus *bsk_slice = get_multi_bit_ith_lwe_gth_group_kth_block(
          bootstrapping_key, g, rev_lwe_iteration, glwe_id, level_id,
          grouping_factor, 2 * polynomial_size, glwe_dimension, level_count);
      Torus *bsk_poly = bsk_slice + poly_id * params::degree;

      // Calculates the monomial degree
      Torus *lwe_array_group =
          block_lwe_array_in + rev_lwe_iteration * grouping_factor;
      uint32_t monomial_degree = calculates_monomial_degree<Torus, params>(
          lwe_array_group, g, grouping_factor);

      synchronize_threads_in_block();
      // Multiply by the bsk element
      polynomial_product_accumulate_by_monomial<Torus, params>(
          accumulator, bsk_poly, monomial_degree, false);
    }

    synchronize_threads_in_block();

    double2 *fft = (double2 *)sharedmem;

    // Move accumulator to local memory
    double2 temp[params::opt / 2];
    int tid = threadIdx.x;
#pragma unroll
    for (int i = 0; i < params::opt / 2; i++) {
      temp[i].x = __ll2double_rn((int64_t)accumulator[tid]);
      temp[i].y =
          __ll2double_rn((int64_t)accumulator[tid + params::degree / 2]);
      temp[i].x /= (double)std::numeric_limits<Torus>::max();
      temp[i].y /= (double)std::numeric_limits<Torus>::max();
      tid += params::degree / params::opt;
    }

    synchronize_threads_in_block();
    // Move from local memory back to shared memory but as complex
    tid = threadIdx.x;
#pragma unroll
    for (int i = 0; i < params::opt / 2; i++) {
      fft[tid] = temp[i];
      tid += params::degree / params::opt;
    }
    synchronize_threads_in_block();
    NSMFFT_direct<HalfDegree<params>>(fft);

    // lwe iteration
    auto keybundle_out = get_ith_mask_kth_block(
        keybundle, blockIdx.x % lwe_chunk_size, glwe_id, level_id,
        polynomial_size, glwe_dimension, level_count);
    auto keybundle_poly = keybundle_out + poly_id * params::degree / 2;

    copy_polynomial<double2, params::opt / 2, params::degree / params::opt>(
        fft, keybundle_poly);
  }
}

template <typename Torus, class params>
__global__ void device_multi_bit_bootstrap_accumulate_step_one(
    Torus *lwe_array_in, Torus *lwe_input_indexes, Torus *lut_vector,
    Torus *lut_vector_indexes, Torus *global_accumulator,
    double2 *global_accumulator_fft, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t lwe_iteration) {

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  selected_memory = sharedmem;

  Torus *accumulator = (Torus *)selected_memory;
  double2 *accumulator_fft =
      (double2 *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.z] * (lwe_dimension + 1)];

  Torus *block_lut_vector = &lut_vector[lut_vector_indexes[blockIdx.z] *
                                        params::degree * (glwe_dimension + 1)];

  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.z * (glwe_dimension + 1)) * params::degree;

  double2 *global_fft_slice =
      global_accumulator_fft +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1) +
       blockIdx.z * level_count * (glwe_dimension + 1)) *
          (polynomial_size / 2);

  if (lwe_iteration == 0) {
    // First iteration
    ////////////////////////////////////////////////////////////
    // Initializes the accumulator with the body of LWE
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    rescale_torus_element(block_lwe_array_in[lwe_dimension], b_hat,
                          2 * params::degree);

    divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                          params::degree / params::opt>(
        accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
        false);

    // Persist
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        accumulator, global_slice);
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        global_slice, accumulator);
  }

  // Perform a rounding to increase the accuracy of the
  // bootstrapped ciphertext
  round_to_closest_multiple_inplace<Torus, params::opt,
                                    params::degree / params::opt>(
      accumulator, base_log, level_count);

  // Decompose the accumulator. Each block gets one level of the
  // decomposition, for the mask and the body (so block 0 will have the
  // accumulator decomposed at level 0, 1 at 1, etc.)
  GadgetMatrix<Torus, params> gadget_acc(base_log, level_count, accumulator);
  gadget_acc.decompose_and_compress_next_polynomial(accumulator_fft,
                                                    blockIdx.x);

  // We are using the same memory space for accumulator_fft and
  // accumulator_rotated, so we need to synchronize here to make sure they
  // don't modify the same memory space at the same time
  // Switch to the FFT space
  NSMFFT_direct<HalfDegree<params>>(accumulator_fft);

  copy_polynomial<double2, params::opt / 2, params::degree / params::opt>(
      accumulator_fft, global_fft_slice);
}

template <typename Torus, class params>
__global__ void device_multi_bit_bootstrap_accumulate_step_two(
    Torus *lwe_array_out, Torus *lwe_output_indexes, double2 *keybundle_array,
    Torus *global_accumulator, double2 *global_accumulator_fft,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t grouping_factor, uint32_t iteration,
    uint32_t lwe_offset, uint32_t lwe_chunk_size) {
  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  selected_memory = sharedmem;
  double2 *accumulator_fft = (double2 *)selected_memory;

  double2 *keybundle = keybundle_array +
                       // select the input
                       blockIdx.x * lwe_chunk_size * level_count *
                           (glwe_dimension + 1) * (glwe_dimension + 1) *
                           (polynomial_size / 2);

  double2 *global_accumulator_fft_input =
      global_accumulator_fft +
      blockIdx.x * level_count * (glwe_dimension + 1) * (polynomial_size / 2);

  for (int level = 0; level < level_count; level++) {
    double2 *global_fft_slice =
        global_accumulator_fft_input +
        level * (glwe_dimension + 1) * (polynomial_size / 2);

    for (int j = 0; j < (glwe_dimension + 1); j++) {
      double2 *fft = global_fft_slice + j * params::degree / 2;

      // Get the bootstrapping key piece necessary for the multiplication
      // It is already in the Fourier domain
      auto bsk_slice =
          get_ith_mask_kth_block(keybundle, iteration, j, level,
                                 polynomial_size, glwe_dimension, level_count);
      auto bsk_poly = bsk_slice + blockIdx.y * params::degree / 2;

      polynomial_product_accumulate_in_fourier_domain<params, double2>(
          accumulator_fft, fft, bsk_poly, !level && !j);
    }
  }

  // Perform the inverse FFT on the result of the GGSW x GLWE and add to the
  // accumulator
  NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1)) * params::degree;

  add_to_torus<Torus, params>(accumulator_fft, global_slice, true);
  synchronize_threads_in_block();

  uint32_t lwe_iteration = iteration + lwe_offset;
  if (lwe_iteration + 1 == (lwe_dimension / grouping_factor)) {
    // Last iteration
    auto block_lwe_array_out =
        &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                           (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra blocks,
      // in case they're not synchronized
      sample_extract_mask<Torus, params>(block_lwe_array_out, global_slice);
    } else if (blockIdx.y == glwe_dimension) {
      sample_extract_body<Torus, params>(block_lwe_array_out, global_slice, 0);
    }
  }
}
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_multibit_bootstrap_keybundle(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size; // accumulator
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_multibit_bootstrap_step_one(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size * 2; // accumulator
}
template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_full_sm_multibit_bootstrap_step_two(uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size; // accumulator
}

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_multibit_bootstrap(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t lwe_chunk_size) {

  uint64_t buffer_size = 0;
  buffer_size += input_lwe_ciphertext_count * lwe_chunk_size * level_count *
                 (glwe_dimension + 1) * (glwe_dimension + 1) *
                 (polynomial_size / 2) * sizeof(double2); // keybundle fft
  buffer_size += input_lwe_ciphertext_count * (glwe_dimension + 1) *
                 level_count * (polynomial_size / 2) *
                 sizeof(double2); // global_accumulator_fft
  buffer_size += input_lwe_ciphertext_count * (glwe_dimension + 1) *
                 polynomial_size * sizeof(Torus); // global_accumulator

  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus, typename STorus, typename params>
__host__ void
scratch_multi_bit_pbs(cuda_stream_t *stream, int8_t **pbs_buffer,
                      uint32_t lwe_dimension, uint32_t glwe_dimension,
                      uint32_t polynomial_size, uint32_t level_count,
                      uint32_t input_lwe_ciphertext_count,
                      uint32_t grouping_factor, uint32_t max_shared_memory,
                      bool allocate_gpu_memory, uint32_t lwe_chunk_size = 0) {

  cudaSetDevice(stream->gpu_index);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate_step_one =
      get_buffer_size_full_sm_multibit_bootstrap_step_one<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate_step_two =
      get_buffer_size_full_sm_multibit_bootstrap_step_two<Torus>(
          polynomial_size);

  check_cuda_error(cudaFuncSetAttribute(
      device_multi_bit_bootstrap_keybundle<Torus, params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
  cudaFuncSetCacheConfig(device_multi_bit_bootstrap_keybundle<Torus, params>,
                         cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  check_cuda_error(cudaFuncSetAttribute(
      device_multi_bit_bootstrap_accumulate_step_one<Torus, params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize,
      full_sm_accumulate_step_one));
  cudaFuncSetCacheConfig(
      device_multi_bit_bootstrap_accumulate_step_one<Torus, params>,
      cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  check_cuda_error(cudaFuncSetAttribute(
      device_multi_bit_bootstrap_accumulate_step_two<Torus, params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize,
      full_sm_accumulate_step_two));
  cudaFuncSetCacheConfig(
      device_multi_bit_bootstrap_accumulate_step_two<Torus, params>,
      cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  if (allocate_gpu_memory) {
    if (!lwe_chunk_size)
      lwe_chunk_size =
          get_average_lwe_chunk_size(lwe_dimension, level_count, glwe_dimension,
                                     input_lwe_ciphertext_count);

    uint64_t buffer_size = get_buffer_size_multibit_bootstrap<Torus>(
        glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, lwe_chunk_size);
    *pbs_buffer = (int8_t *)cuda_malloc_async(buffer_size, stream);
    check_cuda_error(cudaGetLastError());
  }
}

template <typename Torus, typename STorus, class params>
__host__ void host_multi_bit_pbs(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, uint64_t *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t glwe_dimension, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory, uint32_t lwe_chunk_size = 0) {
  cudaSetDevice(stream->gpu_index);

  // If a chunk size is not passed to this function, select one.
  if (!lwe_chunk_size)
    lwe_chunk_size = get_average_lwe_chunk_size(lwe_dimension, level_count,
                                                glwe_dimension, num_samples);
  //
  double2 *keybundle_fft = (double2 *)pbs_buffer;
  double2 *global_accumulator_fft =
      (double2 *)keybundle_fft +
      num_samples * lwe_chunk_size * level_count * (glwe_dimension + 1) *
          (glwe_dimension + 1) * (polynomial_size / 2);
  Torus *global_accumulator =
      (Torus *)global_accumulator_fft +
      (ptrdiff_t)(sizeof(double2) * num_samples * (glwe_dimension + 1) *
                  level_count * (polynomial_size / 2) / sizeof(Torus));

  //
  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate_step_one =
      get_buffer_size_full_sm_multibit_bootstrap_step_one<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate_step_two =
      get_buffer_size_full_sm_multibit_bootstrap_step_two<Torus>(
          polynomial_size);

  uint32_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2);

  //
  dim3 grid_accumulate_step_one(level_count, glwe_dimension + 1, num_samples);
  dim3 grid_accumulate_step_two(num_samples, glwe_dimension + 1);
  dim3 thds(polynomial_size / params::opt, 1, 1);

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

    // Accumulate
    for (int j = 0; j < chunk_size; j++) {
      device_multi_bit_bootstrap_accumulate_step_one<Torus, params>
          <<<grid_accumulate_step_one, thds, full_sm_accumulate_step_one,
             stream->stream>>>(lwe_array_in, lwe_input_indexes, lut_vector,
                               lut_vector_indexes, global_accumulator,
                               global_accumulator_fft, lwe_dimension,
                               glwe_dimension, polynomial_size, base_log,
                               level_count, j + lwe_offset);
      check_cuda_error(cudaGetLastError());

      device_multi_bit_bootstrap_accumulate_step_two<Torus, params>
          <<<grid_accumulate_step_two, thds, full_sm_accumulate_step_two,
             stream->stream>>>(lwe_array_out, lwe_output_indexes, keybundle_fft,
                               global_accumulator, global_accumulator_fft,
                               lwe_dimension, glwe_dimension, polynomial_size,
                               level_count, grouping_factor, j, lwe_offset,
                               lwe_chunk_size);
      check_cuda_error(cudaGetLastError());
    }
  }
}
#endif // MULTIBIT_PBS_H
