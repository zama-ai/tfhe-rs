#ifndef CUDA_MULTIBIT_PBS_CUH
#define CUDA_MULTIBIT_PBS_CUH

#include "cooperative_groups.h"
#include "crypto/gadget.cuh"
#include "crypto/ggsw.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "pbs/pbs_multibit_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "pbs/programmable_bootstrap_multibit.h"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "programmable_bootstrap_cg_classic.cuh"
#include "types/complex/operations.cuh"
#include <vector>

__device__ __forceinline__ int
get_start_ith_ggsw_offset(uint32_t polynomial_size, int glwe_dimension,
                          uint32_t level_count) {
  return polynomial_size * (glwe_dimension + 1) * (glwe_dimension + 1) *
         level_count;
}

template <typename Torus, class params, sharedMemDegree SMD>
__global__ void device_multi_bit_programmable_bootstrap_keybundle(
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes, double2 *keybundle_array,
    const Torus *__restrict__ bootstrapping_key, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t level_count, uint32_t lwe_offset, uint64_t lwe_chunk_size,
    uint64_t keybundle_size_per_input, int8_t *device_mem,
    uint64_t device_memory_size_per_block) {

  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.x + blockIdx.y * gridDim.x +
                      blockIdx.z * gridDim.x * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  // Ids
  uint32_t level_id = blockIdx.z;
  uint32_t glwe_id = blockIdx.y / (glwe_dimension + 1);
  uint32_t poly_id = blockIdx.y % (glwe_dimension + 1);
  uint32_t lwe_iteration = (blockIdx.x % lwe_chunk_size + lwe_offset);
  uint32_t input_idx = blockIdx.x / lwe_chunk_size;

  if (lwe_iteration < (lwe_dimension / grouping_factor)) {

    const Torus *block_lwe_array_in =
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
    const Torus *bsk_slice = get_multi_bit_ith_lwe_gth_group_kth_block(
        bootstrapping_key, 0, rev_lwe_iteration, glwe_id, level_id,
        grouping_factor, 2 * polynomial_size, glwe_dimension, level_count);
    const Torus *bsk_poly_ini = bsk_slice + poly_id * params::degree;

    Torus reg_acc[params::opt];

    copy_polynomial_in_regs<Torus, params::opt, params::degree / params::opt>(
        bsk_poly_ini, reg_acc);

    int offset =
        get_start_ith_ggsw_offset(polynomial_size, glwe_dimension, level_count);

    // Precalculate the monomial degrees and store them in shared memory
    uint32_t *monomial_degrees = (uint32_t *)selected_memory;
    if (threadIdx.x < (1 << grouping_factor)) {
      const Torus *lwe_array_group =
          block_lwe_array_in + rev_lwe_iteration * grouping_factor;
      monomial_degrees[threadIdx.x] = calculates_monomial_degree<Torus, params>(
          lwe_array_group, threadIdx.x, grouping_factor);
    }
    __syncthreads();

    // Accumulate the other terms
    for (int g = 1; g < (1 << grouping_factor); g++) {

      uint32_t monomial_degree = monomial_degrees[g];

      const Torus *bsk_poly = bsk_poly_ini + g * offset;
      // Multiply by the bsk element
      polynomial_accumulate_monic_monomial_mul_on_regs<Torus, params>(
          reg_acc, bsk_poly, monomial_degree);
    }
    __syncthreads(); // needed because we are going to reuse the
                     // shared memory for the fft

    // Move from local memory back to shared memory but as complex
    int tid = threadIdx.x;
    double2 *fft = (double2 *)selected_memory;
#pragma unroll
    for (int i = 0; i < params::opt / 2; i++) {
      fft[tid] =
          make_double2(__ll2double_rn((int64_t)reg_acc[i]) /
                           (double)std::numeric_limits<Torus>::max(),
                       __ll2double_rn((int64_t)reg_acc[i + params::opt / 2]) /
                           (double)std::numeric_limits<Torus>::max());
      tid += params::degree / params::opt;
    }

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

// Calculates the keybundles for 2_2 params
// Polynomial Size = 2048
// Grouping factor = 4
// Glwe dimension = 1
// PBS level = 1
// In this initial version everything is hardcoded as constexpr, we
// will wrap it up in a nicer/cleaner version in the future.
// Additionally, we initialize an int8_t vector with coefficients used in the
// monomial multiplication The size of this vector is 3x2048 and the
// coefficients are: [0 .. 2047] = -1 [2048 .. 4095] = 1 [4096 .. 6143] = -1
// Then we can just calculate the offset needed to apply this coefficients, and
// the operation transforms into a pointwise vector multiplication, avoiding to
// perform extra instructions other than MADD
template <typename Torus, class params, sharedMemDegree SMD>
__global__ void device_multi_bit_programmable_bootstrap_keybundle_2_2_params(
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes, double2 *keybundle_array,
    const Torus *__restrict__ bootstrapping_key, uint32_t lwe_dimension,
    uint32_t lwe_offset, uint64_t lwe_chunk_size,
    uint64_t keybundle_size_per_input) {

  constexpr uint32_t polynomial_size = 2048;
  constexpr uint32_t grouping_factor = 4;
  constexpr uint32_t glwe_dimension = 1;
  constexpr uint32_t level_count = 1;

  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;
  selected_memory = sharedmem;

  int8_t *precalc_coefs =
      selected_memory + (sizeof(uint32_t) * (1 << grouping_factor));
  for (int i = 0; i < params::opt; i++) {
    precalc_coefs[threadIdx.x + i * (params::degree / params::opt)] = -1;
    precalc_coefs[threadIdx.x + i * (params::degree / params::opt) +
                  params::degree] = 1;
    precalc_coefs[threadIdx.x + i * (params::degree / params::opt) +
                  2 * params::degree] = -1;
  }

  double2 *shared_fft = (double2 *)(precalc_coefs + polynomial_size * 3);
  double2 *shared_twiddles = shared_fft + (polynomial_size / 2);
  for (int k = 0; k < params::opt / 2; k++) {
    shared_twiddles[threadIdx.x + k * (params::degree / params::opt)] =
        negtwiddles[threadIdx.x + k * (params::degree / params::opt)];
  }

  // Ids
  constexpr uint32_t level_id = 0;
  uint32_t glwe_id = blockIdx.y / (glwe_dimension + 1);
  uint32_t poly_id = blockIdx.y % (glwe_dimension + 1);
  uint32_t lwe_iteration = (blockIdx.x % lwe_chunk_size + lwe_offset);
  uint32_t input_idx = blockIdx.x / lwe_chunk_size;

  if (lwe_iteration < (lwe_dimension / grouping_factor)) {

    const Torus *block_lwe_array_in =
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
    const Torus *bsk_slice = get_multi_bit_ith_lwe_gth_group_kth_block(
        bootstrapping_key, 0, rev_lwe_iteration, glwe_id, level_id,
        grouping_factor, 2 * polynomial_size, glwe_dimension, level_count);
    const Torus *bsk_poly_ini = bsk_slice + poly_id * params::degree;

    Torus reg_acc[params::opt];

    copy_polynomial_in_regs<Torus, params::opt, params::degree / params::opt>(
        bsk_poly_ini, reg_acc);

    constexpr int offset = polynomial_size * (glwe_dimension + 1) *
                           (glwe_dimension + 1) * level_count;
    // Precalculate the monomial degrees and store them in shared memory
    uint32_t *monomial_degrees = (uint32_t *)selected_memory;

    if (threadIdx.x < (1 << grouping_factor)) {
      const Torus *lwe_array_group =
          block_lwe_array_in + rev_lwe_iteration * grouping_factor;
      monomial_degrees[threadIdx.x] = calculates_monomial_degree<Torus, params>(
          lwe_array_group, threadIdx.x, grouping_factor);
    }
    __syncthreads();

    // Accumulate the other terms
    for (int g = 1; g < (1 << grouping_factor); g++) {

      uint32_t monomial_degree = monomial_degrees[g];

      int full_cycles_count = monomial_degree / params::degree;
      int remainder_degrees = monomial_degree % params::degree;
      int jump = full_cycles_count * params::degree + params::degree -
                 remainder_degrees;

      const Torus *bsk_poly = bsk_poly_ini + g * offset;
      // Multiply by the bsk element
      polynomial_accumulate_monic_monomial_mul_on_regs_precalc<Torus, params>(
          reg_acc, bsk_poly, precalc_coefs + jump, monomial_degree);
    }

    // Move from local memory back to shared memory but as complex
    double2 fft_regs[params::opt / 2];
    double2 *fft = shared_fft;
#pragma unroll
    for (int i = 0; i < params::opt / 2; i++) {
      fft_regs[i] =
          make_double2(__ll2double_rn((int64_t)reg_acc[i]) /
                           (double)std::numeric_limits<Torus>::max(),
                       __ll2double_rn((int64_t)reg_acc[i + params::opt / 2]) /
                           (double)std::numeric_limits<Torus>::max());
    }

    NSMFFT_direct_2_2_params<HalfDegree<params>>(fft, fft_regs,
                                                 shared_twiddles);

    // lwe iteration
    auto keybundle_out = get_ith_mask_kth_block(
        keybundle, blockIdx.x % lwe_chunk_size, glwe_id, level_id,
        polynomial_size, glwe_dimension, level_count);

    auto keybundle_poly = keybundle_out + poly_id * params::degree / 2;
    copy_polynomial_from_regs<double2, params::opt / 2,
                              params::degree / params::opt>(fft_regs,
                                                            keybundle_poly);
  }
}

template <typename Torus, class params, sharedMemDegree SMD, bool is_first_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_accumulate_step_one(
        const Torus *__restrict__ lwe_array_in,
        const Torus *__restrict__ lwe_input_indexes,
        const Torus *__restrict__ lut_vector,
        const Torus *__restrict__ lut_vector_indexes, Torus *global_accumulator,
        double2 *global_accumulator_fft, uint32_t lwe_dimension,
        uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
        uint32_t level_count, int8_t *device_mem,
        uint64_t device_memory_size_per_block) {

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  selected_memory = sharedmem;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.z + blockIdx.y * gridDim.z +
                      blockIdx.x * gridDim.z * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  Torus *accumulator = (Torus *)selected_memory;
  double2 *accumulator_fft =
      (double2 *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double2 *)sharedmem;

  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  Torus *global_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  double2 *global_fft_slice =
      &global_accumulator_fft[(blockIdx.y + blockIdx.z * (glwe_dimension + 1) +
                               blockIdx.x * level_count *
                                   (glwe_dimension + 1)) *
                              (polynomial_size / 2)];

  if constexpr (is_first_iter) {
    // First iteration
    ////////////////////////////////////////////////////////////
    // Initializes the accumulator with the body of LWE
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                   params::log2_degree + 1);

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
  init_decomposer_state_inplace<Torus, params::opt,
                                params::degree / params::opt>(
      accumulator, base_log, level_count);

  // Decompose the accumulator. Each block gets one level of the
  // decomposition, for the mask and the body (so block 0 will have the
  // accumulator decomposed at level 0, 1 at 1, etc.)
  GadgetMatrix<Torus, params> gadget_acc(base_log, level_count, accumulator);
  gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.z);

  // We are using the same memory space for accumulator_fft and
  // accumulator_rotated, so we need to synchronize here to make sure they
  // don't modify the same memory space at the same time
  // Switch to the FFT space
  NSMFFT_direct<HalfDegree<params>>(accumulator_fft);

  copy_polynomial<double2, params::opt / 2, params::degree / params::opt>(
      accumulator_fft, global_fft_slice);
}

template <typename Torus, class params, sharedMemDegree SMD, bool is_last_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_accumulate_step_two(
        Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
        const double2 *__restrict__ keybundle_array, Torus *global_accumulator,
        double2 *join_buffer, uint32_t glwe_dimension, uint32_t polynomial_size,
        uint32_t level_count, uint32_t iteration, uint32_t lwe_chunk_size,
        int8_t *device_mem, uint64_t device_memory_size_per_block,
        uint32_t num_many_lut, uint32_t lut_stride) {
  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  selected_memory = sharedmem;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.x + blockIdx.y * gridDim.x +
                      blockIdx.z * gridDim.x * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  double2 *accumulator_fft = (double2 *)selected_memory;

  //
  const double2 *keybundle =
      &keybundle_array[blockIdx.x * lwe_chunk_size * level_count *
                       (glwe_dimension + 1) * (glwe_dimension + 1) *
                       (polynomial_size / 2)];

  double2 *join_buffer_slice =
      &join_buffer[blockIdx.x * level_count * (glwe_dimension + 1) *
                   (polynomial_size / 2)];

  for (int level = 0; level < level_count; level++) {
    double2 *global_fft_slice =
        &join_buffer_slice[level * (glwe_dimension + 1) *
                           (polynomial_size / 2)];

    for (int j = 0; j < (glwe_dimension + 1); j++) {
      double2 *fft = &global_fft_slice[j * params::degree / 2];

      // Get the bootstrapping key piece necessary for the multiplication
      // It is already in the Fourier domain
      auto bsk_slice =
          get_ith_mask_kth_block(keybundle, iteration, j, level,
                                 polynomial_size, glwe_dimension, level_count);
      auto bsk_poly = &bsk_slice[blockIdx.y * params::degree / 2];

      polynomial_product_accumulate_in_fourier_domain<params, double2>(
          accumulator_fft, fft, bsk_poly, !level && !j);
    }
  }

  // Perform the inverse FFT on the result of the GGSW x GLWE and add to the
  // accumulator
  NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
  Torus *global_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  add_to_torus<Torus, params>(accumulator_fft, global_slice, true);
  __syncthreads();

  if constexpr (is_last_iter) {
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
                                             global_slice, 1, i * lut_stride);
        }
      }
    } else if (blockIdx.y == glwe_dimension) {
      // No need to sync here, it is already synchronized after add_to_torus
      sample_extract_body<Torus, params>(block_lwe_array_out, global_slice, 0);
      if (num_many_lut > 1) {
        for (int i = 1; i < num_many_lut; i++) {

          auto next_lwe_array_out =
              lwe_array_out +
              (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  blockIdx.y * polynomial_size];

          // No need to sync here, it is already synchronized after add_to_torus
          sample_extract_body<Torus, params>(next_block_lwe_array_out,
                                             global_slice, 0, i * lut_stride);
        }
      }
    }
  }
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle(
    uint32_t polynomial_size) {
  return safe_mul_sizeof<double2>(polynomial_size / 2); // accumulator
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one(
    uint32_t polynomial_size) {
  return safe_mul_sizeof<Torus>((size_t)polynomial_size,
                                (size_t)2); // accumulator
}
template <typename Torus>
uint64_t get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one(
    uint32_t polynomial_size) {
  return safe_mul_sizeof<Torus>(polynomial_size); // accumulator
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two(
    uint32_t polynomial_size) {
  return safe_mul_sizeof<Torus>(polynomial_size); // accumulator
}

template <typename Torus, typename params>
__host__ uint64_t scratch_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer<Torus, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  cuda_set_device(gpu_index);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate_step_one =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<Torus>(
          polynomial_size);
  uint64_t full_sm_accumulate_step_two =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<Torus>(
          polynomial_size);
  uint64_t partial_sm_accumulate_step_one =
      get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
          Torus>(polynomial_size);

  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  if (max_shared_memory < partial_sm_accumulate_step_one) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, NOSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, NOSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, NOSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, NOSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory < full_sm_accumulate_step_one) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, PARTIALSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        partial_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, PARTIALSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, PARTIALSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        partial_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, PARTIALSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one<
            Torus, params, FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  if (max_shared_memory < full_sm_accumulate_step_two) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, NOSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, NOSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, NOSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, NOSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two<
            Torus, params, FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  auto lwe_chunk_size = get_lwe_chunk_size<Torus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size, glwe_dimension,
      level_count, full_sm_keybundle);
  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<Torus, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, lwe_chunk_size, PBS_VARIANT::DEFAULT,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, class params>
__host__ void execute_compute_keybundle(
    cudaStream_t stream, uint32_t gpu_index, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *buffer, uint32_t num_samples,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t level_count, uint32_t lwe_offset) {
  cuda_set_device(gpu_index);
  PANIC_IF_FALSE(sizeof(Torus) == 8,
                 "Error: PBS keybundle only supports 64-bit "
                 "Torus type.");
  auto lwe_chunk_size = buffer->lwe_chunk_size;
  uint64_t chunk_size = std::min(
      lwe_chunk_size, (uint64_t)(lwe_dimension / grouping_factor) - lwe_offset);

  uint64_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<Torus>(
          polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  auto d_mem = buffer->d_mem_keybundle;
  auto keybundle_fft = buffer->keybundle_fft;

  // Compute a keybundle
  dim3 grid_keybundle(num_samples * chunk_size,
                      (glwe_dimension + 1) * (glwe_dimension + 1), level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  if (max_shared_memory < full_sm_keybundle) {
    device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>
        <<<grid_keybundle, thds, 0, stream>>>(
            lwe_array_in, lwe_input_indexes, keybundle_fft, bootstrapping_key,
            lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
            level_count, lwe_offset, chunk_size, keybundle_size_per_input,
            d_mem, full_sm_keybundle);
  } else {
    bool supports_tbc =
        has_support_to_cuda_programmable_bootstrap_tbc_multi_bit<uint64_t>(
            num_samples, glwe_dimension, polynomial_size, level_count,
            cuda_get_max_shared_memory(gpu_index));

    if (supports_tbc && polynomial_size == 2048 && grouping_factor == 4 &&
        level_count == 1 && glwe_dimension == 1) {
      dim3 thds_new_keybundle(512, 1, 1);
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_keybundle_2_2_params<
              Torus, Degree<2048>, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, 3 * full_sm_keybundle));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_multi_bit_programmable_bootstrap_keybundle_2_2_params<
              Torus, Degree<2048>, FULLSM>,
          cudaFuncCachePreferShared));
      check_cuda_error(cudaGetLastError());
      device_multi_bit_programmable_bootstrap_keybundle_2_2_params<
          Torus, Degree<2048>, FULLSM><<<grid_keybundle, thds_new_keybundle,
                                         3 * full_sm_keybundle, stream>>>(
          lwe_array_in, lwe_input_indexes, keybundle_fft, bootstrapping_key,
          lwe_dimension, lwe_offset, chunk_size, keybundle_size_per_input);
    } else {
      device_multi_bit_programmable_bootstrap_keybundle<Torus, params, FULLSM>
          <<<grid_keybundle, thds, full_sm_keybundle, stream>>>(
              lwe_array_in, lwe_input_indexes, keybundle_fft, bootstrapping_key,
              lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
              level_count, lwe_offset, chunk_size, keybundle_size_per_input,
              d_mem, 0);
    }
  }
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, class params, bool is_first_iter>
__host__ void execute_step_one(
    cudaStream_t stream, uint32_t gpu_index, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, pbs_buffer<Torus, MULTI_BIT> *buffer,
    uint32_t num_samples, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count) {
  cuda_set_device(gpu_index);
  PANIC_IF_FALSE(
      sizeof(Torus) == 8,
      "Error: Programmable bootstrap multi-bit step one only supports 64-bit "
      "Torus type.");
  uint64_t full_sm_accumulate_step_one =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<Torus>(
          polynomial_size);
  uint64_t partial_sm_accumulate_step_one =
      get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
          Torus>(polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  //
  auto d_mem = buffer->d_mem_acc_step_one;
  auto global_accumulator = buffer->global_accumulator;
  auto global_accumulator_fft = buffer->global_join_buffer;

  dim3 grid_accumulate_step_one(num_samples, glwe_dimension + 1, level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  if (max_shared_memory < partial_sm_accumulate_step_one)
    device_multi_bit_programmable_bootstrap_accumulate_step_one<
        Torus, params, NOSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, 0, stream>>>(
            lwe_array_in, lwe_input_indexes, lut_vector, lut_vector_indexes,
            global_accumulator, global_accumulator_fft, lwe_dimension,
            glwe_dimension, polynomial_size, base_log, level_count, d_mem,
            full_sm_accumulate_step_one);
  else if (max_shared_memory < full_sm_accumulate_step_one)
    device_multi_bit_programmable_bootstrap_accumulate_step_one<
        Torus, params, PARTIALSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, partial_sm_accumulate_step_one,
           stream>>>(lwe_array_in, lwe_input_indexes, lut_vector,
                     lut_vector_indexes, global_accumulator,
                     global_accumulator_fft, lwe_dimension, glwe_dimension,
                     polynomial_size, base_log, level_count, d_mem,
                     partial_sm_accumulate_step_one);
  else
    device_multi_bit_programmable_bootstrap_accumulate_step_one<
        Torus, params, FULLSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, full_sm_accumulate_step_one,
           stream>>>(lwe_array_in, lwe_input_indexes, lut_vector,
                     lut_vector_indexes, global_accumulator,
                     global_accumulator_fft, lwe_dimension, glwe_dimension,
                     polynomial_size, base_log, level_count, d_mem, 0);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, class params, bool is_last_iter>
__host__ void
execute_step_two(cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
                 Torus const *lwe_output_indexes,
                 pbs_buffer<Torus, MULTI_BIT> *buffer, uint32_t num_samples,
                 uint32_t glwe_dimension, uint32_t polynomial_size,
                 uint32_t level_count, uint32_t j, uint32_t num_many_lut,
                 uint32_t lut_stride) {
  cuda_set_device(gpu_index);
  PANIC_IF_FALSE(
      sizeof(Torus) == 8,
      "Error: Programmable bootstrap multi-bit step two only supports 64-bit "
      "Torus type.");
  uint32_t lwe_chunk_size = (uint32_t)(buffer->lwe_chunk_size);
  uint64_t full_sm_accumulate_step_two =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<Torus>(
          polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  auto d_mem = buffer->d_mem_acc_step_two;
  auto keybundle_fft = buffer->keybundle_fft;
  auto global_accumulator = buffer->global_accumulator;
  auto global_accumulator_fft = buffer->global_join_buffer;

  dim3 grid_accumulate_step_two(num_samples, glwe_dimension + 1);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  if (max_shared_memory < full_sm_accumulate_step_two)
    device_multi_bit_programmable_bootstrap_accumulate_step_two<
        Torus, params, NOSM, is_last_iter>
        <<<grid_accumulate_step_two, thds, 0, stream>>>(
            lwe_array_out, lwe_output_indexes, keybundle_fft,
            global_accumulator, global_accumulator_fft, glwe_dimension,
            polynomial_size, level_count, j, lwe_chunk_size, d_mem,
            full_sm_accumulate_step_two, num_many_lut, lut_stride);
  else
    device_multi_bit_programmable_bootstrap_accumulate_step_two<
        Torus, params, FULLSM, is_last_iter>
        <<<grid_accumulate_step_two, thds, full_sm_accumulate_step_two,
           stream>>>(lwe_array_out, lwe_output_indexes, keybundle_fft,
                     global_accumulator, global_accumulator_fft, glwe_dimension,
                     polynomial_size, level_count, j, lwe_chunk_size, d_mem, 0,
                     num_many_lut, lut_stride);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, class params>
__host__ void host_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  auto lwe_chunk_size = buffer->lwe_chunk_size;

  for (uint32_t lwe_offset = 0; lwe_offset < (lwe_dimension / grouping_factor);
       lwe_offset += lwe_chunk_size) {

    // Compute a keybundle
    execute_compute_keybundle<Torus, params>(
        stream, gpu_index, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        buffer, num_samples, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, level_count, lwe_offset);
    // Accumulate
    uint32_t chunk_size =
        std::min((uint32_t)lwe_chunk_size,
                 (lwe_dimension / grouping_factor) - lwe_offset);
    for (uint32_t j = 0; j < chunk_size; j++) {
      bool is_first_iter = (j + lwe_offset) == 0;
      bool is_last_iter =
          (j + lwe_offset) + 1 == (lwe_dimension / grouping_factor);
      if (is_first_iter) {
        execute_step_one<Torus, params, true>(
            stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
            lwe_input_indexes, buffer, num_samples, lwe_dimension,
            glwe_dimension, polynomial_size, base_log, level_count);
      } else {
        execute_step_one<Torus, params, false>(
            stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
            lwe_input_indexes, buffer, num_samples, lwe_dimension,
            glwe_dimension, polynomial_size, base_log, level_count);
      }

      if (is_last_iter) {
        execute_step_two<Torus, params, true>(
            stream, gpu_index, lwe_array_out, lwe_output_indexes, buffer,
            num_samples, glwe_dimension, polynomial_size, level_count, j,
            num_many_lut, lut_stride);
      } else {
        execute_step_two<Torus, params, false>(
            stream, gpu_index, lwe_array_out, lwe_output_indexes, buffer,
            num_samples, glwe_dimension, polynomial_size, level_count, j,
            num_many_lut, lut_stride);
      }
    }
  }
}
#endif // MULTIBIT_PBS_H
