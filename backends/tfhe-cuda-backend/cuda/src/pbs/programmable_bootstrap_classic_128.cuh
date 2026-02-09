#ifndef CUDA_PBS_CUH_128
#define CUDA_PBS_CUH_128

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft128/fft128.cuh"
#include "pbs/bootstrapping_key.cuh"
#include "pbs/pbs_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "programmable_bootstrap.cuh"
#include "types/complex/operations.cuh"

template <typename InputTorus, class params, sharedMemDegree SMD,
          bool first_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_programmable_bootstrap_step_one_128(
        const __uint128_t *__restrict__ lut_vector,
        const InputTorus *__restrict__ lwe_array_in,
        const double *__restrict__ bootstrapping_key,
        __uint128_t *global_accumulator, double *global_join_buffer,
        uint32_t lwe_iteration, uint32_t lwe_dimension,
        uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
        int8_t *device_mem, uint64_t device_memory_size_per_block,
        PBS_MS_REDUCTION_T noise_reduction_type) {

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

  __uint128_t *accumulator = (__uint128_t *)selected_memory;
  double *accumulator_fft =
      (double *)accumulator +
      (ptrdiff_t)(sizeof(__uint128_t) * polynomial_size / sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double *)sharedmem;

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const InputTorus *block_lwe_array_in =
      &lwe_array_in[blockIdx.x * (lwe_dimension + 1)];

  const __uint128_t *block_lut_vector = lut_vector;

  __uint128_t *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1)) * params::degree;

  double *global_fft_slice =
      global_join_buffer + (blockIdx.y + blockIdx.z * (glwe_dimension + 1) +
                            blockIdx.x * level_count * (glwe_dimension + 1)) *
                               (polynomial_size / 2) * 4;

  constexpr auto log_modulus = params::log2_degree + 1;
  if constexpr (first_iter) {
    // First iteration
    // Put "b" in [0, 2N[
    InputTorus b_hat = 0;
    InputTorus correction = 0;
    if (noise_reduction_type == PBS_MS_REDUCTION_T::CENTERED) {
      correction = centered_binary_modulus_switch_body_correction_to_add(
          block_lwe_array_in, lwe_dimension, log_modulus);
    }
    modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                   log_modulus);

    // The y-dimension is used to select the element of the GLWE this block will
    // compute
    divide_by_monomial_negacyclic_inplace<__uint128_t, params::opt,
                                          params::degree / params::opt>(
        accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
        false);

    // Persist
    int tid = threadIdx.x;
    for (int i = 0; i < params::opt; i++) {
      global_slice[tid] = accumulator[tid];
      tid += params::degree / params::opt;
    }
  }

  // Put "a" in [0, 2N[
  InputTorus a_hat = 0;
  modulus_switch<InputTorus>(block_lwe_array_in[lwe_iteration], a_hat,
                             log_modulus);

  __syncthreads();

  // Perform ACC * (X^ä - 1)
  multiply_by_monomial_negacyclic_and_sub_polynomial<
      __uint128_t, params::opt, params::degree / params::opt>(
      global_slice, accumulator, a_hat);

  // Perform a rounding to increase the accuracy of the
  // bootstrapped ciphertext
  init_decomposer_state_inplace<__uint128_t, params::opt,
                                params::degree / params::opt>(
      accumulator, base_log, level_count);

  __syncthreads();

  // Decompose the accumulator. Each block gets one level of the
  // decomposition, for the mask and the body (so block 0 will have the
  // accumulator decomposed at level 0, 1 at 1, etc.)
  GadgetMatrix<__uint128_t, params> gadget_acc(base_log, level_count,
                                               accumulator);
  gadget_acc.decompose_and_compress_level_128(accumulator_fft, blockIdx.z);

  // Switch to the FFT space
  auto acc_fft_re_hi = accumulator_fft + 0 * params::degree / 2;
  auto acc_fft_re_lo = accumulator_fft + 1 * params::degree / 2;
  auto acc_fft_im_hi = accumulator_fft + 2 * params::degree / 2;
  auto acc_fft_im_lo = accumulator_fft + 3 * params::degree / 2;

  auto global_fft_re_hi = global_fft_slice + 0 * params::degree / 2;
  auto global_fft_re_lo = global_fft_slice + 1 * params::degree / 2;
  auto global_fft_im_hi = global_fft_slice + 2 * params::degree / 2;
  auto global_fft_im_lo = global_fft_slice + 3 * params::degree / 2;

  negacyclic_forward_fft_f128<HalfDegree<params>>(acc_fft_re_hi, acc_fft_re_lo,
                                                  acc_fft_im_hi, acc_fft_im_lo);

  int tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    global_fft_re_hi[tid] = acc_fft_re_hi[tid];
    global_fft_re_lo[tid] = acc_fft_re_lo[tid];
    global_fft_im_hi[tid] = acc_fft_im_hi[tid];
    global_fft_im_lo[tid] = acc_fft_im_lo[tid];
    tid += params::degree / params::opt;
  }
}

template <typename Torus, class params, sharedMemDegree SMD, bool last_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_programmable_bootstrap_step_two_128(
        Torus *lwe_array_out, const double *__restrict__ bootstrapping_key,
        Torus *global_accumulator, double *global_join_buffer,
        uint32_t lwe_iteration, uint32_t lwe_dimension,
        uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
        int8_t *device_mem, uint64_t device_memory_size_per_block) {

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
  Torus *accumulator = (Torus *)selected_memory;
  double *accumulator_fft =
      (double *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * params::degree / sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double *)sharedmem;

  for (int level = 0; level < level_count; level++) {
    double *global_fft_slice =
        global_join_buffer + (level + blockIdx.x * level_count) *
                                 (glwe_dimension + 1) * (params::degree / 2) *
                                 4;

    for (int j = 0; j < (glwe_dimension + 1); j++) {
      double *fft = global_fft_slice + j * params::degree / 2 * 4;

      // Get the bootstrapping key piece necessary for the multiplication
      // It is already in the Fourier domain
      auto bsk_slice = get_ith_mask_kth_block_128(
          bootstrapping_key, lwe_iteration, j, level, polynomial_size,
          glwe_dimension, level_count);
      auto bsk_poly = bsk_slice + blockIdx.y * params::degree / 2 * 4;

      polynomial_product_accumulate_in_fourier_domain_128<params>(
          accumulator_fft, fft, bsk_poly, !level && !j);
    }
  }

  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1)) * params::degree;

  // Load the persisted accumulator
  int tid = threadIdx.x;
  for (int i = 0; i < params::opt; i++) {
    accumulator[tid] = global_slice[tid];
    tid += params::degree / params::opt;
  }

  // Perform the inverse FFT on the result of the GGSW x GLWE and add to the
  // accumulator
  auto acc_fft_re_hi = accumulator_fft + 0 * params::degree / 2;
  auto acc_fft_re_lo = accumulator_fft + 1 * params::degree / 2;
  auto acc_fft_im_hi = accumulator_fft + 2 * params::degree / 2;
  auto acc_fft_im_lo = accumulator_fft + 3 * params::degree / 2;

  negacyclic_backward_fft_f128<HalfDegree<params>>(
      acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);

  add_to_torus_128<Torus, params>(acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi,
                                  acc_fft_im_lo, accumulator);

  if constexpr (last_iter) {
    // Last iteration
    auto block_lwe_array_out =
        &lwe_array_out[blockIdx.x * (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra blocks,
      // in case they're not synchronized
      sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
    } else if (blockIdx.y == glwe_dimension) {
      __syncthreads();
      sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
    }
  } else {
    // We don't sync here because we use same indexes to read from `accumulator`
    // as it was used in `add_to_torus_128` to write inside it Persist the
    // updated accumulator
    tid = threadIdx.x;
    for (int i = 0; i < params::opt; i++) {
      global_slice[tid] = accumulator[tid];
      tid += params::degree / params::opt;
    }
  }
}

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
template <typename InputTorus, class params, sharedMemDegree SMD>
__global__ void device_programmable_bootstrap_cg_128(
    __uint128_t *lwe_array_out, const __uint128_t *__restrict__ lut_vector,
    const InputTorus *__restrict__ lwe_array_in,
    const double *__restrict__ bootstrapping_key, double *join_buffer,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, int8_t *device_mem,
    uint64_t device_memory_size_per_block,
    PBS_MS_REDUCTION_T noise_reduction_type) {

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
  __uint128_t *accumulator = (__uint128_t *)selected_memory;
  __uint128_t *accumulator_rotated =
      (__uint128_t *)accumulator + (ptrdiff_t)(polynomial_size);
  double *accumulator_fft =
      (double *)(accumulator_rotated) +
      (ptrdiff_t)(polynomial_size * sizeof(__uint128_t) / sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double *)sharedmem;

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const InputTorus *block_lwe_array_in =
      &lwe_array_in[blockIdx.x * (lwe_dimension + 1)];

  const __uint128_t *block_lut_vector = lut_vector;

  double *block_join_buffer =
      &join_buffer[blockIdx.x * level_count * (glwe_dimension + 1) *
                   params::degree / 2 * 4];
  // Since the space is L1 cache is small, we use the same memory location for
  // the rotated accumulator and the fft accumulator, since we know that the
  // rotated array is not in use anymore by the time we perform the fft

  // Put "b" in [0, 2N[
  constexpr auto log_modulus = params::log2_degree + 1;
  InputTorus b_hat = 0;
  InputTorus correction = 0;
  if (noise_reduction_type == PBS_MS_REDUCTION_T::CENTERED) {
    correction = centered_binary_modulus_switch_body_correction_to_add(
        block_lwe_array_in, lwe_dimension, log_modulus);
  }
  modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                 log_modulus);

  divide_by_monomial_negacyclic_inplace<__uint128_t, params::opt,
                                        params::degree / params::opt>(
      accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
      false);

  for (int i = 0; i < lwe_dimension; i++) {
    __syncthreads();

    // Put "a" in [0, 2N[
    InputTorus a_hat = 0;
    modulus_switch<InputTorus>(block_lwe_array_in[i], a_hat, log_modulus);

    // Perform ACC * (X^ä - 1)
    multiply_by_monomial_negacyclic_and_sub_polynomial<
        __uint128_t, params::opt, params::degree / params::opt>(
        accumulator, accumulator_rotated, a_hat);

    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace<__uint128_t, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, base_log, level_count);

    __syncthreads();

    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<__uint128_t, params> gadget_acc(base_log, level_count,
                                                 accumulator_rotated);
    gadget_acc.decompose_and_compress_level_128(accumulator_fft, blockIdx.z);

    auto acc_fft_re_hi = accumulator_fft + 0 * params::degree / 2;
    auto acc_fft_re_lo = accumulator_fft + 1 * params::degree / 2;
    auto acc_fft_im_hi = accumulator_fft + 2 * params::degree / 2;
    auto acc_fft_im_lo = accumulator_fft + 3 * params::degree / 2;

    negacyclic_forward_fft_f128<HalfDegree<params>>(
        acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);
    __syncthreads();
    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_in_fourier_domain_128<grid_group, params>(
        accumulator_fft, block_join_buffer, bootstrapping_key, i, grid);

    negacyclic_backward_fft_f128<HalfDegree<params>>(
        acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);
    __syncthreads();

    add_to_torus_128<__uint128_t, params>(acc_fft_re_hi, acc_fft_re_lo,
                                          acc_fft_im_hi, acc_fft_im_lo,
                                          accumulator);
  }

  auto block_lwe_array_out =
      &lwe_array_out[blockIdx.x * (glwe_dimension * polynomial_size + 1) +
                     blockIdx.y * polynomial_size];

  if (blockIdx.z == 0) {
    if (blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra blocks,
      // in case they're not synchronized
      sample_extract_mask<__uint128_t, params>(block_lwe_array_out,
                                               accumulator);

    } else if (blockIdx.y == glwe_dimension) {
      __syncthreads();
      sample_extract_body<__uint128_t, params>(block_lwe_array_out, accumulator,
                                               0);
    }
  }
}

template <typename InputTorus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_cg_128(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  cuda_set_device(gpu_index);
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<__uint128_t>(
          polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<__uint128_t>(
          polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg_128<InputTorus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128<InputTorus, params, PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg_128<InputTorus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128<InputTorus, params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL>(
      stream, gpu_index, lwe_dimension, glwe_dimension, polynomial_size,
      level_count, input_lwe_ciphertext_count, PBS_VARIANT::CG,
      allocate_gpu_memory, noise_reduction_type, size_tracker);
  return size_tracker;
}

template <typename InputTorus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  cuda_set_device(gpu_index);
  uint64_t full_sm_step_one =
      get_buffer_size_full_sm_programmable_bootstrap_step_one<__uint128_t>(
          polynomial_size);
  uint64_t full_sm_step_two =
      get_buffer_size_full_sm_programmable_bootstrap_step_two<__uint128_t>(
          polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap<__uint128_t>(
          polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  // Configure step one
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm_step_one) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128<InputTorus, params,
                                                   PARTIALSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128<InputTorus, params,
                                                   PARTIALSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128<InputTorus, params,
                                                   PARTIALSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128<InputTorus, params,
                                                   PARTIALSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128<InputTorus, params, FULLSM,
                                                   true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128<InputTorus, params, FULLSM,
                                                   true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128<InputTorus, params, FULLSM,
                                                   false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128<InputTorus, params, FULLSM,
                                                   false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  // Configure step two
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm_step_two) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two_128<__uint128_t, params,
                                                   PARTIALSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two_128<__uint128_t, params,
                                                   PARTIALSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two_128<__uint128_t, params,
                                                   PARTIALSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two_128<__uint128_t, params,
                                                   PARTIALSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM,
                                                   true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM,
                                                   true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM,
                                                   false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM,
                                                   false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL>(
      stream, gpu_index, lwe_dimension, glwe_dimension, polynomial_size,
      level_count, input_lwe_ciphertext_count, PBS_VARIANT::DEFAULT,
      allocate_gpu_memory, noise_reduction_type, size_tracker);
  return size_tracker;
}

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the PBS on 128 bits inputs, into `buffer`. It also configures SM options on
 * the GPU in case FULLSM or PARTIALSM mode is going to be used.
 */
template <typename InputTorus>
uint64_t scratch_cuda_programmable_bootstrap_128_vector(
    void *stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  auto buffer = (pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **)pbs_buffer;

  if (has_support_to_cuda_programmable_bootstrap_128_cg(
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, max_shared_memory)) {
    switch (polynomial_size) {
    case 256:
      return scratch_programmable_bootstrap_cg_128<InputTorus, Degree<256>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 512:
      return scratch_programmable_bootstrap_cg_128<InputTorus, Degree<512>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 1024:
      return scratch_programmable_bootstrap_cg_128<InputTorus, Degree<1024>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 2048:
      return scratch_programmable_bootstrap_cg_128<InputTorus, Degree<2048>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 4096:
      // We use AmortizedDegree for 4096 to avoid register exhaustion
      return scratch_programmable_bootstrap_cg_128<InputTorus,
                                                   AmortizedDegree<4096>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    default:
      PANIC("Cuda error (classical PBS128): unsupported polynomial size. "
            "Supported N's are powers of two"
            " in the interval [256..4096].")
    }
  } else {
    switch (polynomial_size) {
    case 256:
      return scratch_programmable_bootstrap_128<InputTorus, Degree<256>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 512:
      return scratch_programmable_bootstrap_128<InputTorus, Degree<512>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 1024:
      return scratch_programmable_bootstrap_128<InputTorus, Degree<1024>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 2048:
      return scratch_programmable_bootstrap_128<InputTorus, Degree<2048>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    case 4096:
      // We use AmortizedDegree for 4096 to avoid register exhaustion
      return scratch_programmable_bootstrap_128<InputTorus,
                                                AmortizedDegree<4096>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
      break;
    default:
      PANIC("Cuda error (classical PBS): unsupported polynomial size. "
            "Supported N's are powers of two"
            " in the interval [256..4096].")
    }
  }
}

template <typename InputTorus, class params, bool first_iter>
__host__ void execute_step_one_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t const *lut_vector,
    InputTorus const *lwe_array_in, double const *bootstrapping_key,
    __uint128_t *global_accumulator, double *global_join_buffer,
    PBS_MS_REDUCTION_T noise_reduction_type,
    uint32_t input_lwe_ciphertext_count, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, int8_t *d_mem, int lwe_iteration, uint64_t partial_sm,
    uint64_t partial_dm, uint64_t full_sm, uint64_t full_dm) {

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1, level_count);

  if (max_shared_memory < partial_sm) {
    device_programmable_bootstrap_step_one_128<InputTorus, params, NOSM,
                                               first_iter>
        <<<grid, thds, 0, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, full_dm, noise_reduction_type);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_one_128<InputTorus, params, PARTIALSM,
                                               first_iter>
        <<<grid, thds, partial_sm, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, partial_dm, noise_reduction_type);
  } else {
    device_programmable_bootstrap_step_one_128<InputTorus, params, FULLSM,
                                               first_iter>
        <<<grid, thds, full_sm, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, 0, noise_reduction_type);
  }
  check_cuda_error(cudaGetLastError());
}

template <class params, bool last_iter>
__host__ void execute_step_two_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    double const *bootstrapping_key, __uint128_t *global_accumulator,
    double *global_join_buffer, uint32_t input_lwe_ciphertext_count,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, int8_t *d_mem, int lwe_iteration,
    uint64_t partial_sm, uint64_t partial_dm, uint64_t full_sm,
    uint64_t full_dm) {

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1);

  if (max_shared_memory < partial_sm) {
    device_programmable_bootstrap_step_two_128<__uint128_t, params, NOSM,
                                               last_iter>
        <<<grid, thds, 0, stream>>>(
            lwe_array_out, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, full_dm);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_two_128<__uint128_t, params, PARTIALSM,
                                               last_iter>
        <<<grid, thds, partial_sm, stream>>>(
            lwe_array_out, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, partial_dm);
  } else {
    device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM,
                                               last_iter>
        <<<grid, thds, full_sm, stream>>>(
            lwe_array_out, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, 0);
  }
  check_cuda_error(cudaGetLastError());
}

/*
 * Host wrapper to the programmable bootstrap 128
 */
template <typename InputTorus, class params>
__host__ void host_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *pbs_buffer,
    uint32_t glwe_dimension, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count) {
  cuda_set_device(gpu_index);

  // With SM each block corresponds to either the mask or body, no need to
  // duplicate data for each
  uint64_t full_sm_step_one =
      get_buffer_size_full_sm_programmable_bootstrap_step_one<__uint128_t>(
          polynomial_size);
  uint64_t full_sm_step_two =
      get_buffer_size_full_sm_programmable_bootstrap_step_two<__uint128_t>(
          polynomial_size);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap<__uint128_t>(
          polynomial_size);

  uint64_t partial_dm_step_one = full_sm_step_one - partial_sm;
  uint64_t partial_dm_step_two = full_sm_step_two - partial_sm;
  uint64_t full_dm_step_one = full_sm_step_one;
  uint64_t full_dm_step_two = full_sm_step_two;

  __uint128_t *global_accumulator = pbs_buffer->global_accumulator;
  double *global_join_buffer = pbs_buffer->global_join_buffer;
  int8_t *d_mem = pbs_buffer->d_mem;
  auto noise_reduction_type = pbs_buffer->noise_reduction_type;

  for (int i = 0; i < lwe_dimension; i++) {
    if (i == 0) {
      execute_step_one_128<InputTorus, params, true>(
          stream, gpu_index, lut_vector, lwe_array_in, bootstrapping_key,
          global_accumulator, global_join_buffer, noise_reduction_type,
          input_lwe_ciphertext_count, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, d_mem, i, partial_sm,
          partial_dm_step_one, full_sm_step_one, full_dm_step_one);
    } else {
      execute_step_one_128<InputTorus, params, false>(
          stream, gpu_index, lut_vector, lwe_array_in, bootstrapping_key,
          global_accumulator, global_join_buffer, noise_reduction_type,
          input_lwe_ciphertext_count, lwe_dimension, glwe_dimension,
          polynomial_size, base_log, level_count, d_mem, i, partial_sm,
          partial_dm_step_one, full_sm_step_one, full_dm_step_one);
    }
    if (i == lwe_dimension - 1) {
      execute_step_two_128<params, true>(
          stream, gpu_index, lwe_array_out, bootstrapping_key,
          global_accumulator, global_join_buffer, input_lwe_ciphertext_count,
          lwe_dimension, glwe_dimension, polynomial_size, base_log, level_count,
          d_mem, i, partial_sm, partial_dm_step_two, full_sm_step_two,
          full_dm_step_two);
    } else {
      execute_step_two_128<params, false>(
          stream, gpu_index, lwe_array_out, bootstrapping_key,
          global_accumulator, global_join_buffer, input_lwe_ciphertext_count,
          lwe_dimension, glwe_dimension, polynomial_size, base_log, level_count,
          d_mem, i, partial_sm, partial_dm_step_two, full_sm_step_two,
          full_dm_step_two);
    }
  }
}

template <typename InputTorus, class params>
__host__ void host_programmable_bootstrap_cg_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    uint32_t glwe_dimension, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count) {

  // With SM each block corresponds to either the mask or body, no need to
  // duplicate data for each
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<__uint128_t>(
          polynomial_size);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<__uint128_t>(
          polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);

  uint64_t full_dm = full_sm;

  uint64_t partial_dm = full_dm - partial_sm;

  int8_t *d_mem = buffer->d_mem;
  double *buffer_fft = buffer->global_join_buffer;
  auto noise_reduction_type = buffer->noise_reduction_type;

  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1, level_count);

  void *kernel_args[12];
  kernel_args[0] = &lwe_array_out;
  kernel_args[1] = &lut_vector;
  kernel_args[2] = &lwe_array_in;
  kernel_args[3] = &bootstrapping_key;
  kernel_args[4] = &buffer_fft;
  kernel_args[5] = &lwe_dimension;
  kernel_args[6] = &polynomial_size;
  kernel_args[7] = &base_log;
  kernel_args[8] = &level_count;
  kernel_args[9] = &d_mem;
  kernel_args[11] = &noise_reduction_type;

  if (max_shared_memory < partial_sm) {
    kernel_args[10] = &full_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_programmable_bootstrap_cg_128<InputTorus, params, NOSM>,
        grid, thds, (void **)kernel_args, 0, stream));
  } else if (max_shared_memory < full_sm) {
    kernel_args[10] = &partial_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)
            device_programmable_bootstrap_cg_128<InputTorus, params, PARTIALSM>,
        grid, thds, (void **)kernel_args, partial_sm, stream));
  } else {
    int no_dm = 0;
    kernel_args[10] = &no_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)
            device_programmable_bootstrap_cg_128<InputTorus, params, FULLSM>,
        grid, thds, (void **)kernel_args, full_sm, stream));
  }

  check_cuda_error(cudaGetLastError());
}

// Verify if the grid size satisfies the cooperative group constraints
template <class params>
__host__ bool verify_cuda_programmable_bootstrap_128_cg_grid_size(
    int glwe_dimension, int level_count, int num_samples,
    uint32_t max_shared_memory) {

  // If Cooperative Groups is not supported, no need to check anything else
  if (!cuda_check_support_cooperative_groups())
    return false;

  // Calculate the dimension of the kernel
  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<__uint128_t>(
          params::degree);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<__uint128_t>(
          params::degree);

  int thds = params::degree / params::opt;

  // Get the maximum number of active blocks per streaming multiprocessors
  int number_of_blocks = level_count * (glwe_dimension + 1) * num_samples;
  int max_active_blocks_per_sm;

  if (max_shared_memory < partial_sm) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg_128<__uint128_t, params, NOSM>,
        thds, 0));
  } else if (max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg_128<__uint128_t, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128<__uint128_t, params, PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg_128<__uint128_t, params,
                                                     PARTIALSM>,
        thds, partial_sm));
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg_128<__uint128_t, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128<__uint128_t, params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)
            device_programmable_bootstrap_cg_128<__uint128_t, params, FULLSM>,
        thds, full_sm));
  }

  // Get the number of streaming multiprocessors
  int number_of_sm = 0;
  cudaDeviceGetAttribute(&number_of_sm, cudaDevAttrMultiProcessorCount, 0);

  return number_of_blocks <= max_active_blocks_per_sm * number_of_sm;
}

// Verify if the grid size satisfies the cooperative group constraints
__host__ bool supports_cooperative_groups_on_programmable_bootstrap_128(
    int glwe_dimension, int polynomial_size, int level_count, int num_samples,
    uint32_t max_shared_memory) {
  switch (polynomial_size) {
  case 256:
    return verify_cuda_programmable_bootstrap_128_cg_grid_size<Degree<256>>(
        glwe_dimension, level_count, num_samples, max_shared_memory);
  case 512:
    return verify_cuda_programmable_bootstrap_128_cg_grid_size<Degree<512>>(
        glwe_dimension, level_count, num_samples, max_shared_memory);
  case 1024:
    return verify_cuda_programmable_bootstrap_128_cg_grid_size<Degree<1024>>(
        glwe_dimension, level_count, num_samples, max_shared_memory);
  case 2048:
    return verify_cuda_programmable_bootstrap_128_cg_grid_size<Degree<2048>>(
        glwe_dimension, level_count, num_samples, max_shared_memory);
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    return verify_cuda_programmable_bootstrap_128_cg_grid_size<
        AmortizedDegree<4096>>(glwe_dimension, level_count, num_samples,
                               max_shared_memory);
  default:
    PANIC("Cuda error (classical PBS128): unsupported polynomial size. "
          "Supported N's are powers of two"
          " in the interval [256..4096].")
  }
}
#endif // TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_PBS_PROGRAMMABLE_BOOTSTRAP_CLASSIC_128_CUH_
