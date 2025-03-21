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
#include "types/complex/operations.cuh"

template <typename Torus, class params, sharedMemDegree SMD>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_programmable_bootstrap_step_one_128(
        const Torus *__restrict__ lut_vector,
        const Torus *__restrict__ lwe_array_in,
        const double *__restrict__ bootstrapping_key, Torus *global_accumulator,
        double *global_join_buffer, uint32_t lwe_iteration,
        uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
        uint32_t level_count, int8_t *device_mem,
        uint64_t device_memory_size_per_block) {

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

  Torus *accumulator = (Torus *)selected_memory;
  double *accumulator_fft =
      (double *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double *)sharedmem;

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const Torus *block_lwe_array_in =
      &lwe_array_in[blockIdx.x * (lwe_dimension + 1)];

  const Torus *block_lut_vector = lut_vector;

  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1)) * params::degree;

  double *global_fft_slice =
      global_join_buffer + (blockIdx.y + blockIdx.z * (glwe_dimension + 1) +
                            blockIdx.x * level_count * (glwe_dimension + 1)) *
                               (polynomial_size / 2) * 4;

  if (lwe_iteration == 0) {
    // First iteration
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                   params::log2_degree + 1);
    // The y-dimension is used to select the element of the GLWE this block will
    // compute
    divide_by_monomial_negacyclic_inplace<Torus, params::opt,
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
  Torus a_hat = 0;
  modulus_switch(block_lwe_array_in[lwe_iteration], a_hat,
                 params::log2_degree + 1); // 2 * params::log2_degree + 1);

  synchronize_threads_in_block();

  // Perform ACC * (X^ä - 1)
  multiply_by_monomial_negacyclic_and_sub_polynomial<
      Torus, params::opt, params::degree / params::opt>(global_slice,
                                                        accumulator, a_hat);

  // Perform a rounding to increase the accuracy of the
  // bootstrapped ciphertext
  init_decomposer_state_inplace<Torus, params::opt,
                                params::degree / params::opt>(
      accumulator, base_log, level_count);

  synchronize_threads_in_block();

  // Decompose the accumulator. Each block gets one level of the
  // decomposition, for the mask and the body (so block 0 will have the
  // accumulator decomposed at level 0, 1 at 1, etc.)
  GadgetMatrix<Torus, params> gadget_acc(base_log, level_count, accumulator);
  gadget_acc.decompose_and_compress_level_128(accumulator_fft, blockIdx.z);

  // We are using the same memory space for accumulator_fft and
  // accumulator_rotated, so we need to synchronize here to make sure they
  // don't modify the same memory space at the same time
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

template <typename Torus, class params, sharedMemDegree SMD>
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

  if (lwe_iteration + 1 == lwe_dimension) {
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
      sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
    }
  } else {
    // Persist the updated accumulator
    tid = threadIdx.x;
    for (int i = 0; i < params::opt; i++) {
      global_slice[tid] = accumulator[tid];
      tid += params::degree / params::opt;
    }
  }
}

template <typename params>
__host__ void scratch_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index, pbs_buffer_128<CLASSICAL> **buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

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
        device_programmable_bootstrap_step_one_128<__uint128_t, params,
                                                   PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128<__uint128_t, params,
                                                   PARTIALSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128<__uint128_t, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_one));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128<__uint128_t, params, FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  // Configure step two
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm_step_two) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two_128<__uint128_t, params,
                                                   PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two_128<__uint128_t, params,
                                                   PARTIALSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_two));
    cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  *buffer = new pbs_buffer_128<CLASSICAL>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, PBS_VARIANT::DEFAULT, allocate_gpu_memory);
}

template <class params>
__host__ void execute_step_one_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t const *lut_vector,
    __uint128_t const *lwe_array_in, double const *bootstrapping_key,
    __uint128_t *global_accumulator, double *global_join_buffer,
    uint32_t input_lwe_ciphertext_count, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, int8_t *d_mem, int lwe_iteration, uint64_t partial_sm,
    uint64_t partial_dm, uint64_t full_sm, uint64_t full_dm) {

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1, level_count);

  if (max_shared_memory < partial_sm) {
    device_programmable_bootstrap_step_one_128<__uint128_t, params, NOSM>
        <<<grid, thds, 0, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, full_dm);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_one_128<__uint128_t, params, PARTIALSM>
        <<<grid, thds, partial_sm, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, partial_dm);
  } else {
    device_programmable_bootstrap_step_one_128<__uint128_t, params, FULLSM>
        <<<grid, thds, full_sm, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, 0);
  }
  check_cuda_error(cudaGetLastError());
}

template <class params>
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
    device_programmable_bootstrap_step_two_128<__uint128_t, params, NOSM>
        <<<grid, thds, 0, stream>>>(
            lwe_array_out, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, full_dm);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_two_128<__uint128_t, params, PARTIALSM>
        <<<grid, thds, partial_sm, stream>>>(
            lwe_array_out, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log, level_count, d_mem, partial_dm);
  } else {
    device_programmable_bootstrap_step_two_128<__uint128_t, params, FULLSM>
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
template <class params>
__host__ void host_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, __uint128_t const *lwe_array_in,
    double const *bootstrapping_key, pbs_buffer_128<CLASSICAL> *pbs_buffer,
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

  for (int i = 0; i < lwe_dimension; i++) {
    execute_step_one_128<params>(
        stream, gpu_index, lut_vector, lwe_array_in, bootstrapping_key,
        global_accumulator, global_join_buffer, input_lwe_ciphertext_count,
        lwe_dimension, glwe_dimension, polynomial_size, base_log, level_count,
        d_mem, i, partial_sm, partial_dm_step_one, full_sm_step_one,
        full_dm_step_one);
    execute_step_two_128<params>(
        stream, gpu_index, lwe_array_out, bootstrapping_key, global_accumulator,
        global_join_buffer, input_lwe_ciphertext_count, lwe_dimension,
        glwe_dimension, polynomial_size, base_log, level_count, d_mem, i,
        partial_sm, partial_dm_step_two, full_sm_step_two, full_dm_step_two);
  }
}

#endif // TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_PBS_PROGRAMMABLE_BOOTSTRAP_CLASSIC_128_CUH_
