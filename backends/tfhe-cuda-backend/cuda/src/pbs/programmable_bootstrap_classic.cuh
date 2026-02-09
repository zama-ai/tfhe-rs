#ifndef CUDA_PBS_CUH
#define CUDA_PBS_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "pbs/pbs_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "types/complex/operations.cuh"

template <typename Torus, class params, sharedMemDegree SMD, bool first_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_programmable_bootstrap_step_one(
        const Torus *__restrict__ lut_vector,
        const Torus *__restrict__ lut_vector_indexes,
        const Torus *__restrict__ lwe_array_in,
        const Torus *__restrict__ lwe_input_indexes, Torus *global_accumulator,
        double2 *global_join_buffer, uint32_t lwe_iteration,
        uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
        uint32_t level_count, int8_t *device_mem,
        uint64_t device_memory_size_per_block,
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

  Torus *accumulator = (Torus *)selected_memory;
  double2 *accumulator_fft =
      (double2 *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double2 *)sharedmem;

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1)) * params::degree;

  double2 *global_fft_slice =
      global_join_buffer + (blockIdx.y + blockIdx.z * (glwe_dimension + 1) +
                            blockIdx.x * level_count * (glwe_dimension + 1)) *
                               (polynomial_size / 2);

  if constexpr (first_iter) {
    // First iteration
    // Put "b" in [0, 2N[
    constexpr auto log_modulus = params::log2_degree + 1;
    Torus b_hat = 0;
    Torus correction = 0;
    if (noise_reduction_type == PBS_MS_REDUCTION_T::CENTERED) {
      correction = centered_binary_modulus_switch_body_correction_to_add(
          block_lwe_array_in, lwe_dimension, log_modulus);
    }
    modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                   log_modulus);

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

  __syncthreads();

  // Perform ACC * (X^ä - 1)
  multiply_by_monomial_negacyclic_and_sub_polynomial<
      Torus, params::opt, params::degree / params::opt>(global_slice,
                                                        accumulator, a_hat);

  // Perform a rounding to increase the accuracy of the
  // bootstrapped ciphertext
  init_decomposer_state_inplace<Torus, params::opt,
                                params::degree / params::opt>(
      accumulator, base_log, level_count);

  __syncthreads();

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

  int tid = threadIdx.x;
  for (int i = 0; i < params::opt / 2; i++) {
    global_fft_slice[tid] = accumulator_fft[tid];
    tid += params::degree / params::opt;
  }
}

template <typename Torus, class params, sharedMemDegree SMD, bool last_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_programmable_bootstrap_step_two(
        Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
        const Torus *__restrict__ lut_vector,
        const Torus *__restrict__ lut_vector_indexes,
        const double2 *__restrict__ bootstrapping_key,
        Torus *global_accumulator, double2 *global_join_buffer,
        uint32_t lwe_iteration, uint32_t lwe_dimension,
        uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
        int8_t *device_mem, uint64_t device_memory_size_per_block,
        uint32_t num_many_lut, uint32_t lut_stride) {

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
  double2 *accumulator_fft =
      (double2 *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * params::degree / sizeof(double2));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double2 *)sharedmem;

  for (int level = 0; level < level_count; level++) {
    double2 *global_fft_slice =
        global_join_buffer + (level + blockIdx.x * level_count) *
                                 (glwe_dimension + 1) * (params::degree / 2);

    for (int j = 0; j < (glwe_dimension + 1); j++) {
      double2 *fft = global_fft_slice + j * params::degree / 2;

      // Get the bootstrapping key piece necessary for the multiplication
      // It is already in the Fourier domain
      auto bsk_slice =
          get_ith_mask_kth_block(bootstrapping_key, lwe_iteration, j, level,
                                 polynomial_size, glwe_dimension, level_count);
      auto bsk_poly = bsk_slice + blockIdx.y * params::degree / 2;

      polynomial_product_accumulate_in_fourier_domain<params, double2>(
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
  NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
  add_to_torus<Torus, params>(accumulator_fft, accumulator);

  if constexpr (last_iter) {
    // Last iteration
    auto block_lwe_array_out =
        &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                           (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra blocks,
      // in case they're not synchronized
      sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
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
                                             accumulator, 1, i * lut_stride);
        }
      }
    } else if (blockIdx.y == glwe_dimension) {
      __syncthreads();
      sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
      if (num_many_lut > 1) {
        for (int i = 1; i < num_many_lut; i++) {

          auto next_lwe_array_out =
              lwe_array_out +
              (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  blockIdx.y * polynomial_size];

          // No need to sync, it is already synchronized before the first
          // sample_extract_body call
          sample_extract_body<Torus, params>(next_block_lwe_array_out,
                                             accumulator, 0, i * lut_stride);
        }
      }
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

template <typename Torus>
uint64_t get_buffer_size_programmable_bootstrap(
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {

  uint64_t full_sm_step_one =
      get_buffer_size_full_sm_programmable_bootstrap_step_one<Torus>(
          polynomial_size);
  uint64_t full_sm_step_two =
      get_buffer_size_full_sm_programmable_bootstrap_step_two<Torus>(
          polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap<Torus>(polynomial_size);

  uint64_t partial_dm_step_one = full_sm_step_one - partial_sm;
  uint64_t partial_dm_step_two = full_sm_step_two - partial_sm;
  uint64_t full_dm = full_sm_step_one;

  uint64_t device_mem = 0;
  if (max_shared_memory < partial_sm) {
    device_mem = full_dm * input_lwe_ciphertext_count * level_count *
                 (glwe_dimension + 1);
  } else if (max_shared_memory < full_sm_step_two) {
    device_mem = (partial_dm_step_two + partial_dm_step_one * level_count) *
                 input_lwe_ciphertext_count * (glwe_dimension + 1);
  } else if (max_shared_memory < full_sm_step_one) {
    device_mem = partial_dm_step_one * input_lwe_ciphertext_count *
                 level_count * (glwe_dimension + 1);
  }
  // Otherwise, both kernels run all in shared memory
  uint64_t buffer_size = device_mem +
                         // global_join_buffer
                         (glwe_dimension + 1) * level_count *
                             input_lwe_ciphertext_count *
                             (polynomial_size / 2) * sizeof(double2) +
                         // global_accumulator
                         (glwe_dimension + 1) * input_lwe_ciphertext_count *
                             polynomial_size * sizeof(Torus);
  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus, typename params>
__host__ uint64_t scratch_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer<Torus, CLASSICAL> **buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  cuda_set_device(gpu_index);

  uint64_t full_sm_step_one =
      get_buffer_size_full_sm_programmable_bootstrap_step_one<Torus>(
          polynomial_size);
  uint64_t full_sm_step_two =
      get_buffer_size_full_sm_programmable_bootstrap_step_two<Torus>(
          polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap<Torus>(polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  // Configure step one
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm_step_one) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one<Torus, params, PARTIALSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one<Torus, params, PARTIALSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one<Torus, params, PARTIALSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one<Torus, params, PARTIALSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one<Torus, params, FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one<Torus, params, FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one<Torus, params, FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one<Torus, params, FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  // Configure step two
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm_step_two) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two<Torus, params, PARTIALSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two<Torus, params, PARTIALSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two<Torus, params, PARTIALSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two<Torus, params, PARTIALSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two<Torus, params, FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two<Torus, params, FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_two<Torus, params, FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_two<Torus, params, FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<Torus, CLASSICAL>(
      stream, gpu_index, lwe_dimension, glwe_dimension, polynomial_size,
      level_count, input_lwe_ciphertext_count, PBS_VARIANT::DEFAULT,
      allocate_gpu_memory, noise_reduction_type, size_tracker);
  return size_tracker;
}

template <typename Torus, class params, bool first_iter>
__host__ void execute_step_one(
    cudaStream_t stream, uint32_t gpu_index, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    Torus *global_accumulator, double2 *global_join_buffer,
    uint32_t input_lwe_ciphertext_count, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, int8_t *d_mem, int lwe_iteration, uint64_t partial_sm,
    uint64_t partial_dm, uint64_t full_sm, uint64_t full_dm,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  PANIC_IF_FALSE(sizeof(Torus) == 8,
                 "Error: Programmable bootstrap step one only supports 64-bit "
                 "Torus type.");
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1, level_count);

  if (max_shared_memory < partial_sm) {
    device_programmable_bootstrap_step_one<Torus, params, NOSM, first_iter>
        <<<grid, thds, 0, stream>>>(
            lut_vector, lut_vector_indexes, lwe_array_in, lwe_input_indexes,
            global_accumulator, global_join_buffer, lwe_iteration,
            lwe_dimension, polynomial_size, base_log, level_count, d_mem,
            full_dm, noise_reduction_type);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_one<Torus, params, PARTIALSM, first_iter>
        <<<grid, thds, partial_sm, stream>>>(
            lut_vector, lut_vector_indexes, lwe_array_in, lwe_input_indexes,
            global_accumulator, global_join_buffer, lwe_iteration,
            lwe_dimension, polynomial_size, base_log, level_count, d_mem,
            partial_dm, noise_reduction_type);
  } else {
    device_programmable_bootstrap_step_one<Torus, params, FULLSM, first_iter>
        <<<grid, thds, full_sm, stream>>>(
            lut_vector, lut_vector_indexes, lwe_array_in, lwe_input_indexes,
            global_accumulator, global_join_buffer, lwe_iteration,
            lwe_dimension, polynomial_size, base_log, level_count, d_mem, 0,
            noise_reduction_type);
  }
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, class params, bool last_iter>
__host__ void execute_step_two(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, double2 const *bootstrapping_key,
    Torus *global_accumulator, double2 *global_join_buffer,
    uint32_t input_lwe_ciphertext_count, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, int8_t *d_mem, int lwe_iteration, uint64_t partial_sm,
    uint64_t partial_dm, uint64_t full_sm, uint64_t full_dm,
    uint32_t num_many_lut, uint32_t lut_stride) {
  PANIC_IF_FALSE(sizeof(Torus) == 8,
                 "Error: Programmable bootstrap step two only supports 64-bit "
                 "Torus type.");
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1);

  if (max_shared_memory < partial_sm) {
    device_programmable_bootstrap_step_two<Torus, params, NOSM, last_iter>
        <<<grid, thds, 0, stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            bootstrapping_key, global_accumulator, global_join_buffer,
            lwe_iteration, lwe_dimension, polynomial_size, base_log,
            level_count, d_mem, full_dm, num_many_lut, lut_stride);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_two<Torus, params, PARTIALSM, last_iter>
        <<<grid, thds, partial_sm, stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            bootstrapping_key, global_accumulator, global_join_buffer,
            lwe_iteration, lwe_dimension, polynomial_size, base_log,
            level_count, d_mem, partial_dm, num_many_lut, lut_stride);
  } else {
    device_programmable_bootstrap_step_two<Torus, params, FULLSM, last_iter>
        <<<grid, thds, full_sm, stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            bootstrapping_key, global_accumulator, global_join_buffer,
            lwe_iteration, lwe_dimension, polynomial_size, base_log,
            level_count, d_mem, 0, num_many_lut, lut_stride);
  }
  check_cuda_error(cudaGetLastError());
}
/*
 * Host wrapper to the programmable bootstrap
 */
template <typename Torus, class params>
__host__ void host_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *pbs_buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t num_many_lut, uint32_t lut_stride) {
  cuda_set_device(gpu_index);

  // With SM each block corresponds to either the mask or body, no need to
  // duplicate data for each
  uint64_t full_sm_step_one =
      get_buffer_size_full_sm_programmable_bootstrap_step_one<Torus>(
          polynomial_size);
  uint64_t full_sm_step_two =
      get_buffer_size_full_sm_programmable_bootstrap_step_two<Torus>(
          polynomial_size);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap<Torus>(polynomial_size);

  uint64_t partial_dm_step_one = full_sm_step_one - partial_sm;
  uint64_t partial_dm_step_two = full_sm_step_two - partial_sm;
  uint64_t full_dm_step_one = full_sm_step_one;
  uint64_t full_dm_step_two = full_sm_step_two;

  Torus *global_accumulator = pbs_buffer->global_accumulator;
  double2 *global_join_buffer = pbs_buffer->global_join_buffer;
  int8_t *d_mem = pbs_buffer->d_mem;
  auto noise_reduction_type = pbs_buffer->noise_reduction_type;

  for (int i = 0; i < lwe_dimension; i++) {
    if (i == 0) {
      execute_step_one<Torus, params, true>(
          stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
          lwe_input_indexes, bootstrapping_key, global_accumulator,
          global_join_buffer, input_lwe_ciphertext_count, lwe_dimension,
          glwe_dimension, polynomial_size, base_log, level_count, d_mem, i,
          partial_sm, partial_dm_step_one, full_sm_step_one, full_dm_step_one,
          noise_reduction_type);
    } else {
      execute_step_one<Torus, params, false>(
          stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
          lwe_input_indexes, bootstrapping_key, global_accumulator,
          global_join_buffer, input_lwe_ciphertext_count, lwe_dimension,
          glwe_dimension, polynomial_size, base_log, level_count, d_mem, i,
          partial_sm, partial_dm_step_one, full_sm_step_one, full_dm_step_one,
          noise_reduction_type);
    }
    if (i == lwe_dimension - 1) {
      execute_step_two<Torus, params, true>(
          stream, gpu_index, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, bootstrapping_key, global_accumulator,
          global_join_buffer, input_lwe_ciphertext_count, lwe_dimension,
          glwe_dimension, polynomial_size, base_log, level_count, d_mem, i,
          partial_sm, partial_dm_step_two, full_sm_step_two, full_dm_step_two,
          num_many_lut, lut_stride);
    } else {
      execute_step_two<Torus, params, false>(
          stream, gpu_index, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, bootstrapping_key, global_accumulator,
          global_join_buffer, input_lwe_ciphertext_count, lwe_dimension,
          glwe_dimension, polynomial_size, base_log, level_count, d_mem, i,
          partial_sm, partial_dm_step_two, full_sm_step_two, full_dm_step_two,
          num_many_lut, lut_stride);
    }
  }
}

#endif // CUDA_PBS_CUH
