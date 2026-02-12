#ifndef CUDA_AMORTIZED_PBS_CUH
#define CUDA_AMORTIZED_PBS_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "bootstrapping_key.cuh"
#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "types/complex/operations.cuh"

template <typename Torus, class params, sharedMemDegree SMD>
/*
 * Kernel launched by host_programmable_bootstrap_amortized
 *
 * Uses shared memory to increase performance
 *  - lwe_array_out: output batch of num_samples bootstrapped ciphertexts c =
 * (a0,..an-1,b) where n is the LWE dimension
 *  - lut_vector: should hold as many luts of size polynomial_size
 * as there are input ciphertexts, but actually holds
 * num_luts vectors to reduce memory usage
 *  - lut_vector_indexes: stores the index corresponding to which lut
 * to use for each sample in lut_vector
 *  - lwe_array_in: input batch of num_samples LWE ciphertexts, containing n
 * mask values + 1 body value
 *  - bootstrapping_key: RGSW encryption of the LWE secret key sk1 under secret
 * key sk2
 *  - device_mem: pointer to the device's global memory in case we use it (SMD
 * == NOSM or PARTIALSM)
 *  - lwe_dimension: size of the Torus vector used to encrypt the input
 * LWE ciphertexts - referred to as n above (~ 600)
 *  - polynomial_size: size of the test polynomial (lut) and size of the
 * GLWE polynomial (~1024)
 *  - base_log: log base used for the gadget matrix - B = 2^base_log (~8)
 *  - level_count: number of decomposition levels in the gadget matrix (~4)
 *  - gpu_num: index of the current GPU (useful for multi-GPU computations)
 *  - device_memory_size_per_sample: amount of global memory to allocate if SMD
 * is not FULLSM
 */
__global__ void device_programmable_bootstrap_amortized(
    Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
    const Torus *__restrict__ lut_vector,
    const Torus *__restrict__ lut_vector_indexes,
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes,
    const double2 *__restrict__ bootstrapping_key, int8_t *device_mem,
    uint32_t glwe_dimension, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count,
    size_t device_memory_size_per_sample) {
  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  if constexpr (SMD == FULLSM)
    selected_memory = sharedmem;
  else
    selected_memory = &device_mem[blockIdx.x * device_memory_size_per_sample];

  // For GPU bootstrapping the GLWE dimension is hard-set to 1: there is only
  // one mask polynomial and 1 body to handle.
  Torus *accumulator = (Torus *)selected_memory;
  Torus *accumulator_rotated =
      (Torus *)accumulator +
      (ptrdiff_t)((glwe_dimension + 1) * polynomial_size);
  double2 *res_fft =
      (double2 *)accumulator_rotated + (glwe_dimension + 1) * polynomial_size /
                                           (sizeof(double2) / sizeof(Torus));
  double2 *accumulator_fft = (double2 *)sharedmem;
  if constexpr (SMD != PARTIALSM)
    accumulator_fft = (double2 *)res_fft +
                      (ptrdiff_t)((glwe_dimension + 1) * polynomial_size / 2);

  auto block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];
  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  // Put "b", the body, in [0, 2N[
  constexpr auto log_modulus = params::log2_degree + 1;
  Torus b_hat = 0;
  auto correction = centered_binary_modulus_switch_body_correction_to_add(
      block_lwe_array_in, lwe_dimension, log_modulus);
  modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                 log_modulus);

  divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                        params::degree / params::opt>(
      accumulator, block_lut_vector, b_hat, false, glwe_dimension + 1);

  // Loop over all the mask elements of the sample to accumulate
  // (X^a_i-1) multiplication, decomposition of the resulting polynomial
  // into level_count polynomials, and performing polynomial multiplication
  // via an FFT with the RGSW encrypted secret key
  for (int iteration = 0; iteration < lwe_dimension; iteration++) {
    __syncthreads();

    // Put "a" in [0, 2N[ instead of Zq
    Torus a_hat = 0;
    modulus_switch(block_lwe_array_in[iteration], a_hat, log_modulus);

    // Perform ACC * (X^ä - 1)
    multiply_by_monomial_negacyclic_and_sub_polynomial<
        Torus, params::opt, params::degree / params::opt>(
        accumulator, accumulator_rotated, a_hat, glwe_dimension + 1);

    __syncthreads();

    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace<Torus, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, base_log, level_count, glwe_dimension + 1);

    // Initialize the polynomial multiplication via FFT arrays
    // The polynomial multiplications happens at the block level
    // and each thread handles two or more coefficients
    int pos = threadIdx.x;
    for (int i = 0; i < (glwe_dimension + 1); i++)
      for (int j = 0; j < params::opt / 2; j++) {
        res_fft[pos].x = 0;
        res_fft[pos].y = 0;
        pos += params::degree / params::opt;
      }

    GadgetMatrix<Torus, params> gadget(base_log, level_count,
                                       accumulator_rotated, glwe_dimension + 1);
    // Now that the rotation is done, decompose the resulting polynomial
    // coefficients so as to multiply each decomposed level with the
    // corresponding part of the bootstrapping key
    for (int level = level_count - 1; level >= 0; level--) {
      for (int i = 0; i < (glwe_dimension + 1); i++) {
        gadget.decompose_and_compress_next_polynomial(accumulator_fft, i);

        // Switch to the FFT space
        NSMFFT_direct<HalfDegree<params>>(accumulator_fft);

        // Get the bootstrapping key piece necessary for the multiplication
        // It is already in the Fourier domain
        auto bsk_slice = get_ith_mask_kth_block(bootstrapping_key, iteration, i,
                                                level, polynomial_size,
                                                glwe_dimension, level_count);

        // Perform the coefficient-wise product with the two pieces of
        // bootstrapping key
        for (int j = 0; j < (glwe_dimension + 1); j++) {
          auto bsk_poly = bsk_slice + j * params::degree / 2;
          auto res_fft_poly = res_fft + j * params::degree / 2;
          polynomial_product_accumulate_in_fourier_domain<params, double2>(
              res_fft_poly, accumulator_fft, bsk_poly);
        }
      }
      __syncthreads();
    }

    // Come back to the coefficient representation
    if constexpr (SMD == FULLSM || SMD == NOSM) {
      __syncthreads();

      for (int i = 0; i < (glwe_dimension + 1); i++) {
        auto res_fft_slice = res_fft + i * params::degree / 2;
        NSMFFT_inverse<HalfDegree<params>>(res_fft_slice);
      }
      __syncthreads();

      for (int i = 0; i < (glwe_dimension + 1); i++) {
        auto accumulator_slice = accumulator + i * params::degree;
        auto res_fft_slice = res_fft + i * params::degree / 2;
        add_to_torus<Torus, params>(res_fft_slice, accumulator_slice);
      }
      __syncthreads();
    } else {
#pragma unroll
      for (int i = 0; i < (glwe_dimension + 1); i++) {
        auto accumulator_slice = accumulator + i * params::degree;
        auto res_fft_slice = res_fft + i * params::degree / 2;
        int tid = threadIdx.x;
        for (int j = 0; j < params::opt / 2; j++) {
          accumulator_fft[tid] = res_fft_slice[tid];
          tid = tid + params::degree / params::opt;
        }
        __syncthreads();

        NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
        __syncthreads();

        add_to_torus<Torus, params>(accumulator_fft, accumulator_slice);
      }
      __syncthreads();
    }
  }

  auto block_lwe_array_out =
      &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                     (glwe_dimension * polynomial_size + 1)];

  // The blind rotation for this block is over
  // Now we can perform the sample extraction: for the body it's just
  // the resulting constant coefficient of the accumulator
  // For the mask it's more complicated
  sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator,
                                     glwe_dimension);

  // No need to sync here, it is already synchronized after add_to_torus
  sample_extract_body<Torus, params>(block_lwe_array_out, accumulator,
                                     glwe_dimension);
}

template <typename Torus>
uint64_t get_buffer_size_full_sm_programmable_bootstrap_amortized(
    uint32_t polynomial_size, uint32_t glwe_dimension) {
  return safe_mul_sizeof<Torus>((size_t)polynomial_size,
                                (size_t)(glwe_dimension + 1)) + // accumulator
         safe_mul_sizeof<Torus>(
             (size_t)polynomial_size,
             (size_t)(glwe_dimension + 1)) +             // accumulator rotated
         safe_mul_sizeof<double2>(polynomial_size / 2) + // accumulator fft
         safe_mul_sizeof<double2>((size_t)(polynomial_size / 2),
                                  (size_t)(glwe_dimension + 1)); // res fft
}

template <typename Torus>
uint64_t get_buffer_size_partial_sm_programmable_bootstrap_amortized(
    uint32_t polynomial_size) {
  return safe_mul_sizeof<double2>(polynomial_size / 2); // accumulator fft
}

template <typename Torus>
uint64_t get_buffer_size_programmable_bootstrap_amortized(
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {

  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_amortized<Torus>(
          polynomial_size, glwe_dimension);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_amortized<Torus>(
          polynomial_size);
  uint64_t partial_dm = full_sm - partial_sm;
  uint64_t full_dm = full_sm;
  uint64_t device_mem = 0;
  if (max_shared_memory < partial_sm) {
    device_mem = full_dm * input_lwe_ciphertext_count;
  } else if (max_shared_memory < full_sm) {
    device_mem = partial_dm * input_lwe_ciphertext_count;
  }
  return device_mem + device_mem % sizeof(double2);
}

template <typename Torus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_amortized(
    cudaStream_t stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  cuda_set_device(gpu_index);

  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_amortized<Torus>(
          polynomial_size, glwe_dimension);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_amortized<Torus>(
          polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_amortized<Torus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_amortized<Torus, params, PARTIALSM>,
        cudaFuncCachePreferShared));
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_amortized<Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_amortized<Torus, params, FULLSM>,
        cudaFuncCachePreferShared));
  }
  uint64_t size_tracker = 0;
  uint64_t buffer_size =
      get_buffer_size_programmable_bootstrap_amortized<Torus>(
          glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
          max_shared_memory);
  *pbs_buffer = (int8_t *)cuda_malloc_with_size_tracking_async(
      buffer_size, stream, gpu_index, size_tracker, allocate_gpu_memory);
  check_cuda_error(cudaGetLastError());
  return size_tracker;
}

template <typename Torus, class params>
__host__ void host_programmable_bootstrap_amortized(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lut_vector, Torus *lut_vector_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, double2 *bootstrapping_key,
    int8_t *pbs_buffer, uint32_t glwe_dimension, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count) {
  PANIC_IF_FALSE(sizeof(Torus) == 8,
                 "Error: Programmable bootstrap amortized only supports 64-bit "
                 "Torus type.");
  uint64_t SM_FULL =
      get_buffer_size_full_sm_programmable_bootstrap_amortized<Torus>(
          polynomial_size, glwe_dimension);

  uint64_t SM_PART =
      get_buffer_size_partial_sm_programmable_bootstrap_amortized<Torus>(
          polynomial_size);

  uint64_t DM_PART = SM_FULL - SM_PART;

  uint64_t DM_FULL = SM_FULL;

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);

  // Create a 1-dimensional grid of threads
  // where each block handles 1 sample and each thread
  // handles opt polynomial coefficients
  // (actually opt/2 coefficients since we compress the real polynomial into a
  // complex)
  dim3 grid(input_lwe_ciphertext_count, 1, 1);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  // Launch the kernel using polynomial_size/opt threads
  // where each thread computes opt polynomial coefficients
  // Depending on the required amount of shared memory, choose
  // from one of three templates (no use, partial use or full use
  // of shared memory)
  if (max_shared_memory < SM_PART) {
    device_programmable_bootstrap_amortized<Torus, params, NOSM>
        <<<grid, thds, 0, stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, bootstrapping_key, pbs_buffer,
            glwe_dimension, lwe_dimension, polynomial_size, base_log,
            level_count, DM_FULL);
  } else if (max_shared_memory < SM_FULL) {
    device_programmable_bootstrap_amortized<Torus, params, PARTIALSM>
        <<<grid, thds, SM_PART, stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, bootstrapping_key, pbs_buffer,
            glwe_dimension, lwe_dimension, polynomial_size, base_log,
            level_count, DM_PART);
  } else {
    // For devices with compute capability 7.x a single thread block can
    // address the full capacity of shared memory. Shared memory on the
    // device then has to be allocated dynamically.
    // For lower compute capabilities, this call
    // just does nothing and the amount of shared memory used is 48 KB
    device_programmable_bootstrap_amortized<Torus, params, FULLSM>
        <<<grid, thds, SM_FULL, stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, bootstrapping_key, pbs_buffer,
            glwe_dimension, lwe_dimension, polynomial_size, base_log,
            level_count, 0);
  }
  check_cuda_error(cudaGetLastError());
}

#endif // CNCRT_PBS_H
