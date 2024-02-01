#ifndef CUDA_AMORTIZED_PBS_CUH
#define CUDA_AMORTIZED_PBS_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "bootstrap.h"
#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "types/complex/operations.cuh"

template <typename Torus, class params, sharedMemDegree SMD>
/*
 * Kernel launched by host_bootstrap_amortized
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
 *  - lwe_idx: equal to the number of samples per gpu x gpu_num
 *  - device_memory_size_per_sample: amount of global memory to allocate if SMD
 * is not FULLSM
 */
__global__ void device_bootstrap_amortized(
    Torus *lwe_array_out, Torus *lwe_output_indexes, Torus *lut_vector,
    Torus *lut_vector_indexes, Torus *lwe_array_in, Torus *lwe_input_indexes,
    double2 *bootstrapping_key, int8_t *device_mem, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t lwe_idx,
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
  Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[lwe_idx + blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  // Put "b", the body, in [0, 2N[
  Torus b_hat = 0;
  rescale_torus_element(block_lwe_array_in[lwe_dimension], b_hat,
                        2 * params::degree); // 2 * params::log2_degree + 1);

  divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                        params::degree / params::opt>(
      accumulator, block_lut_vector, b_hat, false, glwe_dimension + 1);

  // Loop over all the mask elements of the sample to accumulate
  // (X^a_i-1) multiplication, decomposition of the resulting polynomial
  // into level_count polynomials, and performing polynomial multiplication
  // via an FFT with the RGSW encrypted secret key
  for (int iteration = 0; iteration < lwe_dimension; iteration++) {
    synchronize_threads_in_block();

    // Put "a" in [0, 2N[ instead of Zq
    Torus a_hat = 0;
    rescale_torus_element(block_lwe_array_in[iteration], a_hat,
                          2 * params::degree); // 2 * params::log2_degree + 1);

    // Perform ACC * (X^ä - 1)
    multiply_by_monomial_negacyclic_and_sub_polynomial<
        Torus, params::opt, params::degree / params::opt>(
        accumulator, accumulator_rotated, a_hat, glwe_dimension + 1);

    synchronize_threads_in_block();

    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    round_to_closest_multiple_inplace<Torus, params::opt,
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
      synchronize_threads_in_block();
    }

    // Come back to the coefficient representation
    if constexpr (SMD == FULLSM || SMD == NOSM) {
      synchronize_threads_in_block();

      for (int i = 0; i < (glwe_dimension + 1); i++) {
        auto res_fft_slice = res_fft + i * params::degree / 2;
        NSMFFT_inverse<HalfDegree<params>>(res_fft_slice);
      }
      synchronize_threads_in_block();

      for (int i = 0; i < (glwe_dimension + 1); i++) {
        auto accumulator_slice = accumulator + i * params::degree;
        auto res_fft_slice = res_fft + i * params::degree / 2;
        add_to_torus<Torus, params>(res_fft_slice, accumulator_slice);
      }
      synchronize_threads_in_block();
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
        synchronize_threads_in_block();

        NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
        synchronize_threads_in_block();

        add_to_torus<Torus, params>(accumulator_fft, accumulator_slice);
      }
      synchronize_threads_in_block();
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
  sample_extract_body<Torus, params>(block_lwe_array_out, accumulator,
                                     glwe_dimension);
}

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_full_sm_bootstrap_amortized(
    uint32_t polynomial_size, uint32_t glwe_dimension) {
  return sizeof(Torus) * polynomial_size * (glwe_dimension + 1) + // accumulator
         sizeof(Torus) * polynomial_size *
             (glwe_dimension + 1) +              // accumulator rotated
         sizeof(double2) * polynomial_size / 2 + // accumulator fft
         sizeof(double2) * polynomial_size / 2 *
             (glwe_dimension + 1); // res fft
}

template <typename Torus>
__host__ __device__ uint64_t
get_buffer_size_partial_sm_bootstrap_amortized(uint32_t polynomial_size) {
  return sizeof(double2) * polynomial_size / 2; // accumulator fft
}

template <typename Torus>
__host__ __device__ uint64_t get_buffer_size_bootstrap_amortized(
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_lwe_ciphertext_count, uint32_t max_shared_memory) {

  uint64_t full_sm = get_buffer_size_full_sm_bootstrap_amortized<Torus>(
      polynomial_size, glwe_dimension);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_bootstrap_amortized<Torus>(polynomial_size);
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

template <typename Torus, typename STorus, typename params>
__host__ void scratch_bootstrap_amortized(
    cuda_stream_t *stream, int8_t **pbs_buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t input_lwe_ciphertext_count,
    uint32_t max_shared_memory, bool allocate_gpu_memory) {
  cudaSetDevice(stream->gpu_index);

  uint64_t full_sm = get_buffer_size_full_sm_bootstrap_amortized<Torus>(
      polynomial_size, glwe_dimension);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_bootstrap_amortized<Torus>(polynomial_size);
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm) {
    cudaFuncSetAttribute(device_bootstrap_amortized<Torus, params, PARTIALSM>,
                         cudaFuncAttributeMaxDynamicSharedMemorySize,
                         partial_sm);
    cudaFuncSetCacheConfig(device_bootstrap_amortized<Torus, params, PARTIALSM>,
                           cudaFuncCachePreferShared);
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_bootstrap_amortized<Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_bootstrap_amortized<Torus, params, FULLSM>,
        cudaFuncCachePreferShared));
  }
  if (allocate_gpu_memory) {
    uint64_t buffer_size = get_buffer_size_bootstrap_amortized<Torus>(
        glwe_dimension, polynomial_size, input_lwe_ciphertext_count,
        max_shared_memory);
    *pbs_buffer = (int8_t *)cuda_malloc_async(buffer_size, stream);
    check_cuda_error(cudaGetLastError());
  }
}

template <typename Torus, class params>
__host__ void host_bootstrap_amortized(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lut_vector, Torus *lut_vector_indexes, Torus *lwe_array_in,
    Torus *lwe_input_indexes, double2 *bootstrapping_key, int8_t *pbs_buffer,
    uint32_t glwe_dimension, uint32_t lwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, uint32_t num_luts, uint32_t lwe_idx,
    uint32_t max_shared_memory) {

  cudaSetDevice(stream->gpu_index);
  uint64_t SM_FULL = get_buffer_size_full_sm_bootstrap_amortized<Torus>(
      polynomial_size, glwe_dimension);

  uint64_t SM_PART =
      get_buffer_size_partial_sm_bootstrap_amortized<Torus>(polynomial_size);

  uint64_t DM_PART = SM_FULL - SM_PART;

  uint64_t DM_FULL = SM_FULL;

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
    device_bootstrap_amortized<Torus, params, NOSM>
        <<<grid, thds, 0, stream->stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, bootstrapping_key, pbs_buffer,
            glwe_dimension, lwe_dimension, polynomial_size, base_log,
            level_count, lwe_idx, DM_FULL);
  } else if (max_shared_memory < SM_FULL) {
    device_bootstrap_amortized<Torus, params, PARTIALSM>
        <<<grid, thds, SM_PART, stream->stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, bootstrapping_key, pbs_buffer,
            glwe_dimension, lwe_dimension, polynomial_size, base_log,
            level_count, lwe_idx, DM_PART);
  } else {
    // For devices with compute capability 7.x a single thread block can
    // address the full capacity of shared memory. Shared memory on the
    // device then has to be allocated dynamically.
    // For lower compute capabilities, this call
    // just does nothing and the amount of shared memory used is 48 KB
    device_bootstrap_amortized<Torus, params, FULLSM>
        <<<grid, thds, SM_FULL, stream->stream>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, bootstrapping_key, pbs_buffer,
            glwe_dimension, lwe_dimension, polynomial_size, base_log,
            level_count, lwe_idx, 0);
  }
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, class params>
int cuda_get_pbs_per_gpu(int polynomial_size) {

  int blocks_per_sm = 0;
  int num_threads = polynomial_size / params::opt;
  cudaGetDeviceCount(0);
  cudaDeviceProp device_properties;
  cudaGetDeviceProperties(&device_properties, 0);
  cudaOccupancyMaxActiveBlocksPerMultiprocessor(
      &blocks_per_sm, device_bootstrap_amortized<Torus, params>, num_threads,
      0);

  return device_properties.multiProcessorCount * blocks_per_sm;
}

#endif // CNCRT_PBS_H
