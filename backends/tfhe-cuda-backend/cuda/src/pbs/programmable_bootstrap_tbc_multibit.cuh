#ifndef CUDA_TBC_MULTIBIT_PBS_CUH
#define CUDA_TBC_MULTIBIT_PBS_CUH

// This macro is needed because in debug mode the compiler doesn't apply all
// optimizations
//  and the register count is higher, which can lead to launch bounds conflicts.
#ifdef __CUDACC_DEBUG__
#define SPECIALIZED_TBC_MULTI_BIT_2_2_PARAMS_LAUNCH_BOUNDS
#else
#define SPECIALIZED_TBC_MULTI_BIT_2_2_PARAMS_LAUNCH_BOUNDS                     \
  __launch_bounds__(512, 2)
#endif

#include "cooperative_groups.h"
#include "crypto/gadget.cuh"
#include "crypto/ggsw.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "pbs/pbs_multibit_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "programmable_bootstrap.cuh"
#include "types/complex/operations.cuh"
#include <vector>

template <typename Torus, class params, sharedMemDegree SMD>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_tbc_accumulate(
        Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
        const Torus *__restrict__ lut_vector,
        const Torus *__restrict__ lut_vector_indexes,
        const Torus *__restrict__ lwe_array_in,
        const Torus *__restrict__ lwe_input_indexes,
        const double2 *__restrict__ keybundle_array, double2 *join_buffer,
        Torus *global_accumulator, uint32_t lwe_dimension,
        uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
        uint32_t level_count, uint32_t grouping_factor, uint32_t lwe_offset,
        uint32_t lwe_chunk_size, uint64_t keybundle_size_per_input,
        int8_t *device_mem, uint64_t device_memory_size_per_block,
        bool support_dsm, uint32_t num_many_lut, uint32_t lut_stride) {

  cluster_group cluster = this_cluster();

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  if constexpr (SMD == FULLSM) {
    // The first (polynomial_size/2) * sizeof(double2) bytes are reserved for
    // external product using distributed shared memory
    selected_memory = sharedmem;
    if (support_dsm)
      selected_memory += sizeof(Torus) * polynomial_size;
  } else {
    int block_index = blockIdx.z + blockIdx.y * gridDim.z +
                      blockIdx.x * gridDim.z * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  Torus *accumulator_rotated = (Torus *)selected_memory;
  double2 *accumulator_fft =
      (double2 *)accumulator_rotated +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  if constexpr (SMD == PARTIALSM) {
    accumulator_fft = (double2 *)sharedmem;
    if (support_dsm)
      accumulator_fft += sizeof(double2) * (polynomial_size / 2);
  }

  // The first dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  double2 *block_join_buffer =
      &join_buffer[blockIdx.x * level_count * (glwe_dimension + 1) *
                   params::degree / 2];

  Torus *global_accumulator_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  const double2 *keybundle =
      &keybundle_array[blockIdx.x * keybundle_size_per_input];

  if (lwe_offset == 0) {
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                   params::log2_degree + 1);

    divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                          params::degree / params::opt>(
        accumulator_rotated, &block_lut_vector[blockIdx.y * params::degree],
        b_hat, false);
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        global_accumulator_slice, accumulator_rotated);
  }

  for (int i = 0; (i + lwe_offset) < lwe_dimension && i < lwe_chunk_size; i++) {
    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace<Torus, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, base_log, level_count);

    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<Torus, params> gadget_acc(base_log, level_count,
                                           accumulator_rotated);
    gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.z);
    NSMFFT_direct<HalfDegree<params>>(accumulator_fft);
    __syncthreads();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_in_fourier_domain<cluster_group, params>(
        accumulator_fft, block_join_buffer, keybundle, i, cluster, support_dsm);
    NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
    __syncthreads();

    add_to_torus<Torus, params>(accumulator_fft, accumulator_rotated, true);
  }

  auto accumulator = accumulator_rotated;

  if (blockIdx.z == 0) {
    if (lwe_offset + lwe_chunk_size >= (lwe_dimension / grouping_factor)) {
      auto block_lwe_array_out =
          &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                             (glwe_dimension * polynomial_size + 1) +
                         blockIdx.y * polynomial_size];

      if (blockIdx.y < glwe_dimension) {
        // Perform a sample extract. At this point, all blocks have the result,
        // but we do the computation at block 0 to avoid waiting for extra
        // blocks, in case they're not synchronized
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
      // Load the accumulator calculated in previous iterations
      copy_polynomial<Torus, params::opt, params::degree / params::opt>(
          accumulator, global_accumulator_slice);
    }
  }
  // Before exiting the kernel we need to sync the cluster to ensure that
  // other blocks can still access the dsm in the mul ggsw glwe
  cluster.sync();
}

// Specialized version for the multi-bit bootstrap using 2_2 params:
// Polynomial size = 2048
// PBS level = 1
// Grouping factor = 4
// PBS base = 22
// Glwe dimension = 1
// At the moment everything is hardcoded as constexpr, but later
// we will generate a cleaner/nicer way handle it.
// Main optimizations:
//- Leverage shared memory to reduce one cluster synchronization. A
//  ping pong buffer is used for that, so everything is synchronized
//  automatically after 2 iterations
//- Move everything to registers to avoid shared memory synchronizations
//- Use a register based fft that uses the minimal synchronizations
//- Register based fourier domain multiplication. Transfer fft's between blocks
// instead of accumulator.
template <typename Torus, class params, sharedMemDegree SMD>
__global__ SPECIALIZED_TBC_MULTI_BIT_2_2_PARAMS_LAUNCH_BOUNDS void
device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params(
    Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
    const Torus *__restrict__ lut_vector,
    const Torus *__restrict__ lut_vector_indexes,
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes,
    const double2 *__restrict__ keybundle_array, Torus *global_accumulator,
    uint32_t lwe_dimension, uint32_t lwe_offset, uint32_t lwe_chunk_size,
    uint64_t keybundle_size_per_input, uint32_t num_many_lut,
    uint32_t lut_stride) {

  constexpr uint32_t level_count = 1;
  constexpr uint32_t grouping_factor = 4;
  constexpr uint32_t polynomial_size = 2048;
  constexpr uint32_t glwe_dimension = 1;
  constexpr uint32_t base_log = 22;
  cluster_group cluster = this_cluster();
  auto this_block_rank = cluster.block_index().y;
  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  // When using 2_2 params and tbc we know everything fits in shared memory
  // The first (polynomial_size/2) * sizeof(double2) bytes are reserved for
  // external product using distributed shared memory
  selected_memory = sharedmem;
  // We know that dsm is supported and we have enough memory
  constexpr uint32_t num_buffers_ping_pong = 2;
  selected_memory += sizeof(Torus) * polynomial_size * num_buffers_ping_pong;

  double2 *accumulator_ping = (double2 *)sharedmem;
  double2 *accumulator_pong = accumulator_ping + (polynomial_size / 2);
  double2 *shared_twiddles = accumulator_pong + (polynomial_size / 2);
  double2 *shared_fft = shared_twiddles + (polynomial_size / 2);
  // accumulator rotated shares the same memory space than the twiddles.
  // it is only used during the sample extract so it is safe to use it
  Torus *accumulator_rotated = (Torus *)selected_memory;

  // Copying the twiddles from global to shared for extra performance
  for (int k = 0; k < params::opt / 2; k++) {
    shared_twiddles[threadIdx.x + k * (params::degree / params::opt)] =
        negtwiddles[threadIdx.x + k * (params::degree / params::opt)];
  }

  // The first dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  Torus *global_accumulator_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  const double2 *keybundle =
      &keybundle_array[blockIdx.x * keybundle_size_per_input];

  // The acc rotated is moved to registers to free shared memory for other
  // potential improvements. itself this change doesn't report much benefit.
  Torus reg_acc_rotated[params::opt];
  if (lwe_offset == 0) {
    // Put "b" in [0, 2N[
    Torus b_hat = 0;
    modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                   params::log2_degree + 1);

    divide_by_monomial_negacyclic_2_2_params_inplace<
        Torus, params::opt, params::degree / params::opt>(
        reg_acc_rotated, &block_lut_vector[blockIdx.y * params::degree], b_hat);
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial_in_regs<Torus, params::opt, params::degree / params::opt>(
        global_accumulator_slice, reg_acc_rotated);
  }

  for (int i = 0; (i + lwe_offset) < lwe_dimension && i < lwe_chunk_size; i++) {
    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace_2_2_params<Torus, params::opt,
                                             params::degree / params::opt,
                                             base_log, level_count>(
        reg_acc_rotated);

    // This is the ping pong buffer logic to avoid a cluster synchronization
    auto accumulator_fft = i % 2 ? accumulator_ping : accumulator_pong;

    double2 fft_out_regs[params::opt / 2];
    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    decompose_and_compress_level_2_2_params<Torus, params, base_log>(
        fft_out_regs, reg_acc_rotated);

    NSMFFT_direct_2_2_params<HalfDegree<params>>(shared_fft, fft_out_regs,
                                                 shared_twiddles);
    // we move registers into shared memory to use dsm
    int tid = threadIdx.x;
    for (Index k = 0; k < params::opt / 4; k++) {
      accumulator_fft[tid] = fft_out_regs[k];
      accumulator_fft[tid + params::degree / 4] =
          fft_out_regs[k + params::opt / 4];
      tid = tid + params::degree / params::opt;
    }

    double2 buffer_regs[params::opt / 2];
    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_in_fourier_domain_2_2_params<
        cluster_group, params, polynomial_size, glwe_dimension, level_count>(
        accumulator_fft, fft_out_regs, buffer_regs, keybundle, i, cluster,
        this_block_rank);

    NSMFFT_inverse_2_2_params<HalfDegree<params>>(shared_fft, buffer_regs,
                                                  shared_twiddles);

    add_to_torus_2_2_params<Torus, params>(buffer_regs, reg_acc_rotated);
  }

  if (lwe_offset + lwe_chunk_size >= (lwe_dimension / grouping_factor)) {

    // Temporary copy to keep the other logic as it is
    for (int i = 0; i < params::opt; i++) {
      accumulator_rotated[threadIdx.x + i * (params::degree / params::opt)] =
          reg_acc_rotated[i];
    }
    __syncthreads();
    auto accumulator = accumulator_rotated;
    auto block_lwe_array_out =
        &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                           (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.y < glwe_dimension) {
      // Perform a sample extract. At this point, all blocks have the result,
      // but we do the computation at block 0 to avoid waiting for extra
      // blocks, in case they're not synchronized
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
      // No need to sync here, it is already synchronized after add_to_torus
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
          // No need to sync here, it is already synchronized after
          // add_to_torus
          sample_extract_body<Torus, params>(next_block_lwe_array_out,
                                             accumulator, 0, i * lut_stride);
        }
      }
    }
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial_from_regs<Torus, params::opt, params::degree / params::opt>(
        reg_acc_rotated, global_accumulator_slice);
  }
  // Before exiting the kernel we need to sync the cluster to ensure that
  // other blocks can still access the dsm in the ping pong buffer
  cluster.sync();
}

template <typename Torus>
uint64_t get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size; // distributed shared memory
}

template <typename Torus>
uint64_t get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size; // accumulator
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size * 2; // accumulator
}

template <typename Torus, typename params>
__host__ uint64_t scratch_tbc_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer<uint64_t, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {
  cuda_set_device(gpu_index);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  bool supports_dsm =
      supports_distributed_shared_memory_on_multibit_programmable_bootstrap<
          Torus>(polynomial_size, max_shared_memory);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_tbc_accumulate =
      get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_sm_tbc_accumulate =
      get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t minimum_sm_tbc_accumulate = 0;
  if (supports_dsm)
    minimum_sm_tbc_accumulate =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params, NOSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle<Torus, params,
                                                          FULLSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  }

  if (max_shared_memory <
      partial_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        minimum_sm_tbc_accumulate));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory <
             full_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        partial_sm_tbc_accumulate + minimum_sm_tbc_accumulate));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        cudaFuncCachePreferShared);
    check_cuda_error(cudaGetLastError());
  } else {
    if (polynomial_size == 2048 && level_count == 1 && glwe_dimension == 1) {
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize,
          full_sm_tbc_accumulate + 2 * minimum_sm_tbc_accumulate));
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          cudaFuncAttributePreferredSharedMemoryCarveout,
          cudaSharedmemCarveoutMaxShared));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          cudaFuncCachePreferShared));
    } else {
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                                 FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize,
          full_sm_tbc_accumulate + minimum_sm_tbc_accumulate));
      cudaFuncSetCacheConfig(
          device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                                 FULLSM>,
          cudaFuncCachePreferShared);
    }
    check_cuda_error(cudaGetLastError());
  }

  auto lwe_chunk_size = get_lwe_chunk_size<Torus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size, glwe_dimension,
      level_count, full_sm_keybundle);
  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<uint64_t, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, lwe_chunk_size, PBS_VARIANT::TBC,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, class params>
__host__ void execute_tbc_external_product_loop(
    cudaStream_t stream, uint32_t gpu_index, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, pbs_buffer<Torus, MULTI_BIT> *buffer,
    uint32_t num_samples, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t lwe_offset, uint32_t num_many_lut,
    uint32_t lut_stride) {

  PANIC_IF_FALSE(
      sizeof(Torus) == 8,
      "Error: Programmable bootstrap multi-bit tbc only supports 64-bit "
      "Torus type.");
  cuda_set_device(gpu_index);

  auto lwe_chunk_size = buffer->lwe_chunk_size;

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  auto supports_dsm =
      supports_distributed_shared_memory_on_multibit_programmable_bootstrap<
          Torus>(polynomial_size, max_shared_memory);

  uint64_t full_dm =
      get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_dm =
      get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t minimum_dm = 0;
  if (supports_dsm)
    minimum_dm =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

  uint64_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2);

  uint32_t chunk_size = (uint32_t)(std::min(
      lwe_chunk_size,
      (uint64_t)(lwe_dimension / grouping_factor) - lwe_offset));

  auto d_mem = buffer->d_mem_acc_tbc;
  auto keybundle_fft = buffer->keybundle_fft;
  auto global_accumulator = buffer->global_accumulator;
  auto buffer_fft = buffer->global_join_buffer;

  dim3 grid_accumulate(num_samples, glwe_dimension + 1, level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  cudaLaunchConfig_t config = {0};
  // The grid dimension is not affected by cluster launch, and is still
  // enumerated using number of blocks. The grid dimension should be a multiple
  // of cluster size.
  config.gridDim = grid_accumulate;
  config.blockDim = thds;

  cudaLaunchAttribute attribute[1];
  attribute[0].id = cudaLaunchAttributeClusterDimension;
  attribute[0].val.clusterDim.x = 1;
  attribute[0].val.clusterDim.y = (glwe_dimension + 1);
  attribute[0].val.clusterDim.z = level_count; // Cluster size in Z-dimension
  config.attrs = attribute;
  config.numAttrs = 1;
  config.stream = stream;

  if (max_shared_memory < partial_dm + minimum_dm) {
    config.dynamicSmemBytes = minimum_dm;
    check_cuda_error(cudaLaunchKernelEx(
        &config,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, keybundle_fft, buffer_fft,
        global_accumulator, lwe_dimension, glwe_dimension, polynomial_size,
        base_log, level_count, grouping_factor, lwe_offset, chunk_size,
        keybundle_size_per_input, d_mem, full_dm, supports_dsm, num_many_lut,
        lut_stride));
  } else if (max_shared_memory < full_dm + minimum_dm) {
    config.dynamicSmemBytes = partial_dm + minimum_dm;
    check_cuda_error(cudaLaunchKernelEx(
        &config,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
        lwe_array_in, lwe_input_indexes, keybundle_fft, buffer_fft,
        global_accumulator, lwe_dimension, glwe_dimension, polynomial_size,
        base_log, level_count, grouping_factor, lwe_offset, chunk_size,
        keybundle_size_per_input, d_mem, partial_dm, supports_dsm, num_many_lut,
        lut_stride));
  } else {
    config.dynamicSmemBytes = full_dm + minimum_dm;
    if (polynomial_size == 2048 && grouping_factor == 4 && level_count == 1 &&
        glwe_dimension == 1 && base_log == 22) {

      config.dynamicSmemBytes = full_dm + 2 * minimum_dm;
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize,
          full_dm + 2 * minimum_dm));
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          cudaFuncAttributePreferredSharedMemoryCarveout,
          cudaSharedmemCarveoutMaxShared));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          cudaFuncCachePreferShared));
      check_cuda_error(cudaLaunchKernelEx(
          &config,
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
          lwe_array_in, lwe_input_indexes, keybundle_fft, global_accumulator,
          lwe_dimension, lwe_offset, chunk_size, keybundle_size_per_input,
          num_many_lut, lut_stride));
    } else {
      check_cuda_error(cudaLaunchKernelEx(
          &config,
          device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                                 FULLSM>,
          lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
          lwe_array_in, lwe_input_indexes, keybundle_fft, buffer_fft,
          global_accumulator, lwe_dimension, glwe_dimension, polynomial_size,
          base_log, level_count, grouping_factor, lwe_offset, chunk_size,
          keybundle_size_per_input, d_mem, 0, supports_dsm, num_many_lut,
          lut_stride));
    }
  }
}

template <typename Torus, class params>
__host__ void host_tbc_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {
  cuda_set_device(gpu_index);

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  for (uint32_t lwe_offset = 0; lwe_offset < (lwe_dimension / grouping_factor);
       lwe_offset += lwe_chunk_size) {

    // Compute a keybundle
    execute_compute_keybundle<Torus, params>(
        stream, gpu_index, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        buffer, num_samples, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, level_count, lwe_offset);

    // Accumulate
    execute_tbc_external_product_loop<Torus, params>(
        stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, lwe_array_out, lwe_output_indexes, buffer,
        num_samples, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, lwe_offset, num_many_lut,
        lut_stride);
  }
}

template <typename Torus>
bool supports_distributed_shared_memory_on_multibit_programmable_bootstrap(
    uint32_t polynomial_size, uint32_t max_shared_memory) {
  uint64_t minimum_sm =
      get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);

  if (max_shared_memory <= minimum_sm) {
    // If we cannot store a single polynomial in a block shared memory we
    // cannot use TBC
    return false;
  } else {
    return cuda_check_support_thread_block_clusters();
  }
}

template <typename Torus, class params>
__host__ bool supports_thread_block_clusters_on_multibit_programmable_bootstrap(
    uint32_t num_samples, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t max_shared_memory) {

  if (!cuda_check_support_thread_block_clusters())
    return false;

  uint64_t full_sm_tbc_accumulate =
      get_buffer_size_full_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_sm_tbc_accumulate =
      get_buffer_size_partial_sm_tbc_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t minimum_sm_tbc_accumulate = 0;
  if (supports_distributed_shared_memory_on_multibit_programmable_bootstrap<
          Torus>(polynomial_size, max_shared_memory))
    minimum_sm_tbc_accumulate =
        get_buffer_size_sm_dsm_plus_tbc_multibit_programmable_bootstrap<Torus>(
            polynomial_size);

  int cluster_size;

  dim3 grid_accumulate(num_samples, glwe_dimension + 1, level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  cudaLaunchConfig_t config = {0};
  // The grid dimension is not affected by cluster launch, and is still
  // enumerated using number of blocks. The grid dimension should be a multiple
  // of cluster size.
  config.gridDim = grid_accumulate;
  config.blockDim = thds;
  config.numAttrs = 0;

  /* Despite the documentation stating that we could have cluster sizes up to 16
   * on H100s if we enable non-portable cluster sizes, this doesn't seem the
   * case and it will fail if we try. Thus, since level_count *
   * (glwe_dimension+1) is usually smaller than 8 at this moment, we will
   * disable cudaFuncAttributeNonPortableClusterSizeAllowed */
  if (max_shared_memory <
      partial_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               NOSM>,
        &config));
  } else if (max_shared_memory <
             full_sm_tbc_accumulate + minimum_sm_tbc_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        cudaFuncAttributeNonPortableClusterSizeAllowed, false));
    check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
        &cluster_size,
        device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                               PARTIALSM>,
        &config));
  } else {
    if (polynomial_size == 2048 && level_count == 1 && glwe_dimension == 1) {
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          cudaFuncAttributeNonPortableClusterSizeAllowed, false));
      check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
          &cluster_size,
          device_multi_bit_programmable_bootstrap_tbc_accumulate_2_2_params<
              Torus, params, FULLSM>,
          &config));
    } else {
      check_cuda_error(cudaFuncSetAttribute(
          device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                                 FULLSM>,
          cudaFuncAttributeNonPortableClusterSizeAllowed, false));
      check_cuda_error(cudaOccupancyMaxPotentialClusterSize(
          &cluster_size,
          device_multi_bit_programmable_bootstrap_tbc_accumulate<Torus, params,
                                                                 FULLSM>,
          &config));
    }
  }

  return cluster_size >= level_count * (glwe_dimension + 1);
}

template bool
supports_distributed_shared_memory_on_multibit_programmable_bootstrap<uint64_t>(
    uint32_t polynomial_size, uint32_t max_shared_memory);
#endif // FASTMULTIBIT_PBS_H
