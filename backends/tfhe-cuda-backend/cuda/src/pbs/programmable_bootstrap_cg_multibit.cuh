#ifndef CUDA_CG_MULTIBIT_PBS_CUH
#define CUDA_CG_MULTIBIT_PBS_CUH

#include "cooperative_groups.h"
#include "crypto/gadget.cuh"
#include "crypto/ggsw.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/twiddles.cuh"
#include "pbs/pbs_multibit_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "programmable_bootstrap.cuh"
#include "programmable_bootstrap_multibit.cuh"
#include "types/complex/operations.cuh"
#include <vector>

template <typename Torus, class params, sharedMemDegree SMD>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_cg_accumulate(
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
        uint32_t num_many_lut, uint32_t lut_stride) {

  grid_group grid = this_grid();

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.z + blockIdx.y * gridDim.z +
                      blockIdx.x * gridDim.z * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  Torus *accumulator_rotated = (Torus *)selected_memory;
  double2 *accumulator_fft =
      (double2 *)accumulator_rotated +
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
    // Load the accumulator_rotated calculated in previous iterations
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        global_accumulator_slice, accumulator_rotated);
  }

  for (int i = 0; (i + lwe_offset) < lwe_dimension && i < lwe_chunk_size; i++) {
    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace<Torus, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, base_log, level_count);

    // Decompose the accumulator_rotated. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator_rotated decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<Torus, params> gadget_acc(base_log, level_count,
                                           accumulator_rotated);
    gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.z);
    NSMFFT_direct<HalfDegree<params>>(accumulator_fft);
    __syncthreads();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_in_fourier_domain<grid_group, params>(
        accumulator_fft, block_join_buffer, keybundle, i, grid);
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
        // blocks, in case they're not synchronized Always extract one by
        // default
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
}

template <typename Torus>
uint64_t get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size; // accumulator
}
template <typename Torus>
uint64_t get_buffer_size_full_sm_cg_multibit_programmable_bootstrap(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size * 2; // accumulator
}

template <typename Torus>
uint64_t get_buffer_size_cg_multibit_programmable_bootstrap(
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t grouping_factor, uint64_t lwe_chunk_size) {

  uint64_t buffer_size = 0;
  buffer_size += input_lwe_ciphertext_count * lwe_chunk_size * level_count *
                 (glwe_dimension + 1) * (glwe_dimension + 1) *
                 (polynomial_size / 2) * sizeof(double2); // keybundle fft
  buffer_size += input_lwe_ciphertext_count * (glwe_dimension + 1) *
                 level_count * (polynomial_size / 2) *
                 sizeof(double2); // join buffer
  buffer_size += input_lwe_ciphertext_count * (glwe_dimension + 1) *
                 polynomial_size * sizeof(Torus); // global_accumulator

  return buffer_size + buffer_size % sizeof(double2);
}

template <typename Torus, typename params>
__host__ uint64_t scratch_cg_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer<Torus, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  cuda_set_device(gpu_index);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<Torus>(
          polynomial_size);
  uint64_t full_sm_cg_accumulate =
      get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_sm_cg_accumulate =
      get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<Torus>(
          polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
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

  if (max_shared_memory < partial_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              NOSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  auto lwe_chunk_size = get_lwe_chunk_size<Torus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size, glwe_dimension,
      level_count, full_sm_keybundle);
  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<Torus, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, lwe_chunk_size, PBS_VARIANT::CG,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, class params>
__host__ void execute_cg_external_product_loop(
    cudaStream_t stream, uint32_t gpu_index, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, pbs_buffer<Torus, MULTI_BIT> *buffer,
    uint32_t num_samples, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t grouping_factor, uint32_t base_log,
    uint32_t level_count, uint32_t lwe_offset, uint32_t num_many_lut,
    uint32_t lut_stride) {
  cuda_set_device(gpu_index);
  PANIC_IF_FALSE(
      sizeof(Torus) == 8,
      "Error: Programmable bootstrap multi-bit cg only supports 64-bit "
      "Torus type.");
  uint64_t full_sm =
      get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_sm =
      get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<Torus>(
          polynomial_size);

  auto full_dm = full_sm;
  auto partial_dm = full_sm - partial_sm;
  uint64_t no_dm = 0;

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  uint64_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2);

  uint32_t chunk_size = (uint32_t)(std::min(
      lwe_chunk_size,
      (uint64_t)(lwe_dimension / grouping_factor) - lwe_offset));

  auto d_mem = buffer->d_mem_acc_cg;
  auto keybundle_fft = buffer->keybundle_fft;
  auto global_accumulator = buffer->global_accumulator;
  auto join_buffer = buffer->global_join_buffer;

  void *kernel_args[22];
  kernel_args[0] = &lwe_array_out;
  kernel_args[1] = &lwe_output_indexes;
  kernel_args[2] = &lut_vector;
  kernel_args[3] = &lut_vector_indexes;
  kernel_args[4] = &lwe_array_in;
  kernel_args[5] = &lwe_input_indexes;
  kernel_args[6] = &keybundle_fft;
  kernel_args[7] = &join_buffer;
  kernel_args[8] = &global_accumulator;
  kernel_args[9] = &lwe_dimension;
  kernel_args[10] = &glwe_dimension;
  kernel_args[11] = &polynomial_size;
  kernel_args[12] = &base_log;
  kernel_args[13] = &level_count;
  kernel_args[14] = &grouping_factor;
  kernel_args[15] = &lwe_offset;
  kernel_args[16] = &chunk_size;
  kernel_args[17] = &keybundle_size_per_input;
  kernel_args[18] = &d_mem;
  kernel_args[20] = &num_many_lut;
  kernel_args[21] = &lut_stride;

  dim3 grid_accumulate(num_samples, glwe_dimension + 1, level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  if (max_shared_memory < partial_dm) {
    kernel_args[19] = &full_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate<
            Torus, params, NOSM>,
        grid_accumulate, thds, (void **)kernel_args, 0, stream));
  } else if (max_shared_memory < full_dm) {
    kernel_args[19] = &partial_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate<
            Torus, params, PARTIALSM>,
        grid_accumulate, thds, (void **)kernel_args, partial_sm, stream));
  } else {
    kernel_args[19] = &no_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate<
            Torus, params, FULLSM>,
        grid_accumulate, thds, (void **)kernel_args, full_sm, stream));
  }
}

template <typename Torus, class params>
__host__ void host_cg_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, uint64_t const *bootstrapping_key,
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
    execute_cg_external_product_loop<Torus, params>(
        stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
        lwe_input_indexes, lwe_array_out, lwe_output_indexes, buffer,
        num_samples, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, base_log, level_count, lwe_offset, num_many_lut,
        lut_stride);
  }
}

// Verify if the grid size satisfies the cooperative group constraints
template <typename Torus, class params>
__host__ bool verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size(
    int glwe_dimension, int level_count, int num_samples,
    uint32_t max_shared_memory) {

  // If Cooperative Groups is not supported, no need to check anything else
  if (!cuda_check_support_cooperative_groups())
    return false;

  // Calculate the dimension of the kernel
  uint64_t full_sm_cg_accumulate =
      get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<Torus>(
          params::degree);
  uint64_t partial_sm_cg_accumulate =
      get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<Torus>(
          params::degree);

  int thds = params::degree / params::opt;

  // Get the maximum number of active blocks per streaming multiprocessors
  int number_of_blocks = level_count * (glwe_dimension + 1) * num_samples;
  int max_active_blocks_per_sm;

  if (max_shared_memory < partial_sm_cg_accumulate) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate<
            Torus, params, NOSM>,
        thds, 0));
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate<
            Torus, params, PARTIALSM>,
        thds, partial_sm_cg_accumulate));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate<Torus, params,
                                                              FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate<
            Torus, params, FULLSM>,
        thds, full_sm_cg_accumulate));
    check_cuda_error(cudaGetLastError());
  }

  // Get the number of streaming multiprocessors
  int number_of_sm = 0;
  cudaDeviceGetAttribute(&number_of_sm, cudaDevAttrMultiProcessorCount, 0);
  return number_of_blocks <= max_active_blocks_per_sm * number_of_sm;
}

// Verify if the grid size for the multi-bit kernel satisfies the cooperative
// group constraints
template <typename Torus>
__host__ bool supports_cooperative_groups_on_multibit_programmable_bootstrap(
    int glwe_dimension, int polynomial_size, int level_count, int num_samples,
    uint32_t max_shared_memory) {
  switch (polynomial_size) {
  case 256:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<
        Torus, AmortizedDegree<256>>(glwe_dimension, level_count, num_samples,
                                     max_shared_memory);
  case 512:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<
        Torus, AmortizedDegree<512>>(glwe_dimension, level_count, num_samples,
                                     max_shared_memory);
  case 1024:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<
        Torus, AmortizedDegree<1024>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 2048:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<
        Torus, AmortizedDegree<2048>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 4096:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<
        Torus, AmortizedDegree<4096>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 8192:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<
        Torus, AmortizedDegree<8192>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  case 16384:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<
        Torus, AmortizedDegree<16384>>(glwe_dimension, level_count, num_samples,
                                       max_shared_memory);
  default:
    PANIC("Cuda error (multi-bit PBS): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..16384].")
  }
}
#endif // FASTMULTIBIT_PBS_H
