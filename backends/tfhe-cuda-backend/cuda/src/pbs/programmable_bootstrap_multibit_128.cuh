#ifndef PROGRAMMABLE_BOOTSTRAP_MULTIBIT_128_CUH
#define PROGRAMMABLE_BOOTSTRAP_MULTIBIT_128_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "fft128/fft128.cuh"
#include "programmable_bootstrap_multibit.cuh"
#include "pbs/pbs_multibit_utilities.h"

template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_128_keybundle(
    uint32_t polynomial_size) {
  return sizeof(__uint128_t) * polynomial_size; // accumulator
}

template <typename InputTorus, class params, sharedMemDegree SMD>
__global__ void device_multi_bit_programmable_bootstrap_keybundle_128(
    const InputTorus *__restrict__ lwe_array_in,
    const InputTorus *__restrict__ lwe_input_indexes, double *keybundle_array,
    const __uint128_t *__restrict__ bootstrapping_key, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t level_count, uint32_t lwe_offset, uint32_t lwe_chunk_size,
    uint32_t keybundle_size_per_input, int8_t *device_mem,
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

    const InputTorus *block_lwe_array_in =
        &lwe_array_in[lwe_input_indexes[input_idx] * (lwe_dimension + 1)];

    double *keybundle = keybundle_array +
                        // select the input
                        input_idx * keybundle_size_per_input;

    ////////////////////////////////////////////////////////////
    // Computes all keybundles
    uint32_t rev_lwe_iteration =
        (lwe_dimension / grouping_factor) - lwe_iteration - 1;

    // ////////////////////////////////
    // Keygen guarantees the first term is a constant term of the polynomial, no
    // polynomial multiplication required
    auto bsk_slice = get_multi_bit_ith_lwe_gth_group_kth_block(
        bootstrapping_key, 0, rev_lwe_iteration, glwe_id, level_id,
        grouping_factor, 2 * polynomial_size, glwe_dimension, level_count);
    auto bsk_poly_ini = bsk_slice + poly_id * params::degree;

    __uint128_t reg_acc[params::opt];

    copy_polynomial_in_regs<__uint128_t, params::opt,
                            params::degree / params::opt>(bsk_poly_ini,
                                                          reg_acc);

    int offset =
        get_start_ith_ggsw_offset(polynomial_size, glwe_dimension, level_count);

    // Precalculate the monomial degrees and store them in shared memory
    uint32_t *monomial_degrees = (uint32_t *)selected_memory;
    if (threadIdx.x < (1 << grouping_factor)) {
      auto lwe_array_group =
          block_lwe_array_in + rev_lwe_iteration * grouping_factor;
      monomial_degrees[threadIdx.x] =
          calculates_monomial_degree<InputTorus, params>(
              lwe_array_group, threadIdx.x, grouping_factor);
    }
    __syncthreads();

    // Accumulate the other terms
    for (int g = 1; g < (1 << grouping_factor); g++) {
      uint32_t monomial_degree = monomial_degrees[g];

      auto bsk_poly = bsk_poly_ini + g * offset;
      // Multiply by the bsk element
      polynomial_accumulate_monic_monomial_mul_on_regs<__uint128_t, params>(
          reg_acc, bsk_poly, monomial_degree);
    }
    __syncthreads(); // needed because we are going to reuse the
                     // shared memory for the fft

    // Move from local memory back to shared memory but as complex
    const double normalization = pow(2., -128.);
    int tid = threadIdx.x;
    double *fft = (double *)selected_memory;
#pragma unroll
    for (int i = 0; i < params::opt / 2; i++) {
      auto re = u128_to_signed_to_f128(reg_acc[i]);
      auto im = u128_to_signed_to_f128(reg_acc[i + params::opt / 2]);

      auto fft_re_hi = fft + tid + 0 * params::degree / 2;
      auto fft_re_lo = fft + tid + 1 * params::degree / 2;
      auto fft_im_hi = fft + tid + 2 * params::degree / 2;
      auto fft_im_lo = fft + tid + 3 * params::degree / 2;

      *fft_re_hi = re.hi * normalization;
      *fft_re_lo = re.lo * normalization;
      *fft_im_hi = im.hi * normalization;
      *fft_im_lo = im.lo * normalization;

      tid += 4 * (params::degree / 2) / params::opt;
    }

    __syncthreads(); // TODO: Do we need this sync?

    auto fft_re_hi = fft + 0 * params::degree / 2;
    auto fft_re_lo = fft + 1 * params::degree / 2;
    auto fft_im_hi = fft + 2 * params::degree / 2;
    auto fft_im_lo = fft + 3 * params::degree / 2;

    negacyclic_forward_fft_f128<HalfDegree<params>>(fft_re_hi, fft_re_lo,
                                                    fft_im_hi, fft_im_lo);

    // lwe iteration
    auto keybundle_out = get_ith_mask_kth_block_128(
        keybundle, blockIdx.x % lwe_chunk_size, glwe_id, level_id,
        polynomial_size, glwe_dimension, level_count);
    auto keybundle_poly = keybundle_out + poly_id * params::degree;

    copy_polynomial<double, params::opt, params::degree / params::opt>(
        fft, keybundle_poly);
  }
}

template <typename InputTorus, class params, sharedMemDegree SMD,
          bool is_first_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_accumulate_step_one_128(
        const InputTorus *__restrict__ lwe_array_in,
        const InputTorus *__restrict__ lwe_input_indexes,
        const __uint128_t *__restrict__ lut_vector,
        const InputTorus *__restrict__ lut_vector_indexes,
        __uint128_t *global_accumulator, double *global_accumulator_fft,
        uint32_t lwe_dimension, uint32_t glwe_dimension,
        uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
        int8_t *device_mem, uint64_t device_memory_size_per_block) {

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

  __uint128_t *accumulator = (__uint128_t *)selected_memory;
  double *accumulator_fft =
      (double *)accumulator +
      (ptrdiff_t)(sizeof(__uint128_t) * polynomial_size / sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double *)sharedmem;

  const InputTorus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  const __uint128_t *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  auto global_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          (params::degree / 2) * 4];

  auto global_fft_slice =
      &global_accumulator_fft[(blockIdx.y + blockIdx.z * (glwe_dimension + 1) +
                               blockIdx.x * level_count *
                                   (glwe_dimension + 1)) *
                              (params::degree / 2) * 4];

  if constexpr (is_first_iter) {
    // First iteration
    ////////////////////////////////////////////////////////////
    // Initializes the accumulator with the body of LWE
    // Put "b" in [0, 2N[
    InputTorus b_hat = 0;
    modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                   params::log2_degree + 1);

    divide_by_monomial_negacyclic_inplace<__uint128_t, params::opt,
                                          params::degree / params::opt>(
        accumulator, &block_lut_vector[blockIdx.y * params::degree], b_hat,
        false);

    // Persist
    copy_polynomial<__uint128_t, params::opt, params::degree / params::opt>(
        accumulator, global_slice);
  } else {
    // Load the accumulator calculated in previous iterations
    copy_polynomial<__uint128_t, params::opt, params::degree / params::opt>(
        global_slice, accumulator);
  }

  // Perform a rounding to increase the accuracy of the
  // bootstrapped ciphertext
  init_decomposer_state_inplace<__uint128_t, params::opt,
                                params::degree / params::opt>(
      accumulator, base_log, level_count);

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

  negacyclic_forward_fft_f128<HalfDegree<params>>(acc_fft_re_hi, acc_fft_re_lo,
                                                  acc_fft_im_hi, acc_fft_im_lo);

  copy_polynomial<double, params::opt, params::degree / params::opt>(
      accumulator_fft, global_fft_slice);
}
template <typename OutputTorus, typename InputTorus, class params,
          sharedMemDegree SMD, bool is_last_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_accumulate_step_two_128(
        OutputTorus *lwe_array_out,
        const InputTorus *__restrict__ lwe_output_indexes,
        const double *__restrict__ keybundle_array,
        OutputTorus *global_accumulator, double *join_buffer,
        uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
        uint32_t iteration, uint32_t lwe_chunk_size, int8_t *device_mem,
        uint64_t device_memory_size_per_block, uint32_t num_many_lut,
        uint32_t lut_stride) {
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

  double *accumulator_fft = (double *)selected_memory;

  const double *keybundle =
      &keybundle_array[blockIdx.x * lwe_chunk_size * level_count *
                       (glwe_dimension + 1) * (glwe_dimension + 1) *
                       polynomial_size * 4];

  double *join_buffer_slice =
      &join_buffer[blockIdx.x * level_count * (glwe_dimension + 1) *
                   polynomial_size * 4];

  for (int level = 0; level < level_count; level++) {
    double *global_fft_slice = &join_buffer_slice[level * (glwe_dimension + 1) *
                                                  (polynomial_size / 2) * 4];

    for (int j = 0; j < (glwe_dimension + 1); j++) {
      auto fft = &global_fft_slice[j * (params::degree / 2) * 4];

      // Get the bootstrapping key piece necessary for the multiplication
      // It is already in the Fourier domain
      auto bsk_slice = get_ith_mask_kth_block_128(keybundle, iteration, j,
                                                  level, polynomial_size,
                                                  glwe_dimension, level_count);
      auto bsk_poly = &bsk_slice[blockIdx.y * params::degree / 2 * 4];

      polynomial_product_accumulate_in_fourier_domain_128<params>(
          accumulator_fft, fft, bsk_poly, !level && !j);
    }
  }

  // Perform the inverse FFT on the result of the GGSW x GLWE and add to the
  // accumulator
  auto acc_fft_re_hi = accumulator_fft + 0 * params::degree / 2;
  auto acc_fft_re_lo = accumulator_fft + 1 * params::degree / 2;
  auto acc_fft_im_hi = accumulator_fft + 2 * params::degree / 2;
  auto acc_fft_im_lo = accumulator_fft + 3 * params::degree / 2;

  negacyclic_backward_fft_f128<HalfDegree<params>>(
      acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);
  auto global_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  add_to_torus_128<OutputTorus, params>(acc_fft_re_hi, acc_fft_re_lo,
                                        acc_fft_im_hi, acc_fft_im_lo,
                                        global_slice, true);
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
      sample_extract_mask<OutputTorus, params>(block_lwe_array_out,
                                               global_slice);
      if (num_many_lut > 1) {
        for (int i = 1; i < num_many_lut; i++) {
          auto next_lwe_array_out =
              lwe_array_out +
              (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  blockIdx.y * polynomial_size];

          sample_extract_mask<OutputTorus, params>(
              next_block_lwe_array_out, global_slice, 1, i * lut_stride);
        }
      }
    } else if (blockIdx.y == glwe_dimension) {
      sample_extract_body<OutputTorus, params>(block_lwe_array_out,
                                               global_slice, 0);
      if (num_many_lut > 1) {
        for (int i = 1; i < num_many_lut; i++) {

          auto next_lwe_array_out =
              lwe_array_out +
              (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  blockIdx.y * polynomial_size];

          sample_extract_body<OutputTorus, params>(
              next_block_lwe_array_out, global_slice, 0, i * lut_stride);
        }
      }
    }
  }
}

template <typename InputTorus, class params>
__host__ void execute_compute_keybundle_128(
    cudaStream_t stream, uint32_t gpu_index, InputTorus const *lwe_array_in,
    InputTorus const *lwe_input_indexes, __uint128_t const *bootstrapping_key,
    pbs_buffer_128<InputTorus, MULTI_BIT> *buffer, uint32_t num_samples,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t level_count, uint32_t lwe_offset) {
  cuda_set_device(gpu_index);

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  uint32_t chunk_size =
      std::min(lwe_chunk_size, (lwe_dimension / grouping_factor) - lwe_offset);

  uint32_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2) * 4;

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_128_keybundle<
          __uint128_t>(polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  auto d_mem = buffer->d_mem_keybundle;
  auto keybundle_fft = buffer->keybundle_fft;

  // Compute a keybundle
  dim3 grid_keybundle(num_samples * chunk_size,
                      (glwe_dimension + 1) * (glwe_dimension + 1), level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);
  if (max_shared_memory < full_sm_keybundle)
    device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus, params,
                                                          NOSM>
        <<<grid_keybundle, thds, 0, stream>>>(
            lwe_array_in, lwe_input_indexes, keybundle_fft, bootstrapping_key,
            lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
            level_count, lwe_offset, chunk_size, keybundle_size_per_input,
            d_mem, full_sm_keybundle);
  else
    device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus, params,
                                                          FULLSM>
        <<<grid_keybundle, thds, full_sm_keybundle, stream>>>(
            lwe_array_in, lwe_input_indexes, keybundle_fft, bootstrapping_key,
            lwe_dimension, glwe_dimension, polynomial_size, grouping_factor,
            level_count, lwe_offset, chunk_size, keybundle_size_per_input,
            d_mem, 0);
  check_cuda_error(cudaGetLastError());
}

template <typename InputTorus, class params, bool is_first_iter>
__host__ void execute_step_one_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t const *lut_vector,
    InputTorus const *lut_vector_indexes, InputTorus const *lwe_array_in,
    InputTorus const *lwe_input_indexes,
    pbs_buffer_128<InputTorus, MULTI_BIT> *buffer, uint32_t num_samples,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count) {
  cuda_set_device(gpu_index);

  uint64_t full_sm_accumulate_step_one =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<
          __uint128_t>(polynomial_size);
  uint64_t partial_sm_accumulate_step_one =
      get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
          __uint128_t>(polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  //
  auto d_mem = buffer->d_mem_acc_step_one;
  auto global_accumulator = buffer->global_accumulator;
  auto global_accumulator_fft = buffer->global_join_buffer;

  dim3 grid_accumulate_step_one(num_samples, glwe_dimension + 1, level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  if (max_shared_memory < partial_sm_accumulate_step_one)
    device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
        InputTorus, params, NOSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, 0, stream>>>(
            lwe_array_in, lwe_input_indexes, lut_vector, lut_vector_indexes,
            global_accumulator, global_accumulator_fft, lwe_dimension,
            glwe_dimension, polynomial_size, base_log, level_count, d_mem,
            full_sm_accumulate_step_one);
  else if (max_shared_memory < full_sm_accumulate_step_one)
    device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
        InputTorus, params, PARTIALSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, partial_sm_accumulate_step_one,
           stream>>>(lwe_array_in, lwe_input_indexes, lut_vector,
                     lut_vector_indexes, global_accumulator,
                     global_accumulator_fft, lwe_dimension, glwe_dimension,
                     polynomial_size, base_log, level_count, d_mem,
                     partial_sm_accumulate_step_one);
  else
    device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
        InputTorus, params, FULLSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, full_sm_accumulate_step_one,
           stream>>>(lwe_array_in, lwe_input_indexes, lut_vector,
                     lut_vector_indexes, global_accumulator,
                     global_accumulator_fft, lwe_dimension, glwe_dimension,
                     polynomial_size, base_log, level_count, d_mem, 0);
  check_cuda_error(cudaGetLastError());
}

template <typename InputTorus, class params, bool is_last_iter>
__host__ void execute_step_two_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    InputTorus const *lwe_output_indexes,
    pbs_buffer_128<InputTorus, MULTI_BIT> *buffer, uint32_t num_samples,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
    uint32_t j, uint32_t num_many_lut, uint32_t lut_stride) {
  cuda_set_device(gpu_index);

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  uint64_t full_sm_accumulate_step_two =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<
          __uint128_t>(polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  auto d_mem = buffer->d_mem_acc_step_two;
  auto keybundle_fft = buffer->keybundle_fft;
  auto global_accumulator = buffer->global_accumulator;
  auto global_accumulator_fft = buffer->global_join_buffer;

  dim3 grid_accumulate_step_two(num_samples, glwe_dimension + 1);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  if (max_shared_memory < full_sm_accumulate_step_two)
    device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
        __uint128_t, InputTorus, params, NOSM, is_last_iter>
        <<<grid_accumulate_step_two, thds, 0, stream>>>(
            lwe_array_out, lwe_output_indexes, keybundle_fft,
            global_accumulator, global_accumulator_fft, glwe_dimension,
            polynomial_size, level_count, j, lwe_chunk_size, d_mem,
            full_sm_accumulate_step_two, num_many_lut, lut_stride);
  else
    device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
        __uint128_t, InputTorus, params, FULLSM, is_last_iter>
        <<<grid_accumulate_step_two, thds, full_sm_accumulate_step_two,
           stream>>>(lwe_array_out, lwe_output_indexes, keybundle_fft,
                     global_accumulator, global_accumulator_fft, glwe_dimension,
                     polynomial_size, level_count, j, lwe_chunk_size, d_mem, 0,
                     num_many_lut, lut_stride);
  check_cuda_error(cudaGetLastError());
}

/*
 * Host wrapper to the multi-bit programmable bootstrap 128
 */
template <typename InputTorus, class params>
__host__ void host_multi_bit_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    InputTorus const *lwe_output_indexes, __uint128_t const *lut_vector,
    InputTorus const *lut_vector_indexes, InputTorus const *lwe_array_in,
    InputTorus const *lwe_input_indexes, __uint128_t const *bootstrapping_key,
    pbs_buffer_128<InputTorus, MULTI_BIT> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  auto lwe_chunk_size = buffer->lwe_chunk_size;

  for (uint32_t lwe_offset = 0; lwe_offset < (lwe_dimension / grouping_factor);
       lwe_offset += lwe_chunk_size) {

    // Compute a keybundle
    execute_compute_keybundle_128<InputTorus, params>(
        stream, gpu_index, lwe_array_in, lwe_input_indexes, bootstrapping_key,
        buffer, num_samples, lwe_dimension, glwe_dimension, polynomial_size,
        grouping_factor, level_count, lwe_offset);
    // Accumulate
    uint32_t chunk_size = std::min(
        lwe_chunk_size, (lwe_dimension / grouping_factor) - lwe_offset);
    for (uint32_t j = 0; j < chunk_size; j++) {
      bool is_first_iter = (j + lwe_offset) == 0;
      bool is_last_iter =
          (j + lwe_offset) + 1 == (lwe_dimension / grouping_factor);
      if (is_first_iter) {
        execute_step_one_128<InputTorus, params, true>(
            stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
            lwe_input_indexes, buffer, num_samples, lwe_dimension,
            glwe_dimension, polynomial_size, base_log, level_count);
      } else {
        execute_step_one_128<InputTorus, params, false>(
            stream, gpu_index, lut_vector, lut_vector_indexes, lwe_array_in,
            lwe_input_indexes, buffer, num_samples, lwe_dimension,
            glwe_dimension, polynomial_size, base_log, level_count);
      }

      if (is_last_iter) {
        execute_step_two_128<InputTorus, params, true>(
            stream, gpu_index, lwe_array_out, lwe_output_indexes, buffer,
            num_samples, glwe_dimension, polynomial_size, level_count, j,
            num_many_lut, lut_stride);
      } else {
        execute_step_two_128<InputTorus, params, false>(
            stream, gpu_index, lwe_array_out, lwe_output_indexes, buffer,
            num_samples, glwe_dimension, polynomial_size, level_count, j,
            num_many_lut, lut_stride);
      }
    }
  }
}

template <typename InputTorus, typename params>
__host__ uint64_t scratch_multi_bit_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  cuda_set_device(gpu_index);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_128_keybundle<
          __uint128_t>(polynomial_size);
  uint64_t full_sm_accumulate_step_one =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_one<
          __uint128_t>(polynomial_size);
  uint64_t full_sm_accumulate_step_two =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_step_two<
          __uint128_t>(polynomial_size);
  uint64_t partial_sm_accumulate_step_one =
      get_buffer_size_partial_sm_multibit_programmable_bootstrap_step_one<
          __uint128_t>(polynomial_size);

  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, NOSM>,
        cudaFuncCachePreferShared));
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, FULLSM>,
        cudaFuncCachePreferShared));
  }

  if (max_shared_memory < partial_sm_accumulate_step_one) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, NOSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, NOSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, NOSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, NOSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory < full_sm_accumulate_step_one) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, PARTIALSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        partial_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, PARTIALSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, PARTIALSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        partial_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, PARTIALSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
            InputTorus, params, FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  if (max_shared_memory < full_sm_accumulate_step_two) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, NOSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, NOSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, NOSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, NOSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            __uint128_t, InputTorus, params, FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  auto lwe_chunk_size = get_lwe_chunk_size_128<InputTorus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size,
      full_sm_keybundle);
  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, lwe_chunk_size, PBS_VARIANT::DEFAULT,
      allocate_gpu_memory, &size_tracker);
  return size_tracker;
}

#endif // PROGRAMMABLE_BOOTSTRAP_MULTIBIT_128_CUH
