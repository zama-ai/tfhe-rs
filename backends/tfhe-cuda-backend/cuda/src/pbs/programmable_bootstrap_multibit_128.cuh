#ifndef PROGRAMMABLE_BOOTSTRAP_MULTIBIT_128_CUH
#define PROGRAMMABLE_BOOTSTRAP_MULTIBIT_128_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "fft128/fft128.cuh"
#include "pbs/pbs_multibit_utilities.h"
#include "programmable_bootstrap_multibit.cuh"
#include "utils/helper.cuh"

template <typename Torus>
uint64_t get_buffer_size_full_sm_multibit_programmable_bootstrap_128_keybundle(
    uint32_t polynomial_size) {
  return sizeof(__uint128_t) * polynomial_size * 2; // accumulator
}

template <typename InputTorus, class params, sharedMemDegree SMD>
__global__ void device_multi_bit_programmable_bootstrap_keybundle_128(
    const InputTorus *__restrict__ lwe_array_in,
    const InputTorus *__restrict__ lwe_input_indexes, double *keybundle_array,
    const __uint128_t *__restrict__ bootstrapping_key, uint32_t lwe_dimension,
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

    auto block_lwe_array_in =
        &lwe_array_in[lwe_input_indexes[input_idx] * (lwe_dimension + 1)];

    auto keybundle = &keybundle_array[
        // select the input
        input_idx * keybundle_size_per_input];

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
    double *fft = (double *)selected_memory;

    auto fft_re_hi = &fft[0 * params::degree / 2];
    auto fft_re_lo = &fft[1 * params::degree / 2];
    auto fft_im_hi = &fft[2 * params::degree / 2];
    auto fft_im_lo = &fft[3 * params::degree / 2];

    convert_u128_on_regs_to_f128_as_torus<params>(
        fft_re_hi, fft_re_lo, fft_im_hi, fft_im_lo, &reg_acc[0],
        &reg_acc[params::opt / 2]);

    __syncthreads(); // TODO: Do we need this sync?

    negacyclic_forward_fft_f128<HalfDegree<params>>(fft_re_hi, fft_re_lo,
                                                    fft_im_hi, fft_im_lo);

    // lwe iteration
    auto keybundle_out = get_ith_mask_kth_block_128(
        keybundle, blockIdx.x % lwe_chunk_size, glwe_id, level_id,
        polynomial_size, glwe_dimension, level_count);
    auto keybundle_poly = keybundle_out + poly_id * (params::degree / 2) * 4;

    copy_polynomial<double, 2 * params::opt, params::degree / params::opt>(
        fft, keybundle_poly);
  }
}

//////////////////////////////////////////////////////////////////
/////////////////// START DEFAULT ///////////////////////////////
template <typename InputTorus, class params, sharedMemDegree SMD,
          bool is_first_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_accumulate_step_one_128(
        const InputTorus *__restrict__ lwe_array_in,
        const InputTorus *__restrict__ lwe_input_indexes,
        const __uint128_t *__restrict__ lut_vector,
        __uint128_t *global_accumulator, double *global_accumulator_fft,
        uint32_t lwe_dimension, uint32_t glwe_dimension,
        uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
        int8_t *device_mem, uint64_t device_memory_size_per_block) {

  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ int8_t sharedmem[];

  int8_t *selected_memory = sharedmem;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.z + blockIdx.y * gridDim.z +
                      blockIdx.x * gridDim.z * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  auto accumulator = reinterpret_cast<__uint128_t *>(selected_memory);
  auto accumulator_fft =
      reinterpret_cast<double *>(accumulator) +
      static_cast<ptrdiff_t>(sizeof(__uint128_t) * polynomial_size /
                             sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = reinterpret_cast<double *>(sharedmem);

  auto block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  auto block_lut_vector = lut_vector;

  auto global_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

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
  auto acc_fft_re_hi = &accumulator_fft[0 * params::degree / 2];
  auto acc_fft_re_lo = &accumulator_fft[1 * params::degree / 2];
  auto acc_fft_im_hi = &accumulator_fft[2 * params::degree / 2];
  auto acc_fft_im_lo = &accumulator_fft[3 * params::degree / 2];

  negacyclic_forward_fft_f128<HalfDegree<params>>(acc_fft_re_hi, acc_fft_re_lo,
                                                  acc_fft_im_hi, acc_fft_im_lo);

  copy_polynomial<double, 2 * params::opt, params::degree / params::opt>(
      accumulator_fft, global_fft_slice);
}
template <typename InputTorus, class params, sharedMemDegree SMD,
          bool is_last_iter>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_accumulate_step_two_128(
        __uint128_t *lwe_array_out,
        const InputTorus *__restrict__ lwe_output_indexes,
        const double *__restrict__ keybundle_array,
        __uint128_t *global_accumulator, double *global_accumulator_fft,
        uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t level_count,
        uint32_t iteration, uint64_t lwe_chunk_size, int8_t *device_mem,
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

  auto accumulator_fft = reinterpret_cast<double *>(selected_memory);

  auto keybundle =
      &keybundle_array[blockIdx.x * lwe_chunk_size * level_count *
                       (glwe_dimension + 1) * (glwe_dimension + 1) *
                       (params::degree / 2) * 4];

  auto global_accumulator_fft_chunk =
      &global_accumulator_fft[blockIdx.x * level_count * (glwe_dimension + 1) *
                              (params::degree / 2) * 4];

  for (int level = 0; level < level_count; level++) {
    auto global_fft_slice =
        &global_accumulator_fft_chunk[level * (glwe_dimension + 1) *
                                      (params::degree / 2) * 4];

    for (int j = 0; j < (glwe_dimension + 1); j++) {
      auto fft = &global_fft_slice[j * (params::degree / 2) * 4];

      // Get the bootstrapping key piece necessary for the multiplication
      // It is already in the Fourier domain
      auto bsk_slice = get_ith_mask_kth_block_128(keybundle, iteration, j,
                                                  level, params::degree,
                                                  glwe_dimension, level_count);
      auto bsk_poly = &bsk_slice[blockIdx.y * params::degree / 2 * 4];

      polynomial_product_accumulate_in_fourier_domain_128<params>(
          accumulator_fft, fft, bsk_poly, !level && !j);
    }
  }

  // Perform the inverse FFT on the result of the GGSW x GLWE and add to the
  // accumulator
  auto acc_fft_re_hi = &accumulator_fft[0 * params::degree / 2];
  auto acc_fft_re_lo = &accumulator_fft[1 * params::degree / 2];
  auto acc_fft_im_hi = &accumulator_fft[2 * params::degree / 2];
  auto acc_fft_im_lo = &accumulator_fft[3 * params::degree / 2];

  negacyclic_backward_fft_f128<HalfDegree<params>>(
      acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);
  auto global_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  add_to_torus_128<__uint128_t, params>(acc_fft_re_hi, acc_fft_re_lo,
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
      sample_extract_mask<__uint128_t, params>(block_lwe_array_out,
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

          sample_extract_mask<__uint128_t, params>(
              next_block_lwe_array_out, global_slice, 1, i * lut_stride);
        }
      }
    } else if (blockIdx.y == glwe_dimension) {
      __syncthreads();
      sample_extract_body<__uint128_t, params>(block_lwe_array_out,
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

          // No need to sync, it is already synchronized before the first
          // sample_extract_body call
          sample_extract_body<__uint128_t, params>(
              next_block_lwe_array_out, global_slice, 0, i * lut_stride);
        }
      }
    }
  }
}

//////////////////////////////////////////////////////////////////
/////////////////// END DEFAULT //////////////////////////////////

//////////////////////////////////////////////////////////////////
/////////////////// START CG /////////////////////////////////////

template <typename InputTorus, class params, sharedMemDegree SMD>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_cg_accumulate_128(
        __uint128_t *lwe_array_out,
        const InputTorus *__restrict__ lwe_output_indexes,
        const __uint128_t *__restrict__ lut_vector,
        const InputTorus *__restrict__ lwe_array_in,
        const InputTorus *__restrict__ lwe_input_indexes,
        const double *__restrict__ keybundle_array, double *join_buffer,
        __uint128_t *global_accumulator, uint32_t lwe_dimension,
        uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
        uint32_t level_count, uint32_t grouping_factor, uint32_t lwe_offset,
        uint64_t lwe_chunk_size, uint64_t keybundle_size_per_input,
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

  auto accumulator_rotated = reinterpret_cast<__uint128_t *>(selected_memory);
  auto accumulator_fft =
      reinterpret_cast<double *>(accumulator_rotated) +
      static_cast<ptrdiff_t>(sizeof(__uint128_t) * polynomial_size /
                             sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = reinterpret_cast<double *>(sharedmem);

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  auto block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  auto block_lut_vector = lut_vector;

  auto block_join_buffer =
      &join_buffer[blockIdx.x * level_count * (glwe_dimension + 1) *
                   (params::degree / 2) * 4];

  auto global_accumulator_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  auto keybundle = &keybundle_array[blockIdx.x * keybundle_size_per_input];

  if (lwe_offset == 0) {
    // Put "b" in [0, 2N[
    InputTorus b_hat = 0;
    modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                   params::log2_degree + 1);

    divide_by_monomial_negacyclic_inplace<__uint128_t, params::opt,
                                          params::degree / params::opt>(
        accumulator_rotated, &block_lut_vector[blockIdx.y * params::degree],
        b_hat, false);
  } else {
    // Load the accumulator_rotated calculated in previous iterations
    copy_polynomial<__uint128_t, params::opt, params::degree / params::opt>(
        global_accumulator_slice, accumulator_rotated);
  }

  for (int i = 0; (i + lwe_offset) < lwe_dimension && i < lwe_chunk_size; i++) {
    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    init_decomposer_state_inplace<__uint128_t, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, base_log, level_count);

    // Decompose the accumulator_rotated. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator_rotated decomposed at level 0, 1 at 1, etc.)
    GadgetMatrix<__uint128_t, params> gadget_acc(base_log, level_count,
                                                 accumulator_rotated);
    gadget_acc.decompose_and_compress_level_128(accumulator_fft, blockIdx.z);

    // Switch to the FFT space
    auto acc_fft_re_hi = &accumulator_fft[0 * params::degree / 2];
    auto acc_fft_re_lo = &accumulator_fft[1 * params::degree / 2];
    auto acc_fft_im_hi = &accumulator_fft[2 * params::degree / 2];
    auto acc_fft_im_lo = &accumulator_fft[3 * params::degree / 2];

    negacyclic_forward_fft_f128<HalfDegree<params>>(
        acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);

    __syncthreads();

    // Perform G^-1(ACC) * GGSW -> GLWE
    mul_ggsw_glwe_in_fourier_domain_128<grid_group, params>(
        accumulator_fft, block_join_buffer, keybundle, i, grid);

    negacyclic_backward_fft_f128<HalfDegree<params>>(
        acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);
    __syncthreads();

    add_to_torus_128<__uint128_t, params>(acc_fft_re_hi, acc_fft_re_lo,
                                          acc_fft_im_hi, acc_fft_im_lo,
                                          accumulator_rotated, true);
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
        sample_extract_mask<__uint128_t, params>(block_lwe_array_out,
                                                 accumulator);

        if (num_many_lut > 1) {
          for (int i = 1; i < num_many_lut; i++) {
            auto next_lwe_array_out =
                lwe_array_out +
                (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
            auto next_block_lwe_array_out =
                &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                        (glwe_dimension * polynomial_size + 1) +
                                    blockIdx.y * polynomial_size];

            sample_extract_mask<__uint128_t, params>(
                next_block_lwe_array_out, accumulator, 1, i * lut_stride);
          }
        }

      } else if (blockIdx.y == glwe_dimension) {
        __syncthreads();
        sample_extract_body<__uint128_t, params>(block_lwe_array_out,
                                                 accumulator, 0);
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
            sample_extract_body<__uint128_t, params>(
                next_block_lwe_array_out, accumulator, 0, i * lut_stride);
          }
        }
      }
    } else {
      // Load the accumulator calculated in previous iterations
      copy_polynomial<__uint128_t, params::opt, params::degree / params::opt>(
          accumulator, global_accumulator_slice);
    }
  }
}

//////////////////////////////////////////////////////////////////
/////////////////// END CG ///////////////////////////////////////

template <typename InputTorus, class params>
__host__ void execute_compute_keybundle_128(
    cudaStream_t stream, uint32_t gpu_index, InputTorus const *lwe_array_in,
    InputTorus const *lwe_input_indexes, __uint128_t const *bootstrapping_key,
    pbs_buffer_128<InputTorus, MULTI_BIT> *buffer, uint32_t num_samples,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t level_count, uint32_t lwe_offset) {
  cuda_set_device(gpu_index);

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  uint64_t chunk_size = std::min(
      lwe_chunk_size, (uint64_t)(lwe_dimension / grouping_factor) - lwe_offset);

  uint64_t keybundle_size_per_input =
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
    InputTorus const *lwe_array_in, InputTorus const *lwe_input_indexes,
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
            lwe_array_in, lwe_input_indexes, lut_vector, global_accumulator,
            global_accumulator_fft, lwe_dimension, glwe_dimension,
            polynomial_size, base_log, level_count, d_mem,
            full_sm_accumulate_step_one);
  else if (max_shared_memory < full_sm_accumulate_step_one)
    device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
        InputTorus, params, PARTIALSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, partial_sm_accumulate_step_one,
           stream>>>(lwe_array_in, lwe_input_indexes, lut_vector,
                     global_accumulator, global_accumulator_fft, lwe_dimension,
                     glwe_dimension, polynomial_size, base_log, level_count,
                     d_mem, partial_sm_accumulate_step_one);
  else
    device_multi_bit_programmable_bootstrap_accumulate_step_one_128<
        InputTorus, params, FULLSM, is_first_iter>
        <<<grid_accumulate_step_one, thds, full_sm_accumulate_step_one,
           stream>>>(lwe_array_in, lwe_input_indexes, lut_vector,
                     global_accumulator, global_accumulator_fft, lwe_dimension,
                     glwe_dimension, polynomial_size, base_log, level_count,
                     d_mem, 0);
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
        InputTorus, params, NOSM, is_last_iter>
        <<<grid_accumulate_step_two, thds, 0, stream>>>(
            lwe_array_out, lwe_output_indexes, keybundle_fft,
            global_accumulator, global_accumulator_fft, glwe_dimension,
            polynomial_size, level_count, j, lwe_chunk_size, d_mem,
            full_sm_accumulate_step_two, num_many_lut, lut_stride);
  else
    device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
        InputTorus, params, FULLSM, is_last_iter>
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
    InputTorus const *lwe_array_in, InputTorus const *lwe_input_indexes,
    __uint128_t const *bootstrapping_key,
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
    uint64_t chunk_size =
        std::min((uint32_t)lwe_chunk_size,
                 (lwe_dimension / grouping_factor) - lwe_offset);
    for (uint32_t j = 0; j < chunk_size; j++) {
      bool is_first_iter = (j + lwe_offset) == 0;
      bool is_last_iter =
          (j + lwe_offset) + 1 == (lwe_dimension / grouping_factor);
      if (is_first_iter) {
        execute_step_one_128<InputTorus, params, true>(
            stream, gpu_index, lut_vector, lwe_array_in, lwe_input_indexes,
            buffer, num_samples, lwe_dimension, glwe_dimension, polynomial_size,
            base_log, level_count);
      } else {
        execute_step_one_128<InputTorus, params, false>(
            stream, gpu_index, lut_vector, lwe_array_in, lwe_input_indexes,
            buffer, num_samples, lwe_dimension, glwe_dimension, polynomial_size,
            base_log, level_count);
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

template <typename InputTorus, class params>
__host__ void execute_cg_external_product_loop_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t const *lut_vector,
    InputTorus const *lwe_array_in, InputTorus const *lwe_input_indexes,
    __uint128_t *lwe_array_out, InputTorus const *lwe_output_indexes,
    pbs_buffer_128<InputTorus, MULTI_BIT> *buffer, uint32_t num_samples,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t grouping_factor, uint32_t base_log, uint32_t level_count,
    uint32_t lwe_offset, uint32_t num_many_lut, uint32_t lut_stride) {
  cuda_set_device(gpu_index);

  const uint64_t full_sm =
      get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<__uint128_t>(
          polynomial_size);
  const uint64_t partial_sm =
      get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<
          __uint128_t>(polynomial_size);

  auto full_dm = full_sm;
  auto partial_dm = full_sm - partial_sm;
  uint64_t no_dm = 0;

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  uint64_t keybundle_size_per_input =
      lwe_chunk_size * level_count * (glwe_dimension + 1) *
      (glwe_dimension + 1) * (polynomial_size / 2) * 4;

  uint64_t chunk_size = std::min(
      lwe_chunk_size, (uint64_t)(lwe_dimension / grouping_factor) - lwe_offset);

  auto d_mem = buffer->d_mem_acc_cg;
  auto keybundle_fft = buffer->keybundle_fft;
  auto global_accumulator = buffer->global_accumulator;
  auto join_buffer = buffer->global_join_buffer;

  void *kernel_args[21];
  kernel_args[0] = &lwe_array_out;
  kernel_args[1] = &lwe_output_indexes;
  kernel_args[2] = &lut_vector;
  kernel_args[3] = &lwe_array_in;
  kernel_args[4] = &lwe_input_indexes;
  kernel_args[5] = &keybundle_fft;
  kernel_args[6] = &join_buffer;
  kernel_args[7] = &global_accumulator;
  kernel_args[8] = &lwe_dimension;
  kernel_args[9] = &glwe_dimension;
  kernel_args[10] = &polynomial_size;
  kernel_args[11] = &base_log;
  kernel_args[12] = &level_count;
  kernel_args[13] = &grouping_factor;
  kernel_args[14] = &lwe_offset;
  kernel_args[15] = &chunk_size;
  kernel_args[16] = &keybundle_size_per_input;
  kernel_args[17] = &d_mem;
  kernel_args[19] = &num_many_lut;
  kernel_args[20] = &lut_stride;

  dim3 grid_accumulate(num_samples, glwe_dimension + 1, level_count);
  dim3 thds(polynomial_size / params::opt, 1, 1);

  if (max_shared_memory < partial_dm) {
    kernel_args[18] = &full_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            InputTorus, params, NOSM>,
        grid_accumulate, thds, (void **)kernel_args, 0, stream));
  } else if (max_shared_memory < full_dm) {
    kernel_args[18] = &partial_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            InputTorus, params, PARTIALSM>,
        grid_accumulate, thds, (void **)kernel_args, partial_sm, stream));
  } else {
    kernel_args[18] = &no_dm;
    check_cuda_error(cudaLaunchCooperativeKernel(
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            InputTorus, params, FULLSM>,
        grid_accumulate, thds, (void **)kernel_args, full_sm, stream));
  }
}

template <typename InputTorus, class params>
__host__ void host_cg_multi_bit_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    InputTorus const *lwe_output_indexes, __uint128_t const *lut_vector,
    InputTorus const *lwe_array_in, InputTorus const *lwe_input_indexes,
    __uint128_t const *bootstrapping_key,
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
    execute_cg_external_product_loop_128<InputTorus, params>(
        stream, gpu_index, lut_vector, lwe_array_in, lwe_input_indexes,
        lwe_array_out, lwe_output_indexes, buffer, num_samples, lwe_dimension,
        glwe_dimension, polynomial_size, grouping_factor, base_log, level_count,
        lwe_offset, num_many_lut, lut_stride);
  }
}

template <typename InputTorus, typename params>
__host__ uint64_t scratch_multi_bit_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  cuda_set_device(gpu_index);

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

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
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
            InputTorus, params, NOSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            InputTorus, params, NOSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            InputTorus, params, NOSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            InputTorus, params, NOSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            InputTorus, params, FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            InputTorus, params, FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            InputTorus, params, FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize,
        full_sm_accumulate_step_two));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_step_two_128<
            InputTorus, params, FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  auto lwe_chunk_size = get_lwe_chunk_size_128<InputTorus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size, glwe_dimension,
      level_count, full_sm_keybundle);
  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, lwe_chunk_size, PBS_VARIANT::DEFAULT,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename InputTorus, typename params>
__host__ uint64_t scratch_cg_multi_bit_programmable_bootstrap_128(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, MULTI_BIT> **buffer, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t level_count,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory) {

  cuda_set_device(gpu_index);

  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_128_keybundle<
          __uint128_t>(polynomial_size);
  uint64_t full_sm_cg_accumulate =
      get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<__uint128_t>(
          polynomial_size);
  uint64_t partial_sm_cg_accumulate =
      get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<
          __uint128_t>(polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, NOSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle_128<InputTorus,
                                                              params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  if (max_shared_memory < partial_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<InputTorus,
                                                                  params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<InputTorus,
                                                                  params, NOSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            InputTorus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            InputTorus, params, PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            InputTorus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            InputTorus, params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  auto lwe_chunk_size = get_lwe_chunk_size_128<InputTorus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size, glwe_dimension,
      level_count, full_sm_keybundle);
  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, lwe_chunk_size, PBS_VARIANT::CG,
      allocate_gpu_memory, size_tracker);
  return size_tracker;
}

// Verify if the grid size satisfies the cooperative group constraints
template <typename Torus, class params>
__host__ bool verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size_128(
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
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            Torus, params, NOSM>,
        thds, 0);
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<Torus, params,
                                                                  PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm_cg_accumulate));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<Torus, params,
                                                                  PARTIALSM>,
        cudaFuncCachePreferShared);
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            Torus, params, PARTIALSM>,
        thds, partial_sm_cg_accumulate);
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<Torus, params,
                                                                  FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_cg_accumulate));
    cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_cg_accumulate_128<Torus, params,
                                                                  FULLSM>,
        cudaFuncCachePreferShared);
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_multi_bit_programmable_bootstrap_cg_accumulate_128<
            Torus, params, FULLSM>,
        thds, full_sm_cg_accumulate);
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
__host__ bool
supports_cooperative_groups_on_multibit_programmable_bootstrap_128(
    int glwe_dimension, int polynomial_size, int level_count, int num_samples,
    uint32_t max_shared_memory) {
  switch (polynomial_size) {
  case 256:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size_128<
        Torus, Degree<256>>(glwe_dimension, level_count, num_samples,
                            max_shared_memory);
  case 512:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size_128<
        Torus, Degree<512>>(glwe_dimension, level_count, num_samples,
                            max_shared_memory);
  case 1024:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size_128<
        Torus, Degree<1024>>(glwe_dimension, level_count, num_samples,
                             max_shared_memory);
  case 2048:
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size_128<
        Torus, Degree<2048>>(glwe_dimension, level_count, num_samples,
                             max_shared_memory);
  case 4096:
    // We use AmortizedDegree for 4096 to avoid register exhaustion
    return verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size_128<
        Torus, AmortizedDegree<4096>>(glwe_dimension, level_count, num_samples,
                                      max_shared_memory);
  default:
    PANIC(
        "Cuda error (multi-bit PBS128): unsupported polynomial size. Supported "
        "N's are powers of two"
        " in the interval [256..4096].")
  }
}

#endif // PROGRAMMABLE_BOOTSTRAP_MULTIBIT_128_CUH
