#ifndef CUDA_PBS_CUH_128_HALFHALF
#define CUDA_PBS_CUH_128_HALFHALF

// Halfhalf (HP+HR) generalized PBS-128 kernels.
// Belorgey et al., "Revisiting key decomposition techniques for FHE",
// ePrint 2023/771.
// Bernard & Joye, "Bootstrapping (t)FHE ciphertexts via automorphisms",
// ePrint 2025/163.

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
#include "programmable_bootstrap_classic_128.cuh"
#include "types/complex/operations.cuh"

inline void validate_halfhalf_params(CudaHalfhalfPbsParamsFFI p) {
  PANIC_IF_FALSE(p.polynomial_size > 0,
                 "Halfhalf PBS: polynomial_size must be > 0");
  PANIC_IF_FALSE(p.glwe_dimension > 0,
                 "Halfhalf PBS: glwe_dimension must be > 0");
  PANIC_IF_FALSE(p.split_index > 0 && p.split_index < p.input_lwe_dimension,
                 "Halfhalf PBS: split_index must satisfy 0 < split_index < "
                 "input_lwe_dimension");
  PANIC_IF_FALSE(p.level_count_1_mask > 0,
                 "Halfhalf PBS: level_count_1_mask must be > 0");
  PANIC_IF_FALSE(p.level_count_1_body > 0,
                 "Halfhalf PBS: level_count_1_body must be > 0");
  PANIC_IF_FALSE(p.level_count_2_mask > 0,
                 "Halfhalf PBS: level_count_2_mask must be > 0");
  PANIC_IF_FALSE(p.level_count_2_body > 0,
                 "Halfhalf PBS: level_count_2_body must be > 0");
  PANIC_IF_FALSE(p.level_count_1_mask >= p.level_count_1_body,
                 "Halfhalf PBS: level_count_1_body must be <= "
                 "level_count_1_mask (body GLev rows must not exceed mask GLev "
                 "rows)");
  PANIC_IF_FALSE(p.level_count_2_mask >= p.level_count_2_body,
                 "Halfhalf PBS: level_count_2_body must be <= "
                 "level_count_2_mask (body GLev rows must not exceed mask GLev "
                 "rows)");
  PANIC_IF_FALSE(p.base_log_1_mask > 0,
                 "Halfhalf PBS: base_log_1_mask must be > 0");
  PANIC_IF_FALSE(p.base_log_1_body > 0,
                 "Halfhalf PBS: base_log_1_body must be > 0");
  PANIC_IF_FALSE(p.base_log_2_mask > 0,
                 "Halfhalf PBS: base_log_2_mask must be > 0");
  PANIC_IF_FALSE(p.base_log_2_body > 0,
                 "Halfhalf PBS: base_log_2_body must be > 0");
  PANIC_IF_FALSE((uint64_t)p.base_log_1_mask * p.level_count_1_mask <= 128,
                 "Halfhalf PBS: base_log_1_mask * level_count_1_mask > 128");
  PANIC_IF_FALSE((uint64_t)p.base_log_1_body * p.level_count_1_body <= 128,
                 "Halfhalf PBS: base_log_1_body * level_count_1_body > 128");
  PANIC_IF_FALSE((uint64_t)p.base_log_2_mask * p.level_count_2_mask <= 128,
                 "Halfhalf PBS: base_log_2_mask * level_count_2_mask > 128");
  PANIC_IF_FALSE((uint64_t)p.base_log_2_body * p.level_count_2_body <= 128,
                 "Halfhalf PBS: base_log_2_body * level_count_2_body > 128");
}

inline __host__ __device__ uint32_t
halfhalf_group_max_level(uint32_t level_mask, uint32_t level_body) {
  return (level_mask > level_body) ? level_mask : level_body;
}

inline uint32_t halfhalf_global_max_level(CudaHalfhalfPbsParamsFFI p) {
  uint32_t max1 =
      halfhalf_group_max_level(p.level_count_1_mask, p.level_count_1_body);
  uint32_t max2 =
      halfhalf_group_max_level(p.level_count_2_mask, p.level_count_2_body);
  return (max1 > max2) ? max1 : max2;
}

// Compact BSK accessor for the halfhalf layout. It mirrors the standard-domain
// container HalfProductGgswCiphertext on the Rust side, defined in
// tfhe/src/core_crypto/entities/half_product_ggsw_ciphertext.rs, so a reference
// key uploads as-is. Per GGSW entry the mask block comes first, and both blocks
// are level-major with levels in decreasing order:
//
//   mask block, k * level_mask GLWE ciphertexts:
//     [ lvl l_msk: rows 0..k-1 ] ... [ lvl 1: rows 0..k-1 ]
//   body block, level_body GLWE ciphertexts:
//     [ lvl l_body ] ... [ lvl 1 ]
//
// Each GLWE ciphertext is (k+1) polynomials; each polynomial is poly_size/2*4
// doubles in the f128 Fourier domain. Kernel index `level` corresponds to
// DecompositionLevel(level + 1), so index 0 carries the largest multiplicative
// factor and belongs in the last slot, which is why the slot is
// level_count - 1 - level.
//
// Callers must ensure level < level_mask for mask rows and level < level_body
// for the body row: both slot subtractions are unsigned and wrap otherwise.
template <typename T>
__host__ __device__ const T *
get_halfhalf_bsk_slice(const T *group_bsk, int entry_idx, int glev_row,
                       int level, uint32_t polynomial_size,
                       uint32_t glwe_dimension, uint32_t level_mask,
                       uint32_t level_body) {

  uint32_t k = glwe_dimension;
  uint32_t glwe_size = k + 1;
  size_t doubles_per_poly = polynomial_size / 2 * 4;

  size_t polys_per_entry = glwe_size * (k * level_mask + level_body);
  size_t entry_offset = entry_idx * polys_per_entry * doubles_per_poly;

  size_t glwe_ct_index;
  if (glev_row < (int)k) {
    glwe_ct_index = (size_t)(level_mask - 1 - level) * k + glev_row;
  } else {
    glwe_ct_index = (size_t)k * level_mask + (level_body - 1 - level);
  }

  return &group_bsk[entry_offset +
                    glwe_ct_index * glwe_size * doubles_per_poly];
}

// Doubles occupied by section 1 of the compact halfhalf key, which is also the
// offset of section 2's base pointer. Every launch path needs it, because the
// blind rotation switches key section at split_index, so it lives here rather
// than being spelled out per path.
inline size_t halfhalf_section_1_bsk_doubles(CudaHalfhalfPbsParamsFFI p) {
  return (size_t)p.split_index * (size_t)(p.glwe_dimension + 1) *
         (size_t)(p.glwe_dimension * p.level_count_1_mask +
                  p.level_count_1_body) *
         (size_t)(p.polynomial_size / 2) * 4;
}

// Variant of mul_ggsw_glwe_in_fourier_domain_128 for compact halfhalf BSK.
// The BSK consists of two groups stored contiguously. The caller provides a
// pointer to the current group's base and the group-local iteration index.
// level_mask / level_body are the per-row level counts for the current group.
// The grid z-dimension may exceed level_mask; excess blocks produce
// zero join-buffer entries to avoid BSK out-of-bounds reads.
template <typename G, class params>
__device__ void mul_ggsw_glwe_in_fourier_domain_128_halfhalf(
    double *fft, double *join_buffer, const double *__restrict__ group_bsk,
    uint32_t group_local_iteration, uint32_t level_mask, uint32_t level_body,
    G &group) {
  const uint32_t polynomial_size = params::degree;
  const uint32_t glwe_dimension = gridDim.y - 1;
  const uint32_t level_count = gridDim.z;

  auto this_block_rank = get_this_block_rank<G>(group, false);

  bool has_bsk = (blockIdx.z < level_mask) &&
                 !(blockIdx.y == glwe_dimension && blockIdx.z >= level_body);

  const double *bsk_slice = nullptr;
  if (has_bsk)
    bsk_slice = get_halfhalf_bsk_slice(
        group_bsk, (int)group_local_iteration, (int)blockIdx.y, (int)blockIdx.z,
        polynomial_size, glwe_dimension, level_mask, level_body);

  for (int j = 0; j < (int)(glwe_dimension + 1); j++) {
    int idx = (j + this_block_rank) % (glwe_dimension + 1);
    auto buffer_slice =
        get_join_buffer_element_128<G>(blockIdx.z, idx, group, join_buffer,
                                       polynomial_size, glwe_dimension, false);

    if (has_bsk) {
      auto bsk_poly = bsk_slice + idx * polynomial_size / 2 * 4;
      polynomial_product_accumulate_in_fourier_domain_128<params>(
          buffer_slice, fft, bsk_poly, j == 0);
    } else if (j == 0) {
      int tid = threadIdx.x;
      for (int c = 0; c < params::opt / 2; c++) {
        buffer_slice[0 * params::degree / 2 + tid] = 0.0;
        buffer_slice[1 * params::degree / 2 + tid] = 0.0;
        buffer_slice[2 * params::degree / 2 + tid] = 0.0;
        buffer_slice[3 * params::degree / 2 + tid] = 0.0;
        tid += params::degree / params::opt;
      }
    }
    // j > 0 with !has_bsk: fft is zero, so accumulating zero is a no-op
    group.sync();
  }

  for (int l = 0; l < (int)level_count; l++) {
    auto cur_src_acc =
        get_join_buffer_element_128<G>(l, blockIdx.y, group, join_buffer,
                                       polynomial_size, glwe_dimension, false);

    polynomial_accumulate_in_fourier_domain_128<params>(fft, cur_src_acc,
                                                        l == 0);
  }

  __syncthreads();
}

// CG kernel for halfhalf PBS-128.
// Processes a single BSK group over the entry range [iter_start, iter_end).
// The host launches this kernel twice (once per group) with different z-grids.
// max_z_global stabilizes device_mem indexing across launches.
// global_accumulator persists the accumulator between the two launches.
template <typename InputTorus, class params, sharedMemDegree SMD>
__global__ void device_programmable_bootstrap_cg_128_halfhalf(
    __uint128_t *lwe_array_out, const __uint128_t *__restrict__ lut_vector,
    const InputTorus *__restrict__ lwe_array_in,
    const double *__restrict__ group_bsk, double *join_buffer,
    __uint128_t *global_accumulator, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t iter_start, uint32_t iter_end,
    uint32_t base_log_mask, uint32_t level_count_mask, uint32_t base_log_body,
    uint32_t level_count_body, uint32_t max_z_global, bool do_init,
    bool do_extract, int8_t *device_mem, uint64_t device_memory_size_per_block,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  grid_group grid = this_grid();

  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;
  uint32_t glwe_dimension = gridDim.y - 1;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.z + blockIdx.y * max_z_global +
                      blockIdx.x * max_z_global * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  __uint128_t *accumulator = (__uint128_t *)selected_memory;
  __uint128_t *accumulator_rotated =
      (__uint128_t *)accumulator + (ptrdiff_t)(polynomial_size);
  double *accumulator_fft =
      (double *)(accumulator_rotated) +
      (ptrdiff_t)(polynomial_size * sizeof(__uint128_t) / sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double *)sharedmem;

  const InputTorus *block_lwe_array_in =
      &lwe_array_in[blockIdx.x * (lwe_dimension + 1)];

  const __uint128_t *block_lut_vector = lut_vector;

  double *block_join_buffer =
      &join_buffer[blockIdx.x * max_z_global * (glwe_dimension + 1) *
                   params::degree / 2 * 4];

  __uint128_t *global_acc_slice =
      &global_accumulator[(blockIdx.y + blockIdx.x * (glwe_dimension + 1)) *
                          params::degree];

  bool is_body = (blockIdx.y == glwe_dimension);
  uint32_t my_base_log = is_body ? base_log_body : base_log_mask;
  uint32_t my_level_count = is_body ? level_count_body : level_count_mask;

  if (do_init) {
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
  } else {
    copy_polynomial<__uint128_t, params::opt, params::degree / params::opt>(
        global_acc_slice, accumulator);
  }

  constexpr auto log_modulus = params::log2_degree + 1;

  for (uint32_t i = iter_start; i < iter_end; i++) {
    __syncthreads();

    InputTorus a_hat = 0;
    modulus_switch<InputTorus>(block_lwe_array_in[i], a_hat, log_modulus);

    multiply_by_monomial_negacyclic_and_sub_polynomial<
        __uint128_t, params::opt, params::degree / params::opt>(
        accumulator, accumulator_rotated, a_hat);

    init_decomposer_state_inplace<__uint128_t, params::opt,
                                  params::degree / params::opt>(
        accumulator_rotated, my_base_log, my_level_count);

    __syncthreads();

    auto acc_fft_re_hi = accumulator_fft + 0 * params::degree / 2;
    auto acc_fft_re_lo = accumulator_fft + 1 * params::degree / 2;
    auto acc_fft_im_hi = accumulator_fft + 2 * params::degree / 2;
    auto acc_fft_im_lo = accumulator_fft + 3 * params::degree / 2;

    if (blockIdx.z < my_level_count) {
      GadgetMatrix<__uint128_t, params> gadget_acc(my_base_log, my_level_count,
                                                   accumulator_rotated);
      gadget_acc.decompose_and_compress_level_128(accumulator_fft, blockIdx.z);

      negacyclic_forward_fft_f128<HalfDegree<params>>(
          acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);
    } else {
      int tid = threadIdx.x;
      for (int c = 0; c < params::opt / 2; c++) {
        accumulator_fft[0 * params::degree / 2 + tid] = 0.0;
        accumulator_fft[1 * params::degree / 2 + tid] = 0.0;
        accumulator_fft[2 * params::degree / 2 + tid] = 0.0;
        accumulator_fft[3 * params::degree / 2 + tid] = 0.0;
        tid += params::degree / params::opt;
      }
    }

    __syncthreads();

    uint32_t group_local_iter = i - iter_start;

    mul_ggsw_glwe_in_fourier_domain_128_halfhalf<grid_group, params>(
        accumulator_fft, block_join_buffer, group_bsk, group_local_iter,
        level_count_mask, level_count_body, grid);

    negacyclic_backward_fft_f128<HalfDegree<params>>(
        acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);
    __syncthreads();

    add_to_torus_128<__uint128_t, params>(acc_fft_re_hi, acc_fft_re_lo,
                                          acc_fft_im_hi, acc_fft_im_lo,
                                          accumulator);
  }

  if (do_extract) {
    auto block_lwe_array_out =
        &lwe_array_out[blockIdx.x * (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.z == 0) {
      if (blockIdx.y < glwe_dimension) {
        sample_extract_mask<__uint128_t, params>(block_lwe_array_out,
                                                 accumulator);
      } else if (blockIdx.y == glwe_dimension) {
        __syncthreads();
        sample_extract_body<__uint128_t, params>(block_lwe_array_out,
                                                 accumulator, 0);
      }
    }
  } else if (blockIdx.z == 0) {
    copy_polynomial<__uint128_t, params::opt, params::degree / params::opt>(
        accumulator, global_acc_slice);
  }
}

// Blocks per SM that the DEFAULT variant kernels are compiled to keep
// resident. Both steps are bound by global memory traffic (step one streams the
// join buffer out, step two reads it back together with the BSK), so a second
// resident block is what hides that latency. Asking for it caps the per-thread
// register budget at (registers per SM) / (2 * threads per block); ptxas meets
// the cap by keeping fewer loads in flight rather than spilling. Amortized
// degree configurations give each thread params::opt times more work, cannot
// meet the cap without spilling to local memory, and their shared memory
// footprint already limits them to a single resident block, so they keep the
// default residency.
template <class params> constexpr uint32_t halfhalf_default_blocks_per_sm() {
#ifdef __CUDACC_DEBUG__
  // Debug builds skip optimizations and need more registers, so requesting a
  // second resident block there would only force spills.
  return 1;
#else
  return params::opt == choose_opt(params::degree) ? 2 : 1;
#endif
}

// DEFAULT variant: step one decomposes and FFTs the accumulator.
// The host resolves the per-group decomposition params before launch, keeping
// the group selection out of the device hot path.
template <typename InputTorus, class params, sharedMemDegree SMD,
          bool first_iter>
__global__ void __launch_bounds__(params::degree / params::opt,
                                  halfhalf_default_blocks_per_sm<params>())
    device_programmable_bootstrap_step_one_128_halfhalf(
        const __uint128_t *__restrict__ lut_vector,
        const InputTorus *__restrict__ lwe_array_in,
        const double *__restrict__ bootstrapping_key,
        __uint128_t *global_accumulator, double *global_join_buffer,
        uint32_t lwe_iteration, uint32_t lwe_dimension,
        uint32_t polynomial_size, uint32_t base_log_mask,
        uint32_t level_count_mask, uint32_t base_log_body,
        uint32_t level_count_body, uint32_t current_max_level,
        int8_t *device_mem, uint64_t device_memory_size_per_block,
        PBS_MS_REDUCTION_T noise_reduction_type) {

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

  const InputTorus *block_lwe_array_in =
      &lwe_array_in[blockIdx.x * (lwe_dimension + 1)];

  const __uint128_t *block_lut_vector = lut_vector;

  __uint128_t *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1)) * params::degree;

  double *global_fft_slice =
      global_join_buffer +
      (blockIdx.y + blockIdx.z * (glwe_dimension + 1) +
       blockIdx.x * current_max_level * (glwe_dimension + 1)) *
          (polynomial_size / 2) * 4;

  bool is_body = (blockIdx.y == glwe_dimension);
  uint32_t my_base_log = is_body ? base_log_body : base_log_mask;
  uint32_t my_level_count = is_body ? level_count_body : level_count_mask;

  constexpr auto log_modulus = params::log2_degree + 1;
  if constexpr (first_iter) {
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

    copy_polynomial<__uint128_t, params::opt, params::degree / params::opt>(
        accumulator, global_slice);
  }

  InputTorus a_hat = 0;
  modulus_switch<InputTorus>(block_lwe_array_in[lwe_iteration], a_hat,
                             log_modulus);

  __syncthreads();

  multiply_by_monomial_negacyclic_and_sub_polynomial<
      __uint128_t, params::opt, params::degree / params::opt>(
      global_slice, accumulator, a_hat);

  init_decomposer_state_inplace<__uint128_t, params::opt,
                                params::degree / params::opt>(
      accumulator, my_base_log, my_level_count);

  __syncthreads();

  auto acc_fft_re_hi = accumulator_fft + 0 * params::degree / 2;
  auto acc_fft_re_lo = accumulator_fft + 1 * params::degree / 2;
  auto acc_fft_im_hi = accumulator_fft + 2 * params::degree / 2;
  auto acc_fft_im_lo = accumulator_fft + 3 * params::degree / 2;

  auto gfft_re_hi = global_fft_slice + 0 * params::degree / 2;
  auto gfft_re_lo = global_fft_slice + 1 * params::degree / 2;
  auto gfft_im_hi = global_fft_slice + 2 * params::degree / 2;
  auto gfft_im_lo = global_fft_slice + 3 * params::degree / 2;

  if (blockIdx.z < my_level_count) {
    GadgetMatrix<__uint128_t, params> gadget_acc(my_base_log, my_level_count,
                                                 accumulator);
    gadget_acc.decompose_and_compress_level_128(accumulator_fft, blockIdx.z);

    negacyclic_forward_fft_f128<HalfDegree<params>>(
        acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);

    int tid = threadIdx.x;
    for (int i = 0; i < params::opt / 2; i++) {
      gfft_re_hi[tid] = acc_fft_re_hi[tid];
      gfft_re_lo[tid] = acc_fft_re_lo[tid];
      gfft_im_hi[tid] = acc_fft_im_hi[tid];
      gfft_im_lo[tid] = acc_fft_im_lo[tid];
      tid += params::degree / params::opt;
    }
  } else {
    int tid = threadIdx.x;
    for (int i = 0; i < params::opt / 2; i++) {
      gfft_re_hi[tid] = 0.0;
      gfft_re_lo[tid] = 0.0;
      gfft_im_hi[tid] = 0.0;
      gfft_im_lo[tid] = 0.0;
      tid += params::degree / params::opt;
    }
  }
}

// DEFAULT variant: step two performs BSK multiplication and IFFT.
// Group selection is pre-computed on the host to reduce register pressure.
// CT_LEVEL_MASK/CT_LEVEL_BODY: when non-zero, the level loop uses these
// compile-time constants for full unrolling and static branch elimination.
template <typename Torus, class params, sharedMemDegree SMD, bool last_iter,
          uint32_t CT_LEVEL_MASK = 0, uint32_t CT_LEVEL_BODY = 0>
__global__ void __launch_bounds__(params::degree / params::opt,
                                  halfhalf_default_blocks_per_sm<params>())
    device_programmable_bootstrap_step_two_128_halfhalf(
        Torus *lwe_array_out, const double *__restrict__ group_bsk,
        Torus *global_accumulator, double *global_join_buffer,
        uint32_t group_local_iter, uint32_t polynomial_size,
        uint32_t level_mask_g, uint32_t level_body_g, int8_t *device_mem,
        uint64_t device_memory_size_per_block) {

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

  Torus *accumulator = (Torus *)selected_memory;
  double *accumulator_fft =
      (double *)accumulator +
      (ptrdiff_t)(sizeof(Torus) * params::degree / sizeof(double));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = (double *)sharedmem;

  const uint32_t level_mask = CT_LEVEL_MASK > 0 ? CT_LEVEL_MASK : level_mask_g;
  const uint32_t level_body = CT_LEVEL_MASK > 0 ? CT_LEVEL_BODY : level_body_g;

#pragma unroll
  for (int level = 0; level < (int)level_mask; level++) {
    double *global_fft_slice =
        global_join_buffer + (level + blockIdx.x * level_mask) *
                                 (glwe_dimension + 1) * (params::degree / 2) *
                                 4;
    for (int j = 0; j < (int)(glwe_dimension + 1); j++) {
      if (j == (int)glwe_dimension && level >= (int)level_body)
        continue;
      double *fft = global_fft_slice + j * params::degree / 2 * 4;
      auto bsk_slice = get_halfhalf_bsk_slice(
          group_bsk, (int)group_local_iter, j, level, polynomial_size,
          glwe_dimension, level_mask, level_body);
      auto bsk_poly = bsk_slice + blockIdx.y * params::degree / 2 * 4;
      polynomial_product_accumulate_in_fourier_domain_128<params>(
          accumulator_fft, fft, bsk_poly, !level && !j);
    }
  }

  Torus *global_slice =
      global_accumulator +
      (blockIdx.y + blockIdx.x * (glwe_dimension + 1)) * params::degree;

  copy_polynomial<Torus, params::opt, params::degree / params::opt>(
      global_slice, accumulator);

  auto acc_fft_re_hi = accumulator_fft + 0 * params::degree / 2;
  auto acc_fft_re_lo = accumulator_fft + 1 * params::degree / 2;
  auto acc_fft_im_hi = accumulator_fft + 2 * params::degree / 2;
  auto acc_fft_im_lo = accumulator_fft + 3 * params::degree / 2;

  negacyclic_backward_fft_f128<HalfDegree<params>>(
      acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi, acc_fft_im_lo);

  add_to_torus_128<Torus, params>(acc_fft_re_hi, acc_fft_re_lo, acc_fft_im_hi,
                                  acc_fft_im_lo, accumulator);

  if constexpr (last_iter) {
    auto block_lwe_array_out =
        &lwe_array_out[blockIdx.x * (glwe_dimension * polynomial_size + 1) +
                       blockIdx.y * polynomial_size];

    if (blockIdx.y < glwe_dimension) {
      sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
    } else if (blockIdx.y == glwe_dimension) {
      __syncthreads();
      sample_extract_body<Torus, params>(block_lwe_array_out, accumulator, 0);
    }
  } else {
    copy_polynomial<Torus, params::opt, params::degree / params::opt>(
        accumulator, global_slice);
  }
}

// Scratch allocation for CG variant
template <typename InputTorus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_cg_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t max_level_count, uint32_t input_lwe_ciphertext_count,
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
        device_programmable_bootstrap_cg_128_halfhalf<InputTorus, params,
                                                      PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128_halfhalf<InputTorus, params,
                                                      PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg_128_halfhalf<InputTorus, params,
                                                      FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128_halfhalf<InputTorus, params,
                                                      FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL>(
      stream, gpu_index, lwe_dimension, glwe_dimension, polynomial_size,
      max_level_count, input_lwe_ciphertext_count, PBS_VARIANT::CG,
      allocate_gpu_memory, noise_reduction_type, size_tracker);
  return size_tracker;
}

// Scratch allocation for DEFAULT variant
template <typename InputTorus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t max_level_count, uint32_t input_lwe_ciphertext_count,
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
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            PARTIALSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            PARTIALSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            PARTIALSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            PARTIALSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            FULLSM, true>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            FULLSM, true>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            FULLSM, false>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_one));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                            FULLSM, false>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  // Configure step two (generic + compile-time-specialized instantiations).
  if (max_shared_memory >= partial_sm && max_shared_memory < full_sm_step_two) {
    auto set = [&](auto fn) {
      check_cuda_error(cudaFuncSetAttribute(
          fn, cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
      check_cuda_error(cudaFuncSetCacheConfig(fn, cudaFuncCachePreferShared));
    };
    set(device_programmable_bootstrap_step_two_128_halfhalf<__uint128_t, params,
                                                            PARTIALSM, true>);
    set(device_programmable_bootstrap_step_two_128_halfhalf<__uint128_t, params,
                                                            PARTIALSM, false>);
    if constexpr (params::degree == 2048) {
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, PARTIALSM, true, 2, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, PARTIALSM, false, 2, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, PARTIALSM, true, 3, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, PARTIALSM, false, 3, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, PARTIALSM, true, 3, 3>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, PARTIALSM, false, 3, 3>);
    }
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory >= partial_sm) {
    auto set = [&](auto fn) {
      check_cuda_error(cudaFuncSetAttribute(
          fn, cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_step_two));
      check_cuda_error(cudaFuncSetCacheConfig(fn, cudaFuncCachePreferShared));
    };
    set(device_programmable_bootstrap_step_two_128_halfhalf<__uint128_t, params,
                                                            FULLSM, true>);
    set(device_programmable_bootstrap_step_two_128_halfhalf<__uint128_t, params,
                                                            FULLSM, false>);
    if constexpr (params::degree == 2048) {
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, FULLSM, true, 2, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, FULLSM, false, 2, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, FULLSM, true, 3, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, FULLSM, false, 3, 2>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, FULLSM, true, 3, 3>);
      set(device_programmable_bootstrap_step_two_128_halfhalf<
          __uint128_t, params, FULLSM, false, 3, 3>);
    }
    check_cuda_error(cudaGetLastError());
  }

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL>(
      stream, gpu_index, lwe_dimension, glwe_dimension, polynomial_size,
      max_level_count, input_lwe_ciphertext_count, PBS_VARIANT::DEFAULT,
      allocate_gpu_memory, noise_reduction_type, size_tracker);
  return size_tracker;
}

// SM count of gpu_index. The device is explicit, like in
// cuda_get_max_shared_memory, so that a caller which knows its target device
// can ask about it without having to make it current first.
__host__ inline int get_number_of_sms_on_device(uint32_t gpu_index) {
  int number_of_sm = 0;
  check_cuda_error(cudaDeviceGetAttribute(&number_of_sm,
                                          cudaDevAttrMultiProcessorCount,
                                          static_cast<int>(gpu_index)));
  return number_of_sm;
}

// CG support check for halfhalf
template <class params>
__host__ bool verify_cuda_programmable_bootstrap_128_halfhalf_cg_grid_size(
    int glwe_dimension, int max_level_count, int num_samples,
    uint32_t max_shared_memory) {

  if (!cuda_check_support_cooperative_groups())
    return false;

  uint64_t full_sm =
      get_buffer_size_full_sm_programmable_bootstrap_cg<__uint128_t>(
          params::degree);

  uint64_t partial_sm =
      get_buffer_size_partial_sm_programmable_bootstrap_cg<__uint128_t>(
          params::degree);

  int thds = params::degree / params::opt;

  int number_of_blocks = max_level_count * (glwe_dimension + 1) * num_samples;
  int max_active_blocks_per_sm;

  if (max_shared_memory < partial_sm) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg_128_halfhalf<__uint128_t,
                                                              params, NOSM>,
        thds, 0));
  } else if (max_shared_memory < full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg_128_halfhalf<__uint128_t, params,
                                                      PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128_halfhalf<__uint128_t, params,
                                                      PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg_128_halfhalf<
            __uint128_t, params, PARTIALSM>,
        thds, partial_sm));
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_programmable_bootstrap_cg_128_halfhalf<__uint128_t, params,
                                                      FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_programmable_bootstrap_cg_128_halfhalf<__uint128_t, params,
                                                      FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_active_blocks_per_sm,
        (void *)device_programmable_bootstrap_cg_128_halfhalf<__uint128_t,
                                                              params, FULLSM>,
        thds, full_sm));
  }

  // A cooperative launch requires every block to be resident at once, so the
  // grid may not exceed what the device can hold.
  //
  // The SM count is read from the current device rather than from an explicit
  // one: the occupancy, attribute and cache-config calls above all act on the
  // current device and take no device argument, so the count they get
  // multiplied by has to come from that same device. Targeting an explicit
  // gpu_index here would mean setting the device inside this check, which is a
  // separate change.
  int current_device = 0;
  check_cuda_error(cudaGetDevice(&current_device));

  return number_of_blocks <=
         max_active_blocks_per_sm *
             get_number_of_sms_on_device(static_cast<uint32_t>(current_device));
}

__host__ bool
supports_cooperative_groups_on_programmable_bootstrap_128_halfhalf(
    int glwe_dimension, int polynomial_size, int max_level_count,
    int num_samples, uint32_t max_shared_memory);

// Largest batch measured to favor CG over the DEFAULT step_one/step_two pair,
// on H100 (sm_90) with the noise squashing parameters (N=2048, k=2, split
// decomposition levels 2/2 and 3/2). DEFAULT overtakes CG well before batch 16,
// so the crossover lies between this bound and that batch; the value is the
// largest batch actually measured to favor CG rather than the middle of that
// bracket. It is a heuristic that another GPU or another parameter set may
// place elsewhere.
static constexpr uint32_t PBS_128_HALFHALF_CG_MAX_INPUT_LWE_CIPHERTEXT_COUNT =
    8;

// Top-level scratch that selects CG > DEFAULT. CG holds the whole blind
// rotation in one cooperative launch, which only pays off while DEFAULT is
// still launch-bound: DEFAULT walks the bootstrapping key on the host and
// launches step_one and step_two once per key entry, so its launch count is
// fixed by lwe_dimension and does not shrink with the batch. Past the bound
// above, DEFAULT's grid carries enough blocks to hide that cost and CG cannot
// grow its grid any further, because a cooperative launch needs every block
// resident at once. The per-variant entry points below are not affected: they
// honor the caller's choice as long as it is supported.
template <typename InputTorus>
uint64_t scratch_cuda_programmable_bootstrap_128_halfhalf_vector(
    void *stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t max_level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  auto buffer = (pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **)pbs_buffer;

  if (input_lwe_ciphertext_count <=
          PBS_128_HALFHALF_CG_MAX_INPUT_LWE_CIPHERTEXT_COUNT &&
      supports_cooperative_groups_on_programmable_bootstrap_128_halfhalf(
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, max_shared_memory)) {
    switch (polynomial_size) {
    case 256:
      return scratch_programmable_bootstrap_cg_128_halfhalf<InputTorus,
                                                            Degree<256>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 512:
      return scratch_programmable_bootstrap_cg_128_halfhalf<InputTorus,
                                                            Degree<512>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 1024:
      return scratch_programmable_bootstrap_cg_128_halfhalf<InputTorus,
                                                            Degree<1024>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 2048:
      return scratch_programmable_bootstrap_cg_128_halfhalf<InputTorus,
                                                            Degree<2048>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 4096:
      return scratch_programmable_bootstrap_cg_128_halfhalf<
          InputTorus, AmortizedDegree<4096>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    default:
      PANIC("Cuda error (classical PBS128 halfhalf): unsupported polynomial "
            "size. Supported N's are powers of two in [256..4096].")
    }
  } else {
    switch (polynomial_size) {
    case 256:
      return scratch_programmable_bootstrap_128_halfhalf<InputTorus,
                                                         Degree<256>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 512:
      return scratch_programmable_bootstrap_128_halfhalf<InputTorus,
                                                         Degree<512>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 1024:
      return scratch_programmable_bootstrap_128_halfhalf<InputTorus,
                                                         Degree<1024>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 2048:
      return scratch_programmable_bootstrap_128_halfhalf<InputTorus,
                                                         Degree<2048>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    case 4096:
      return scratch_programmable_bootstrap_128_halfhalf<InputTorus,
                                                         AmortizedDegree<4096>>(
          static_cast<cudaStream_t>(stream), gpu_index, buffer, lwe_dimension,
          glwe_dimension, polynomial_size, max_level_count,
          input_lwe_ciphertext_count, allocate_gpu_memory,
          noise_reduction_type);
    default:
      PANIC("Cuda error (classical PBS128 halfhalf): unsupported polynomial "
            "size. Supported N's are powers of two in [256..4096].")
    }
  }
}

// Host wrappers for step_one and step_two (DEFAULT variant)
template <typename InputTorus, class params, bool first_iter>
__host__ void execute_step_one_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t const *lut_vector,
    InputTorus const *lwe_array_in, double const *bootstrapping_key,
    __uint128_t *global_accumulator, double *global_join_buffer,
    PBS_MS_REDUCTION_T noise_reduction_type,
    uint32_t input_lwe_ciphertext_count, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log_mask,
    uint32_t level_count_mask, uint32_t base_log_body,
    uint32_t level_count_body, uint32_t current_max_level, int8_t *d_mem,
    uint32_t lwe_iteration, uint64_t partial_sm, uint64_t partial_dm,
    uint64_t full_sm, uint64_t full_dm) {

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  int thds = polynomial_size / params::opt;
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1, current_max_level);

  if (max_shared_memory < partial_sm) {
    device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                        NOSM, first_iter>
        <<<grid, thds, 0, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log_mask, level_count_mask, base_log_body, level_count_body,
            current_max_level, d_mem, full_dm, noise_reduction_type);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                        PARTIALSM, first_iter>
        <<<grid, thds, partial_sm, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log_mask, level_count_mask, base_log_body, level_count_body,
            current_max_level, d_mem, partial_dm, noise_reduction_type);
  } else {
    device_programmable_bootstrap_step_one_128_halfhalf<InputTorus, params,
                                                        FULLSM, first_iter>
        <<<grid, thds, full_sm, stream>>>(
            lut_vector, lwe_array_in, bootstrapping_key, global_accumulator,
            global_join_buffer, lwe_iteration, lwe_dimension, polynomial_size,
            base_log_mask, level_count_mask, base_log_body, level_count_body,
            current_max_level, d_mem, 0, noise_reduction_type);
  }
  check_cuda_error(cudaGetLastError());
}

// SMD-dispatch helper for step_two. Selects NOSM/PARTIALSM/FULLSM and
// launches the kernel with the given compile-time level constants.
template <class params, bool last_iter, uint32_t CT_LM = 0, uint32_t CT_LB = 0>
__host__ void launch_step_two_128_halfhalf(
    cudaStream_t stream, dim3 grid, int thds, __uint128_t *lwe_array_out,
    double const *group_bsk, __uint128_t *global_accumulator,
    double *global_join_buffer, uint32_t group_local_iter,
    uint32_t polynomial_size, uint32_t level_mask_g, uint32_t level_body_g,
    int8_t *d_mem, uint64_t partial_sm, uint64_t partial_dm, uint64_t full_sm,
    uint64_t full_dm, uint32_t max_shared_memory) {

  if (max_shared_memory < partial_sm) {
    device_programmable_bootstrap_step_two_128_halfhalf<
        __uint128_t, params, NOSM, last_iter, CT_LM, CT_LB>
        <<<grid, thds, 0, stream>>>(lwe_array_out, group_bsk,
                                    global_accumulator, global_join_buffer,
                                    group_local_iter, polynomial_size,
                                    level_mask_g, level_body_g, d_mem, full_dm);
  } else if (max_shared_memory < full_sm) {
    device_programmable_bootstrap_step_two_128_halfhalf<
        __uint128_t, params, PARTIALSM, last_iter, CT_LM, CT_LB>
        <<<grid, thds, partial_sm, stream>>>(
            lwe_array_out, group_bsk, global_accumulator, global_join_buffer,
            group_local_iter, polynomial_size, level_mask_g, level_body_g,
            d_mem, partial_dm);
  } else {
    device_programmable_bootstrap_step_two_128_halfhalf<
        __uint128_t, params, FULLSM, last_iter, CT_LM, CT_LB>
        <<<grid, thds, full_sm, stream>>>(
            lwe_array_out, group_bsk, global_accumulator, global_join_buffer,
            group_local_iter, polynomial_size, level_mask_g, level_body_g,
            d_mem, 0);
  }
  check_cuda_error(cudaGetLastError());
}

template <class params, bool last_iter>
__host__ void execute_step_two_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    double const *group_bsk, __uint128_t *global_accumulator,
    double *global_join_buffer, uint32_t input_lwe_ciphertext_count,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t group_local_iter, uint32_t level_mask_g, uint32_t level_body_g,
    int8_t *d_mem, uint64_t partial_sm, uint64_t partial_dm, uint64_t full_sm,
    uint64_t full_dm) {

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  cuda_set_device(gpu_index);
  dim3 grid(input_lwe_ciphertext_count, glwe_dimension + 1);

  int thds = polynomial_size / params::opt;

  if constexpr (params::degree == 2048) {
    if (level_mask_g == 2 && level_body_g == 2) {
      launch_step_two_128_halfhalf<params, last_iter, 2, 2>(
          stream, grid, thds, lwe_array_out, group_bsk, global_accumulator,
          global_join_buffer, group_local_iter, polynomial_size, level_mask_g,
          level_body_g, d_mem, partial_sm, partial_dm, full_sm, full_dm,
          max_shared_memory);
      return;
    }
    if (level_mask_g == 3 && level_body_g == 2) {
      launch_step_two_128_halfhalf<params, last_iter, 3, 2>(
          stream, grid, thds, lwe_array_out, group_bsk, global_accumulator,
          global_join_buffer, group_local_iter, polynomial_size, level_mask_g,
          level_body_g, d_mem, partial_sm, partial_dm, full_sm, full_dm,
          max_shared_memory);
      return;
    }
    if (level_mask_g == 3 && level_body_g == 3) {
      launch_step_two_128_halfhalf<params, last_iter, 3, 3>(
          stream, grid, thds, lwe_array_out, group_bsk, global_accumulator,
          global_join_buffer, group_local_iter, polynomial_size, level_mask_g,
          level_body_g, d_mem, partial_sm, partial_dm, full_sm, full_dm,
          max_shared_memory);
      return;
    }
  }

  launch_step_two_128_halfhalf<params, last_iter>(
      stream, grid, thds, lwe_array_out, group_bsk, global_accumulator,
      global_join_buffer, group_local_iter, polynomial_size, level_mask_g,
      level_body_g, d_mem, partial_sm, partial_dm, full_sm, full_dm,
      max_shared_memory);
}

// Host wrapper for DEFAULT variant
template <typename InputTorus, class params>
__host__ void host_programmable_bootstrap_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *pbs_buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params,
    uint32_t input_lwe_ciphertext_count) {
  cuda_set_device(gpu_index);

  uint32_t lwe_dimension = halfhalf_params.input_lwe_dimension;
  uint32_t glwe_dimension = halfhalf_params.glwe_dimension;
  uint32_t polynomial_size = halfhalf_params.polynomial_size;

  uint32_t max_level_1 = halfhalf_group_max_level(
      halfhalf_params.level_count_1_mask, halfhalf_params.level_count_1_body);
  uint32_t max_level_2 = halfhalf_group_max_level(
      halfhalf_params.level_count_2_mask, halfhalf_params.level_count_2_body);
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

  size_t group1_bsk_doubles = halfhalf_section_1_bsk_doubles(halfhalf_params);

  for (uint32_t i = 0; i < lwe_dimension; i++) {
    bool in_group1 = (i < halfhalf_params.split_index);
    uint32_t current_max_level = in_group1 ? max_level_1 : max_level_2;

    uint32_t base_log_mask = in_group1 ? halfhalf_params.base_log_1_mask
                                       : halfhalf_params.base_log_2_mask;
    uint32_t level_count_mask = in_group1 ? halfhalf_params.level_count_1_mask
                                          : halfhalf_params.level_count_2_mask;
    uint32_t base_log_body = in_group1 ? halfhalf_params.base_log_1_body
                                       : halfhalf_params.base_log_2_body;
    uint32_t level_count_body = in_group1 ? halfhalf_params.level_count_1_body
                                          : halfhalf_params.level_count_2_body;

    if (i == 0) {
      execute_step_one_128_halfhalf<InputTorus, params, true>(
          stream, gpu_index, lut_vector, lwe_array_in, bootstrapping_key,
          global_accumulator, global_join_buffer, noise_reduction_type,
          input_lwe_ciphertext_count, lwe_dimension, glwe_dimension,
          polynomial_size, base_log_mask, level_count_mask, base_log_body,
          level_count_body, current_max_level, d_mem, i, partial_sm,
          partial_dm_step_one, full_sm_step_one, full_dm_step_one);
    } else {
      execute_step_one_128_halfhalf<InputTorus, params, false>(
          stream, gpu_index, lut_vector, lwe_array_in, bootstrapping_key,
          global_accumulator, global_join_buffer, noise_reduction_type,
          input_lwe_ciphertext_count, lwe_dimension, glwe_dimension,
          polynomial_size, base_log_mask, level_count_mask, base_log_body,
          level_count_body, current_max_level, d_mem, i, partial_sm,
          partial_dm_step_one, full_sm_step_one, full_dm_step_one);
    }

    const double *group_bsk =
        in_group1 ? bootstrapping_key : bootstrapping_key + group1_bsk_doubles;
    uint32_t group_local_iter = in_group1 ? i : i - halfhalf_params.split_index;

    if (i == lwe_dimension - 1) {
      execute_step_two_128_halfhalf<params, true>(
          stream, gpu_index, lwe_array_out, group_bsk, global_accumulator,
          global_join_buffer, input_lwe_ciphertext_count, glwe_dimension,
          polynomial_size, group_local_iter, level_count_mask, level_count_body,
          d_mem, partial_sm, partial_dm_step_two, full_sm_step_two,
          full_dm_step_two);
    } else {
      execute_step_two_128_halfhalf<params, false>(
          stream, gpu_index, lwe_array_out, group_bsk, global_accumulator,
          global_join_buffer, input_lwe_ciphertext_count, glwe_dimension,
          polynomial_size, group_local_iter, level_count_mask, level_count_body,
          d_mem, partial_sm, partial_dm_step_two, full_sm_step_two,
          full_dm_step_two);
    }
  }
}

// Launches one phase of the two-phase CG halfhalf PBS-128.
template <typename InputTorus, class params, sharedMemDegree SMD>
__host__ void launch_cg_128_halfhalf_phase(
    cudaStream_t stream, dim3 grid, int thds, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *group_bsk, double *join_buffer,
    __uint128_t *global_accumulator, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t iter_start, uint32_t iter_end,
    uint32_t base_log_mask, uint32_t level_count_mask, uint32_t base_log_body,
    uint32_t level_count_body, uint32_t max_z_global, bool do_init,
    bool do_extract, int8_t *d_mem, uint64_t device_memory_size_per_block,
    PBS_MS_REDUCTION_T noise_reduction_type, uint64_t shared_mem_bytes) {

  void *kernel_args[20];
  kernel_args[0] = &lwe_array_out;
  kernel_args[1] = &lut_vector;
  kernel_args[2] = &lwe_array_in;
  kernel_args[3] = &group_bsk;
  kernel_args[4] = &join_buffer;
  kernel_args[5] = &global_accumulator;
  kernel_args[6] = &lwe_dimension;
  kernel_args[7] = &polynomial_size;
  kernel_args[8] = &iter_start;
  kernel_args[9] = &iter_end;
  kernel_args[10] = &base_log_mask;
  kernel_args[11] = &level_count_mask;
  kernel_args[12] = &base_log_body;
  kernel_args[13] = &level_count_body;
  kernel_args[14] = &max_z_global;
  kernel_args[15] = &do_init;
  kernel_args[16] = &do_extract;
  kernel_args[17] = &d_mem;
  kernel_args[18] = &device_memory_size_per_block;
  kernel_args[19] = &noise_reduction_type;

  check_cuda_error(cudaLaunchCooperativeKernel(
      (void *)device_programmable_bootstrap_cg_128_halfhalf<InputTorus, params,
                                                            SMD>,
      grid, thds, (void **)kernel_args, shared_mem_bytes, stream));
  check_cuda_error(cudaGetLastError());
}

// Host wrapper for CG variant: two cooperative launches (one per BSK group).
template <typename InputTorus, class params>
__host__ void host_programmable_bootstrap_cg_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    CudaHalfhalfPbsParamsFFI halfhalf_params,
    uint32_t input_lwe_ciphertext_count) {

  uint32_t lwe_dimension = halfhalf_params.input_lwe_dimension;
  uint32_t glwe_dimension = halfhalf_params.glwe_dimension;
  uint32_t polynomial_size = halfhalf_params.polynomial_size;

  uint32_t max_level_1 = halfhalf_group_max_level(
      halfhalf_params.level_count_1_mask, halfhalf_params.level_count_1_body);
  uint32_t max_level_2 = halfhalf_group_max_level(
      halfhalf_params.level_count_2_mask, halfhalf_params.level_count_2_body);
  uint32_t max_z_global =
      (max_level_1 > max_level_2) ? max_level_1 : max_level_2;

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
  double *join_buffer = buffer->global_join_buffer;
  __uint128_t *global_accumulator = buffer->global_accumulator;
  auto noise_reduction_type = buffer->noise_reduction_type;

  int thds = polynomial_size / params::opt;

  size_t group1_bsk_doubles = halfhalf_section_1_bsk_doubles(halfhalf_params);

  const double *group1_bsk = bootstrapping_key;
  const double *group2_bsk = bootstrapping_key + group1_bsk_doubles;

  uint32_t split = halfhalf_params.split_index;

  // Phase 1: group 1 entries [0, split_index), z_dim = max_level_1
  dim3 grid1(input_lwe_ciphertext_count, glwe_dimension + 1, max_level_1);
  uint32_t iter_start_1 = 0;
  uint32_t iter_end_1 = split;

  // Phase 2: group 2 entries [split_index, lwe_dimension), z_dim = max_level_2
  dim3 grid2(input_lwe_ciphertext_count, glwe_dimension + 1, max_level_2);
  uint32_t iter_start_2 = split;
  uint32_t iter_end_2 = lwe_dimension;

  if (max_shared_memory < partial_sm) {
    launch_cg_128_halfhalf_phase<InputTorus, params, NOSM>(
        stream, grid1, thds, lwe_array_out, lut_vector, lwe_array_in,
        group1_bsk, join_buffer, global_accumulator, lwe_dimension,
        polynomial_size, iter_start_1, iter_end_1,
        halfhalf_params.base_log_1_mask, halfhalf_params.level_count_1_mask,
        halfhalf_params.base_log_1_body, halfhalf_params.level_count_1_body,
        max_z_global, true, false, d_mem, full_dm, noise_reduction_type, 0);

    launch_cg_128_halfhalf_phase<InputTorus, params, NOSM>(
        stream, grid2, thds, lwe_array_out, lut_vector, lwe_array_in,
        group2_bsk, join_buffer, global_accumulator, lwe_dimension,
        polynomial_size, iter_start_2, iter_end_2,
        halfhalf_params.base_log_2_mask, halfhalf_params.level_count_2_mask,
        halfhalf_params.base_log_2_body, halfhalf_params.level_count_2_body,
        max_z_global, false, true, d_mem, full_dm, noise_reduction_type, 0);
  } else if (max_shared_memory < full_sm) {
    launch_cg_128_halfhalf_phase<InputTorus, params, PARTIALSM>(
        stream, grid1, thds, lwe_array_out, lut_vector, lwe_array_in,
        group1_bsk, join_buffer, global_accumulator, lwe_dimension,
        polynomial_size, iter_start_1, iter_end_1,
        halfhalf_params.base_log_1_mask, halfhalf_params.level_count_1_mask,
        halfhalf_params.base_log_1_body, halfhalf_params.level_count_1_body,
        max_z_global, true, false, d_mem, partial_dm, noise_reduction_type,
        partial_sm);

    launch_cg_128_halfhalf_phase<InputTorus, params, PARTIALSM>(
        stream, grid2, thds, lwe_array_out, lut_vector, lwe_array_in,
        group2_bsk, join_buffer, global_accumulator, lwe_dimension,
        polynomial_size, iter_start_2, iter_end_2,
        halfhalf_params.base_log_2_mask, halfhalf_params.level_count_2_mask,
        halfhalf_params.base_log_2_body, halfhalf_params.level_count_2_body,
        max_z_global, false, true, d_mem, partial_dm, noise_reduction_type,
        partial_sm);
  } else {
    uint64_t no_dm = 0;
    launch_cg_128_halfhalf_phase<InputTorus, params, FULLSM>(
        stream, grid1, thds, lwe_array_out, lut_vector, lwe_array_in,
        group1_bsk, join_buffer, global_accumulator, lwe_dimension,
        polynomial_size, iter_start_1, iter_end_1,
        halfhalf_params.base_log_1_mask, halfhalf_params.level_count_1_mask,
        halfhalf_params.base_log_1_body, halfhalf_params.level_count_1_body,
        max_z_global, true, false, d_mem, no_dm, noise_reduction_type, full_sm);

    launch_cg_128_halfhalf_phase<InputTorus, params, FULLSM>(
        stream, grid2, thds, lwe_array_out, lut_vector, lwe_array_in,
        group2_bsk, join_buffer, global_accumulator, lwe_dimension,
        polynomial_size, iter_start_2, iter_end_2,
        halfhalf_params.base_log_2_mask, halfhalf_params.level_count_2_mask,
        halfhalf_params.base_log_2_body, halfhalf_params.level_count_2_body,
        max_z_global, false, true, d_mem, no_dm, noise_reduction_type, full_sm);
  }
}

// ---------------------------------------------------------------------------
// Relaxed arithmetic, host-driven thread block cluster flavor of the halfhalf
// PBS-128.
//
// Counterpart of device_programmable_bootstrap_host_driven_tbc_128 in
// programmable_bootstrap_classic_128.cuh, whose comments describe the shape in
// full: the blind-rotation loop runs on the host, one launch per iteration; a
// cluster is (glwe_dimension + 1) blocks with no level dimension, so every
// block decomposes all of its own row's levels and publishes them; and the
// accumulator comes back from the GGSW product in registers.
//
// Host driving is what makes the flavor usable here at all. The single-launch
// cluster kernel cannot change decomposition parameters mid-rotation, whereas
// this one carries them as template arguments of a per-iteration launch, so the
// host swaps the key base pointer and the four decomposition scalars at the
// section boundary exactly as the DEFAULT step-one/step-two path does.
//
// Two things the vanilla flavor does not have to carry:
//   * within a section the k mask rows and the body row have different
//     (base_log, level_count) pairs, so the decomposer is instantiated twice
//     and the block picks on its own rank, which is uniform across its threads;
//   * shared memory is sized on level_mask, the larger of the two, so the body
//     block leaves its tail levels unwritten. Nothing reads them: a block
//     reading the body row stops at level_body.
// ---------------------------------------------------------------------------

// The halfhalf noise-squashing shape this flavor is compiled for. Like the
// vanilla flavor's PBS128_SNS_* constants, these are the only values it is
// instantiated at: the decomposition, the GGSW product and the cluster geometry
// are all compile-time constants, and the published Fourier buffers only fit
// two blocks per SM at N = 2048.
//
// Section 1 covers blind-rotation iterations [0, split_index) and section 2
// covers [split_index, input_lwe_dimension).
constexpr uint32_t PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE = 2048;
constexpr uint32_t PBS128_HALFHALF_SNS_GLWE_DIMENSION = 2;
constexpr uint32_t PBS128_HALFHALF_SNS_BASE_LOG_1_MASK = 32;
constexpr uint32_t PBS128_HALFHALF_SNS_LEVEL_1_MASK = 2;
constexpr uint32_t PBS128_HALFHALF_SNS_BASE_LOG_1_BODY = 31;
constexpr uint32_t PBS128_HALFHALF_SNS_LEVEL_1_BODY = 2;
constexpr uint32_t PBS128_HALFHALF_SNS_BASE_LOG_2_MASK = 24;
constexpr uint32_t PBS128_HALFHALF_SNS_LEVEL_2_MASK = 3;
constexpr uint32_t PBS128_HALFHALF_SNS_BASE_LOG_2_BODY = 31;
constexpr uint32_t PBS128_HALFHALF_SNS_LEVEL_2_BODY = 2;

// Shared memory is sized on the larger of the two sections' mask level counts,
// so that one support check covers both launches.
constexpr uint32_t PBS128_HALFHALF_SNS_MAX_LEVEL_MASK =
    PBS128_HALFHALF_SNS_LEVEL_1_MASK > PBS128_HALFHALF_SNS_LEVEL_2_MASK
        ? PBS128_HALFHALF_SNS_LEVEL_1_MASK
        : PBS128_HALFHALF_SNS_LEVEL_2_MASK;

// Judgement calls of the relaxed arithmetic's error model, kept next to the
// asserts that use them so a reviewer can argue with the numbers rather than
// reverse-engineer them.
//
// p, the precision the model credits the relaxed accumulation with. Measured
// against a __float128 reference (see the table in polynomial_math.cuh), the
// relaxed nine-term product keeps 88.3 correct bits where the fully
// renormalized double-double keeps 88.9. The model charges 6 bits against the
// 106-bit double-double mantissa instead of the measured 0.6, which leaves room
// for the forward and inverse transforms' own rounding on top of the
// accumulation's.
constexpr uint32_t RELAXED_FP128_MANTISSA_BITS = 106;
constexpr uint32_t RELAXED_FP128_PRECISION_CHARGE_BITS = 6;
constexpr uint32_t RELAXED_FP128_PRECISION_BITS =
    RELAXED_FP128_MANTISSA_BITS - RELAXED_FP128_PRECISION_CHARGE_BITS;

// The accepted error, in units of the torus LSB that add_to_torus_128 rounds
// to. A quarter leaves that rounding half an LSB of margin. It is a calibration
// against what is already in production, not a bound derived from scratch: the
// ordinary noise-squashing shape of the vanilla flavor (k = 2, l = 3,
// Bg = 2^24, 9 products) sits at 0.23 of an LSB, and the halfhalf families
// below all sit under it.
constexpr double RELAXED_FP128_MAX_ERROR_LSB = 0.25;

// 2^e as a double. The gadget exponents here reach 96, past what a shift on
// uint64_t can express, and std::ldexp is not constexpr, so this stays usable
// inside a static_assert.
constexpr double relaxed_two_pow_f64(int e) {
  return e == 0 ? 1.0
                : (e > 0 ? 2.0 * relaxed_two_pow_f64(e - 1)
                         : 0.5 * relaxed_two_pow_f64(e + 1));
}

// Square of the relaxed floating-point error of one blind-rotation iteration,
// in units of the torus LSB:
//
//   2^-p * (B^(l+1) / 2) * R * sqrt(4 / (3k))
//
// with B = 2^base_log, l the level count of the row's decomposition, R the
// number of Fourier-domain products accumulated into one output row and k the
// GLWE dimension. Squared because sqrt is not constexpr and both sides of the
// comparison are positive.
constexpr double relaxed_error_lsb_squared(uint32_t base_log,
                                           uint32_t level_count,
                                           uint32_t num_products,
                                           uint32_t glwe_dimension) {
  const double half_gadget_over_precision =
      relaxed_two_pow_f64(static_cast<int>(base_log * (level_count + 1)) - 1 -
                          static_cast<int>(RELAXED_FP128_PRECISION_BITS));
  const double scaled =
      half_gadget_over_precision * static_cast<double>(num_products);
  return scaled * scaled * 4.0 / (3.0 * static_cast<double>(glwe_dimension));
}

// R, per section. Every output row accumulates over every (row, level) pair of
// the GGSW: k mask rows at level_mask levels plus the body row at level_body.
// So R belongs to the section, and the mask and body decompositions of one
// section share it, differing only in (base_log, level_count).
constexpr uint32_t PBS128_HALFHALF_SNS_PRODUCTS_1 =
    PBS128_HALFHALF_SNS_GLWE_DIMENSION * PBS128_HALFHALF_SNS_LEVEL_1_MASK +
    PBS128_HALFHALF_SNS_LEVEL_1_BODY;
constexpr uint32_t PBS128_HALFHALF_SNS_PRODUCTS_2 =
    PBS128_HALFHALF_SNS_GLWE_DIMENSION * PBS128_HALFHALF_SNS_LEVEL_2_MASK +
    PBS128_HALFHALF_SNS_LEVEL_2_BODY;

// The error gate on every shape the flavor is instantiated at. It sits outside
// the sm_90 guard below on purpose: the kernel it protects is only compiled for
// compute capability 9.0, and a parameter change that broke the error budget
// would otherwise go unnoticed on every other architecture, CI included.
constexpr double RELAXED_FP128_MAX_ERROR_LSB_SQUARED =
    RELAXED_FP128_MAX_ERROR_LSB * RELAXED_FP128_MAX_ERROR_LSB;
static_assert(relaxed_error_lsb_squared(PBS128_HALFHALF_SNS_BASE_LOG_1_MASK,
                                        PBS128_HALFHALF_SNS_LEVEL_1_MASK,
                                        PBS128_HALFHALF_SNS_PRODUCTS_1,
                                        PBS128_HALFHALF_SNS_GLWE_DIMENSION) <
                  RELAXED_FP128_MAX_ERROR_LSB_SQUARED,
              "relaxed arithmetic: section 1 mask decomposition exceeds the "
              "accepted fraction of a torus LSB");
static_assert(relaxed_error_lsb_squared(PBS128_HALFHALF_SNS_BASE_LOG_1_BODY,
                                        PBS128_HALFHALF_SNS_LEVEL_1_BODY,
                                        PBS128_HALFHALF_SNS_PRODUCTS_1,
                                        PBS128_HALFHALF_SNS_GLWE_DIMENSION) <
                  RELAXED_FP128_MAX_ERROR_LSB_SQUARED,
              "relaxed arithmetic: section 1 body decomposition exceeds the "
              "accepted fraction of a torus LSB");
static_assert(relaxed_error_lsb_squared(PBS128_HALFHALF_SNS_BASE_LOG_2_MASK,
                                        PBS128_HALFHALF_SNS_LEVEL_2_MASK,
                                        PBS128_HALFHALF_SNS_PRODUCTS_2,
                                        PBS128_HALFHALF_SNS_GLWE_DIMENSION) <
                  RELAXED_FP128_MAX_ERROR_LSB_SQUARED,
              "relaxed arithmetic: section 2 mask decomposition exceeds the "
              "accepted fraction of a torus LSB");
static_assert(relaxed_error_lsb_squared(PBS128_HALFHALF_SNS_BASE_LOG_2_BODY,
                                        PBS128_HALFHALF_SNS_LEVEL_2_BODY,
                                        PBS128_HALFHALF_SNS_PRODUCTS_2,
                                        PBS128_HALFHALF_SNS_GLWE_DIMENSION) <
                  RELAXED_FP128_MAX_ERROR_LSB_SQUARED,
              "relaxed arithmetic: section 2 body decomposition exceeds the "
              "accepted fraction of a torus LSB");

inline bool is_halfhalf_noise_squashing_shape(CudaHalfhalfPbsParamsFFI p) {
  return p.polynomial_size == PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE &&
         p.glwe_dimension == PBS128_HALFHALF_SNS_GLWE_DIMENSION &&
         p.base_log_1_mask == PBS128_HALFHALF_SNS_BASE_LOG_1_MASK &&
         p.level_count_1_mask == PBS128_HALFHALF_SNS_LEVEL_1_MASK &&
         p.base_log_1_body == PBS128_HALFHALF_SNS_BASE_LOG_1_BODY &&
         p.level_count_1_body == PBS128_HALFHALF_SNS_LEVEL_1_BODY &&
         p.base_log_2_mask == PBS128_HALFHALF_SNS_BASE_LOG_2_MASK &&
         p.level_count_2_mask == PBS128_HALFHALF_SNS_LEVEL_2_MASK &&
         p.base_log_2_body == PBS128_HALFHALF_SNS_BASE_LOG_2_BODY &&
         p.level_count_2_body == PBS128_HALFHALF_SNS_LEVEL_2_BODY;
}

// Both entry points of the flavor take this, not just the one that launches.
// The scratch function sizes the accumulator from `p` while configuring kernels
// compiled for the constants above, so a shape it accepted and the launch path
// then refused would have already allocated a buffer of the wrong size.
inline void panic_unless_halfhalf_relaxed_shape(CudaHalfhalfPbsParamsFFI p) {
  PANIC_IF_FALSE(
      is_halfhalf_noise_squashing_shape(p) &&
          cuda_check_support_thread_block_clusters(),
      "Cuda error: the host-driven TBC implementation of the "
      "128-bit halfhalf programmable bootstrap only supports the "
      "noise-squashing parameters (N=%u, k=%u, section 1 mask "
      "l=%u Bg=2^%u body l=%u Bg=2^%u, section 2 mask l=%u Bg=2^%u "
      "body l=%u Bg=2^%u) on a GPU with distributed shared memory.",
      PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE, PBS128_HALFHALF_SNS_GLWE_DIMENSION,
      PBS128_HALFHALF_SNS_LEVEL_1_MASK, PBS128_HALFHALF_SNS_BASE_LOG_1_MASK,
      PBS128_HALFHALF_SNS_LEVEL_1_BODY, PBS128_HALFHALF_SNS_BASE_LOG_1_BODY,
      PBS128_HALFHALF_SNS_LEVEL_2_MASK, PBS128_HALFHALF_SNS_BASE_LOG_2_MASK,
      PBS128_HALFHALF_SNS_LEVEL_2_BODY, PBS128_HALFHALF_SNS_BASE_LOG_2_BODY);
}

#if CUDA_ARCH >= 900

// Counterpart of mul_ggsw_glwe_in_fourier_domain_128_host_driven_tbc for the
// compact halfhalf key layout. Two differences: the key is addressed through
// get_halfhalf_bsk_slice, and the number of published levels is a property of
// the row being read, level_mask for the k mask rows and level_body for the
// body row.
//
// That is also why the loops are nested row-outer / level-inner here and
// level-outer / row-inner in the vanilla flavor. Starting the row walk one past
// this block's own rank keeps the blocks off the same peer at the same time,
// which is the property the vanilla ordering was after.
//
// `fft` points at level 0 of this block's published buffers.
template <typename G, class params, uint32_t level_mask, uint32_t level_body,
          uint32_t glwe_dimension>
__device__ void mul_ggsw_glwe_in_fourier_domain_128_host_driven_tbc_halfhalf(
    double2 &acc_re_hi, double2 &acc_re_lo, double2 &acc_im_hi,
    double2 &acc_im_lo, double *fft, const double *__restrict__ group_bsk,
    uint32_t group_local_iteration, G &group, int this_block_rank) {
  constexpr int fourier_poly_size = params::degree / 2 * 4;

  acc_re_hi = make_double2(0.0, 0.0);
  acc_re_lo = make_double2(0.0, 0.0);
  acc_im_hi = make_double2(0.0, 0.0);
  acc_im_lo = make_double2(0.0, 0.0);

  const bool is_body_row = (this_block_rank == (int)glwe_dimension);
  const uint32_t my_level_count = is_body_row ? level_body : level_mask;

  // Phase 1 -- the products that read this block's OWN levels, which depend
  // only on the caller's __syncthreads() and not on the cluster barrier, so
  // their key loads are in flight while the peers finish their transforms.
  //
  // The first one opens the accumulator lanes with the cheap form. Level 0
  // exists for every row, mask or body, so peeling it is always legal.
  {
    auto bsk_poly =
        get_halfhalf_bsk_slice(group_bsk, (int)group_local_iteration,
                               this_block_rank, 0, params::degree,
                               glwe_dimension, level_mask, level_body) +
        (ptrdiff_t)this_block_rank * fourier_poly_size;
    polynomial_product_accumulate_in_fourier_domain_128_pairs_relaxed<
        params, /*opening=*/true>(acc_re_hi, acc_re_lo, acc_im_hi, acc_im_lo,
                                  fft, bsk_poly);
  }
  // Rolled: with the register accumulator live, unrolling costs more in
  // register pressure than it returns.
#pragma unroll 1
  for (uint32_t l = 1; l < my_level_count; l++) {
    auto bsk_poly =
        get_halfhalf_bsk_slice(group_bsk, (int)group_local_iteration,
                               this_block_rank, (int)l, params::degree,
                               glwe_dimension, level_mask, level_body) +
        (ptrdiff_t)this_block_rank * fourier_poly_size;
    polynomial_product_accumulate_in_fourier_domain_128_pairs_relaxed<
        params, /*opening=*/false>(acc_re_hi, acc_re_lo, acc_im_hi, acc_im_lo,
                                   fft + (ptrdiff_t)l * fourier_poly_size,
                                   bsk_poly);
  }

  // Every block has published all its levels; the peers' buffers are readable.
  group.sync();

  // Phase 2 -- the remaining products, reading the peers' shared memory.
#pragma unroll 1
  for (uint32_t j = 1; j < glwe_dimension + 1; j++) {
    const uint32_t idx = (j + this_block_rank) % (glwe_dimension + 1);
    const uint32_t peer_level_count =
        (idx == glwe_dimension) ? level_body : level_mask;
#pragma unroll 1
    for (uint32_t l = 0; l < peer_level_count; l++) {
      const double *peer =
          group.map_shared_rank(fft + (ptrdiff_t)l * fourier_poly_size, idx);
      auto bsk_poly =
          get_halfhalf_bsk_slice(group_bsk, (int)group_local_iteration,
                                 (int)idx, (int)l, params::degree,
                                 glwe_dimension, level_mask, level_body) +
          (ptrdiff_t)this_block_rank * fourier_poly_size;
      polynomial_product_accumulate_in_fourier_domain_128_pairs_relaxed<
          params, /*opening=*/false>(acc_re_hi, acc_re_lo, acc_im_hi, acc_im_lo,
                                     peer, bsk_poly);
    }
  }
  finalize_relaxed_fp128_pair(acc_re_hi, acc_re_lo);
  finalize_relaxed_fp128_pair(acc_im_hi, acc_im_lo);

  // The result stays in the caller's registers: the inverse transform consumes
  // it directly, and takes the barrier that frees the buffers itself.
}

// Rotation, full decomposition and the forward transform of every published
// level, at one row's (base_log, level_count). Factored out so the mask rows
// and the body row can each instantiate it at their own compile-time
// decomposition parameters; the caller selects on the block's rank, which is
// uniform across the block, so the __syncthreads() below are never divergent.
template <class params, uint32_t base_log, uint32_t level_count>
__device__ __forceinline__ void rotate_decompose_and_transform_128_halfhalf(
    double *accumulator_fft, const __uint128_t *accumulator, uint32_t a_hat) {
  // Perform ACC * (X^a_hat - 1), round, and decompose every level.
  rotate_and_decompose_all_levels_128<__uint128_t, params, base_log,
                                      level_count>(accumulator_fft, accumulator,
                                                   a_hat);

  // The relaxed forward fft has no entry barrier, so the levels are bracketed
  // once here and once after the loop.
  __syncthreads();
#pragma unroll 1
  for (uint32_t l = 0; l < level_count; l++) {
    negacyclic_forward_fft_f128_relaxed<HalfDegree<params>>(
        get_current_fft_level<params>(accumulator_fft, l));
  }
  __syncthreads();
}

template <typename InputTorus, class params, bool is_first_iter,
          bool is_last_iter, uint32_t base_log_mask, uint32_t level_mask,
          uint32_t base_log_body, uint32_t level_body, uint32_t glwe_dimension>
__global__ void __launch_bounds__(params::degree / params::opt, 2)
    device_programmable_bootstrap_host_driven_tbc_128_halfhalf(
        __uint128_t *lwe_array_out, const __uint128_t *__restrict__ lut_vector,
        const InputTorus *__restrict__ lwe_array_in,
        const double *__restrict__ group_bsk, __uint128_t *global_accumulator,
        uint32_t lwe_iteration, uint32_t group_local_iteration,
        uint32_t lwe_dimension, PBS_MS_REDUCTION_T noise_reduction_type) {
  constexpr int half_degree = params::degree / 2;
  constexpr int fourier_poly_size = half_degree * 4;
  constexpr int stride = params::degree / params::opt;
  constexpr auto log_modulus = params::log2_degree + 1;

  // The body block publishes into the allocation sized for a mask block, and
  // a block reading the body row stops at level_body, so a body row with more
  // levels than a mask row would both overflow the allocation and drop terms.
  // The Rust-facing entry point rejects that shape in validate_halfhalf_params.
  static_assert(level_mask >= level_body,
                "level_body must not exceed level_mask");
  // Level 1 is reused as the torus accumulator once the inverse transform has
  // taken the barrier that frees the published buffers.
  static_assert(level_mask >= 2,
                "the flavor needs at least two published Fourier buffers");
  // rotate_and_decompose_all_levels_128 writes the first level's digits to
  // Fourier level level_count - 1 BEFORE the barrier that frees the
  // accumulator, and that write is safe only because it lands above level 0.
  // A single-level decomposer would aim it at level 0, which aliases the
  // accumulator its own rotation pass is still reading at other coefficient
  // positions, so the body row needs two levels of its own, not just no more
  // than the mask row's.
  static_assert(level_body >= 2,
                "a single-level body decomposer would write into the "
                "accumulator it is still reading");

  cluster_group cluster = this_cluster();
  // The GLWE row this block owns, and what every index below means. It happens
  // to equal blockIdx.y only because the grid and the cluster have the same y
  // extent; the rank is the load-bearing quantity, so it is used throughout.
  const int this_block_rank = cluster.block_index().y;
  const bool is_body_row = (this_block_rank == (int)glwe_dimension);

  // level_mask Fourier buffers followed by the modulus-switch scratch. Level 0
  // doubles as the torus accumulator: the rotation reads it before any level
  // overwrites it.
  extern __shared__ int8_t sharedmem[];
  double *accumulator_fft = (double *)sharedmem;
  __uint128_t *accumulator = (__uint128_t *)sharedmem;
  InputTorus *ms_scratch =
      (InputTorus *)(sharedmem + (ptrdiff_t)level_mask * fourier_poly_size *
                                     sizeof(double));

  const InputTorus *block_lwe_array_in =
      &lwe_array_in[blockIdx.x * (lwe_dimension + 1)];
  __uint128_t *global_slice =
      global_accumulator +
      ((uint32_t)this_block_rank + blockIdx.x * (glwe_dimension + 1)) *
          params::degree;

  // Put "a" in [0, 2N[
  InputTorus a_hat = 0;
  modulus_switch<InputTorus>(block_lwe_array_in[lwe_iteration], a_hat,
                             log_modulus);

  if constexpr (is_first_iter) {
    // Put "b" in [0, 2N[ and rotate the LUT into the accumulator.
    InputTorus b_hat = 0;
    InputTorus correction = 0;
    if (noise_reduction_type == PBS_MS_REDUCTION_T::CENTERED) {
      correction =
          centered_binary_modulus_switch_body_correction_to_add_cooperative<
              InputTorus, stride / 32>(block_lwe_array_in, lwe_dimension,
                                       log_modulus, ms_scratch);
    }
    modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                   log_modulus);
    divide_by_monomial_negacyclic_inplace<__uint128_t, params::opt, stride>(
        accumulator, &lut_vector[this_block_rank * params::degree], b_hat,
        false);
    // The decompositions overwrite this buffer; the next launch reads it back.
    copy_polynomial_rolled<__uint128_t, params::opt, stride>(accumulator,
                                                             global_slice);
  } else {
    copy_polynomial_rolled<__uint128_t, params::opt, stride>(global_slice,
                                                             accumulator);
  }
  __syncthreads();

  // The two decomposers are mutually exclusive, so their register live ranges
  // do not overlap; only the code size doubles. The if constexpr collapses them
  // back to one when a section happens to give the mask rows and the body row
  // the same pair.
  if constexpr (base_log_mask == base_log_body && level_mask == level_body) {
    rotate_decompose_and_transform_128_halfhalf<params, base_log_mask,
                                                level_mask>(
        accumulator_fft, accumulator, (uint32_t)a_hat);
  } else if (is_body_row) {
    rotate_decompose_and_transform_128_halfhalf<params, base_log_body,
                                                level_body>(
        accumulator_fft, accumulator, (uint32_t)a_hat);
  } else {
    rotate_decompose_and_transform_128_halfhalf<params, base_log_mask,
                                                level_mask>(
        accumulator_fft, accumulator, (uint32_t)a_hat);
  }

  // Perform G^-1(ACC) * GGSW -> GLWE, reading the peers' published levels. The
  // result comes back in registers.
  double2 acc_re_hi, acc_re_lo, acc_im_hi, acc_im_lo;
  mul_ggsw_glwe_in_fourier_domain_128_host_driven_tbc_halfhalf<
      cluster_group, params, level_mask, level_body, glwe_dimension>(
      acc_re_hi, acc_re_lo, acc_im_hi, acc_im_lo, accumulator_fft, group_bsk,
      group_local_iteration, cluster, this_block_rank);

  // Consumes the accumulator straight from registers and takes the barrier that
  // frees the published levels partway through, once its register-only levels
  // are done.
  // The relaxed ifft does a cluster sync before using the shared mem. Level 0
  // receives the result.
  negacyclic_backward_fft_f128_relaxed<cluster_group, HalfDegree<params>>(
      accumulator_fft, acc_re_hi, acc_re_lo, acc_im_hi, acc_im_lo, cluster);

  // Level 1 is only free after that barrier, so the torus accumulator is loaded
  // here rather than alongside the transform.
  __uint128_t *torus =
      (__uint128_t *)get_current_fft_level<params>(accumulator_fft, 1);
  // No barrier needed: the copy and add_to_torus_128 touch the same four
  // positions in the same thread.
  copy_polynomial_rolled<__uint128_t, params::opt, stride>(global_slice, torus);
  // Level 0's four planes are half_degree apart.
  add_to_torus_128<__uint128_t, params>(
      accumulator_fft + 0 * half_degree, accumulator_fft + 1 * half_degree,
      accumulator_fft + 2 * half_degree, accumulator_fft + 3 * half_degree,
      torus);

  if constexpr (is_last_iter) {
    auto block_lwe_array_out =
        &lwe_array_out[blockIdx.x * (glwe_dimension * params::degree + 1) +
                       this_block_rank * params::degree];
    // Perform a sample extract
    if (is_body_row) {
      __syncthreads();
      sample_extract_body<__uint128_t, params>(block_lwe_array_out, torus, 0);
    } else {
      sample_extract_mask<__uint128_t, params>(block_lwe_array_out, torus);
    }
  } else {
    copy_polynomial<__uint128_t, params::opt, stride>(torus, global_slice);
  }
}

// Raises the shared-memory limit on one instantiation. The buffer sizing is the
// vanilla flavor's, read at this section's mask level count.
template <typename InputTorus, class params, bool is_first_iter,
          bool is_last_iter, uint32_t base_log_mask, uint32_t level_mask,
          uint32_t base_log_body, uint32_t level_body, uint32_t glwe_dimension>
__host__ void configure_one_host_driven_tbc_128_halfhalf() {
  check_cuda_error(cudaFuncSetAttribute(
      device_programmable_bootstrap_host_driven_tbc_128_halfhalf<
          InputTorus, params, is_first_iter, is_last_iter, base_log_mask,
          level_mask, base_log_body, level_body, glwe_dimension>,
      cudaFuncAttributeMaxDynamicSharedMemorySize,
      get_buffer_size_host_driven_tbc_128<params, InputTorus, level_mask>()));
}

// Four instantiations, not eight: validate_halfhalf_params enforces
// 0 < split_index < input_lwe_dimension, so neither section is empty, section 1
// always owns the first blind-rotation iteration and section 2 always owns the
// last, and no section ever needs both flags set.
template <typename InputTorus, class params>
__host__ void configure_host_driven_tbc_128_halfhalf() {
  configure_one_host_driven_tbc_128_halfhalf<
      InputTorus, params, true, false, PBS128_HALFHALF_SNS_BASE_LOG_1_MASK,
      PBS128_HALFHALF_SNS_LEVEL_1_MASK, PBS128_HALFHALF_SNS_BASE_LOG_1_BODY,
      PBS128_HALFHALF_SNS_LEVEL_1_BODY, PBS128_HALFHALF_SNS_GLWE_DIMENSION>();
  configure_one_host_driven_tbc_128_halfhalf<
      InputTorus, params, false, false, PBS128_HALFHALF_SNS_BASE_LOG_1_MASK,
      PBS128_HALFHALF_SNS_LEVEL_1_MASK, PBS128_HALFHALF_SNS_BASE_LOG_1_BODY,
      PBS128_HALFHALF_SNS_LEVEL_1_BODY, PBS128_HALFHALF_SNS_GLWE_DIMENSION>();
  configure_one_host_driven_tbc_128_halfhalf<
      InputTorus, params, false, false, PBS128_HALFHALF_SNS_BASE_LOG_2_MASK,
      PBS128_HALFHALF_SNS_LEVEL_2_MASK, PBS128_HALFHALF_SNS_BASE_LOG_2_BODY,
      PBS128_HALFHALF_SNS_LEVEL_2_BODY, PBS128_HALFHALF_SNS_GLWE_DIMENSION>();
  configure_one_host_driven_tbc_128_halfhalf<
      InputTorus, params, false, true, PBS128_HALFHALF_SNS_BASE_LOG_2_MASK,
      PBS128_HALFHALF_SNS_LEVEL_2_MASK, PBS128_HALFHALF_SNS_BASE_LOG_2_BODY,
      PBS128_HALFHALF_SNS_LEVEL_2_BODY, PBS128_HALFHALF_SNS_GLWE_DIMENSION>();
}

template <typename InputTorus, class params, bool is_first_iter,
          bool is_last_iter, uint32_t base_log_mask, uint32_t level_mask,
          uint32_t base_log_body, uint32_t level_body, uint32_t glwe_dimension>
__host__ void execute_host_driven_tbc_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *group_bsk, __uint128_t *global_accumulator,
    uint32_t input_lwe_ciphertext_count, uint32_t lwe_dimension,
    uint32_t lwe_iteration, uint32_t group_local_iteration,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  auto kernel = device_programmable_bootstrap_host_driven_tbc_128_halfhalf<
      InputTorus, params, is_first_iter, is_last_iter, base_log_mask,
      level_mask, base_log_body, level_body, glwe_dimension>;
  constexpr uint64_t full_sm =
      get_buffer_size_host_driven_tbc_128<params, InputTorus, level_mask>();

  cudaLaunchConfig_t config = {0};
  config.gridDim = dim3(input_lwe_ciphertext_count, glwe_dimension + 1, 1);
  config.blockDim = params::degree / params::opt;
  config.stream = stream;
  config.dynamicSmemBytes = full_sm;

  cudaLaunchAttribute attribute[2];
  attribute[0].id = cudaLaunchAttributeClusterDimension;
  attribute[0].val.clusterDim.x = 1;
  attribute[0].val.clusterDim.y = glwe_dimension + 1;
  attribute[0].val.clusterDim.z = 1;
  attribute[1].id = cudaLaunchAttributeClusterSchedulingPolicyPreference;
  attribute[1].val.clusterSchedulingPolicyPreference =
      cudaClusterSchedulingPolicyLoadBalancing;
  config.attrs = attribute;
  config.numAttrs = 2;

  check_cuda_error(cudaLaunchKernelEx(
      &config, kernel, lwe_array_out, lut_vector, lwe_array_in, group_bsk,
      global_accumulator, lwe_iteration, group_local_iteration, lwe_dimension,
      noise_reduction_type));
}

// Allocates the flavor's buffer and raises the shared-memory limit on all four
// instantiations. Mirrors scratch_programmable_bootstrap_host_driven_tbc_128.
template <typename InputTorus, typename params>
__host__ uint64_t scratch_programmable_bootstrap_host_driven_tbc_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> **buffer,
    CudaHalfhalfPbsParamsFFI p, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  static_assert(params::degree == PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE,
                "the host-driven TBC flavor is only compiled for the "
                "noise-squashing polynomial size");
  panic_unless_halfhalf_relaxed_shape(p);

  cuda_set_device(gpu_index);
  configure_host_driven_tbc_128_halfhalf<InputTorus, params>();

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL>(
      stream, gpu_index, p.input_lwe_dimension, p.glwe_dimension,
      p.polynomial_size, halfhalf_global_max_level(p),
      input_lwe_ciphertext_count, PBS_VARIANT::TBC_HOST_DRIVEN,
      allocate_gpu_memory, noise_reduction_type, size_tracker);
  return size_tracker;
}

// One launch per blind-rotation iteration, with the section that iteration
// belongs to selecting the instantiation and the key base pointer.
template <typename InputTorus, class params>
__host__ void host_programmable_bootstrap_host_driven_tbc_128_halfhalf(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *lwe_array_out,
    __uint128_t const *lut_vector, InputTorus const *lwe_array_in,
    double const *bootstrapping_key,
    pbs_buffer_128<InputTorus, PBS_TYPE::CLASSICAL> *buffer,
    CudaHalfhalfPbsParamsFFI p, uint32_t input_lwe_ciphertext_count) {

  constexpr uint32_t glwe_dimension = PBS128_HALFHALF_SNS_GLWE_DIMENSION;
  static_assert(params::degree == PBS128_HALFHALF_SNS_POLYNOMIAL_SIZE,
                "the host-driven TBC flavor is only compiled for the "
                "noise-squashing polynomial size");
  panic_unless_halfhalf_relaxed_shape(p);

  cuda_set_device(gpu_index);
  const uint32_t lwe_dimension = p.input_lwe_dimension;
  const uint32_t split = p.split_index;
  auto noise_reduction_type = buffer->noise_reduction_type;
  auto *global_accumulator = buffer->global_accumulator;
  // The scratch function already raised the shared-memory limit.

  double const *section_2_bsk =
      bootstrapping_key + halfhalf_section_1_bsk_doubles(p);

  for (uint32_t i = 0; i < lwe_dimension; i++) {
    if (i < split) {
      if (i == 0)
        execute_host_driven_tbc_128_halfhalf<
            InputTorus, params, true, false,
            PBS128_HALFHALF_SNS_BASE_LOG_1_MASK,
            PBS128_HALFHALF_SNS_LEVEL_1_MASK,
            PBS128_HALFHALF_SNS_BASE_LOG_1_BODY,
            PBS128_HALFHALF_SNS_LEVEL_1_BODY, glwe_dimension>(
            stream, gpu_index, lwe_array_out, lut_vector, lwe_array_in,
            bootstrapping_key, global_accumulator, input_lwe_ciphertext_count,
            lwe_dimension, i, i, noise_reduction_type);
      else
        execute_host_driven_tbc_128_halfhalf<
            InputTorus, params, false, false,
            PBS128_HALFHALF_SNS_BASE_LOG_1_MASK,
            PBS128_HALFHALF_SNS_LEVEL_1_MASK,
            PBS128_HALFHALF_SNS_BASE_LOG_1_BODY,
            PBS128_HALFHALF_SNS_LEVEL_1_BODY, glwe_dimension>(
            stream, gpu_index, lwe_array_out, lut_vector, lwe_array_in,
            bootstrapping_key, global_accumulator, input_lwe_ciphertext_count,
            lwe_dimension, i, i, noise_reduction_type);
    } else {
      const uint32_t group_local_iteration = i - split;
      if (i == lwe_dimension - 1)
        execute_host_driven_tbc_128_halfhalf<
            InputTorus, params, false, true,
            PBS128_HALFHALF_SNS_BASE_LOG_2_MASK,
            PBS128_HALFHALF_SNS_LEVEL_2_MASK,
            PBS128_HALFHALF_SNS_BASE_LOG_2_BODY,
            PBS128_HALFHALF_SNS_LEVEL_2_BODY, glwe_dimension>(
            stream, gpu_index, lwe_array_out, lut_vector, lwe_array_in,
            section_2_bsk, global_accumulator, input_lwe_ciphertext_count,
            lwe_dimension, i, group_local_iteration, noise_reduction_type);
      else
        execute_host_driven_tbc_128_halfhalf<
            InputTorus, params, false, false,
            PBS128_HALFHALF_SNS_BASE_LOG_2_MASK,
            PBS128_HALFHALF_SNS_LEVEL_2_MASK,
            PBS128_HALFHALF_SNS_BASE_LOG_2_BODY,
            PBS128_HALFHALF_SNS_LEVEL_2_BODY, glwe_dimension>(
            stream, gpu_index, lwe_array_out, lut_vector, lwe_array_in,
            section_2_bsk, global_accumulator, input_lwe_ciphertext_count,
            lwe_dimension, i, group_local_iteration, noise_reduction_type);
    }
  }
}

// The cluster is (glwe_dimension + 1) = 3 blocks, inside the portable limit of
// 8, so unlike the tbc flavor it needs no non-portable cluster-size opt-in.
template <typename InputTorus, class params>
__host__ bool
has_support_to_cuda_programmable_bootstrap_host_driven_tbc_128_halfhalf(
    CudaHalfhalfPbsParamsFFI p, uint32_t max_shared_memory) {
  if (!is_halfhalf_noise_squashing_shape(p))
    return false;
  if (!cuda_check_support_thread_block_clusters())
    return false;
  return max_shared_memory >=
         get_buffer_size_host_driven_tbc_128<
             params, InputTorus, PBS128_HALFHALF_SNS_MAX_LEVEL_MASK>();
}
#else
// Distributed shared memory is an sm_90 feature; without it the host-driven TBC
// flavor is not compiled and can never be selected.
template <typename InputTorus, class params>
__host__ bool
has_support_to_cuda_programmable_bootstrap_host_driven_tbc_128_halfhalf(
    CudaHalfhalfPbsParamsFFI, uint32_t) {
  return false;
}
#endif

#endif // CUDA_PBS_CUH_128_HALFHALF
