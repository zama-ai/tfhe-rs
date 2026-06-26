#ifndef CUDA_PBS_CUH
#define CUDA_PBS_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

// This macro is needed because in debug mode the compiler doesn't apply all
// optimizations
//  and the register count is higher, which can lead to launch bounds conflicts.
#ifdef __CUDACC_DEBUG__
#define SPECIALIZED_2_2_PARAMS_LAUNCH_BOUNDS
#else
#define SPECIALIZED_2_2_PARAMS_LAUNCH_BOUNDS __launch_bounds__(1024)
#endif

#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "device.h"
#include "fft/bnsmfft.cuh"
#include "fft/fft16x4x16.cuh"
#include "fft/twiddles.cuh"
#include "pbs/pbs_utilities.h"
#include "pbs/programmable_bootstrap.cuh"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial_math.cuh"
#include "types/complex/operations.cuh"

#ifdef __CUDACC_DEBUG__
#define SPECIALIZED_2_2_PARAMS_THROUGHPUT_LAUNCH_BOUNDS
#else
#define SPECIALIZED_2_2_PARAMS_THROUGHPUT_LAUNCH_BOUNDS                        \
  __launch_bounds__(128, 2)
#endif

// Helper function to get shared memory size for specialized 2_2_params kernel
template <typename Torus>
uint64_t get_buffer_size_full_sm_programmable_bootstrap_specialized_2_2_params(
    uint32_t polynomial_size) {
  return sizeof(Torus) * polynomial_size * 5;
}

// ─────────────────────────────────────────────────────────────────────────────
// SMEM layout for the FFT16x4x16-based mixprecision specialized kernel
//
//   [0 .. TW_SMEM_DOUBLES-1]                       tw_1024 (1920 doubles)
//   [FFT16x4x16_DUAL_COMPACT_TW_OFFSET ..]          compact_twiddles (102)
//   [FFT16x4x16_DUAL_XPOSE0_OFFSET ..]              xpose0 / comm0 / final_acc0
//   [FFT16x4x16_DUAL_XPOSE1_OFFSET ..]              xpose1 / comm1 / final_acc1
//   [FFT16x4x16_DUAL_BARRIER0_OFFSET ..]            barrier0 / barrier1 /
//   startup [FFT16x4x16_DUAL_TWIST_OFFSET ..]               twist half-table
//   (1026) [SMEM_ACC_OFFSET_DOUBLES ..]                    Torus (uint64)
//   running acc
//                                                    storage (2 × 2048 u64 →
//                                                    4096 doubles)
//
// The xpose region per y-group serves three roles in sequence:
//   1. transpose scratch during forward FFT;
//   2. cross-y communication buffer for the GGSW pointwise multiply
//      (other_fft_ptr in the GGSW helper);
//   3. final uint64 accumulator on the last loop iteration, read by
//      sample_extract_mask / sample_extract_body.
// All three uses are sequenced by __syncthreads / mbarrier syncs in the
// kernel; they never overlap in time.
// ─────────────────────────────────────────────────────────────────────────────
static constexpr int
    SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_ACC_OFFSET_DOUBLES =
        FFT16x4x16_DUAL_TWIST_OFFSET + 2 * 513;
// 2 y-groups × 2048 uint32 elements = 2048 doubles.
static constexpr int SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_ACC_DOUBLES =
    2048;
// Precalc-coefs sign table for the rotation step. Compact layout: one
// int8_t per `block_size`-position chunk, since the band sign is constant
// within each band (-1, +1, -1) and the band width equals `params::degree`,
// an exact multiple of `block_size`. With block_size = 64 and degree = 2048,
// each band collapses from 2048 entries to 32 entries.
//   3 × 32 bytes = 96 bytes = 12 doubles.
static constexpr int
    SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_PRECALC_OFFSET_DOUBLES =
        SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_ACC_OFFSET_DOUBLES +
        SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_ACC_DOUBLES;
static constexpr int SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_PRECALC_DOUBLES =
    12;
// Precomputed modswitched a_hat table (uint32 per LWE coefficient). The actual
// size depends on lwe_dimension and is appended at the end of the smem
// allocation; the offset is fixed at compile time.
static constexpr int
    SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_AHAT_OFFSET_DOUBLES =
        SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_PRECALC_OFFSET_DOUBLES +
        SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_PRECALC_DOUBLES;
// Fixed-region smem (everything except the a_hat table).
static constexpr size_t SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_FIXED_BYTES =
    static_cast<size_t>(
        SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_AHAT_OFFSET_DOUBLES) *
    sizeof(double);

template <typename Torus>
uint64_t
get_buffer_size_full_sm_programmable_bootstrap_specialized_2_2_params_throughput(
    uint32_t lwe_dimension) {
  // a_hat table: one uint32 per LWE coefficient, padded to 8 bytes so the
  // address arithmetic above stays aligned for any subsequent double-typed
  // region we might add later.
  uint64_t ahat_bytes =
      (static_cast<uint64_t>(lwe_dimension) * sizeof(uint32_t) + 7ull) &
      ~static_cast<uint64_t>(7);
  return SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_FIXED_BYTES + ahat_bytes;
}

// Residency budget for the mixprecision specialized kernel: 114 KiB/block keeps
// 2 blocks/SM on H100 (228 KiB carveout). Promoted from the old launch guard so
// the applicability predicate and the launch path share one value.
static constexpr uint64_t
    SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_BUDGET_BYTES = 114ull * 1024ull;

// True if the FFT16x4x16 mixprecision specialized kernel is applicable for the
// given parameters.
template <typename Torus>
__host__ bool specialized_2_2_use_throughput_oriented(
    uint32_t polynomial_size, uint32_t glwe_dimension, uint32_t level_count,
    uint32_t lwe_dimension, uint32_t max_shared_memory) {
  if (polynomial_size != 2048 || glwe_dimension != 1 || level_count != 1)
    return false;
  uint64_t mp_smem =
      get_buffer_size_full_sm_programmable_bootstrap_specialized_2_2_params_throughput<
          Torus>(lwe_dimension);
  return mp_smem <= SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_BUDGET_BYTES &&
         mp_smem <= static_cast<uint64_t>(max_shared_memory);
}

// We validate that the params and shared memory constraints for the specialized
// 2_2_params kernel are met.
template <typename Torus>
__host__ bool specialized_2_2_params_checker(uint32_t polynomial_size,
                                             uint32_t glwe_dimension,
                                             uint32_t level_count,
                                             uint32_t max_shared_memory) {
  uint64_t required_shared_memory =
      get_buffer_size_full_sm_programmable_bootstrap_specialized_2_2_params<
          Torus>(polynomial_size);
  return polynomial_size == 2048 && glwe_dimension == 1 && level_count == 1 &&
         max_shared_memory >= required_shared_memory;
}

// This condition is more restrictive to enable the specialized only on high-end
// GPUs, which are the ones that can really benefit from it due to its high
// double precision pressure.
template <typename Torus>
__host__ bool supports_specialized_2_2_params(uint32_t polynomial_size,
                                              uint32_t glwe_dimension,
                                              uint32_t level_count,
                                              uint32_t max_shared_memory) {
  cudaDeviceProp deviceProp;
  cudaGetDeviceProperties(&deviceProp, 0);
  check_cuda_error(cudaGetLastError());
  if (deviceProp.minor != 0 || deviceProp.major < 7) {
    return false;
  }
  return specialized_2_2_params_checker<Torus>(polynomial_size, glwe_dimension,
                                               level_count, max_shared_memory);
}

// Specialized 1-block kernel for 2_2_params (N=2048, k=1, l=1, log(B)=21-25,
// n=918)
template <typename Torus, class params, uint32_t base_log>
__global__ SPECIALIZED_2_2_PARAMS_LAUNCH_BOUNDS void
device_programmable_bootstrap_specialized_2_2_params(
    Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
    const Torus *__restrict__ lut_vector,
    const Torus *__restrict__ lut_vector_indexes,
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes,
    const double2 *__restrict__ bootstrapping_key, uint32_t lwe_dimension,
    uint32_t num_many_lut, uint32_t lut_stride,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  constexpr uint32_t level_count = 1;
  constexpr uint32_t polynomial_size = 2048;
  constexpr uint32_t glwe_dimension = 1;
  auto this_block_rank = threadIdx.y;
  extern __shared__ int8_t sharedmem[];

  // Shared Memory Layout:
  // We divide the shared memory in three sections to make sure the data is not
  // overlapped
  // |          GLWE0          |         GLWE1           | Common for both |
  // | acc block0 | fft block0 | acc block1 | fft block1 | shared twiddles |
  double2 *base_smem = (double2 *)sharedmem;
  double2 *accumulator_fft =
      base_smem + (polynomial_size / 2) * threadIdx.y * 2;
  double2 *shared_fft = accumulator_fft + polynomial_size / 2;
  double2 *shared_twiddles = base_smem + 2 * polynomial_size;

  Torus *accumulator = (Torus *)shared_fft;

  shared_twiddles[threadIdx.x + threadIdx.y * (params::degree / params::opt)] =
      negtwiddles[threadIdx.x + threadIdx.y * (params::degree / params::opt)];

  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];

  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  constexpr auto log_modulus = params::log2_degree + 1;
  Torus b_hat = 0;
  Torus correction = 0;
  if (noise_reduction_type == PBS_MS_REDUCTION_T::CENTERED) {
    correction = centered_binary_modulus_switch_body_correction_to_add(
        block_lwe_array_in, lwe_dimension, log_modulus);
  }
  modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                 log_modulus);

  Torus reg_acc_try[params::opt];
  divide_by_monomial_negacyclic_2_2_params_inplace<
      Torus, params::opt, params::degree / params::opt>(
      reg_acc_try, &block_lut_vector[threadIdx.y * params::degree], b_hat);

  for (int i = 0; i < params::opt; i++) {
    accumulator[threadIdx.x + i * (params::degree / params::opt)] =
        reg_acc_try[i];
  }

  Torus temp_a_hat = 0;
  for (int i = 0; i < lwe_dimension; i++) {
    constexpr int WARP_SIZE = 32;
    if (i % WARP_SIZE == 0 && (i + threadIdx.x % WARP_SIZE) < lwe_dimension) {
      modulus_switch(block_lwe_array_in[i + threadIdx.x % WARP_SIZE],
                     temp_a_hat, log_modulus);
    }
    Torus a_hat = __shfl_sync(0xFFFFFFFF, temp_a_hat, i % WARP_SIZE);

    __syncthreads();
    Torus reg_acc_rotated[params::opt];
    multiply_by_monomial_negacyclic_and_sub_polynomial_both_in_regs<
        Torus, params::opt, params::degree / params::opt>(
        accumulator, reg_acc_try, reg_acc_rotated, a_hat);

    init_decomposer_state_inplace_2_2_params<Torus, params::opt,
                                             params::degree / params::opt,
                                             base_log, level_count>(
        reg_acc_rotated);

    double2 fft_out_regs[params::opt / 2];
    decompose_and_compress_level_2_2_params<Torus, params, base_log>(
        fft_out_regs, reg_acc_rotated);
    NSMFFT_direct_2_2_params<HalfDegree<params>>(shared_fft, fft_out_regs,
                                                 shared_twiddles);
    int tid = threadIdx.x;
    for (Index k = 0; k < params::opt / 4; k++) {
      accumulator_fft[tid] = fft_out_regs[k];
      accumulator_fft[tid + params::degree / 4] =
          fft_out_regs[k + params::opt / 4];
      tid = tid + params::degree / params::opt;
    }

    double2 buffer_regs[params::opt / 2];
    mul_ggsw_glwe_in_fourier_domain_2_2_params_classical_no_tbc<
        params, polynomial_size, glwe_dimension, level_count>(
        accumulator_fft, fft_out_regs, buffer_regs, base_smem,
        bootstrapping_key, i, this_block_rank);

    NSMFFT_inverse_2_2_params<HalfDegree<params>>(shared_fft, buffer_regs,
                                                  shared_twiddles);
    add_to_torus_2_2_params_using_regs<Torus, params>(buffer_regs, reg_acc_try);

    for (int i = 0; i < params::opt; i++) {
      accumulator[threadIdx.x + i * (params::degree / params::opt)] =
          reg_acc_try[i];
    }
  }
  auto block_lwe_array_out =
      &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                         (glwe_dimension * polynomial_size + 1) +
                     threadIdx.y * polynomial_size];

  if (blockIdx.z == 0) {
    if (threadIdx.y < glwe_dimension) {
      sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);

      if (num_many_lut > 1) {
        for (int i = 1; i < num_many_lut; i++) {
          auto next_lwe_array_out =
              lwe_array_out +
              (i * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  threadIdx.y * polynomial_size];

          sample_extract_mask<Torus, params>(next_block_lwe_array_out,
                                             accumulator, 1, i * lut_stride);
        }
      }
    } else if (threadIdx.y == glwe_dimension) {
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
                                  threadIdx.y * polynomial_size];
          // No need to sync, it is already synchronized before the first
          // sample_extract_body call
          sample_extract_body<Torus, params>(next_block_lwe_array_out,
                                             accumulator, 0, i * lut_stride);
        }
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  FFT16x4x16-based of the specialized 2_2_params kernel that aims at improving
//  throughput
//
//  Block: (64, 2, 1) — threadIdx.y selects mask (0) / body (1). Each y-group
//  runs an independent 64-thread 1024-point FFT16x4x16. The running PBS
//  accumulator is kept in uint32 (registers + shared) and only upcast to
//  uint64 on the very last loop iteration, when the result is consumed by
//  sample_extract_{mask,body}.
//
//  Layout assumption: this kernel REQUIRES the bsk to have been produced by
//  batch_FFT16x4x16_classical_specialized so that bsk[tid + i*64] holds the
//  bit-reversed frequency Â_bsk[d_rev16(i)*64 + tid] — matching the
//  accumulator's FFT16x4x16 output.
//  It is tuned for H100 executed exploiting at maximum shared memory of
//  registers of that architecture.
// ─────────────────────────────────────────────────────────────────────────────
template <typename Torus, class params, uint32_t base_log>
__global__ SPECIALIZED_2_2_PARAMS_THROUGHPUT_LAUNCH_BOUNDS void
device_programmable_bootstrap_specialized_2_2_params_throughput(
    Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
    const Torus *__restrict__ lut_vector,
    const Torus *__restrict__ lut_vector_indexes,
    const Torus *__restrict__ lwe_array_in,
    const Torus *__restrict__ lwe_input_indexes,
    const double2 *__restrict__ bootstrapping_key, uint32_t lwe_dimension,
    uint32_t num_many_lut, uint32_t lut_stride,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  constexpr uint32_t level_count = 1;
  constexpr uint32_t polynomial_size = 2048;
  constexpr uint32_t glwe_dimension = 1;
  const int fft_id = threadIdx.y;

  extern __shared__ int8_t sharedmem[];
  double *smem = reinterpret_cast<double *>(sharedmem);

  // FFT pointer base & per-y scratch
  const double2 *tw_shared = reinterpret_cast<const double2 *>(smem);
  const double *compact_twiddles = smem + FFT16x4x16_DUAL_COMPACT_TW_OFFSET;
  double *smem_xpose = smem + (fft_id == 0 ? FFT16x4x16_DUAL_XPOSE0_OFFSET
                                           : FFT16x4x16_DUAL_XPOSE1_OFFSET);
  // PONG buffer for the fwd-FFT ping-pong path (eliminates 2 mbarrier_syncs per
  // fwd call). PING is `smem_xpose` above; PONG is the symmetric extra slot.
  double *smem_xpose_pong =
      smem + (fft_id == 0 ? FFT16x4x16_DUAL_XPOSE0_PONG_OFFSET
                          : FFT16x4x16_DUAL_XPOSE1_PONG_OFFSET);
  // Swapped pair for the IFFT path: y=0 uses XPOSE1+pong, y=1 uses XPOSE0+pong.
  // The swap makes the IFFT writes disjoint from the OTHER y-group's GGSW
  // reads of `other_fft_ptr`, which lets us drop the pre-IFFT block-wide
  // __syncthreads. `smem_xpose_inv` aliases the bytes of `other_fft_ptr` but
  // typed as double* for the inverse-core helper signature.
  double *smem_xpose_inv = smem + (fft_id == 0 ? FFT16x4x16_DUAL_XPOSE1_OFFSET
                                               : FFT16x4x16_DUAL_XPOSE0_OFFSET);
  double *smem_xpose_inv_pong =
      smem + (fft_id == 0 ? FFT16x4x16_DUAL_XPOSE1_PONG_OFFSET
                          : FFT16x4x16_DUAL_XPOSE0_PONG_OFFSET);
  double2 *smem_comm = reinterpret_cast<double2 *>(smem_xpose);
  double2 *other_fft_ptr = reinterpret_cast<double2 *>(
      smem + (fft_id == 0 ? FFT16x4x16_DUAL_XPOSE1_OFFSET
                          : FFT16x4x16_DUAL_XPOSE0_OFFSET));

  // Fixed home for the final uint64 accumulator, independent of the per-iter
  // fwd/inv buffer swap below. After the last iteration's __syncthreads all
  // xpose buffers are free, so the result deterministically lands in
  // xpose0/xpose1 and sample_extract reads it back from the same place.
  Torus *final_accumulator = reinterpret_cast<Torus *>(
      smem + (fft_id == 0 ? FFT16x4x16_DUAL_XPOSE0_OFFSET
                          : FFT16x4x16_DUAL_XPOSE1_OFFSET));

  FFT16x4x16MBarrierStorage *barrier =
      fft16x4x16_dual_mbarrier_storage(smem, fft_id);
  FFT16x4x16MBarrierStorage *startup_barrier =
      fft16x4x16_dual_startup_mbarrier_storage(smem);

  double2 *smem_twist =
      reinterpret_cast<double2 *>(smem + FFT16x4x16_DUAL_TWIST_OFFSET);

  // Per-y uint32 accumulator slice (2048 elements per y-group)
  uint32_t *shared_accumulator_all = reinterpret_cast<uint32_t *>(
      smem + SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_ACC_OFFSET_DOUBLES);
  uint32_t *shared_accumulator =
      shared_accumulator_all + fft_id * polynomial_size;

  // Precalc-coefs sign table (compact): 3 bands of 32 int8_t = [-1, +1, -1],
  // one entry per 64-position chunk. Filled once cooperatively below and
  // indexed per iteration with `precalc_coefs + base_chunk`, where
  // `base_chunk = (jump + threadIdx.x) >> 6`. Because the band width (=
  // params::degree = 2048) is a multiple of block_size (= 64), the band of
  // every position in a 64-chunk is the same as the band of the chunk's
  // start, so the per-position resolution of the old 6144-byte table is
  // unnecessary.
  int8_t *precalc_coefs = reinterpret_cast<int8_t *>(
      smem + SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_PRECALC_OFFSET_DOUBLES);

  // Precomputed modswitched a_hat table — one uint32 per LWE coefficient.
  // Filled cooperatively below; read once per PBS iteration as a broadcast
  // load. Replaces the per-iter warp-aligned conditional modswitch + shfl_sync
  // pattern of the legacy classic kernel, freeing the compiler from the
  // per-iter dependency on temp_a_hat.
  uint32_t *a_hat_table = reinterpret_cast<uint32_t *>(
      smem + SPECIALIZED_2_2_PARAMS_MIXPRECISION_SMEM_AHAT_OFFSET_DOUBLES);

  // Initialise mbarriers (no-ops on pre-SM90); named-barrier publish to 128 t.
  if (threadIdx.x == 0 && threadIdx.y == 0) {
    fft16x4x16_mbarrier_init_raw(fft16x4x16_dual_mbarrier_storage(smem, 0), 2u);
    fft16x4x16_mbarrier_init_raw(fft16x4x16_dual_mbarrier_storage(smem, 1), 2u);
    fft16x4x16_mbarrier_init_raw(startup_barrier, 4u); // 4 warps in the block
  }
  fft16x4x16_named_barrier_sync(15u, 128u);

  // Cooperative twiddle / compact_twiddles load (128-thread loader).
  fft16x4x16_load_shared_twiddles_128t(smem);
  // Startup sync is block-wide (all 4 warps) → plain __syncthreads() (bar.sync
  // 0) replacing the mbarrier spin. Per-group FFT syncs use named ids 1/2 (see
  // sync_coupled_warps); the mbarrier storage/init above is now unused
  // but left in place so the smem layout is unchanged for the A/B.
  __syncthreads();

  // Preload the 3 compact 4×4 twiddles into per-thread registers (one-time
  // load from smem `compact_twiddles`). Lets the FFT cores use the
  // _compact_regs variants below, which skip the per-iter smem fetch +
  // warp-shuffle + lane<16 branch inside `mul_twiddles_4x4`.
  const int lo4 = threadIdx.x & 15;
  double2 compact_w1 =
      make_double2(compact_twiddles[lo4], compact_twiddles[3 * 17 + lo4]);
  double2 compact_w2 = make_double2(compact_twiddles[17 + lo4],
                                    compact_twiddles[3 * 17 + 17 + lo4]);
  double2 compact_w3 = make_double2(compact_twiddles[34 + lo4],
                                    compact_twiddles[3 * 17 + 34 + lo4]);

  // Negacyclic twist half-table (513 entries → 1026 doubles).
  const int linear_tid = threadIdx.x + threadIdx.y * 64;
  for (int idx = linear_tid; idx < 512; idx += 128)
    smem_twist[idx] = twisting_twiddles[idx];
  if (linear_tid == 0)
    smem_twist[512] = twisting_twiddles[512];
  __syncthreads();

  // Per-block input & LUT slices
  const Torus *block_lwe_array_in =
      &lwe_array_in[lwe_input_indexes[blockIdx.x] * (lwe_dimension + 1)];
  const Torus *block_lut_vector =
      &lut_vector[lut_vector_indexes[blockIdx.x] * params::degree *
                  (glwe_dimension + 1)];

  constexpr auto log_modulus = params::log2_degree + 1;
  Torus b_hat = 0;
  Torus correction = 0;
  if (noise_reduction_type == PBS_MS_REDUCTION_T::CENTERED) {
    // Block-cooperative reduction. We borrow the head of
    // shared_accumulator_all as a 2 * num_warps * sizeof(Torus) = 64-byte
    // scratch: it is 8-byte aligned (the doubles offset is a multiple of 8)
    // and is not written until after this call returns.
    Torus *ms_scratch = reinterpret_cast<Torus *>(shared_accumulator_all);
    correction =
        centered_binary_modulus_switch_body_correction_to_add_cooperative<
            Torus, /*num_warps=*/4>(block_lwe_array_in, lwe_dimension,
                                    log_modulus, ms_scratch);
  }
  modulus_switch(block_lwe_array_in[lwe_dimension] + correction, b_hat,
                 log_modulus);

  uint32_t reg_acc_running[params::opt];
  // The difference with previous functions is that this stores the accumulator
  //  in 32-bit.
  divide_by_monomial_negacyclic_2_2_params_throughput<
      Torus, uint32_t, params::opt, params::degree / params::opt>(
      reg_acc_running, &block_lut_vector[threadIdx.y * params::degree], b_hat);

#pragma unroll
  for (int i = 0; i < params::opt; i++) {
    shared_accumulator[threadIdx.x + i * (params::degree / params::opt)] =
        reg_acc_running[i];
  }

  // Because our thread block is 2D, we need to use linear_tid to make a
  // cooperative calculation of modswitch and the precalc coefs. Keep in mind
  // that both glwe use the same rotation so modswitch is reusable. The same
  // block also initialises precalc_coefs: 3 concatenated bands of 32 int8_t
  // with values [-1, +1, -1] (one entry per 64-position chunk). Used by the
  // compact precalc rotation helper to read the negacyclic sign each PBS
  // iteration.
  {
    const int linear_tid = threadIdx.x + threadIdx.y * 64;
    for (int idx = linear_tid; idx < static_cast<int>(lwe_dimension);
         idx += 128) {
      Torus a_hat_full = 0;
      modulus_switch(block_lwe_array_in[idx], a_hat_full, log_modulus);
      a_hat_table[idx] = static_cast<uint32_t>(a_hat_full);
    }
    // 96-byte sign table: lanes < 32 of the block write one byte per band.
    if (linear_tid < 32) {
      precalc_coefs[linear_tid + 0] = -1;
      precalc_coefs[linear_tid + 32] = 1;
      precalc_coefs[linear_tid + 64] = -1;
    }
  }
  // We need to sync to make sure all writes to shared memory happened before
  // starting the loop
  __syncthreads();

  // We preload some of the twiddles to registers to squeeze all possible
  // performance on the fft Experimentally 4 registers was the best balance to
  // avoid the register growth affects the optimizations in other regions.
  const double2 tw_cache_r7 = tw_shared[7 * 64 + threadIdx.x];
  const double2 tw_cache_r3 = tw_shared[3 * 64 + threadIdx.x];
  const double2 tw_cache_r11 = tw_shared[11 * 64 + threadIdx.x];
  const double2 tw_cache_r1 = tw_shared[1 * 64 + threadIdx.x];

  // ── Main PBS loop ──────────────────────────────────────────────────────────
  for (int i = 0; i < lwe_dimension; i++) {
    // Syncs only the warps participating on each fft
    // Effectively means that only syncs threads with the same threadIdx.y
    // that only takes values 0 or 1. So it syncs groups of 64 threads.
    sync_coupled_warps();
    // Broadcast load: all 128 threads read the same slot of the precomputed
    // table — single smem transaction, no warp shuffle, no conditional.
    uint32_t a_hat = a_hat_table[i];

    // Monomial mul using a compact precalculated table as in keybundle
    const uint32_t full_cycles = a_hat >> params::log2_degree;
    const uint32_t remainder = a_hat & (params::degree - 1);
    const uint32_t jump =
        full_cycles * params::degree + params::degree - remainder;
    constexpr uint32_t log2_block_size =
        params::log2_degree - log2_int(params::opt);
    const uint32_t base_chunk = (jump + threadIdx.x) >> log2_block_size;
    uint32_t reg_rotated[params::opt];
    multiply_by_monomial_negacyclic_and_sub_polynomial_both_in_regs_precalc_compact<
        uint32_t, params::opt, params::degree / params::opt>(
        shared_accumulator, reg_acc_running, reg_rotated,
        precalc_coefs + base_chunk, a_hat);

    // Quantize the rotated value to baselog balanced form for the gadget.
    init_decomposer_state_inplace_2_2_params<uint32_t, params::opt,
                                             params::degree / params::opt,
                                             base_log, level_count>(
        reg_rotated);

    // In 2_2 params we can make a simplified decomposition, since the
    // init decomposition already does generates the final version.
    double2 fft_out_regs[params::opt / 2];
    decompose_balanced_simplified<params>(fft_out_regs, reg_rotated);

    FFT16x4x16_fwd_optimized_for_pbs(
        fft_out_regs, tw_shared, smem_twist, smem_xpose, smem_xpose_pong,
        compact_w1, compact_w2, compact_w3, barrier, tw_cache_r7, tw_cache_r3,
        tw_cache_r11, tw_cache_r1);

    // Copy fft from regs to shared memory to be used in the external product
#pragma unroll
    for (int j = 0; j < params::opt / 2; j++)
      smem_comm[threadIdx.x + j * 64] = fft_out_regs[j];

    // Only full synchronization needed per iteration, mirrors the cluster sync
    // we had in the tbc.
    __syncthreads();

    double2 buffer_regs[params::opt / 2];
    mul_ggsw_glwe_in_fourier_domain_2_2_params_fused_no_tbc<
        params, polynomial_size, glwe_dimension, level_count>(
        nullptr, fft_out_regs, buffer_regs, other_fft_ptr, bootstrapping_key,
        i);

    // The inverse FFT expects natural-order input → unscramble once here.
    // This is resolved at compilation time so it is free
    double2 buffer_natural[params::opt / 2];
#pragma unroll
    for (int j = 0; j < params::opt / 2; j++)
      buffer_natural[j] = buffer_regs[bitreversal16(j)];

    FFT16x4x16_inv_optimized_for_pbs(
        buffer_natural, tw_shared, smem_twist, smem_xpose_inv_pong,
        smem_xpose_inv, compact_w1, compact_w2, compact_w3, barrier,
        tw_cache_r7, tw_cache_r3, tw_cache_r11, tw_cache_r1);

    // Last iteration requires the final accumulation in 64-bit precision.
    bool is_last_iter = (i + 1 >= lwe_dimension);

    if (is_last_iter) {
      // We store the output accumulation into shared memory, we are reusing
      // regions so we must sync to make sure no thread is reading from it
      // anymore.
      __syncthreads();
      constexpr int upshift = sizeof(Torus) * 8 - 32;
#pragma unroll
      for (int j = 0; j < params::opt / 2; j++) {
        Torus torus_real = 0, torus_imag = 0;
        typecast_double_round_to_torus<Torus>(buffer_natural[j].x, torus_real);
        typecast_double_round_to_torus<Torus>(buffer_natural[j].y, torus_imag);
        int k = bitreversal16(j);
        Torus prev_real_high = static_cast<Torus>(reg_acc_running[k])
                               << upshift;
        Torus prev_imag_high =
            static_cast<Torus>(reg_acc_running[k + params::opt / 2]) << upshift;
        int pos_real = threadIdx.x + k * (params::degree / params::opt);
        int pos_imag = pos_real + params::degree / 2;
        final_accumulator[pos_real] = prev_real_high + torus_real;
        final_accumulator[pos_imag] = prev_imag_high + torus_imag;
      }
    } else {
      // For all intermediate steps we round the accumulator to uint32_t
      // With 2_2 params we only need base_log bits + round
      // and baselog + round is < 32
#pragma unroll
      for (int j = 0; j < params::opt / 2; j++) {
        uint32_t torus_real = 0, torus_imag = 0;
        typecast_double_round_to_torus<uint32_t>(buffer_natural[j].x,
                                                 torus_real);
        typecast_double_round_to_torus<uint32_t>(buffer_natural[j].y,
                                                 torus_imag);
        int k = bitreversal16(j);
        reg_acc_running[k] += torus_real;
        reg_acc_running[k + params::opt / 2] += torus_imag;
      }
#pragma unroll
      for (int k = 0; k < params::opt; k++) {
        shared_accumulator[threadIdx.x + k * (params::degree / params::opt)] =
            reg_acc_running[k];
      }
    }

    // At the end of the iteration we need to swap buffers to use a ping pong
    // strategy that save us extra syncs.
    // Swap fwd <-> inv buffer roles for the next iteration so its forward FFT
    // writes the set THIS y-group's inverse FFT just wrote (within-y WAW),
    // which keeps the top-of-loop barrier a 64-thread named sync.
    double *tmp_xpose = smem_xpose;
    smem_xpose = smem_xpose_inv;
    smem_xpose_inv = tmp_xpose;
    double *tmp_pong = smem_xpose_pong;
    smem_xpose_pong = smem_xpose_inv_pong;
    smem_xpose_inv_pong = tmp_pong;
    smem_comm = reinterpret_cast<double2 *>(smem_xpose);
    other_fft_ptr = reinterpret_cast<double2 *>(smem_xpose_inv);
  }

  // Sample extraction follows the same logic than other pbs
  if (blockIdx.z == 0) {
    auto block_lwe_array_out =
        &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                           (glwe_dimension * polynomial_size + 1) +
                       threadIdx.y * polynomial_size];

    if (threadIdx.y < glwe_dimension) {
      sample_extract_mask<Torus, params>(block_lwe_array_out,
                                         final_accumulator);

      if (num_many_lut > 1) {
        for (int n = 1; n < num_many_lut; n++) {
          auto next_lwe_array_out =
              lwe_array_out +
              (n * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  threadIdx.y * polynomial_size];
          sample_extract_mask<Torus, params>(
              next_block_lwe_array_out, final_accumulator, 1, n * lut_stride);
        }
      }
    } else if (threadIdx.y == glwe_dimension) {
      __syncthreads();
      sample_extract_body<Torus, params>(block_lwe_array_out, final_accumulator,
                                         0);

      if (num_many_lut > 1) {
        for (int n = 1; n < num_many_lut; n++) {
          auto next_lwe_array_out =
              lwe_array_out +
              (n * gridDim.x * (glwe_dimension * polynomial_size + 1));
          auto next_block_lwe_array_out =
              &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                      (glwe_dimension * polynomial_size + 1) +
                                  threadIdx.y * polynomial_size];
          sample_extract_body<Torus, params>(
              next_block_lwe_array_out, final_accumulator, 0, n * lut_stride);
        }
      }
    }
  }
}

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
    device_mem = safe_mul(full_dm, (size_t)input_lwe_ciphertext_count,
                          (size_t)level_count, (size_t)(glwe_dimension + 1));
  } else if (max_shared_memory < full_sm_step_two) {
    device_mem = safe_mul(partial_dm_step_two + safe_mul(partial_dm_step_one,
                                                         (size_t)level_count),
                          (size_t)input_lwe_ciphertext_count,
                          (size_t)(glwe_dimension + 1));
  } else if (max_shared_memory < full_sm_step_one) {
    device_mem =
        safe_mul(partial_dm_step_one, (size_t)input_lwe_ciphertext_count,
                 (size_t)level_count, (size_t)(glwe_dimension + 1));
  }
  // Otherwise, both kernels run all in shared memory
  uint64_t buffer_size =
      device_mem +
      // global_join_buffer
      safe_mul_sizeof<double2>(
          safe_mul((size_t)(glwe_dimension + 1), (size_t)level_count),
          (size_t)input_lwe_ciphertext_count, (size_t)(polynomial_size / 2)) +
      // global_accumulator
      safe_mul_sizeof<Torus>((size_t)(glwe_dimension + 1),
                             (size_t)input_lwe_ciphertext_count,
                             (size_t)polynomial_size);
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

enum class ClassicalLaunchMode {
  AUTO,
  SPECIALIZED_2_2,
};

template <typename Torus, class params>
__host__ void host_programmable_bootstrap_with_mode(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *pbs_buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t num_many_lut, uint32_t lut_stride,
    ClassicalLaunchMode launch_mode) {
  cuda_set_device(gpu_index);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  bool use_specialized;
  if (launch_mode == ClassicalLaunchMode::SPECIALIZED_2_2) {
    // This is a more relaxed constraint that just makes sure we have the right
    // params and enough shared memory. It is used in the test.
    use_specialized = specialized_2_2_params_checker<uint64_t>(
        polynomial_size, glwe_dimension, level_count,
        cuda_get_max_shared_memory(gpu_index));
    PANIC_IF_FALSE(
        use_specialized,
        "Cuda error (classical PBS): forced specialized 2_2 requires "
        "(N=2048, level_count=1, glwe_dimension=1, sufficient shared memory).");
  } else {
    // In auto mode we also check the compute capability.
    use_specialized = supports_specialized_2_2_params<Torus>(
        polynomial_size, glwe_dimension, level_count, max_shared_memory);
  }

  if (use_specialized) {
    auto noise_reduction_type = pbs_buffer->noise_reduction_type;

    // Kept the old specialized version as fallback, default is throughput
    // oriented version.
    if (specialized_2_2_use_throughput_oriented<Torus>(
            polynomial_size, glwe_dimension, level_count, lwe_dimension,
            max_shared_memory)) {
      using mp_params = AccumulatorDegree<2048>;
      int mp_thds = polynomial_size / mp_params::opt; // 64
      dim3 grid(input_lwe_ciphertext_count, 1, level_count);
      dim3 mp_block(mp_thds, glwe_dimension + 1, 1); // (64, 2, 1) = 128 threads
      uint64_t mp_smem =
          get_buffer_size_full_sm_programmable_bootstrap_specialized_2_2_params_throughput<
              Torus>(lwe_dimension);

      // 2-block-per-SM residency guard (H100 with
      // cudaSharedmemCarveoutMaxShared = 228 KiB → 114 KiB per block at
      // occupancy 2). With the fwd-FFT ping-pong PONG buffers in the smem
      // layout, lwe_dimension ≲ 1370 fits. Larger params would silently drop to
      // 1 block/SM — panic instead so the regression is visible.
      if (mp_smem > 114ull * 1024ull) {
        PANIC("specialized 2_2 mixprecision smem exceeds 2-block-per-SM "
              "residency budget (114 KiB); shrink PONG or revisit layout");
      }

#define LAUNCH_SPECIALIZED_2_2_MIXPRECISION(BL)                                \
  do {                                                                         \
    check_cuda_error(cudaFuncSetAttribute(                                     \
        device_programmable_bootstrap_specialized_2_2_params_throughput<       \
            Torus, mp_params, BL>,                                             \
        cudaFuncAttributeMaxDynamicSharedMemorySize, mp_smem));                \
    check_cuda_error(cudaFuncSetAttribute(                                     \
        device_programmable_bootstrap_specialized_2_2_params_throughput<       \
            Torus, mp_params, BL>,                                             \
        cudaFuncAttributePreferredSharedMemoryCarveout,                        \
        cudaSharedmemCarveoutMaxShared));                                      \
    check_cuda_error(cudaFuncSetCacheConfig(                                   \
        device_programmable_bootstrap_specialized_2_2_params_throughput<       \
            Torus, mp_params, BL>,                                             \
        cudaFuncCachePreferShared));                                           \
    check_cuda_error(cudaGetLastError());                                      \
    device_programmable_bootstrap_specialized_2_2_params_throughput<           \
        Torus, mp_params, BL><<<grid, mp_block, mp_smem, stream>>>(            \
        lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,     \
        lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,     \
        num_many_lut, lut_stride, noise_reduction_type);                       \
    check_cuda_error(cudaGetLastError());                                      \
  } while (0)

      switch (base_log) {
      case 21:
        LAUNCH_SPECIALIZED_2_2_MIXPRECISION(21);
        break;
      case 22:
        LAUNCH_SPECIALIZED_2_2_MIXPRECISION(22);
        break;
      case 23:
        LAUNCH_SPECIALIZED_2_2_MIXPRECISION(23);
        break;
      case 24:
        LAUNCH_SPECIALIZED_2_2_MIXPRECISION(24);
        break;
      case 25:
        LAUNCH_SPECIALIZED_2_2_MIXPRECISION(25);
        break;
      default:
        PANIC("Unsupported base_log value for specialized 2_2_params "
              "mixprecision kernel");
      }
#undef LAUNCH_SPECIALIZED_2_2_MIXPRECISION
      return;
    }

    int thds = polynomial_size / params::opt;
    dim3 grid(input_lwe_ciphertext_count, 1, level_count);
    dim3 new_block(thds, glwe_dimension + 1, 1);
    uint64_t full_sm_specialized =
        get_buffer_size_full_sm_programmable_bootstrap_specialized_2_2_params<
            Torus>(polynomial_size);

    // Switch on base_log to select the correct template instantiation
    switch (base_log) {
    case 21:
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               21>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_specialized));
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               21>,
          cudaFuncAttributePreferredSharedMemoryCarveout,
          cudaSharedmemCarveoutMaxShared));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               21>,
          cudaFuncCachePreferShared));
      check_cuda_error(cudaGetLastError());
      device_programmable_bootstrap_specialized_2_2_params<Torus, params, 21>
          <<<grid, new_block, full_sm_specialized, stream>>>(
              lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
              lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
              num_many_lut, lut_stride, noise_reduction_type);
      check_cuda_error(cudaGetLastError());
      break;
    case 22:
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               22>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_specialized));
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               22>,
          cudaFuncAttributePreferredSharedMemoryCarveout,
          cudaSharedmemCarveoutMaxShared));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               22>,
          cudaFuncCachePreferShared));
      check_cuda_error(cudaGetLastError());
      device_programmable_bootstrap_specialized_2_2_params<Torus, params, 22>
          <<<grid, new_block, full_sm_specialized, stream>>>(
              lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
              lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
              num_many_lut, lut_stride, noise_reduction_type);
      check_cuda_error(cudaGetLastError());
      break;
    case 23:
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               23>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_specialized));
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               23>,
          cudaFuncAttributePreferredSharedMemoryCarveout,
          cudaSharedmemCarveoutMaxShared));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               23>,
          cudaFuncCachePreferShared));
      check_cuda_error(cudaGetLastError());
      device_programmable_bootstrap_specialized_2_2_params<Torus, params, 23>
          <<<grid, new_block, full_sm_specialized, stream>>>(
              lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
              lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
              num_many_lut, lut_stride, noise_reduction_type);
      check_cuda_error(cudaGetLastError());
      break;
    case 24:
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               24>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_specialized));
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               24>,
          cudaFuncAttributePreferredSharedMemoryCarveout,
          cudaSharedmemCarveoutMaxShared));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               24>,
          cudaFuncCachePreferShared));
      check_cuda_error(cudaGetLastError());
      device_programmable_bootstrap_specialized_2_2_params<Torus, params, 24>
          <<<grid, new_block, full_sm_specialized, stream>>>(
              lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
              lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
              num_many_lut, lut_stride, noise_reduction_type);
      check_cuda_error(cudaGetLastError());
      break;
    case 25:
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               25>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_specialized));
      check_cuda_error(cudaFuncSetAttribute(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               25>,
          cudaFuncAttributePreferredSharedMemoryCarveout,
          cudaSharedmemCarveoutMaxShared));
      check_cuda_error(cudaFuncSetCacheConfig(
          device_programmable_bootstrap_specialized_2_2_params<Torus, params,
                                                               25>,
          cudaFuncCachePreferShared));
      check_cuda_error(cudaGetLastError());
      device_programmable_bootstrap_specialized_2_2_params<Torus, params, 25>
          <<<grid, new_block, full_sm_specialized, stream>>>(
              lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
              lwe_array_in, lwe_input_indexes, bootstrapping_key, lwe_dimension,
              num_many_lut, lut_stride, noise_reduction_type);
      check_cuda_error(cudaGetLastError());
      break;
    default:
      PANIC("Unsupported base_log value for specialized 2_2_params kernel");
    }
    return;
  }

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
  host_programmable_bootstrap_with_mode<Torus, params>(
      stream, gpu_index, lwe_array_out, lwe_output_indexes, lut_vector,
      lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
      pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size, base_log,
      level_count, input_lwe_ciphertext_count, num_many_lut, lut_stride,
      ClassicalLaunchMode::AUTO);
}

template <typename Torus, class params>
__host__ void host_programmable_bootstrap_specialized_2_2(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, double2 const *bootstrapping_key,
    pbs_buffer<Torus, CLASSICAL> *pbs_buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    uint32_t num_many_lut, uint32_t lut_stride) {
  host_programmable_bootstrap_with_mode<Torus, params>(
      stream, gpu_index, lwe_array_out, lwe_output_indexes, lut_vector,
      lut_vector_indexes, lwe_array_in, lwe_input_indexes, bootstrapping_key,
      pbs_buffer, glwe_dimension, lwe_dimension, polynomial_size, base_log,
      level_count, input_lwe_ciphertext_count, num_many_lut, lut_stride,
      ClassicalLaunchMode::SPECIALIZED_2_2);
}

#endif // CUDA_PBS_CUH
