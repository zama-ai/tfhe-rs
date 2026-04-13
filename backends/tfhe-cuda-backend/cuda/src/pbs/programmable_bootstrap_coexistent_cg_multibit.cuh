#ifndef CUDA_COEXISTENT_CG_MULTIBIT_PBS_CUH
#define CUDA_COEXISTENT_CG_MULTIBIT_PBS_CUH

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
#include "programmable_bootstrap_cg_multibit.cuh"
#include "programmable_bootstrap_multibit.cuh"
#include "types/complex/operations.cuh"
#include "utils/helper.cuh"
#include <cuda/atomic>
#include <vector>

// Inter-chunk idle wait: KB and ACC may sleep for many chunks while
// waiting for the other kernel to finish. Longer sleep reduces SM
// contention but increases wakeup latency.
constexpr uint32_t COEXISTENT_CG_SLEEP_NS = 64;

// Intra-chunk barrier wait: all blocks within a kernel finish near-
// simultaneously, so the last-arrival wait is very short.
constexpr uint32_t COEXISTENT_CG_BARRIER_SLEEP_NS = 8;

// ============================================================================
// Synchronization primitives for the coexistent-CG variant
// ============================================================================
//
// Two persistent kernels (keybundle + accumulator) run on separate streams
// and communicate through a double-buffered producer-consumer protocol:
//
//   buffer[0]   buffer[1]
//   +-------+   +-------+
//   | KB: 0 |   |       |   chunk 0: KB writes buf[0]
//   +-------+   +-------+
//   +-------+   +-------+
//   |       |   | KB: 1 |   chunk 1: KB writes buf[1], ACC reads buf[0]
//   +-------+   +-------+
//   +-------+   +-------+
//   | KB: 2 |   |       |   chunk 2: KB writes buf[0], ACC reads buf[1]
//   +-------+   +-------+
//   ...
//
// Signaling protocol:
//   kb_chunk_written:  KB stores (chunk_idx+1) after all KB blocks finish
//   chunk_idx acc_chunk_done:    ACC stores (chunk_idx+1) after all ACC blocks
//   finish chunk_idx
//
// KB wait condition before writing chunk N (N >= 2):
//   acc_chunk_done >= N-1
//   This means ACC finished chunk N-2 (which used buffer[N%2]), so the buffer
//   is free.
//
// ACC wait condition before reading chunk N:
//   kb_chunk_written >= N+1
//   This means KB finished writing chunk N into buffer[N%2].
//
// Safety: KB writes buffer[N%2], ACC reads buffer[(N-1)%2]. Since
// N%2 != (N-1)%2, the two kernels always access different buffers.
// ============================================================================

struct alignas(8) CoexistentCgSyncState {
  // Inter-kernel signaling: monotonically increasing chunk indices
  cuda::atomic<uint32_t, cuda::thread_scope_device> kb_chunk_written;
  cuda::atomic<uint32_t, cuda::thread_scope_device> acc_chunk_done;

  // Per-chunk countdown: "all blocks done" within each kernel.
  // For KB, this counts the physical grid blocks (grid-stride),
  // not the logical work items.
  cuda::atomic<uint32_t, cuda::thread_scope_device> blocks_done_kb;
  cuda::atomic<uint32_t, cuda::thread_scope_device> blocks_done_acc;

  uint32_t total_chunks;
  uint32_t num_kb_blocks;
  uint32_t num_acc_blocks;
};

// Ensure the pbs_buffer allocates enough space for this struct
static_assert(sizeof(CoexistentCgSyncState) <= COEXISTENT_CG_SYNC_STATE_SIZE,
              "CoexistentCgSyncState exceeds COEXISTENT_CG_SYNC_STATE_SIZE; "
              "increase the constant in pbs_multibit_utilities.h");

// Re-entrant barrier for the accumulator kernel. Replaces
// cooperative_groups::this_grid().sync() which cannot be used here since we
// launch two independent kernels (not one cooperative launch).
//
// The generation counter prevents late-arriving blocks from racing into the
// next sync() call before all blocks have left the current one.
struct CountdownBarrier {
  cuda::atomic<uint32_t, cuda::thread_scope_device> *counter;
  cuda::atomic<uint32_t, cuda::thread_scope_device> *generation;
  uint32_t total;

  // All threads in all blocks must call sync(). The implementation:
  //   1. Block-internal barrier (__syncthreads) to ensure all threads in this
  //      block have finished their work
  //   2. Thread 0 of each block does the inter-block countdown
  //   3. Block-internal barrier to broadcast the result to all threads
  __device__ void sync() {
    __syncthreads();

    if (threadIdx.x == 0) {
      // Acquire: ensures we see all writes made before the previous
      // sync's release (the generation increment)
      uint32_t gen = generation->load(cuda::memory_order_acquire);

      if (counter->fetch_sub(1, cuda::memory_order_acq_rel) == 1) {
        // Last block to arrive: reset counter and advance generation
        counter->store(total, cuda::memory_order_relaxed);
        // Release: makes the counter reset and generation increment
        // visible to all spinners
        generation->fetch_add(1, cuda::memory_order_release);
      } else {
        // All blocks finish near-simultaneously, so the wait is brief
        while (generation->load(cuda::memory_order_acquire) == gen)
          __nanosleep(COEXISTENT_CG_BARRIER_SLEEP_NS);
      }
    }

    __syncthreads();
  }
};

// ============================================================================
// Persistent keybundle kernel (grid-stride, double-buffered)
// ============================================================================
// Uses a grid-stride loop to decouple the physical grid size from the logical
// work. The physical grid is sized to fit entirely on the KB SMs, while the
// logical work per chunk can be much larger. Each physical block iterates
// over logical work items:
//
//   linear_idx = blockIdx.x; linear_idx < total_logical_blocks; linear_idx +=
//   gridDim.x
//
// The linear_idx is then decomposed into (input_idx, chunk_slot, glwe_id,
// poly_id, level_id) matching the non-persistent kernel's grid layout.
//
// This eliminates the constraint that chunk_size * blocks_per_unit <= SM
// capacity, allowing much larger chunks and fewer synchronization rounds.

template <typename Torus, class params, sharedMemDegree SMD>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_keybundle_persistent(
        const Torus *__restrict__ lwe_array_in,
        const Torus *__restrict__ lwe_input_indexes, double2 *keybundle_fft_a,
        double2 *keybundle_fft_b, const Torus *__restrict__ bootstrapping_key,
        CoexistentCgSyncState *sync_state, uint32_t lwe_dimension,
        uint32_t glwe_dimension, uint32_t polynomial_size,
        uint32_t grouping_factor, uint32_t level_count, uint64_t lwe_chunk_size,
        uint64_t keybundle_size_per_input, int8_t *device_mem,
        uint64_t device_memory_size_per_block, uint32_t num_samples,
        uint32_t total_logical_blocks) {

  // Grid-stride: each physical block uses its own device memory slot
  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    selected_memory = &device_mem[blockIdx.x * device_memory_size_per_block];
  }

  uint32_t total_chunks = sync_state->total_chunks;
  uint32_t glwe_dim_p1 = glwe_dimension + 1;
  uint32_t glwe_sq = glwe_dim_p1 * glwe_dim_p1;

  for (uint32_t chunk_idx = 0; chunk_idx < total_chunks; chunk_idx++) {

    // Two-step barrier between chunks:
    //
    // Step 1: Wait for the previous chunk's kb_chunk_written signal.
    // This ensures the last KB block from chunk (chunk_idx-1) has finished
    // resetting blocks_done_kb and storing kb_chunk_written before any block
    // enters chunk_idx's countdown. Without this, a non-last block can
    // reach the chunk_idx countdown while the last block from the previous
    // chunk is still executing its reset+signal sequence.
    //
    // Step 2: Wait for ACC to release the double-buffer slot.
    // For chunk_idx >= 2, ACC must have finished reading from
    // buffer[chunk_idx % 2] (which it used for chunk_idx - 2).
    if (threadIdx.x == 0) {
      if (chunk_idx > 0) {
        while (sync_state->kb_chunk_written.load(cuda::memory_order_acquire) <
               chunk_idx)
          __nanosleep(COEXISTENT_CG_SLEEP_NS);
      }
      if (chunk_idx >= 2) {
        while (sync_state->acc_chunk_done.load(cuda::memory_order_acquire) <
               chunk_idx - 1)
          __nanosleep(COEXISTENT_CG_SLEEP_NS);
      }
    }
    __syncthreads();

    // Select the active buffer based on chunk parity
    double2 *active_keybundle_fft =
        (chunk_idx % 2 == 0) ? keybundle_fft_a : keybundle_fft_b;

    // Safe: chunk_idx * lwe_chunk_size <= lwe_dimension / grouping_factor <=
    // UINT32_MAX, validated at launch
    uint32_t lwe_offset = static_cast<uint32_t>(chunk_idx * lwe_chunk_size);
    uint32_t chunk_size = static_cast<uint32_t>(min(
        lwe_chunk_size,
        static_cast<uint64_t>(lwe_dimension / grouping_factor) - lwe_offset));

    // Grid-stride loop: each physical block processes multiple logical blocks
    for (uint32_t linear_idx = blockIdx.x; linear_idx < total_logical_blocks;
         linear_idx += gridDim.x) {

      // Decompose linear_idx into the original 3D grid coordinates:
      //   original blockIdx.x = input_idx * lwe_chunk_size + chunk_slot
      //   original blockIdx.y = glwe_id * (glwe_dim+1) + poly_id
      //   original blockIdx.z = level_id
      //
      // Layout: linear_idx = orig_bx + orig_by * dim_x + orig_bz * dim_x *
      // dim_y
      //   dim_x = num_samples * lwe_chunk_size
      //   dim_y = (glwe_dim+1)^2
      //   dim_z = level_count
      // Safe: num_samples * lwe_chunk_size fits in uint32_t (validated at
      // launch via total_logical_kb_blocks <= UINT32_MAX)
      uint32_t dim_x = static_cast<uint32_t>(num_samples * lwe_chunk_size);
      uint32_t orig_bx = linear_idx % dim_x;
      uint32_t tmp = linear_idx / dim_x;
      uint32_t orig_by = tmp % glwe_sq;
      uint32_t level_id = tmp / glwe_sq;

      uint32_t glwe_id = orig_by / glwe_dim_p1;
      uint32_t poly_id = orig_by % glwe_dim_p1;
      uint32_t chunk_slot = orig_bx % static_cast<uint32_t>(lwe_chunk_size);
      uint32_t input_idx = orig_bx / static_cast<uint32_t>(lwe_chunk_size);
      uint32_t lwe_iteration = chunk_slot + lwe_offset;

      if (lwe_iteration < (lwe_dimension / grouping_factor) &&
          chunk_slot < chunk_size) {

        double2 *keybundle =
            active_keybundle_fft + input_idx * keybundle_size_per_input;

        uint32_t rev_lwe_iteration =
            ((lwe_dimension / grouping_factor) - lwe_iteration - 1);

        // First GGSW term: constant polynomial, no monomial multiply needed
        const Torus *bsk_slice = get_multi_bit_ith_lwe_gth_group_kth_block(
            bootstrapping_key, 0, rev_lwe_iteration, glwe_id, level_id,
            grouping_factor, 2 * polynomial_size, glwe_dimension, level_count);
        const Torus *bsk_poly_ini = bsk_slice + poly_id * params::degree;

        Torus reg_acc[params::opt];
        copy_polynomial_in_regs<Torus, params::opt,
                                params::degree / params::opt>(bsk_poly_ini,
                                                              reg_acc);

        int offset = get_start_ith_ggsw_offset(polynomial_size, glwe_dimension,
                                               level_count);

        // Monomial degrees stored in shared memory
        uint32_t *monomial_degrees =
            reinterpret_cast<uint32_t *>(selected_memory);
        if (threadIdx.x < (1 << grouping_factor)) {
          const Torus *block_lwe_array_in =
              &lwe_array_in[lwe_input_indexes[input_idx] * (lwe_dimension + 1)];
          const Torus *lwe_array_group =
              block_lwe_array_in + rev_lwe_iteration * grouping_factor;
          monomial_degrees[threadIdx.x] =
              calculates_monomial_degree<Torus, params>(
                  lwe_array_group, threadIdx.x, grouping_factor);
        }
        __syncthreads();

        // Accumulate remaining GGSW terms (g = 1 .. 2^grouping_factor - 1)
        for (int g = 1; g < (1 << grouping_factor); g++) {
          uint32_t monomial_degree = monomial_degrees[g];
          const Torus *bsk_poly = bsk_poly_ini + g * offset;
          polynomial_accumulate_monic_monomial_mul_on_regs<Torus, params>(
              reg_acc, bsk_poly, monomial_degree);
        }
        __syncthreads();

        // Convert to Fourier domain
        int tid = threadIdx.x;
        double2 *fft = reinterpret_cast<double2 *>(selected_memory);
#pragma unroll
        for (int i = 0; i < params::opt / 2; i++) {
          fft[tid] = make_double2(
              __ll2double_rn((int64_t)reg_acc[i]) /
                  (double)std::numeric_limits<Torus>::max(),
              __ll2double_rn((int64_t)reg_acc[i + params::opt / 2]) /
                  (double)std::numeric_limits<Torus>::max());
          tid += params::degree / params::opt;
        }

        NSMFFT_direct<HalfDegree<params>>(fft);

        auto keybundle_out = get_ith_mask_kth_block(
            keybundle, chunk_slot, glwe_id, level_id, polynomial_size,
            glwe_dimension, level_count);
        auto keybundle_poly = keybundle_out + poly_id * params::degree / 2;

        copy_polynomial<double2, params::opt / 2, params::degree / params::opt>(
            fft, keybundle_poly);
      }
    }

    // All physical KB blocks must finish the grid-stride loop before
    // signaling that the chunk is ready. The last block to arrive signals.
    __threadfence();
    if (threadIdx.x == 0) {
      uint32_t prev =
          sync_state->blocks_done_kb.fetch_sub(1, cuda::memory_order_acq_rel);
      if (prev == 1) {
        sync_state->blocks_done_kb.store(sync_state->num_kb_blocks,
                                         cuda::memory_order_relaxed);
        sync_state->kb_chunk_written.store(chunk_idx + 1,
                                           cuda::memory_order_release);
      }
      // Non-last blocks proceed without spinning. The release-acquire chain
      // (KB release kb_chunk_written -> ACC acquire kb_chunk_written
      //  ACC release acc_chunk_done -> KB acquire acc_chunk_done)
      // ensures the countdown is reset before any block re-enters compute.
    }
  }
}

// ============================================================================
// Persistent accumulator kernel (double-buffered)
// ============================================================================
// Same computation as device_multi_bit_programmable_bootstrap_cg_accumulate,
// but:
//   1. Loops over chunks internally
//   2. Uses CountdownBarrier instead of grid_group for grid-wide sync
//   3. Reads from the double-buffered keybundle_fft_a / keybundle_fft_b

template <typename Torus, class params, sharedMemDegree SMD>
__global__ void __launch_bounds__(params::degree / params::opt)
    device_multi_bit_programmable_bootstrap_accumulate_persistent(
        Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
        const Torus *__restrict__ lut_vector,
        const Torus *__restrict__ lut_vector_indexes,
        const Torus *__restrict__ lwe_array_in,
        const Torus *__restrict__ lwe_input_indexes,
        const double2 *__restrict__ keybundle_fft_a,
        const double2 *__restrict__ keybundle_fft_b, double2 *join_buffer,
        Torus *global_accumulator, CoexistentCgSyncState *sync_state,
        cuda::atomic<uint32_t, cuda::thread_scope_device> *cb_counter,
        cuda::atomic<uint32_t, cuda::thread_scope_device> *cb_generation,
        uint32_t lwe_dimension, uint32_t glwe_dimension,
        uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
        uint32_t grouping_factor, uint64_t lwe_chunk_size,
        uint64_t keybundle_size_per_input, int8_t *device_mem,
        uint64_t device_memory_size_per_block, uint32_t num_many_lut,
        uint32_t lut_stride) {

  extern __shared__ int8_t sharedmem[];
  int8_t *selected_memory;

  if constexpr (SMD == FULLSM) {
    selected_memory = sharedmem;
  } else {
    int block_index = blockIdx.z + blockIdx.y * gridDim.z +
                      blockIdx.x * gridDim.z * gridDim.y;
    selected_memory = &device_mem[block_index * device_memory_size_per_block];
  }

  Torus *accumulator_rotated = reinterpret_cast<Torus *>(selected_memory);
  double2 *accumulator_fft =
      reinterpret_cast<double2 *>(accumulator_rotated) +
      (ptrdiff_t)(sizeof(Torus) * polynomial_size / sizeof(double2));

  if constexpr (SMD == PARTIALSM)
    accumulator_fft = reinterpret_cast<double2 *>(sharedmem);

  // Per-sample pointers (constant across all chunks)
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

  // Build the CountdownBarrier for intra-accumulator grid sync
  uint32_t num_acc_blocks = sync_state->num_acc_blocks;
  CountdownBarrier barrier{cb_counter, cb_generation, num_acc_blocks};

  uint32_t total_chunks = sync_state->total_chunks;

  for (uint32_t chunk_idx = 0; chunk_idx < total_chunks; chunk_idx++) {

    // Wait for KB to finish writing this chunk
    if (threadIdx.x == 0) {
      while (sync_state->kb_chunk_written.load(cuda::memory_order_acquire) <
             chunk_idx + 1)
        __nanosleep(COEXISTENT_CG_SLEEP_NS);
    }
    __syncthreads();

    // Select the buffer that KB wrote this chunk into
    const double2 *active_keybundle_fft =
        (chunk_idx % 2 == 0) ? keybundle_fft_a : keybundle_fft_b;
    const double2 *keybundle =
        &active_keybundle_fft[blockIdx.x * keybundle_size_per_input];

    // Safe: chunk_idx * lwe_chunk_size <= lwe_dimension / grouping_factor <=
    // UINT32_MAX, validated at launch
    uint32_t lwe_offset = static_cast<uint32_t>(chunk_idx * lwe_chunk_size);
    uint32_t chunk_size = static_cast<uint32_t>(min(
        lwe_chunk_size,
        static_cast<uint64_t>(lwe_dimension / grouping_factor) - lwe_offset));

    // Initialize or load the accumulator
    if (lwe_offset == 0) {
      Torus b_hat = 0;
      modulus_switch(block_lwe_array_in[lwe_dimension], b_hat,
                     params::log2_degree + 1);
      divide_by_monomial_negacyclic_inplace<Torus, params::opt,
                                            params::degree / params::opt>(
          accumulator_rotated, &block_lut_vector[blockIdx.y * params::degree],
          b_hat, false);
    } else {
      copy_polynomial<Torus, params::opt, params::degree / params::opt>(
          global_accumulator_slice, accumulator_rotated);
    }

    // Inner loop: process each LWE index in this chunk
    for (uint32_t i = 0; i < chunk_size; i++) {
      init_decomposer_state_inplace<Torus, params::opt,
                                    params::degree / params::opt>(
          accumulator_rotated, base_log, level_count);

      GadgetMatrix<Torus, params> gadget_acc(base_log, level_count,
                                             accumulator_rotated);
      gadget_acc.decompose_and_compress_level(accumulator_fft, blockIdx.z);
      NSMFFT_direct<HalfDegree<params>>(accumulator_fft);
      __syncthreads();

      // GGSW x GLWE multiply using CountdownBarrier for grid-wide sync
      mul_ggsw_glwe_in_fourier_domain<CountdownBarrier, params>(
          accumulator_fft, block_join_buffer, keybundle, i, barrier);
      NSMFFT_inverse<HalfDegree<params>>(accumulator_fft);
      __syncthreads();

      add_to_torus<Torus, params>(accumulator_fft, accumulator_rotated, true);
    }

    auto accumulator = accumulator_rotated;

    if (blockIdx.z == 0) {
      bool is_last_chunk =
          (lwe_offset + chunk_size >= (lwe_dimension / grouping_factor));
      if (is_last_chunk) {
        auto block_lwe_array_out =
            &lwe_array_out[lwe_output_indexes[blockIdx.x] *
                               (glwe_dimension * polynomial_size + 1) +
                           blockIdx.y * polynomial_size];

        if (blockIdx.y < glwe_dimension) {
          sample_extract_mask<Torus, params>(block_lwe_array_out, accumulator);
          if (num_many_lut > 1) {
            for (uint32_t m = 1; m < num_many_lut; m++) {
              auto next_lwe_array_out =
                  lwe_array_out +
                  (m * gridDim.x * (glwe_dimension * polynomial_size + 1));
              auto next_block_lwe_array_out =
                  &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                          (glwe_dimension * polynomial_size +
                                           1) +
                                      blockIdx.y * polynomial_size];
              sample_extract_mask<Torus, params>(
                  next_block_lwe_array_out, accumulator, 1, m * lut_stride);
            }
          }
        } else if (blockIdx.y == glwe_dimension) {
          __syncthreads();
          sample_extract_body<Torus, params>(block_lwe_array_out, accumulator,
                                             0);
          if (num_many_lut > 1) {
            for (uint32_t m = 1; m < num_many_lut; m++) {
              auto next_lwe_array_out =
                  lwe_array_out +
                  (m * gridDim.x * (glwe_dimension * polynomial_size + 1));
              auto next_block_lwe_array_out =
                  &next_lwe_array_out[lwe_output_indexes[blockIdx.x] *
                                          (glwe_dimension * polynomial_size +
                                           1) +
                                      blockIdx.y * polynomial_size];
              sample_extract_body<Torus, params>(
                  next_block_lwe_array_out, accumulator, 0, m * lut_stride);
            }
          }
        }
      } else {
        // Not the last chunk: persist accumulator to global memory
        copy_polynomial<Torus, params::opt, params::degree / params::opt>(
            accumulator, global_accumulator_slice);
      }
    }

    // Signal KB that this chunk's buffer is now free for reuse
    __threadfence();
    if (threadIdx.x == 0) {
      uint32_t prev =
          sync_state->blocks_done_acc.fetch_sub(1, cuda::memory_order_acq_rel);
      if (prev == 1) {
        sync_state->blocks_done_acc.store(sync_state->num_acc_blocks,
                                          cuda::memory_order_relaxed);
        sync_state->acc_chunk_done.store(chunk_idx + 1,
                                         cuda::memory_order_release);
      }
      // Non-last blocks proceed without spinning. The release-acquire chain
      // (ACC release acc_chunk_done -> KB acquire acc_chunk_done
      //  KB release kb_chunk_written -> ACC acquire kb_chunk_written)
      // ensures the countdown is reset before any block re-enters compute.
    }
  }
}

// ============================================================================
// Scratch allocation
// ============================================================================

template <typename Torus, typename params>
__host__ uint64_t scratch_coexistent_cg_multi_bit_programmable_bootstrap(
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

  // Configure keybundle kernel shared memory / cache
  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, NOSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_keybundle));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  // Configure accumulator kernel shared memory / cache
  if (max_shared_memory < partial_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, NOSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, 0));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, NOSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, PARTIALSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, partial_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, PARTIALSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  } else {
    check_cuda_error(cudaFuncSetAttribute(
        device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, full_sm_cg_accumulate));
    check_cuda_error(cudaFuncSetCacheConfig(
        device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, FULLSM>,
        cudaFuncCachePreferShared));
    check_cuda_error(cudaGetLastError());
  }

  // Compute coexistent chunk size: the keybundle and accumulator kernels must
  // both fit on the GPU simultaneously.
  //
  // Occupancy query: how many blocks of each kernel fit per SM
  int thds = polynomial_size / params::opt;
  int max_bsm_kb = 0;
  int max_bsm_acc = 0;

  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_kb,
        (void *)device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, NOSM>,
        thds, 0));
  } else {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_kb,
        (void *)device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, FULLSM>,
        thds, full_sm_keybundle));
  }

  if (max_shared_memory < partial_sm_cg_accumulate) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_acc,
        (void *)device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, NOSM>,
        thds, 0));
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_acc,
        (void *)device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, PARTIALSM>,
        thds, partial_sm_cg_accumulate));
  } else {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_acc,
        (void *)device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, FULLSM>,
        thds, full_sm_cg_accumulate));
  }

  PANIC_IF_FALSE(
      max_bsm_acc > 0,
      "coexistent-cg: accumulator kernel does not fit on a single SM "
      "— reduce shared memory usage");
  PANIC_IF_FALSE(max_bsm_kb > 0,
                 "coexistent-cg: keybundle kernel does not fit on a single SM "
                 "— reduce shared memory usage");

  int num_sms = 0;
  check_cuda_error(cudaDeviceGetAttribute(
      &num_sms, cudaDevAttrMultiProcessorCount, gpu_index));

  // The accumulator grid is fixed; the keybundle grid scales with chunk_size.
  // Use uint64_t intermediates to avoid signed overflow on the product.
  uint64_t acc_blocks_64;
  bool ov_acc = __builtin_mul_overflow(
      static_cast<uint64_t>(input_lwe_ciphertext_count),
      static_cast<uint64_t>(glwe_dimension + 1) * level_count, &acc_blocks_64);
  PANIC_IF_FALSE(!ov_acc, "coexistent-cg: acc_blocks computation overflowed");
  PANIC_IF_FALSE(acc_blocks_64 <= UINT32_MAX,
                 "coexistent-cg: acc_blocks exceeds uint32_t range");
  auto acc_blocks = static_cast<uint32_t>(acc_blocks_64);

  int sms_for_acc = CEIL_DIV(acc_blocks, max_bsm_acc);
  int sms_for_kb = num_sms - sms_for_acc;

  // blocks_per_unit = how many KB blocks are needed for the smallest chunk
  // (chunk_size=1). Used to ensure the physical KB grid is large enough to
  // run at least one logical work unit without excessive grid-stride
  // serialization (which would bottleneck the pipeline).
  uint64_t blocks_per_unit_64;
  bool ov_bpu = __builtin_mul_overflow(
      static_cast<uint64_t>(input_lwe_ciphertext_count),
      static_cast<uint64_t>(glwe_dimension + 1) *
          static_cast<uint64_t>(glwe_dimension + 1) * level_count,
      &blocks_per_unit_64);
  PANIC_IF_FALSE(!ov_bpu,
                 "coexistent-cg: blocks_per_unit computation overflowed");

  // Feasibility: ACC must fit (sms_for_acc <= num_sms) AND the KB physical
  // capacity (sms_for_kb * max_bsm_kb) must cover at least one logical unit
  // (blocks_per_unit) so grid-stride serialization doesn't bottleneck the
  // pipeline. If KB is severely starved for SMs, coexistent throughput drops
  // below CG and fallback is better.
  bool feasible = (sms_for_kb >= 1) && (static_cast<uint64_t>(sms_for_kb) *
                                            static_cast<uint64_t>(max_bsm_kb) >=
                                        blocks_per_unit_64);

  if (!feasible) {
    // When coexistence is infeasible, fall back to the regular CG path:
    // configure CG accumulate kernel attributes and use CG chunk sizing.
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
          cudaFuncAttributeMaxDynamicSharedMemorySize,
          partial_sm_cg_accumulate));
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

    uint64_t cg_chunk_size = get_lwe_chunk_size<Torus, params>(
        gpu_index, input_lwe_ciphertext_count, polynomial_size, glwe_dimension,
        level_count, full_sm_keybundle);

    uint64_t size_tracker = 0;
    *buffer = new pbs_buffer<Torus, MULTI_BIT>(
        stream, gpu_index, glwe_dimension, polynomial_size, level_count,
        input_lwe_ciphertext_count, cg_chunk_size, PBS_VARIANT::COEXISTENT_CG,
        allocate_gpu_memory, size_tracker);
    (*buffer)->coexistent_feasible = false;
    return size_tracker;
  }

  // With grid-stride KB, chunk_size is no longer constrained by KB SM capacity.
  // Use the same sqrt-based heuristic as the CG variant for balanced chunk
  // sizing.
  uint64_t coexistent_chunk_size = get_lwe_chunk_size<Torus, params>(
      gpu_index, input_lwe_ciphertext_count, polynomial_size, glwe_dimension,
      level_count, full_sm_keybundle);

  uint64_t size_tracker = 0;
  *buffer = new pbs_buffer<Torus, MULTI_BIT>(
      stream, gpu_index, glwe_dimension, polynomial_size, level_count,
      input_lwe_ciphertext_count, coexistent_chunk_size,
      PBS_VARIANT::COEXISTENT_CG, allocate_gpu_memory, size_tracker);
  (*buffer)->coexistent_feasible = true;

  return size_tracker;
}

// ============================================================================
// Host launch
// ============================================================================

template <typename Torus, class params>
__host__ void host_coexistent_cg_multi_bit_programmable_bootstrap(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lut_vector,
    Torus const *lut_vector_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, uint64_t const *bootstrapping_key,
    pbs_buffer<Torus, MULTI_BIT> *buffer, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t grouping_factor,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_many_lut, uint32_t lut_stride) {

  cuda_set_device(gpu_index);

  PANIC_IF_FALSE(
      sizeof(Torus) == 8,
      "Error: Coexistent-CG multi-bit PBS only supports 64-bit Torus.");

  // If the scratch function determined that co-resident persistent kernels
  // are infeasible on this GPU, transparently fall back to a non-persistent
  // variant. Try CG first (sequential keybundle + cooperative accumulator);
  // if the cooperative grid is too large, fall back to DEFAULT (two-step
  // accumulator with no cooperative-group constraint).
  if (!buffer->coexistent_feasible) {
    auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
    bool cg_supported =
        verify_cuda_programmable_bootstrap_cg_multi_bit_grid_size<Torus,
                                                                  params>(
            glwe_dimension, level_count, num_samples, max_shared_memory);
    if (cg_supported) {
      host_cg_multi_bit_programmable_bootstrap<Torus, params>(
          stream, gpu_index, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
          polynomial_size, grouping_factor, base_log, level_count, num_samples,
          num_many_lut, lut_stride);
    } else {
      // bootstrapping_key is uint64_t const*, and Torus is uint64_t
      // (enforced by the sizeof check above), so the types are identical.
      host_multi_bit_programmable_bootstrap<Torus, params>(
          stream, gpu_index, lwe_array_out, lwe_output_indexes, lut_vector,
          lut_vector_indexes, lwe_array_in, lwe_input_indexes,
          bootstrapping_key, buffer, glwe_dimension, lwe_dimension,
          polynomial_size, grouping_factor, base_log, level_count, num_samples,
          num_many_lut, lut_stride);
    }
    return;
  }

  auto lwe_chunk_size = buffer->lwe_chunk_size;
  PANIC_IF_FALSE(lwe_chunk_size <= static_cast<uint64_t>(UINT32_MAX),
                 "coexistent-cg: lwe_chunk_size exceeds uint32_t range");
  uint32_t total_chunks = CEIL_DIV(lwe_dimension / grouping_factor,
                                   static_cast<uint32_t>(lwe_chunk_size));

  uint64_t chunk_size_for_grid = std::min(
      lwe_chunk_size, static_cast<uint64_t>(lwe_dimension / grouping_factor));
  PANIC_IF_FALSE(chunk_size_for_grid <= static_cast<uint64_t>(UINT32_MAX),
                 "coexistent-cg: chunk_size_for_grid exceeds uint32_t range");

  // KB grid: with grid-stride, the physical grid is clamped to the KB SM
  // capacity. The logical work per chunk can be larger.
  uint32_t glwe_dim_p1 = glwe_dimension + 1;
  uint64_t total_logical_kb_blocks_64 =
      safe_mul(safe_mul(static_cast<size_t>(num_samples),
                        static_cast<size_t>(chunk_size_for_grid)),
               safe_mul(static_cast<size_t>(glwe_dim_p1 * glwe_dim_p1),
                        static_cast<size_t>(level_count)));
  PANIC_IF_FALSE(total_logical_kb_blocks_64 <= UINT32_MAX,
                 "coexistent-cg: total_logical_kb_blocks exceeds uint32_t");
  uint32_t total_logical_kb_blocks =
      static_cast<uint32_t>(total_logical_kb_blocks_64);

  // Occupancy query for KB
  uint64_t full_sm_keybundle =
      get_buffer_size_full_sm_multibit_programmable_bootstrap_keybundle<Torus>(
          polynomial_size);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  int thds_val = polynomial_size / params::opt;
  int max_bsm_kb = 0;
  if (max_shared_memory < full_sm_keybundle) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_kb,
        (void *)device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, NOSM>,
        thds_val, 0));
  } else {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_kb,
        (void *)device_multi_bit_programmable_bootstrap_keybundle_persistent<
            Torus, params, FULLSM>,
        thds_val, full_sm_keybundle));
  }
  int max_bsm_acc = 0;
  uint64_t full_sm_cg_accumulate =
      get_buffer_size_full_sm_cg_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  uint64_t partial_sm_cg_accumulate =
      get_buffer_size_partial_sm_cg_multibit_programmable_bootstrap<Torus>(
          polynomial_size);
  if (max_shared_memory < partial_sm_cg_accumulate) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_acc,
        (void *)device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, NOSM>,
        thds_val, 0));
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_acc,
        (void *)device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, PARTIALSM>,
        thds_val, partial_sm_cg_accumulate));
  } else {
    check_cuda_error(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_bsm_acc,
        (void *)device_multi_bit_programmable_bootstrap_accumulate_persistent<
            Torus, params, FULLSM>,
        thds_val, full_sm_cg_accumulate));
  }

  int num_sms = 0;
  check_cuda_error(cudaDeviceGetAttribute(
      &num_sms, cudaDevAttrMultiProcessorCount, gpu_index));

  // Accumulator grid: identical to the CG variant. Must be fully resident.
  dim3 grid_acc(num_samples, glwe_dimension + 1, level_count);
  uint64_t num_acc_blocks_64;
  bool ov_acc1 = __builtin_mul_overflow(static_cast<uint64_t>(grid_acc.x),
                                        static_cast<uint64_t>(grid_acc.y),
                                        &num_acc_blocks_64);
  PANIC_IF_FALSE(!ov_acc1,
                 "coexistent-cg: num_acc_blocks multiplication overflowed");
  uint64_t num_acc_blocks_full;
  bool ov_acc2 = __builtin_mul_overflow(num_acc_blocks_64,
                                        static_cast<uint64_t>(grid_acc.z),
                                        &num_acc_blocks_full);
  PANIC_IF_FALSE(!ov_acc2,
                 "coexistent-cg: num_acc_blocks multiplication overflowed");
  PANIC_IF_FALSE(num_acc_blocks_full <= UINT32_MAX,
                 "coexistent-cg: num_acc_blocks exceeds uint32_t range");
  uint32_t num_acc_blocks = static_cast<uint32_t>(num_acc_blocks_full);

  int sms_for_acc = CEIL_DIV(num_acc_blocks, max_bsm_acc);
  int sms_for_kb = std::max(1, num_sms - sms_for_acc);

  // KB physical grid: fill the available KB SMs, capped by logical work
  uint32_t kb_physical_blocks = static_cast<uint32_t>(std::min(
      static_cast<uint64_t>(sms_for_kb) * static_cast<uint64_t>(max_bsm_kb),
      static_cast<uint64_t>(total_logical_kb_blocks)));
  dim3 grid_kb(kb_physical_blocks, 1, 1);

  dim3 thds(polynomial_size / params::opt, 1, 1);

  // Initialize sync state on the host and copy to device.
  // num_kb_blocks refers to the physical grid for the countdown barrier.
  CoexistentCgSyncState host_sync;
  new (&host_sync.kb_chunk_written)
      cuda::atomic<uint32_t, cuda::thread_scope_device>(0);
  new (&host_sync.acc_chunk_done)
      cuda::atomic<uint32_t, cuda::thread_scope_device>(0);
  new (&host_sync.blocks_done_kb)
      cuda::atomic<uint32_t, cuda::thread_scope_device>(kb_physical_blocks);
  new (&host_sync.blocks_done_acc)
      cuda::atomic<uint32_t, cuda::thread_scope_device>(num_acc_blocks);
  host_sync.total_chunks = total_chunks;
  host_sync.num_kb_blocks = kb_physical_blocks;
  host_sync.num_acc_blocks = num_acc_blocks;

  // Initialize CountdownBarrier counter and generation on device
  uint32_t initial_counter = num_acc_blocks;
  uint32_t initial_generation = 0;

  auto sync_state =
      static_cast<CoexistentCgSyncState *>(buffer->coexistent_sync_state);
  auto cb_counter = buffer->cb_counter;
  auto cb_generation = buffer->cb_generation;
  auto stream_kb = buffer->coexistent_stream_kb;
  auto stream_acc = buffer->coexistent_stream_acc;
  auto done_event = buffer->coexistent_done_event;

  // Synchronous copies: the source is stack-local, so we use cudaMemcpy
  // (not cudaMemcpyAsync) to make the intent explicit and avoid fragile
  // reliance on the CUDA runtime's pageable-memory staging path.
  static_assert(sizeof(cuda::atomic<uint32_t, cuda::thread_scope_device>) ==
                    sizeof(uint32_t),
                "cuda::atomic<uint32_t> size assumption violated");

  check_cuda_error(cudaMemcpy(sync_state, &host_sync,
                              sizeof(CoexistentCgSyncState),
                              cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(cb_counter, &initial_counter, sizeof(uint32_t),
                              cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(cb_generation, &initial_generation,
                              sizeof(uint32_t), cudaMemcpyHostToDevice));

  // Both internal streams must wait for the caller stream's prior work
  // (e.g., BSK conversion) to complete before launching the kernels.
  cudaEvent_t caller_ready;
  check_cuda_error(
      cudaEventCreateWithFlags(&caller_ready, cudaEventDisableTiming));
  check_cuda_error(cudaEventRecord(caller_ready, stream));
  check_cuda_error(cudaStreamWaitEvent(stream_kb, caller_ready, 0));
  check_cuda_error(cudaStreamWaitEvent(stream_acc, caller_ready, 0));
  check_cuda_error(cudaEventDestroy(caller_ready));

  auto d_mem_keybundle = buffer->d_mem_keybundle;
  auto d_mem_acc_cg = buffer->d_mem_acc_cg;
  auto keybundle_fft_a = buffer->keybundle_fft;
  auto keybundle_fft_b = buffer->coexistent_keybundle_fft_b;
  auto global_accumulator = buffer->global_accumulator;
  auto join_buffer = buffer->global_join_buffer;

  uint64_t keybundle_size_per_input = safe_mul(
      (size_t)lwe_chunk_size, (size_t)level_count, (size_t)(glwe_dimension + 1),
      (size_t)(glwe_dimension + 1), (size_t)(polynomial_size / 2));

  // Launch keybundle persistent kernel on stream_kb (1D grid-stride)
  if (max_shared_memory < full_sm_keybundle) {
    device_multi_bit_programmable_bootstrap_keybundle_persistent<Torus, params,
                                                                 NOSM>
        <<<grid_kb, thds, 0, stream_kb>>>(
            lwe_array_in, lwe_input_indexes, keybundle_fft_a, keybundle_fft_b,
            bootstrapping_key, sync_state, lwe_dimension, glwe_dimension,
            polynomial_size, grouping_factor, level_count, chunk_size_for_grid,
            keybundle_size_per_input, d_mem_keybundle, full_sm_keybundle,
            num_samples, total_logical_kb_blocks);
  } else {
    device_multi_bit_programmable_bootstrap_keybundle_persistent<Torus, params,
                                                                 FULLSM>
        <<<grid_kb, thds, full_sm_keybundle, stream_kb>>>(
            lwe_array_in, lwe_input_indexes, keybundle_fft_a, keybundle_fft_b,
            bootstrapping_key, sync_state, lwe_dimension, glwe_dimension,
            polynomial_size, grouping_factor, level_count, chunk_size_for_grid,
            keybundle_size_per_input, d_mem_keybundle, 0, num_samples,
            total_logical_kb_blocks);
  }
  check_cuda_error(cudaGetLastError());

  // Launch accumulator persistent kernel on stream_acc.
  // No ordering event needed between KB and ACC: the sync state was
  // initialized via synchronous cudaMemcpy before any kernel launch, so it
  // is visible to both kernels. stream_acc already waits for caller_ready.
  // An event that serializes ACC after KB would cause deadlock since KB
  // spins waiting for ACC's acc_chunk_done signal.
  uint64_t full_dm = full_sm_cg_accumulate;
  uint64_t partial_dm = full_sm_cg_accumulate - partial_sm_cg_accumulate;

  if (max_shared_memory < partial_sm_cg_accumulate) {
    device_multi_bit_programmable_bootstrap_accumulate_persistent<Torus, params,
                                                                  NOSM>
        <<<grid_acc, thds, 0, stream_acc>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, keybundle_fft_a, keybundle_fft_b,
            join_buffer, global_accumulator, sync_state, cb_counter,
            cb_generation, lwe_dimension, glwe_dimension, polynomial_size,
            base_log, level_count, grouping_factor, chunk_size_for_grid,
            keybundle_size_per_input, d_mem_acc_cg, full_dm, num_many_lut,
            lut_stride);
  } else if (max_shared_memory < full_sm_cg_accumulate) {
    device_multi_bit_programmable_bootstrap_accumulate_persistent<Torus, params,
                                                                  PARTIALSM>
        <<<grid_acc, thds, partial_sm_cg_accumulate, stream_acc>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, keybundle_fft_a, keybundle_fft_b,
            join_buffer, global_accumulator, sync_state, cb_counter,
            cb_generation, lwe_dimension, glwe_dimension, polynomial_size,
            base_log, level_count, grouping_factor, chunk_size_for_grid,
            keybundle_size_per_input, d_mem_acc_cg, partial_dm, num_many_lut,
            lut_stride);
  } else {
    device_multi_bit_programmable_bootstrap_accumulate_persistent<Torus, params,
                                                                  FULLSM>
        <<<grid_acc, thds, full_sm_cg_accumulate, stream_acc>>>(
            lwe_array_out, lwe_output_indexes, lut_vector, lut_vector_indexes,
            lwe_array_in, lwe_input_indexes, keybundle_fft_a, keybundle_fft_b,
            join_buffer, global_accumulator, sync_state, cb_counter,
            cb_generation, lwe_dimension, glwe_dimension, polynomial_size,
            base_log, level_count, grouping_factor, chunk_size_for_grid,
            keybundle_size_per_input, d_mem_acc_cg, 0, num_many_lut,
            lut_stride);
  }
  check_cuda_error(cudaGetLastError());

  // Chain the caller stream to wait for both persistent kernels to finish.
  // Use a temporary event for stream_kb to avoid reusing done_event while
  // it may still be referenced by a pending cudaStreamWaitEvent.
  cudaEvent_t kb_done;
  check_cuda_error(cudaEventCreateWithFlags(&kb_done, cudaEventDisableTiming));
  check_cuda_error(cudaEventRecord(kb_done, stream_kb));
  check_cuda_error(cudaStreamWaitEvent(stream, kb_done, 0));
  check_cuda_error(cudaEventDestroy(kb_done));

  check_cuda_error(cudaEventRecord(done_event, stream_acc));
  check_cuda_error(cudaStreamWaitEvent(stream, done_event, 0));
}

#endif // CUDA_COEXISTENT_CG_MULTIBIT_PBS_CUH
