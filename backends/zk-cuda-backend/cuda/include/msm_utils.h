#pragma once

// MSM memory management structs and implementation functions.
//
// This header owns the struct definitions for pre-allocated MSM contexts
// (scratch/cleanup/async pattern) and cached base-point contexts, plus all
// the functions that operate on them.  c_wrapper.cu provides the thin
// extern "C" forwarding layer that the FFI surface (api.h) declares.
//
// Only included from c_wrapper.cu -- no ODR concerns for non-inline defs.

#include "bls12_446_params.h"
#include "checked_arithmetic.h"
#include "device.h"
#include "msm.h"
#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <mutex>

#include "../../../tfhe-cuda-backend/cuda/src/utils/helper_profile.cuh"

// ============================================================================
// Montgomery conversion helpers (C++ linkage, call template functions)
// ============================================================================

static void convert_g1_points_to_montgomery(cudaStream_t stream,
                                            uint32_t gpu_index,
                                            G1Affine *d_points, uint32_t n) {
  point_to_montgomery_batch_async<G1Affine>(stream, gpu_index, d_points, n);
}

static void convert_g2_points_to_montgomery(cudaStream_t stream,
                                            uint32_t gpu_index,
                                            G2Affine *d_points, uint32_t n) {
  point_to_montgomery_batch_async<G2Affine>(stream, gpu_index, d_points, n);
}

// ============================================================================
// G1 MSM scratch/cleanup/async pattern
// ============================================================================
// Pre-allocates device buffers once, then reuses them across multiple MSM
// calls. This eliminates per-call malloc/free overhead from the managed wrapper
// path.
//
//   scratch_zk_g1_msm   — allocate device buffers for up to max_n points
//   zk_g1_msm_async     — copy host data, convert to Montgomery, run MSM
//   cleanup_zk_g1_msm   — free device buffers, delete context

struct zk_g1_msm_mem {
  G1Affine *d_points;      // device buffer for G1 affine points
  Scalar *d_scalars;       // device buffer for scalars
  G1Projective *d_scratch; // Pippenger scratch buffer
  uint32_t capacity;       // max number of points this context can handle

  // For split launch/finalize: host buffer for Pippenger window sums.
  // Allocated during scratch, populated by the async D2H copy in
  // zk_g1_msm_cached_launch_async, consumed by zk_g1_msm_finalize.
  G1Projective *h_window_sums; // pinned host memory for window sums
  uint32_t max_num_windows;    // capacity of h_window_sums
  uint32_t num_windows;        // set during launch, used by finalize
  uint32_t window_size;        // set during launch, used by finalize
};

// ============================================================================
// G2 MSM scratch/cleanup/async pattern
// ============================================================================
// Pre-allocates device buffers once, then reuses them across multiple MSM
// calls. This eliminates per-call malloc/free overhead from the managed wrapper
// path.
//
//   scratch_zk_g2_msm   — allocate device buffers for up to max_n points
//   zk_g2_msm_async     — copy host data, convert to Montgomery, run MSM
//   cleanup_zk_g2_msm   — free device buffers, delete context

struct zk_g2_msm_mem {
  G2Affine *d_points;      // device buffer for G2 affine points
  Scalar *d_scalars;       // device buffer for scalars
  G2Projective *d_scratch; // Pippenger scratch buffer
  uint32_t capacity;       // max number of points this context can handle

  // For split launch/finalize: host buffer for Pippenger window sums.
  // Allocated during scratch, populated by the async D2H copy in
  // zk_g2_msm_cached_launch_async, consumed by zk_g2_msm_finalize.
  G2Projective *h_window_sums; // pinned host memory for window sums
  uint32_t max_num_windows;    // capacity of h_window_sums
  uint32_t num_windows;        // set during launch, used by finalize
  uint32_t window_size;        // set during launch, used by finalize
};

// ============================================================================
// Cached G1 base points on device
// ============================================================================
// For verify workloads that reuse the same CRS/PublicParams across many calls,
// we cache the G1 base points on device in Montgomery form.
// This avoids repeated CPU-side conversion and H2D copies per MSM call.
//
//   scratch_zk_cached_g1_points — allocate, copy H2D, convert to Montgomery
//   cleanup_zk_cached_g1_points — free device buffer, delete context
//   zk_g1_msm_cached_async     — MSM using cached device points (scalars-only
//   H2D)

struct zk_cached_g1_points {
  G1Affine *d_points; // device buffer, Montgomery form
  uint32_t n;         // number of points
  uint32_t gpu_index; // GPU this buffer lives on
};

// ============================================================================
// Cached G2 base points on device
// ============================================================================
// For verify workloads that reuse the same CRS/PublicParams across many calls,
// we cache the G2 base points (g_hat_list) on device in Montgomery form.
// This avoids repeated CPU-side conversion and H2D copies per MSM call.
//
//   scratch_zk_cached_g2_points — allocate, copy H2D, convert to Montgomery
//   cleanup_zk_cached_g2_points — free device buffer, delete context
//   zk_g2_msm_cached_async     — MSM using cached device points (scalars-only
//   H2D)

struct zk_cached_g2_points {
  G2Affine *d_points; // device buffer, Montgomery form
  uint32_t n;         // number of points
  uint32_t gpu_index; // GPU this buffer lives on
};

// ============================================================================
// Implementation functions (C++ linkage, called by extern "C" wrappers)
// ============================================================================
// All functions live in the zk_msm namespace to avoid name collisions with
// the extern "C" FFI symbols defined in c_wrapper.cu.

namespace zk_msm {

// --- G1 MSM scratch/cleanup/async ----------------------------------------

void scratch_zk_g1_msm(cudaStream_t stream, uint32_t gpu_index,
                       zk_g1_msm_mem **mem, uint32_t max_n,
                       uint64_t *size_tracker, bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr, "scratch_zk_g1_msm: mem is null");
  PANIC_IF_FALSE(max_n > 0, "scratch_zk_g1_msm: max_n must be positive");
  PANIC_IF_FALSE(stream != nullptr, "scratch_zk_g1_msm: stream is null");
  PANIC_IF_FALSE(size_tracker != nullptr,
                 "scratch_zk_g1_msm: size_tracker is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "scratch_zk_g1_msm: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());

  *mem = new zk_g1_msm_mem;
  (*mem)->capacity = max_n;

  uint64_t &tracker = *size_tracker;

  size_t points_bytes = safe_mul_sizeof<G1Affine>(static_cast<size_t>(max_n));
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(max_n));
  size_t scratch_bytes = pippenger_scratch_size_g1(max_n, gpu_index);

  (*mem)->d_points =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
  (*mem)->d_scalars =
      static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
          scalars_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
  (*mem)->d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

  // Allocate pinned host buffer for window sums (used by launch/finalize
  // split). Pinned memory is required for the async D2H copy to be truly async.
  const uint32_t max_num_windows =
      CEIL_DIV(Scalar::NUM_BITS, MSM_G1_WINDOW_SIZE);
  (*mem)->max_num_windows = max_num_windows;
  (*mem)->num_windows = 0;
  (*mem)->window_size = 0;

  size_t window_sums_bytes =
      safe_mul_sizeof<G1Projective>(static_cast<size_t>(max_num_windows));
  // TODO: benchmark cudaMallocHost (pinned memory) — it may improve async D2H
  // overlap
  (*mem)->h_window_sums =
      static_cast<G1Projective *>(malloc(window_sums_bytes));
  PANIC_IF_FALSE((*mem)->h_window_sums != nullptr,
                 "scratch_zk_g1_msm: malloc failed for h_window_sums");
}

void cleanup_zk_g1_msm(cudaStream_t stream, uint32_t gpu_index,
                       zk_g1_msm_mem **mem, bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                 "cleanup_zk_g1_msm: mem is null");
  PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_g1_msm: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "cleanup_zk_g1_msm: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());

  cuda_drop_with_size_tracking_async((*mem)->d_points, stream, gpu_index,
                                     allocate_gpu_memory);
  cuda_drop_with_size_tracking_async((*mem)->d_scalars, stream, gpu_index,
                                     allocate_gpu_memory);
  cuda_drop_with_size_tracking_async((*mem)->d_scratch, stream, gpu_index,
                                     allocate_gpu_memory);

  // Free the host buffer for window sums
  if ((*mem)->h_window_sums != nullptr) {
    free((*mem)->h_window_sums);
  }

  delete *mem;
  *mem = nullptr;

  cuda_synchronize_stream(stream, gpu_index);
}

void zk_g1_msm_async(cudaStream_t stream, uint32_t gpu_index,
                     zk_g1_msm_mem *mem, G1Projective *h_result,
                     const G1Affine *h_points, const Scalar *h_scalars,
                     uint32_t n, bool points_in_montgomery) {
  PUSH_RANGE("G1 MSM ASYNC (SCRATCH)");
  PANIC_IF_FALSE(mem != nullptr, "zk_g1_msm_async: mem is null");
  PANIC_IF_FALSE(n > 0, "zk_g1_msm_async: n must be positive, got %u", n);
  PANIC_IF_FALSE(n <= mem->capacity,
                 "zk_g1_msm_async: n=%u exceeds pre-allocated capacity=%u", n,
                 mem->capacity);
  PANIC_IF_FALSE(stream != nullptr, "zk_g1_msm_async: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "zk_g1_msm_async: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(h_result != nullptr, "zk_g1_msm_async: h_result is null");
  PANIC_IF_FALSE(h_points != nullptr, "zk_g1_msm_async: h_points is null");
  PANIC_IF_FALSE(h_scalars != nullptr, "zk_g1_msm_async: h_scalars is null");

  size_t points_bytes = safe_mul_sizeof<G1Affine>(static_cast<size_t>(n));
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));

  // Copy host data into pre-allocated device buffers
  cuda_memcpy_async_to_gpu(mem->d_points, h_points, points_bytes, stream,
                           gpu_index);
  cuda_memcpy_async_to_gpu(mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  // Convert points to Montgomery form on device if needed
  if (!points_in_montgomery) {
    convert_g1_points_to_montgomery(stream, gpu_index, mem->d_points, n);
    check_cuda_error(cudaGetLastError());
  }

  // Run MSM using pre-allocated scratch buffer (zero internal allocations).
  // point_msm_g1_async expects Montgomery-form points.
  point_msm_g1_async(stream, gpu_index, h_result, mem->d_points, mem->d_scalars,
                     n, mem->d_scratch);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// --- Cached G1 base points -----------------------------------------------

void scratch_zk_cached_g1_points(cudaStream_t stream, uint32_t gpu_index,
                                 zk_cached_g1_points **mem,
                                 const G1Affine *h_points, uint32_t n,
                                 uint64_t *size_tracker,
                                 bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr, "scratch_zk_cached_g1_points: mem is null");
  PANIC_IF_FALSE(h_points != nullptr,
                 "scratch_zk_cached_g1_points: h_points is null");
  PANIC_IF_FALSE(n > 0, "scratch_zk_cached_g1_points: n must be positive");
  PANIC_IF_FALSE(stream != nullptr,
                 "scratch_zk_cached_g1_points: stream is null");
  PANIC_IF_FALSE(size_tracker != nullptr,
                 "scratch_zk_cached_g1_points: size_tracker is null");
  PANIC_IF_FALSE(
      gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
      "scratch_zk_cached_g1_points: invalid gpu_index=%u (gpu_count=%d)",
      gpu_index, cuda_get_number_of_gpus());

  *mem = new zk_cached_g1_points;
  (*mem)->n = n;
  (*mem)->gpu_index = gpu_index;

  uint64_t &tracker = *size_tracker;
  size_t points_bytes = safe_mul_sizeof<G1Affine>(static_cast<size_t>(n));

  (*mem)->d_points =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

  // Copy host points to device, then convert to Montgomery form in-place
  cuda_memcpy_async_to_gpu((*mem)->d_points, h_points, points_bytes, stream,
                           gpu_index);
  convert_g1_points_to_montgomery(stream, gpu_index, (*mem)->d_points, n);
  check_cuda_error(cudaGetLastError());

  // Ensure points are fully resident and converted before returning,
  // so the cache is immediately usable by any stream.
  cuda_synchronize_stream(stream, gpu_index);
}

void cleanup_zk_cached_g1_points(cudaStream_t stream, uint32_t gpu_index,
                                 zk_cached_g1_points **mem,
                                 bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                 "cleanup_zk_cached_g1_points: mem is null");
  PANIC_IF_FALSE(stream != nullptr,
                 "cleanup_zk_cached_g1_points: stream is null");

  cuda_drop_with_size_tracking_async((*mem)->d_points, stream, gpu_index,
                                     allocate_gpu_memory);

  delete *mem;
  *mem = nullptr;

  cuda_synchronize_stream(stream, gpu_index);
}

void zk_g1_msm_cached_async(cudaStream_t stream, uint32_t gpu_index,
                            zk_g1_msm_mem *msm_mem, G1Projective *h_result,
                            const zk_cached_g1_points *cached,
                            uint32_t point_offset, const Scalar *h_scalars,
                            uint32_t n) {
  PUSH_RANGE("G1 MSM CACHED");
  PANIC_IF_FALSE(msm_mem != nullptr, "zk_g1_msm_cached_async: msm_mem is null");
  PANIC_IF_FALSE(cached != nullptr, "zk_g1_msm_cached_async: cached is null");
  PANIC_IF_FALSE(n > 0, "zk_g1_msm_cached_async: n must be positive, got %u",
                 n);
  PANIC_IF_FALSE(n <= msm_mem->capacity,
                 "zk_g1_msm_cached_async: n=%u exceeds msm_mem capacity=%u", n,
                 msm_mem->capacity);
  PANIC_IF_FALSE(
      static_cast<uint64_t>(point_offset) + n <= cached->n,
      "zk_g1_msm_cached_async: point_offset=%u + n=%u exceeds cached points=%u",
      point_offset, n, cached->n);
  PANIC_IF_FALSE(stream != nullptr, "zk_g1_msm_cached_async: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "zk_g1_msm_cached_async: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(
      gpu_index == cached->gpu_index,
      "zk_g1_msm_cached_async: gpu_index=%u but cached points are on gpu=%u",
      gpu_index, cached->gpu_index);
  PANIC_IF_FALSE(h_result != nullptr,
                 "zk_g1_msm_cached_async: h_result is null");
  PANIC_IF_FALSE(h_scalars != nullptr,
                 "zk_g1_msm_cached_async: h_scalars is null");

  // Only scalars need H2D transfer — points are already on device in Montgomery
  // form
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
  cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  // Cached points are already in Montgomery form, which is what Pippenger
  // expects. The scratch buffer from msm_mem was sized for msm_mem->capacity >=
  // n, and pippenger_scratch_size is monotonically non-decreasing, so it is
  // sufficient.
  point_msm_g1_async(stream, gpu_index, h_result,
                     cached->d_points + point_offset, msm_mem->d_scalars, n,
                     msm_mem->d_scratch);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// --- Split launch/finalize for pipelined G1 MSM --------------------------
// These two functions split the MSM into a truly async GPU launch and a
// CPU-side finalize step. Between launch and finalize the caller can do
// CPU work while the GPU kernels execute concurrently.
//
// Flow:
//   1. zk_g1_msm_cached_launch_async — H2D scalars, GPU phases 1-3, async D2H
//      of window sums. Returns immediately (stream NOT synchronized).
//   2. (caller does CPU work here while GPU is busy)
//   3. zk_g1_msm_finalize — syncs stream, runs CPU Horner combine, writes
//   result.

void zk_g1_msm_cached_launch_async(cudaStream_t stream, uint32_t gpu_index,
                                   zk_g1_msm_mem *msm_mem,
                                   const zk_cached_g1_points *cached,
                                   uint32_t point_offset,
                                   const Scalar *h_scalars, uint32_t n) {
  PUSH_RANGE("G1 MSM CACHED LAUNCH");
  PANIC_IF_FALSE(msm_mem != nullptr,
                 "zk_g1_msm_cached_launch_async: msm_mem is null");
  PANIC_IF_FALSE(cached != nullptr,
                 "zk_g1_msm_cached_launch_async: cached is null");
  PANIC_IF_FALSE(
      n > 0, "zk_g1_msm_cached_launch_async: n must be positive, got %u", n);
  PANIC_IF_FALSE(
      n <= msm_mem->capacity,
      "zk_g1_msm_cached_launch_async: n=%u exceeds msm_mem capacity=%u", n,
      msm_mem->capacity);
  PANIC_IF_FALSE(
      static_cast<uint64_t>(point_offset) + n <= cached->n,
      "zk_g1_msm_cached_launch_async: point_offset=%u + n=%u exceeds cached "
      "points=%u",
      point_offset, n, cached->n);
  PANIC_IF_FALSE(stream != nullptr,
                 "zk_g1_msm_cached_launch_async: stream is null");
  PANIC_IF_FALSE(
      gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
      "zk_g1_msm_cached_launch_async: invalid gpu_index=%u (gpu_count=%d)",
      gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(
      gpu_index == cached->gpu_index,
      "zk_g1_msm_cached_launch_async: gpu_index=%u but cached points are on "
      "gpu=%u",
      gpu_index, cached->gpu_index);
  PANIC_IF_FALSE(h_scalars != nullptr,
                 "zk_g1_msm_cached_launch_async: h_scalars is null");
  PANIC_IF_FALSE(
      msm_mem->h_window_sums != nullptr,
      "zk_g1_msm_cached_launch_async: h_window_sums is null (scratch not "
      "allocated?)");

  // H2D transfer: only scalars (points are already cached on device)
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
  cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  // Launch Pippenger phases 1-3 + async D2H of window sums into msm_mem.
  // num_windows and window_size are written to msm_mem for finalize.
  point_msm_g1_launch_async(stream, gpu_index, msm_mem->h_window_sums,
                            cached->d_points + point_offset, msm_mem->d_scalars,
                            n, msm_mem->d_scratch, msm_mem->num_windows,
                            msm_mem->window_size);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// Synchronizes the stream and runs the CPU Horner combine on the window sums
// that were copied D2H during the launch phase. Writes the final G1 MSM result
// to `h_result`.
void zk_g1_msm_finalize(cudaStream_t stream, uint32_t gpu_index,
                        const zk_g1_msm_mem *msm_mem, G1Projective *h_result) {
  PUSH_RANGE("G1 MSM FINALIZE");
  PANIC_IF_FALSE(msm_mem != nullptr, "zk_g1_msm_finalize: msm_mem is null");
  PANIC_IF_FALSE(h_result != nullptr, "zk_g1_msm_finalize: h_result is null");
  PANIC_IF_FALSE(stream != nullptr, "zk_g1_msm_finalize: stream is null");
  PANIC_IF_FALSE(msm_mem->num_windows > 0,
                 "zk_g1_msm_finalize: num_windows is 0 (launch not called?)");
  PANIC_IF_FALSE(msm_mem->h_window_sums != nullptr,
                 "zk_g1_msm_finalize: h_window_sums is null");

  // Block until all GPU work (kernels + D2H copy) has completed
  cuda_synchronize_stream(stream, gpu_index);

  // Run CPU Horner combine to produce the final MSM result
  point_msm_g1_horner_finalize(h_result, msm_mem->h_window_sums,
                               msm_mem->num_windows, msm_mem->window_size);
  POP_RANGE();
}

// --- G2 MSM scratch/cleanup/async ----------------------------------------

void scratch_zk_g2_msm(cudaStream_t stream, uint32_t gpu_index,
                       zk_g2_msm_mem **mem, uint32_t max_n,
                       uint64_t *size_tracker, bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr, "scratch_zk_g2_msm: mem is null");
  PANIC_IF_FALSE(max_n > 0, "scratch_zk_g2_msm: max_n must be positive");
  PANIC_IF_FALSE(stream != nullptr, "scratch_zk_g2_msm: stream is null");
  PANIC_IF_FALSE(size_tracker != nullptr,
                 "scratch_zk_g2_msm: size_tracker is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "scratch_zk_g2_msm: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());

  *mem = new zk_g2_msm_mem;
  (*mem)->capacity = max_n;

  uint64_t &tracker = *size_tracker;

  size_t points_bytes = safe_mul_sizeof<G2Affine>(static_cast<size_t>(max_n));
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(max_n));
  size_t scratch_bytes = pippenger_scratch_size_g2(max_n, gpu_index);

  (*mem)->d_points =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
  (*mem)->d_scalars =
      static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
          scalars_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
  (*mem)->d_scratch =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

  // Allocate pinned host buffer for window sums (used by launch/finalize
  // split). Pinned memory is required for the async D2H copy to be truly async.
  // Window count is constant for G2 (fixed window size), but we compute it
  // from the constants rather than hardcoding.
  const uint32_t max_num_windows =
      CEIL_DIV(Scalar::NUM_BITS, MSM_G2_WINDOW_SIZE);
  (*mem)->max_num_windows = max_num_windows;
  (*mem)->num_windows = 0;
  (*mem)->window_size = 0;

  size_t window_sums_bytes =
      safe_mul_sizeof<G2Projective>(static_cast<size_t>(max_num_windows));
  // TODO: benchmark cudaMallocHost (pinned memory) — it may improve async D2H
  // overlap
  (*mem)->h_window_sums =
      static_cast<G2Projective *>(malloc(window_sums_bytes));
  PANIC_IF_FALSE((*mem)->h_window_sums != nullptr,
                 "scratch_zk_g2_msm: malloc failed for h_window_sums");
}

void cleanup_zk_g2_msm(cudaStream_t stream, uint32_t gpu_index,
                       zk_g2_msm_mem **mem, bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                 "cleanup_zk_g2_msm: mem is null");
  PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_g2_msm: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "cleanup_zk_g2_msm: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());

  cuda_drop_with_size_tracking_async((*mem)->d_points, stream, gpu_index,
                                     allocate_gpu_memory);
  cuda_drop_with_size_tracking_async((*mem)->d_scalars, stream, gpu_index,
                                     allocate_gpu_memory);
  cuda_drop_with_size_tracking_async((*mem)->d_scratch, stream, gpu_index,
                                     allocate_gpu_memory);

  // Free the host buffer for window sums
  if ((*mem)->h_window_sums != nullptr) {
    free((*mem)->h_window_sums);
  }

  delete *mem;
  *mem = nullptr;

  cuda_synchronize_stream(stream, gpu_index);
}

void zk_g2_msm_async(cudaStream_t stream, uint32_t gpu_index,
                     zk_g2_msm_mem *mem, G2Projective *h_result,
                     const G2Affine *h_points, const Scalar *h_scalars,
                     uint32_t n, bool points_in_montgomery) {
  PUSH_RANGE("G2 MSM ASYNC (SCRATCH)");
  PANIC_IF_FALSE(mem != nullptr, "zk_g2_msm_async: mem is null");
  PANIC_IF_FALSE(n > 0, "zk_g2_msm_async: n must be positive, got %u", n);
  PANIC_IF_FALSE(n <= mem->capacity,
                 "zk_g2_msm_async: n=%u exceeds pre-allocated capacity=%u", n,
                 mem->capacity);
  PANIC_IF_FALSE(stream != nullptr, "zk_g2_msm_async: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "zk_g2_msm_async: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(h_result != nullptr, "zk_g2_msm_async: h_result is null");
  PANIC_IF_FALSE(h_points != nullptr, "zk_g2_msm_async: h_points is null");
  PANIC_IF_FALSE(h_scalars != nullptr, "zk_g2_msm_async: h_scalars is null");

  size_t points_bytes = safe_mul_sizeof<G2Affine>(static_cast<size_t>(n));
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));

  // Copy host data into pre-allocated device buffers
  cuda_memcpy_async_to_gpu(mem->d_points, h_points, points_bytes, stream,
                           gpu_index);
  cuda_memcpy_async_to_gpu(mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  // Convert points to Montgomery form on device if needed
  if (!points_in_montgomery) {
    convert_g2_points_to_montgomery(stream, gpu_index, mem->d_points, n);
    check_cuda_error(cudaGetLastError());
  }

  // Run MSM using pre-allocated scratch buffer (zero internal allocations).
  // point_msm_g2_async expects Montgomery-form points.
  point_msm_g2_async(stream, gpu_index, h_result, mem->d_points, mem->d_scalars,
                     n, mem->d_scratch);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// --- Cached G2 base points -----------------------------------------------

void scratch_zk_cached_g2_points(cudaStream_t stream, uint32_t gpu_index,
                                 zk_cached_g2_points **mem,
                                 const G2Affine *h_points, uint32_t n,
                                 uint64_t *size_tracker,
                                 bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr, "scratch_zk_cached_g2_points: mem is null");
  PANIC_IF_FALSE(h_points != nullptr,
                 "scratch_zk_cached_g2_points: h_points is null");
  PANIC_IF_FALSE(n > 0, "scratch_zk_cached_g2_points: n must be positive");
  PANIC_IF_FALSE(stream != nullptr,
                 "scratch_zk_cached_g2_points: stream is null");
  PANIC_IF_FALSE(size_tracker != nullptr,
                 "scratch_zk_cached_g2_points: size_tracker is null");
  PANIC_IF_FALSE(
      gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
      "scratch_zk_cached_g2_points: invalid gpu_index=%u (gpu_count=%d)",
      gpu_index, cuda_get_number_of_gpus());

  *mem = new zk_cached_g2_points;
  (*mem)->n = n;
  (*mem)->gpu_index = gpu_index;

  uint64_t &tracker = *size_tracker;
  size_t points_bytes = safe_mul_sizeof<G2Affine>(static_cast<size_t>(n));

  (*mem)->d_points =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

  // Copy host points to device, then convert to Montgomery form in-place
  cuda_memcpy_async_to_gpu((*mem)->d_points, h_points, points_bytes, stream,
                           gpu_index);
  convert_g2_points_to_montgomery(stream, gpu_index, (*mem)->d_points, n);
  check_cuda_error(cudaGetLastError());

  // Ensure points are fully resident and converted before returning,
  // so the cache is immediately usable by any stream.
  cuda_synchronize_stream(stream, gpu_index);
}

void cleanup_zk_cached_g2_points(cudaStream_t stream, uint32_t gpu_index,
                                 zk_cached_g2_points **mem,
                                 bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                 "cleanup_zk_cached_g2_points: mem is null");
  PANIC_IF_FALSE(stream != nullptr,
                 "cleanup_zk_cached_g2_points: stream is null");

  cuda_drop_with_size_tracking_async((*mem)->d_points, stream, gpu_index,
                                     allocate_gpu_memory);

  delete *mem;
  *mem = nullptr;

  cuda_synchronize_stream(stream, gpu_index);
}

void zk_g2_msm_cached_async(cudaStream_t stream, uint32_t gpu_index,
                            zk_g2_msm_mem *msm_mem, G2Projective *h_result,
                            const zk_cached_g2_points *cached,
                            uint32_t point_offset, const Scalar *h_scalars,
                            uint32_t n) {
  PUSH_RANGE("G2 MSM CACHED");
  PANIC_IF_FALSE(msm_mem != nullptr, "zk_g2_msm_cached_async: msm_mem is null");
  PANIC_IF_FALSE(cached != nullptr, "zk_g2_msm_cached_async: cached is null");
  PANIC_IF_FALSE(n > 0, "zk_g2_msm_cached_async: n must be positive, got %u",
                 n);
  PANIC_IF_FALSE(n <= msm_mem->capacity,
                 "zk_g2_msm_cached_async: n=%u exceeds msm_mem capacity=%u", n,
                 msm_mem->capacity);
  PANIC_IF_FALSE(
      static_cast<uint64_t>(point_offset) + n <= cached->n,
      "zk_g2_msm_cached_async: point_offset=%u + n=%u exceeds cached points=%u",
      point_offset, n, cached->n);
  PANIC_IF_FALSE(stream != nullptr, "zk_g2_msm_cached_async: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "zk_g2_msm_cached_async: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(
      gpu_index == cached->gpu_index,
      "zk_g2_msm_cached_async: gpu_index=%u but cached points are on gpu=%u",
      gpu_index, cached->gpu_index);
  PANIC_IF_FALSE(h_result != nullptr,
                 "zk_g2_msm_cached_async: h_result is null");
  PANIC_IF_FALSE(h_scalars != nullptr,
                 "zk_g2_msm_cached_async: h_scalars is null");

  // Only scalars need H2D transfer — points are already on device in Montgomery
  // form
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
  cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  // Cached points are already in Montgomery form, which is what Pippenger
  // expects. The scratch buffer from msm_mem was sized for msm_mem->capacity >=
  // n, and pippenger_scratch_size is monotonically non-decreasing, so it is
  // sufficient.
  point_msm_g2_async(stream, gpu_index, h_result,
                     cached->d_points + point_offset, msm_mem->d_scalars, n,
                     msm_mem->d_scratch);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// --- Split launch/finalize for pipelined G2 MSM --------------------------
// These two functions split the MSM into a truly async GPU launch and a
// CPU-side finalize step. Between launch and finalize the caller can do
// CPU work (e.g., pairings) while the GPU kernels execute concurrently.
//
// Flow:
//   1. zk_g2_msm_cached_launch_async — H2D scalars, GPU phases 1-3, async D2H
//      of window sums. Returns immediately (stream NOT synchronized).
//   2. (caller does CPU work here while GPU is busy)
//   3. zk_g2_msm_finalize — syncs stream, runs CPU Horner combine, writes
//   result.

// Launches G2 MSM asynchronously using cached device base points. Only scalars
// are transferred H2D. The MSM kernels and D2H copy of window sums are queued
// on `stream` but NOT synchronized — the caller must call
// `zk_g2_msm_finalize()` after any desired CPU overlap to get the final result.
void zk_g2_msm_cached_launch_async(cudaStream_t stream, uint32_t gpu_index,
                                   zk_g2_msm_mem *msm_mem,
                                   const zk_cached_g2_points *cached,
                                   uint32_t point_offset,
                                   const Scalar *h_scalars, uint32_t n) {
  PUSH_RANGE("G2 MSM CACHED LAUNCH");
  PANIC_IF_FALSE(msm_mem != nullptr,
                 "zk_g2_msm_cached_launch_async: msm_mem is null");
  PANIC_IF_FALSE(cached != nullptr,
                 "zk_g2_msm_cached_launch_async: cached is null");
  PANIC_IF_FALSE(
      n > 0, "zk_g2_msm_cached_launch_async: n must be positive, got %u", n);
  PANIC_IF_FALSE(
      n <= msm_mem->capacity,
      "zk_g2_msm_cached_launch_async: n=%u exceeds msm_mem capacity=%u", n,
      msm_mem->capacity);
  PANIC_IF_FALSE(
      static_cast<uint64_t>(point_offset) + n <= cached->n,
      "zk_g2_msm_cached_launch_async: point_offset=%u + n=%u exceeds cached "
      "points=%u",
      point_offset, n, cached->n);
  PANIC_IF_FALSE(stream != nullptr,
                 "zk_g2_msm_cached_launch_async: stream is null");
  PANIC_IF_FALSE(
      gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
      "zk_g2_msm_cached_launch_async: invalid gpu_index=%u (gpu_count=%d)",
      gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(
      gpu_index == cached->gpu_index,
      "zk_g2_msm_cached_launch_async: gpu_index=%u but cached points are on "
      "gpu=%u",
      gpu_index, cached->gpu_index);
  PANIC_IF_FALSE(h_scalars != nullptr,
                 "zk_g2_msm_cached_launch_async: h_scalars is null");
  PANIC_IF_FALSE(
      msm_mem->h_window_sums != nullptr,
      "zk_g2_msm_cached_launch_async: h_window_sums is null (scratch not "
      "allocated?)");

  // H2D transfer: only scalars (points are already cached on device)
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
  cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  // Launch Pippenger phases 1-3 + async D2H of window sums into msm_mem.
  // num_windows and window_size are written to msm_mem for finalize.
  point_msm_g2_launch_async(stream, gpu_index, msm_mem->h_window_sums,
                            cached->d_points + point_offset, msm_mem->d_scalars,
                            n, msm_mem->d_scratch, msm_mem->num_windows,
                            msm_mem->window_size);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// Synchronizes the stream and runs the CPU Horner combine on the window sums
// that were copied D2H during the launch phase. Writes the final MSM result
// to `h_result`.
void zk_g2_msm_finalize(cudaStream_t stream, uint32_t gpu_index,
                        const zk_g2_msm_mem *msm_mem, G2Projective *h_result) {
  PUSH_RANGE("G2 MSM FINALIZE");
  PANIC_IF_FALSE(msm_mem != nullptr, "zk_g2_msm_finalize: msm_mem is null");
  PANIC_IF_FALSE(h_result != nullptr, "zk_g2_msm_finalize: h_result is null");
  PANIC_IF_FALSE(stream != nullptr, "zk_g2_msm_finalize: stream is null");
  PANIC_IF_FALSE(msm_mem->num_windows > 0,
                 "zk_g2_msm_finalize: num_windows is 0 (launch not called?)");
  PANIC_IF_FALSE(msm_mem->h_window_sums != nullptr,
                 "zk_g2_msm_finalize: h_window_sums is null");

  // Block until all GPU work (kernels + D2H copy) has completed
  cuda_synchronize_stream(stream, gpu_index);

  // Run CPU Horner combine (~0.1 ms) to produce the final MSM result
  point_msm_g2_horner_finalize(h_result, msm_mem->h_window_sums,
                               msm_mem->num_windows, msm_mem->window_size);
  POP_RANGE();
}

// ============================================================================
// Global singleton cache for CRS base points across all GPUs
// ============================================================================
// Populated once via zk_msm_cache_acquire(), lives until zk_msm_cache_reset()
// or process exit. Protected by a std::mutex for the populate-or-return check.
// Once populated, all readers access immutable data (base points in Montgomery
// form on each GPU), so no lock is needed for reads.

static constexpr uint32_t MAX_CACHE_GPUS = 16;

struct ZkMsmCache {
  zk_cached_g1_points *g1_per_gpu[MAX_CACHE_GPUS];
  zk_cached_g2_points *g2_per_gpu[MAX_CACHE_GPUS];
  cudaStream_t mgmt_streams[MAX_CACHE_GPUS];
  uint32_t num_gpus;
  // Cache key: (g1_ptr, g1_len, g2_ptr, g2_len)
  uintptr_t key[4];
  bool populated;
  // Number of outstanding acquire() calls that haven't been release()d yet.
  // Eviction is deferred until ref_count reaches 0.
  uint32_t ref_count;

  ZkMsmCache()
      : num_gpus(0), key{0, 0, 0, 0}, populated(false), ref_count(0) {
    memset(g1_per_gpu, 0, sizeof(g1_per_gpu));
    memset(g2_per_gpu, 0, sizeof(g2_per_gpu));
    memset(mgmt_streams, 0, sizeof(mgmt_streams));
  }
};

static std::mutex &cache_mutex() {
  static std::mutex mtx;
  return mtx;
}

static std::condition_variable &cache_cv() {
  static std::condition_variable cv;
  return cv;
}

static ZkMsmCache &global_cache() {
  static ZkMsmCache cache;
  return cache;
}

// Free all device resources in the cache. Caller must hold cache_mutex.
static void cache_free_resources(ZkMsmCache &cache) {
  if (!cache.populated)
    return;

  for (uint32_t gpu_idx = 0; gpu_idx < cache.num_gpus; gpu_idx++) {
    cudaStream_t stream = cache.mgmt_streams[gpu_idx];

    if (cache.g2_per_gpu[gpu_idx] != nullptr) {
      cleanup_zk_cached_g2_points(stream, gpu_idx, &cache.g2_per_gpu[gpu_idx],
                                  true);
    }
    if (cache.g1_per_gpu[gpu_idx] != nullptr) {
      cleanup_zk_cached_g1_points(stream, gpu_idx, &cache.g1_per_gpu[gpu_idx],
                                  true);
    }

    cuda_destroy_stream(stream, gpu_idx);
    cache.mgmt_streams[gpu_idx] = nullptr;
  }

  cache.populated = false;
  memset(cache.key, 0, sizeof(cache.key));
  cache.num_gpus = 0;
}

// Acquire the cache. If the key matches, increments the reference count and
// returns immediately (cache hit). If the key differs (or first call), waits
// for all outstanding references to be released, evicts the old cache, and
// populates a new one by uploading g1/g2 base points to every GPU.
// The caller MUST call zk_msm_cache_release() when done using the pointers.
// Returns num_gpus; caller uses get_g1/get_g2 to retrieve per-GPU pointers.
uint32_t zk_msm_cache_acquire(const G1Affine *g1_points, uint32_t n_g1,
                              const G2Affine *g2_points, uint32_t n_g2,
                              const uintptr_t key[4]) {
  std::unique_lock<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();

  // Fast path: cache hit — same CRS, just bump ref_count
  if (cache.populated && memcmp(cache.key, key, sizeof(cache.key)) == 0) {
    cache.ref_count++;
    return cache.num_gpus;
  }

  // Key mismatch: must evict and repopulate. Wait for all outstanding
  // references to be released — evicting while ref_count > 0 would cause
  // use-after-free for callers still holding cached pointers.
  cache_cv().wait(lock, [&cache] { return cache.ref_count == 0; });

  // Evict old cache if populated
  cache_free_resources(cache);

  // Populate new cache across all available GPUs
  int gpu_count = cuda_get_number_of_gpus();
  PANIC_IF_FALSE(gpu_count > 0, "zk_msm_cache_acquire: no GPUs available");
  PANIC_IF_FALSE(static_cast<uint32_t>(gpu_count) <= MAX_CACHE_GPUS,
                 "zk_msm_cache_acquire: gpu_count=%d exceeds MAX_CACHE_GPUS=%u",
                 gpu_count, MAX_CACHE_GPUS);

  cache.num_gpus = static_cast<uint32_t>(gpu_count);
  memcpy(cache.key, key, sizeof(cache.key));

  for (uint32_t gpu_idx = 0; gpu_idx < cache.num_gpus; gpu_idx++) {
    cache.mgmt_streams[gpu_idx] = cuda_create_stream(gpu_idx);
    cudaStream_t stream = cache.mgmt_streams[gpu_idx];

    // Upload G1 base points (H2D + Montgomery conversion) if provided
    if (g1_points != nullptr && n_g1 > 0) {
      uint64_t size_tracker = 0;
      scratch_zk_cached_g1_points(stream, gpu_idx, &cache.g1_per_gpu[gpu_idx],
                                  g1_points, n_g1, &size_tracker, true);
    }

    // Upload G2 base points (H2D + Montgomery conversion) if provided
    if (g2_points != nullptr && n_g2 > 0) {
      uint64_t size_tracker = 0;
      scratch_zk_cached_g2_points(stream, gpu_idx, &cache.g2_per_gpu[gpu_idx],
                                  g2_points, n_g2, &size_tracker, true);
    }
  }

  cache.populated = true;
  cache.ref_count = 1;
  return cache.num_gpus;
}

// Release a reference to the cache. Must be called once for each
// successful zk_msm_cache_acquire() call. When the last reference is
// released, the cache remains populated (for potential reuse) but is
// eligible for eviction by a future acquire with a different key.
void zk_msm_cache_release() {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.ref_count > 0,
                 "zk_msm_cache_release: ref_count is already 0 (double release?)");
  cache.ref_count--;
  // Wake any acquire() waiting to evict the cache with a different key.
  if (cache.ref_count == 0) {
    cache_cv().notify_all();
  }
}

// Get the cached G1 device pointer for a specific GPU.
// Returns nullptr if no G1 points were cached.
const zk_cached_g1_points *zk_msm_cache_get_g1(uint32_t gpu_index) {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.populated, "zk_msm_cache_get_g1: cache not populated");
  PANIC_IF_FALSE(gpu_index < cache.num_gpus,
                 "zk_msm_cache_get_g1: gpu_index=%u >= num_gpus=%u", gpu_index,
                 cache.num_gpus);
  return cache.g1_per_gpu[gpu_index];
}

// Get the cached G2 device pointer for a specific GPU.
// Returns nullptr if no G2 points were cached.
const zk_cached_g2_points *zk_msm_cache_get_g2(uint32_t gpu_index) {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.populated, "zk_msm_cache_get_g2: cache not populated");
  PANIC_IF_FALSE(gpu_index < cache.num_gpus,
                 "zk_msm_cache_get_g2: gpu_index=%u >= num_gpus=%u", gpu_index,
                 cache.num_gpus);
  return cache.g2_per_gpu[gpu_index];
}

// Get number of GPUs the cache covers.
uint32_t zk_msm_cache_num_gpus() {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.populated, "zk_msm_cache_num_gpus: cache not populated");
  return cache.num_gpus;
}

// Free all cached resources. Safe to call even if not populated.
void zk_msm_cache_reset() {
  std::lock_guard<std::mutex> lock(cache_mutex());
  cache_free_resources(global_cache());
}

} // namespace zk_msm
