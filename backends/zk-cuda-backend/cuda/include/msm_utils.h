#pragma once

#include "bls12_446_params.h"
#include "checked_arithmetic.h"
#include "device.h"
#include "msm.h"
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>

#include "../../../tfhe-cuda-backend/cuda/src/utils/helper_profile.cuh"

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

template <typename AffineType> struct MsmTraits;

template <> struct MsmTraits<G1Affine> {
  static constexpr uint32_t WindowSize = MSM_G1_WINDOW_SIZE;
  using ProjectiveType = G1Projective;

  static size_t scratch_size(uint32_t n, uint32_t gpu_index) {
    return pippenger_scratch_size_g1(n, gpu_index);
  }

  static void convert_to_montgomery(cudaStream_t stream, uint32_t gpu_index,
                                    G1Affine *d_points, uint32_t n) {
    point_to_montgomery_batch_async<G1Affine>(stream, gpu_index, d_points, n);
  }

  static void launch_async(cudaStream_t stream, uint32_t gpu_index,
                           ProjectiveType *h_window_sums,
                           const G1Affine *d_points, const Scalar *d_scalars,
                           uint32_t n, ProjectiveType *d_scratch,
                           uint32_t &out_num_windows,
                           uint32_t &out_window_size) {
    point_msm_g1_launch_async(stream, gpu_index, h_window_sums, d_points,
                              d_scalars, n, d_scratch, out_num_windows,
                              out_window_size);
  }

  static void horner_finalize(ProjectiveType *h_result,
                              const ProjectiveType *h_window_sums,
                              uint32_t num_windows, uint32_t window_size) {
    point_msm_g1_horner_finalize(h_result, h_window_sums, num_windows,
                                 window_size);
  }
};

template <> struct MsmTraits<G2Affine> {
  static constexpr uint32_t WindowSize = MSM_G2_WINDOW_SIZE;
  using ProjectiveType = G2Projective;

  static size_t scratch_size(uint32_t n, uint32_t gpu_index) {
    return pippenger_scratch_size_g2(n, gpu_index);
  }

  static void convert_to_montgomery(cudaStream_t stream, uint32_t gpu_index,
                                    G2Affine *d_points, uint32_t n) {
    point_to_montgomery_batch_async<G2Affine>(stream, gpu_index, d_points, n);
  }

  static void launch_async(cudaStream_t stream, uint32_t gpu_index,
                           ProjectiveType *h_window_sums,
                           const G2Affine *d_points, const Scalar *d_scalars,
                           uint32_t n, ProjectiveType *d_scratch,
                           uint32_t &out_num_windows,
                           uint32_t &out_window_size) {
    point_msm_g2_launch_async(stream, gpu_index, h_window_sums, d_points,
                              d_scalars, n, d_scratch, out_num_windows,
                              out_window_size);
  }

  static void horner_finalize(ProjectiveType *h_result,
                              const ProjectiveType *h_window_sums,
                              uint32_t num_windows, uint32_t window_size) {
    point_msm_g2_horner_finalize(h_result, h_window_sums, num_windows,
                                 window_size);
  }
};

// Pre-allocated MSM context reused across many MSM calls. Holds device
// buffers for points, scalars, Pippenger scratch, and a host buffer for
// window sums (used by the launch/finalize split).
template <typename AffineType> struct zk_msm_mem {
  using Traits = MsmTraits<AffineType>;
  using ProjType = typename Traits::ProjectiveType;

  AffineType *d_points; // device buffer for affine points
  Scalar *d_scalars;    // device buffer for scalars
  ProjType *d_scratch;  // Pippenger scratch buffer
  uint32_t capacity;    // max number of points this context can handle

  // Host buffer for Pippenger window sums. Allocated once during scratch
  // setup, filled by async D2H in launch, read by finalize.
  ProjType *h_window_sums;  // host memory for window sums
  uint32_t max_num_windows; // capacity of h_window_sums
  uint32_t num_windows;     // set during launch, used by finalize
  uint32_t window_size;     // set during launch, used by finalize
};

using zk_g1_msm_mem = zk_msm_mem<G1Affine>;
using zk_g2_msm_mem = zk_msm_mem<G2Affine>;

// Base points cached on device in Montgomery form. Set up once per CRS
// and reused across verify MSM calls.
template <typename AffineType> struct zk_cached_points {
  AffineType *d_points; // device buffer, Montgomery form
  uint32_t n;           // number of points
  uint32_t gpu_index;   // GPU this buffer lives on
};

using zk_cached_g1_points = zk_cached_points<G1Affine>;
using zk_cached_g2_points = zk_cached_points<G2Affine>;

template <typename AffineType>
void scratch_zk_msm(cudaStream_t stream, uint32_t gpu_index,
                    zk_msm_mem<AffineType> **mem, uint32_t max_n,
                    uint64_t *size_tracker, bool allocate_gpu_memory) {
  using Traits = MsmTraits<AffineType>;
  using ProjType = typename Traits::ProjectiveType;

  PANIC_IF_FALSE(mem != nullptr, "scratch_zk_msm: mem is null");
  PANIC_IF_FALSE(max_n > 0, "scratch_zk_msm: max_n must be positive");
  PANIC_IF_FALSE(stream != nullptr, "scratch_zk_msm: stream is null");
  PANIC_IF_FALSE(size_tracker != nullptr,
                 "scratch_zk_msm: size_tracker is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "scratch_zk_msm: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());

  *mem = new zk_msm_mem<AffineType>;
  (*mem)->capacity = max_n;

  uint64_t &tracker = *size_tracker;

  size_t points_bytes = safe_mul_sizeof<AffineType>(static_cast<size_t>(max_n));
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(max_n));
  size_t scratch_bytes = Traits::scratch_size(max_n, gpu_index);

  (*mem)->d_points =
      static_cast<AffineType *>(cuda_malloc_with_size_tracking_async(
          points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
  (*mem)->d_scalars =
      static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
          scalars_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
  (*mem)->d_scratch =
      static_cast<ProjType *>(cuda_malloc_with_size_tracking_async(
          scratch_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

  // Allocate host buffer for window sums (used by launch/finalize split).
  const uint32_t max_num_windows =
      CEIL_DIV(Scalar::NUM_BITS, Traits::WindowSize);
  (*mem)->max_num_windows = max_num_windows;
  (*mem)->num_windows = 0;
  (*mem)->window_size = 0;

  size_t window_sums_bytes =
      safe_mul_sizeof<ProjType>(static_cast<size_t>(max_num_windows));
  // TODO: benchmark cudaMallocHost (pinned memory) -- it may improve async D2H
  // overlap
  (*mem)->h_window_sums = static_cast<ProjType *>(malloc(window_sums_bytes));
  PANIC_IF_FALSE((*mem)->h_window_sums != nullptr,
                 "scratch_zk_msm: malloc failed for h_window_sums");
}

template <typename AffineType>
void cleanup_zk_msm(cudaStream_t stream, uint32_t gpu_index,
                    zk_msm_mem<AffineType> **mem, bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                 "cleanup_zk_msm: mem is null");
  PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_msm: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "cleanup_zk_msm: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());

  cuda_drop_with_size_tracking_async((*mem)->d_points, stream, gpu_index,
                                     allocate_gpu_memory);
  cuda_drop_with_size_tracking_async((*mem)->d_scalars, stream, gpu_index,
                                     allocate_gpu_memory);
  cuda_drop_with_size_tracking_async((*mem)->d_scratch, stream, gpu_index,
                                     allocate_gpu_memory);

  if ((*mem)->h_window_sums != nullptr) {
    free((*mem)->h_window_sums);
  }

  delete *mem;
  *mem = nullptr;

  cuda_synchronize_stream(stream, gpu_index);
}

// Reuses scratch.h_window_sums to avoid per-call malloc/free.
template <typename AffineType>
void zk_msm_async(cudaStream_t stream, uint32_t gpu_index,
                  zk_msm_mem<AffineType> *mem,
                  typename MsmTraits<AffineType>::ProjectiveType *h_result,
                  const AffineType *h_points, const Scalar *h_scalars,
                  uint32_t n, bool points_in_montgomery) {
  using Traits = MsmTraits<AffineType>;

  PUSH_RANGE("MSM ASYNC (SCRATCH)");
  PANIC_IF_FALSE(mem != nullptr, "zk_msm_async: mem is null");
  PANIC_IF_FALSE(n > 0, "zk_msm_async: n must be positive, got %u", n);
  PANIC_IF_FALSE(n <= mem->capacity,
                 "zk_msm_async: n=%u exceeds pre-allocated capacity=%u", n,
                 mem->capacity);
  PANIC_IF_FALSE(stream != nullptr, "zk_msm_async: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "zk_msm_async: invalid gpu_index=%u (gpu_count=%d)", gpu_index,
                 cuda_get_number_of_gpus());
  PANIC_IF_FALSE(h_result != nullptr, "zk_msm_async: h_result is null");
  PANIC_IF_FALSE(h_points != nullptr, "zk_msm_async: h_points is null");
  PANIC_IF_FALSE(h_scalars != nullptr, "zk_msm_async: h_scalars is null");

  size_t points_bytes = safe_mul_sizeof<AffineType>(static_cast<size_t>(n));
  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));

  cuda_memcpy_async_to_gpu(mem->d_points, h_points, points_bytes, stream,
                           gpu_index);
  cuda_memcpy_async_to_gpu(mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  if (!points_in_montgomery) {
    Traits::convert_to_montgomery(stream, gpu_index, mem->d_points, n);
    check_cuda_error(cudaGetLastError());
  }

  Traits::launch_async(stream, gpu_index, mem->h_window_sums, mem->d_points,
                       mem->d_scalars, n, mem->d_scratch, mem->num_windows,
                       mem->window_size);
  cuda_synchronize_stream(stream, gpu_index);
  Traits::horner_finalize(h_result, mem->h_window_sums, mem->num_windows,
                          mem->window_size);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

template <typename AffineType>
void scratch_zk_cached_points(cudaStream_t stream, uint32_t gpu_index,
                              zk_cached_points<AffineType> **mem,
                              const AffineType *h_points, uint32_t n,
                              uint64_t *size_tracker,
                              bool allocate_gpu_memory) {
  using Traits = MsmTraits<AffineType>;

  PANIC_IF_FALSE(mem != nullptr, "scratch_zk_cached_points: mem is null");
  PANIC_IF_FALSE(h_points != nullptr,
                 "scratch_zk_cached_points: h_points is null");
  PANIC_IF_FALSE(n > 0, "scratch_zk_cached_points: n must be positive");
  PANIC_IF_FALSE(stream != nullptr, "scratch_zk_cached_points: stream is null");
  PANIC_IF_FALSE(size_tracker != nullptr,
                 "scratch_zk_cached_points: size_tracker is null");
  PANIC_IF_FALSE(
      gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
      "scratch_zk_cached_points: invalid gpu_index=%u (gpu_count=%d)",
      gpu_index, cuda_get_number_of_gpus());

  *mem = new zk_cached_points<AffineType>;
  (*mem)->n = n;
  (*mem)->gpu_index = gpu_index;

  uint64_t &tracker = *size_tracker;
  size_t points_bytes = safe_mul_sizeof<AffineType>(static_cast<size_t>(n));

  (*mem)->d_points =
      static_cast<AffineType *>(cuda_malloc_with_size_tracking_async(
          points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

  cuda_memcpy_async_to_gpu((*mem)->d_points, h_points, points_bytes, stream,
                           gpu_index);
  Traits::convert_to_montgomery(stream, gpu_index, (*mem)->d_points, n);
  check_cuda_error(cudaGetLastError());

  // Sync so the cache is immediately usable by any stream.
  cuda_synchronize_stream(stream, gpu_index);
}

template <typename AffineType>
void cleanup_zk_cached_points(cudaStream_t stream, uint32_t gpu_index,
                              zk_cached_points<AffineType> **mem,
                              bool allocate_gpu_memory) {
  PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                 "cleanup_zk_cached_points: mem is null");
  PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_cached_points: stream is null");

  cuda_drop_with_size_tracking_async((*mem)->d_points, stream, gpu_index,
                                     allocate_gpu_memory);

  delete *mem;
  *mem = nullptr;

  cuda_synchronize_stream(stream, gpu_index);
}

template <typename AffineType>
void zk_msm_cached_async(
    cudaStream_t stream, uint32_t gpu_index, zk_msm_mem<AffineType> *msm_mem,
    typename MsmTraits<AffineType>::ProjectiveType *h_result,
    const zk_cached_points<AffineType> *cached, uint32_t point_offset,
    const Scalar *h_scalars, uint32_t n) {
  using Traits = MsmTraits<AffineType>;

  PUSH_RANGE("MSM CACHED");
  PANIC_IF_FALSE(msm_mem != nullptr, "zk_msm_cached_async: msm_mem is null");
  PANIC_IF_FALSE(cached != nullptr, "zk_msm_cached_async: cached is null");
  PANIC_IF_FALSE(n > 0, "zk_msm_cached_async: n must be positive, got %u", n);
  PANIC_IF_FALSE(n <= msm_mem->capacity,
                 "zk_msm_cached_async: n=%u exceeds msm_mem capacity=%u", n,
                 msm_mem->capacity);
  PANIC_IF_FALSE(
      static_cast<uint64_t>(point_offset) + n <= cached->n,
      "zk_msm_cached_async: point_offset=%u + n=%u exceeds cached points=%u",
      point_offset, n, cached->n);
  PANIC_IF_FALSE(stream != nullptr, "zk_msm_cached_async: stream is null");
  PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                 "zk_msm_cached_async: invalid gpu_index=%u (gpu_count=%d)",
                 gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(
      gpu_index == cached->gpu_index,
      "zk_msm_cached_async: gpu_index=%u but cached points are on gpu=%u",
      gpu_index, cached->gpu_index);
  PANIC_IF_FALSE(h_result != nullptr, "zk_msm_cached_async: h_result is null");
  PANIC_IF_FALSE(h_scalars != nullptr,
                 "zk_msm_cached_async: h_scalars is null");

  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
  cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  // Cached points are already in Montgomery form, which is what Pippenger
  // expects. The scratch buffer from msm_mem was sized for msm_mem->capacity >=
  // n, and pippenger_scratch_size is monotonically non-decreasing, so it is
  // sufficient.
  Traits::launch_async(stream, gpu_index, msm_mem->h_window_sums,
                       cached->d_points + point_offset, msm_mem->d_scalars, n,
                       msm_mem->d_scratch, msm_mem->num_windows,
                       msm_mem->window_size);
  cuda_synchronize_stream(stream, gpu_index);
  Traits::horner_finalize(h_result, msm_mem->h_window_sums,
                          msm_mem->num_windows, msm_mem->window_size);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// Splits MSM into an async GPU launch and a CPU-side finalize, so the
// caller can overlap CPU work (e.g. pairings) with GPU execution.

template <typename AffineType>
void zk_msm_cached_launch_async(cudaStream_t stream, uint32_t gpu_index,
                                zk_msm_mem<AffineType> *msm_mem,
                                const zk_cached_points<AffineType> *cached,
                                uint32_t point_offset, const Scalar *h_scalars,
                                uint32_t n) {
  using Traits = MsmTraits<AffineType>;

  PUSH_RANGE("MSM CACHED LAUNCH");
  PANIC_IF_FALSE(msm_mem != nullptr,
                 "zk_msm_cached_launch_async: msm_mem is null");
  PANIC_IF_FALSE(cached != nullptr,
                 "zk_msm_cached_launch_async: cached is null");
  PANIC_IF_FALSE(n > 0,
                 "zk_msm_cached_launch_async: n must be positive, got %u", n);
  PANIC_IF_FALSE(n <= msm_mem->capacity,
                 "zk_msm_cached_launch_async: n=%u exceeds msm_mem capacity=%u",
                 n, msm_mem->capacity);
  PANIC_IF_FALSE(
      static_cast<uint64_t>(point_offset) + n <= cached->n,
      "zk_msm_cached_launch_async: point_offset=%u + n=%u exceeds cached "
      "points=%u",
      point_offset, n, cached->n);
  PANIC_IF_FALSE(stream != nullptr,
                 "zk_msm_cached_launch_async: stream is null");
  PANIC_IF_FALSE(
      gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
      "zk_msm_cached_launch_async: invalid gpu_index=%u (gpu_count=%d)",
      gpu_index, cuda_get_number_of_gpus());
  PANIC_IF_FALSE(
      gpu_index == cached->gpu_index,
      "zk_msm_cached_launch_async: gpu_index=%u but cached points are on "
      "gpu=%u",
      gpu_index, cached->gpu_index);
  PANIC_IF_FALSE(h_scalars != nullptr,
                 "zk_msm_cached_launch_async: h_scalars is null");
  PANIC_IF_FALSE(
      msm_mem->h_window_sums != nullptr,
      "zk_msm_cached_launch_async: h_window_sums is null (scratch not "
      "allocated?)");

  size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
  cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes, stream,
                           gpu_index);

  Traits::launch_async(stream, gpu_index, msm_mem->h_window_sums,
                       cached->d_points + point_offset, msm_mem->d_scalars, n,
                       msm_mem->d_scratch, msm_mem->num_windows,
                       msm_mem->window_size);
  check_cuda_error(cudaGetLastError());
  POP_RANGE();
}

// Syncs the stream, runs CPU Horner combine on the window sums from the
// launch phase, and writes the final result to `h_result`.
template <typename AffineType>
void zk_msm_finalize(cudaStream_t stream, uint32_t gpu_index,
                     const zk_msm_mem<AffineType> *msm_mem,
                     typename MsmTraits<AffineType>::ProjectiveType *h_result) {
  using Traits = MsmTraits<AffineType>;

  PUSH_RANGE("MSM FINALIZE");
  PANIC_IF_FALSE(msm_mem != nullptr, "zk_msm_finalize: msm_mem is null");
  PANIC_IF_FALSE(h_result != nullptr, "zk_msm_finalize: h_result is null");
  PANIC_IF_FALSE(stream != nullptr, "zk_msm_finalize: stream is null");
  PANIC_IF_FALSE(msm_mem->num_windows > 0,
                 "zk_msm_finalize: num_windows is 0 (launch not called?)");
  PANIC_IF_FALSE(msm_mem->h_window_sums != nullptr,
                 "zk_msm_finalize: h_window_sums is null");

  cuda_synchronize_stream(stream, gpu_index);

  Traits::horner_finalize(h_result, msm_mem->h_window_sums,
                          msm_mem->num_windows, msm_mem->window_size);
  POP_RANGE();
}

void scratch_zk_g1_msm_impl(cudaStream_t stream, uint32_t gpu_index,
                            zk_g1_msm_mem **mem, uint32_t max_n,
                            uint64_t *size_tracker, bool allocate_gpu_memory) {
  scratch_zk_msm<G1Affine>(stream, gpu_index, mem, max_n, size_tracker,
                           allocate_gpu_memory);
}

void cleanup_zk_g1_msm_impl(cudaStream_t stream, uint32_t gpu_index,
                            zk_g1_msm_mem **mem, bool allocate_gpu_memory) {
  cleanup_zk_msm<G1Affine>(stream, gpu_index, mem, allocate_gpu_memory);
}

void scratch_zk_cached_g1_points_impl(cudaStream_t stream, uint32_t gpu_index,
                                      zk_cached_g1_points **mem,
                                      const G1Affine *h_points, uint32_t n,
                                      uint64_t *size_tracker,
                                      bool allocate_gpu_memory) {
  scratch_zk_cached_points<G1Affine>(stream, gpu_index, mem, h_points, n,
                                     size_tracker, allocate_gpu_memory);
}

void cleanup_zk_cached_g1_points_impl(cudaStream_t stream, uint32_t gpu_index,
                                      zk_cached_g1_points **mem,
                                      bool allocate_gpu_memory) {
  cleanup_zk_cached_points<G1Affine>(stream, gpu_index, mem,
                                     allocate_gpu_memory);
}

void zk_g1_msm_cached_async_impl(cudaStream_t stream, uint32_t gpu_index,
                                 zk_g1_msm_mem *msm_mem, G1Projective *h_result,
                                 const zk_cached_g1_points *cached,
                                 uint32_t point_offset, const Scalar *h_scalars,
                                 uint32_t n) {
  zk_msm_cached_async<G1Affine>(stream, gpu_index, msm_mem, h_result, cached,
                                point_offset, h_scalars, n);
}

void scratch_zk_g2_msm_impl(cudaStream_t stream, uint32_t gpu_index,
                            zk_g2_msm_mem **mem, uint32_t max_n,
                            uint64_t *size_tracker, bool allocate_gpu_memory) {
  scratch_zk_msm<G2Affine>(stream, gpu_index, mem, max_n, size_tracker,
                           allocate_gpu_memory);
}

void cleanup_zk_g2_msm_impl(cudaStream_t stream, uint32_t gpu_index,
                            zk_g2_msm_mem **mem, bool allocate_gpu_memory) {
  cleanup_zk_msm<G2Affine>(stream, gpu_index, mem, allocate_gpu_memory);
}

void scratch_zk_cached_g2_points_impl(cudaStream_t stream, uint32_t gpu_index,
                                      zk_cached_g2_points **mem,
                                      const G2Affine *h_points, uint32_t n,
                                      uint64_t *size_tracker,
                                      bool allocate_gpu_memory) {
  scratch_zk_cached_points<G2Affine>(stream, gpu_index, mem, h_points, n,
                                     size_tracker, allocate_gpu_memory);
}

void cleanup_zk_cached_g2_points_impl(cudaStream_t stream, uint32_t gpu_index,
                                      zk_cached_g2_points **mem,
                                      bool allocate_gpu_memory) {
  cleanup_zk_cached_points<G2Affine>(stream, gpu_index, mem,
                                     allocate_gpu_memory);
}

void zk_g2_msm_cached_async_impl(cudaStream_t stream, uint32_t gpu_index,
                                 zk_g2_msm_mem *msm_mem, G2Projective *h_result,
                                 const zk_cached_g2_points *cached,
                                 uint32_t point_offset, const Scalar *h_scalars,
                                 uint32_t n) {
  zk_msm_cached_async<G2Affine>(stream, gpu_index, msm_mem, h_result, cached,
                                point_offset, h_scalars, n);
}

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
  // Content-hash key: (g1_hash, g1_len, g2_hash, g2_len)
  uintptr_t key[4];
  bool populated;
  // Number of outstanding acquire() calls that haven't been release()d yet.
  // Eviction is deferred until ref_count reaches 0.
  uint32_t ref_count;

  ZkMsmCache() : num_gpus(0), key{0, 0, 0, 0}, populated(false), ref_count(0) {
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
      cleanup_zk_cached_g2_points_impl(stream, gpu_idx,
                                       &cache.g2_per_gpu[gpu_idx], true);
    }
    if (cache.g1_per_gpu[gpu_idx] != nullptr) {
      cleanup_zk_cached_g1_points_impl(stream, gpu_idx,
                                       &cache.g1_per_gpu[gpu_idx], true);
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
uint32_t zk_msm_cache_acquire_impl(const G1Affine *g1_points, uint32_t n_g1,
                                   const G2Affine *g2_points, uint32_t n_g2,
                                   const uintptr_t key[4],
                                   uint64_t *size_tracker) {
  std::unique_lock<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  // Fast path: cache hit -- same CRS, just bump ref_count
  if (cache.populated && memcmp(cache.key, key, sizeof(cache.key)) == 0) {
    cache.ref_count++;
    return cache.num_gpus;
  }

  // Key mismatch: must evict and repopulate. Wait for all outstanding
  // references to be released -- evicting while ref_count > 0 would cause
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

    if (g1_points != nullptr && n_g1 > 0) {
      scratch_zk_cached_g1_points_impl(stream, gpu_idx,
                                       &cache.g1_per_gpu[gpu_idx], g1_points,
                                       n_g1, size_tracker, true);
    }

    if (g2_points != nullptr && n_g2 > 0) {
      scratch_zk_cached_g2_points_impl(stream, gpu_idx,
                                       &cache.g2_per_gpu[gpu_idx], g2_points,
                                       n_g2, size_tracker, true);
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
void zk_msm_cache_release_impl() {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(
      cache.ref_count > 0,
      "zk_msm_cache_release: ref_count is already 0 (double release?)");
  cache.ref_count--;
  // Wake any acquire() waiting to evict the cache with a different key.
  if (cache.ref_count == 0) {
    cache_cv().notify_all();
  }
}

const zk_cached_g1_points *zk_msm_cache_get_g1_impl(uint32_t gpu_index) {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.populated, "zk_msm_cache_get_g1: cache not populated");
  PANIC_IF_FALSE(gpu_index < cache.num_gpus,
                 "zk_msm_cache_get_g1: gpu_index=%u >= num_gpus=%u", gpu_index,
                 cache.num_gpus);
  return cache.g1_per_gpu[gpu_index];
}

const zk_cached_g2_points *zk_msm_cache_get_g2_impl(uint32_t gpu_index) {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.populated, "zk_msm_cache_get_g2: cache not populated");
  PANIC_IF_FALSE(gpu_index < cache.num_gpus,
                 "zk_msm_cache_get_g2: gpu_index=%u >= num_gpus=%u", gpu_index,
                 cache.num_gpus);
  return cache.g2_per_gpu[gpu_index];
}

uint32_t zk_msm_cache_num_gpus_impl() {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.populated, "zk_msm_cache_num_gpus: cache not populated");
  return cache.num_gpus;
}

void zk_msm_cache_reset_impl() {
  std::lock_guard<std::mutex> lock(cache_mutex());
  ZkMsmCache &cache = global_cache();
  PANIC_IF_FALSE(cache.ref_count == 0,
                 "zk_msm_cache_reset: called with %u outstanding references",
                 cache.ref_count);
  cache_free_resources(cache);
}
