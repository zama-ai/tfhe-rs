#include "../common.cuh"
#include "checked_arithmetic.h"
#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <algorithm>
#include <type_traits>
#include <vector>

// ============================================================================
// Kernel Launch Parameter Helpers
// ============================================================================

// Phase 1: Helper structure for accumulate_all_windows kernel launch parameters
template <typename AffineType> struct Phase1KernelLaunchParams {
  uint32_t adjusted_threads_per_block;
  uint32_t num_blocks_per_window;
  size_t accum_shared_mem;

  Phase1KernelLaunchParams(uint32_t n, uint32_t requested_threads_per_block,
                           uint32_t bucket_count, uint32_t gpu_index) {
    // Shared memory layout:
    // - bucket_counts:  [bucket_count] * sizeof(uint32_t)
    // - bucket_offsets: [bucket_count] * sizeof(uint32_t)
    // - sorted_points:  [threads_per_block] * sizeof(AffineType)
    //
    // sorted_points starts at 2*bucket_count uint32_t slots. Since
    // bucket_count = 2^(c-1)+1 (always odd), 2*bucket_count is always even,
    // so the byte offset 2*bucket_count*4 is always a multiple of 8.
    // No alignment padding is needed.
    const size_t fixed_shared_mem = 2 * bucket_count * sizeof(uint32_t);
    constexpr size_t per_thread_shared_mem = sizeof(AffineType);

    const uint32_t max_shared_mem_per_block =
        cuda_get_max_shared_memory_per_block(gpu_index);

    const size_t available_shared_mem =
        (max_shared_mem_per_block > fixed_shared_mem)
            ? (max_shared_mem_per_block - fixed_shared_mem)
            : 0;
    const uint32_t max_threads_for_shared_mem =
        available_shared_mem / per_thread_shared_mem;

    adjusted_threads_per_block =
        std::min(requested_threads_per_block, max_threads_for_shared_mem);

    PANIC_IF_FALSE(adjusted_threads_per_block > 0,
                   "Phase1KernelLaunchParams: insufficient shared memory for "
                   "kernel launch (max_shared=%u, fixed=%zu)",
                   max_shared_mem_per_block, fixed_shared_mem);

    num_blocks_per_window = CEIL_DIV(n, adjusted_threads_per_block);
    accum_shared_mem =
        fixed_shared_mem + adjusted_threads_per_block * per_thread_shared_mem;
  }
};

// Phase 2: Helper structure for reduce_all_windows kernel launch parameters
template <typename ProjectiveType> struct Phase2KernelLaunchParams {
  uint32_t adjusted_threads;
  size_t shared_mem;

  Phase2KernelLaunchParams(uint32_t requested_threads, uint32_t gpu_index) {
    const uint32_t max_shared_mem_per_block =
        cuda_get_max_shared_memory_per_block(gpu_index);

    const uint32_t max_threads_for_shared =
        max_shared_mem_per_block / sizeof(ProjectiveType);

    uint32_t threads = std::min(requested_threads, max_threads_for_shared);
    threads = std::min(threads, static_cast<uint32_t>(KERNEL_THREADS_MAX));

    // Round up to nearest power of 2 (required for tree reduction)
    uint32_t pow2_threads = 1;
    while (pow2_threads < threads)
      pow2_threads *= 2;

    if (safe_mul_sizeof<ProjectiveType>(static_cast<size_t>(pow2_threads)) >
        max_shared_mem_per_block) {
      pow2_threads /= 2;
    }
    adjusted_threads = pow2_threads;
    shared_mem =
        safe_mul_sizeof<ProjectiveType>(static_cast<size_t>(adjusted_threads));
  }
};

// ============================================================================
// Pippenger Algorithm MSM kernels and helpers
// ============================================================================
// Template kernels are defined in msm/common.cuh

// Helper function to extract a window from a multi-limb scalar (internal)
__device__ __forceinline__ uint32_t extract_window_multi_internal(
    const UNSIGNED_LIMB *scalar, uint32_t scalar_limbs, uint32_t window_idx,
    uint32_t window_size) {
  const uint32_t total_bits = scalar_limbs * LIMB_BITS;
  const uint32_t bit_offset = window_idx * window_size;
  if (bit_offset >= total_bits)
    return 0;

  const uint32_t limb_idx = bit_offset / LIMB_BITS;
  const uint32_t bit_in_limb = bit_offset % LIMB_BITS;

  if (limb_idx >= scalar_limbs)
    return 0;

  const UNSIGNED_LIMB mask = (1ULL << window_size) - 1;
  UNSIGNED_LIMB window = (scalar[limb_idx] >> bit_in_limb) & mask;

  // If window spans two limbs, combine them
  if (bit_in_limb + window_size > LIMB_BITS && limb_idx + 1 < scalar_limbs) {
    const uint32_t bits_from_next = (bit_in_limb + window_size) - LIMB_BITS;
    const UNSIGNED_LIMB next_bits =
        scalar[limb_idx + 1] & ((1ULL << bits_from_next) - 1);
    window |= (next_bits << (window_size - bits_from_next));
  }

  return static_cast<uint32_t>(window);
}

// Wrapper for external API (scalar is uint64_t* from FFI)
// Handles conversion from 64-bit limbs to UNSIGNED_LIMB
__device__ __forceinline__ uint32_t
extract_window_multi(const uint64_t *scalar, uint32_t scalar_limbs_64,
                     uint32_t window_idx, uint32_t window_size) {
  // Byte layout is identical on little-endian, so we can reinterpret_cast
  // and adjust the limb count
  const UNSIGNED_LIMB *scalar_native =
      reinterpret_cast<const UNSIGNED_LIMB *>(scalar);
  const uint32_t scalar_limbs_native = scalar_limbs_64 * (64 / LIMB_BITS);
  return extract_window_multi_internal(scalar_native, scalar_limbs_native,
                                       window_idx, window_size);
}

// Helper function to extract a window from a BigInt scalar
__device__ __forceinline__ uint32_t extract_window_bigint(
    const Scalar &scalar, uint32_t window_idx, uint32_t window_size) {
  return extract_window_multi_internal(scalar.limb, ZP_LIMBS, window_idx,
                                       window_size);
}

// ============================================================================
// Preprocessing kernel: scalar → signed-digit representation
// ============================================================================
//
// Converts each scalar into balanced signed-digit form before the main MSM,
// eliminating any need for a correction term.
//
// For each window w (LSB-first, w=0 = least significant), with carry from the
// previous window:
//
//   effective = raw_digit + carry
//   if effective > half:   digit = effective - 2^c  (negative), carry = 1
//   else:                  digit = effective         (zero or positive), carry
//   = 0
//
// where half = 2^(c-1), c = window_size.
//
// Result: digit ∈ {-(half-1), …, half}, so |digit| ≤ half = bucket_count - 1.
// Positive digit → add point P to bucket[digit].
// Negative digit → add -P (Y-negated) to bucket[|digit|].
// Zero digit     → skip.
//
// Output layout: d_signed_digits[window_idx * n + point_idx], where window_idx
// is in Horner (MSB-first) order so the main kernel indexes it directly.
// This layout is column-major in window_idx: threads in a warp (consecutive
// point_idx) access the same window row → coalesced reads in the main kernel.
//
// num_windows is set to (scalar_bits + window_size) / window_size so there is
// always at least one partial or empty window at the top to absorb any carry
// propagated out of the last full window.
__global__ void kernel_preprocess_signed_digits(
    int8_t *__restrict__ d_signed_digits, // [num_windows * n], Horner-ordered
    const Scalar *__restrict__ d_scalars, uint32_t n, uint32_t num_windows,
    uint32_t window_size) {
  const uint32_t point_idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (point_idx >= n)
    return;

  const uint32_t half = 1u << (window_size - 1);
  const uint32_t full = 1u << window_size;

  const Scalar &scalar = d_scalars[point_idx];
  uint32_t carry = 0;

  // Iterate windows LSB-first so carry flows correctly from low to high.
  for (uint32_t w = 0; w < num_windows; w++) {
    uint32_t raw = extract_window_bigint(scalar, w, window_size);
    uint32_t effective = raw + carry;
    carry = 0;

    int8_t sd;
    if (effective > half) {
      carry = 1;
      sd = -(int8_t)(full - effective); // negative balanced digit
    } else {
      sd = (int8_t)effective; // zero or positive digit
    }

    // Remap LSB-first index w to MSB-first kernel window_idx:
    //   window_idx = num_windows - 1 - w
    d_signed_digits[(num_windows - 1 - w) * (size_t)n + point_idx] = sd;
  }
  // carry == 0 guaranteed: the extra top window absorbs any final carry.
}

// ============================================================================
// Phase 1: Accumulate all windows in parallel using sort-then-reduce
// ============================================================================
//
// Grid: (num_windows * num_blocks_per_window) blocks.
// Each block processes a slice of points for ONE window.
//
// The signed digit for each point has already been computed by
// kernel_preprocess_signed_digits. Negative digits mean the point's Y was
// pre-negated in the preprocessing step — here we just negate it inline before
// scattering, which is cheaper than reading a separate flag array.
//
// Shared memory layout (no sorted_buckets — not needed without correction):
//   [bucket_counts (bc)] [bucket_offsets (bc)] [sorted_points (blockDim.x)]
template <typename AffineType, typename ProjectiveType>
__global__ void kernel_accumulate_all_windows(
    ProjectiveType *__restrict__ all_block_buckets, // [num_windows * num_blocks
                                                    // * bucket_count]
    const AffineType *__restrict__ points,
    const int8_t *__restrict__ d_signed_digits, // [num_windows * n]
    uint32_t num_points, uint32_t num_windows, uint32_t num_blocks_per_window,
    uint32_t bucket_count) {
  using ProjectivePoint = Projective<ProjectiveType>;
  using XYZZType = typename XYZZFor<ProjectiveType>::Type;
  using XYZZPoint = XYZZ<XYZZType>;

  const uint32_t window_idx = blockIdx.x / num_blocks_per_window;
  const uint32_t block_within_window = blockIdx.x % num_blocks_per_window;

  if (window_idx >= num_windows)
    return;

  uint32_t bucket_offset =
      (window_idx * num_blocks_per_window + block_within_window) * bucket_count;
  ProjectiveType *my_buckets = all_block_buckets + bucket_offset;

  // Shared memory: [bucket_counts][bucket_offsets][sorted_points]
  extern __shared__ char shared_mem[];
  auto *bucket_counts_arr = reinterpret_cast<uint32_t *>(shared_mem);
  auto *bucket_offsets_arr = bucket_counts_arr + bucket_count;
  auto *sorted_points =
      reinterpret_cast<AffineType *>(bucket_offsets_arr + bucket_count);

  if (threadIdx.x < bucket_count) {
    bucket_counts_arr[threadIdx.x] = 0;
  }
  __syncthreads();

  // Each thread reads its signed digit and loads its affine point.
  // Negative digit: negate Y and use |digit| as bucket index.
  // Zero digit:     skip (my_bucket = 0).
  const uint32_t point_idx = threadIdx.x + block_within_window * blockDim.x;
  AffineType my_point;
  uint32_t my_bucket = 0;
  const bool valid = point_idx < num_points;

  if (valid) {
    const int8_t sd =
        d_signed_digits[window_idx * (size_t)num_points + point_idx];
    my_point = points[point_idx];

    if (sd < 0) {
      my_point.y = -my_point.y; // negate Y for negative digit
      my_bucket = (uint32_t)(-sd);
    } else {
      my_bucket = (uint32_t)sd; // 0 means skip
    }
  }

  if (valid && my_bucket > 0) {
    atomicAdd(&bucket_counts_arr[my_bucket], 1);
  }
  __syncthreads();

  // Thread 0 computes prefix sums (bucket start offsets).
  if (threadIdx.x == 0) {
    uint32_t offset = 0;
    for (uint32_t b = 0; b < bucket_count; b++) {
      bucket_offsets_arr[b] = offset;
      offset += bucket_counts_arr[b];
      bucket_counts_arr[b] = 0; // reset to zero for use as a scatter counter
    }
  }
  __syncthreads();

  // Scatter: each thread writes its (possibly Y-negated) point into the sorted
  // position for its bucket.
  if (valid && my_bucket > 0) {
    uint32_t pos = bucket_offsets_arr[my_bucket] +
                   atomicAdd(&bucket_counts_arr[my_bucket], 1);
    sorted_points[pos] = my_point;
  }
  __syncthreads();

  // Bucket reduction: each thread owns one or more buckets (stride by
  // blockDim.x). Points for bucket b occupy sorted_points[start..start+count].
  for (uint32_t bucket = threadIdx.x + 1; bucket < bucket_count;
       bucket += blockDim.x) {
    const uint32_t start = bucket_offsets_arr[bucket];
    const uint32_t count = bucket_counts_arr[bucket];

    if (count == 0) {
      ProjectivePoint::point_at_infinity(my_buckets[bucket]);
      continue;
    }

    XYZZType sum;
    XYZZPoint::point_at_infinity(sum);
    for (uint32_t i = 0; i < count; i++) {
      XYZZPoint::mixed_add(sum, sorted_points[start + i]);
    }

    ProjectiveType proj;
    XYZZPoint::to_projective(proj, sum);
    ProjectivePoint::point_copy(my_buckets[bucket], proj);
  }
}

// Kernel: Reduce ALL windows' buckets in parallel
// Grid: (num_windows * num_buckets) blocks
// Each block reduces one (window, bucket) pair across all block contributions
template <typename ProjectiveType>
__global__ void kernel_reduce_all_windows(
    ProjectiveType
        *__restrict__ all_final_buckets, // [num_windows * NUM_BUCKETS]
    const ProjectiveType
        *__restrict__ all_block_buckets, // [num_windows * num_blocks *
                                         // NUM_BUCKETS]
    uint32_t num_windows, uint32_t num_blocks_per_window,
    uint32_t num_buckets) {
  using ProjectivePoint = Projective<ProjectiveType>;

  const uint32_t flat_idx = blockIdx.x;
  const uint32_t window_idx = flat_idx / num_buckets;
  const uint32_t bucket_idx = flat_idx % num_buckets;

  if (window_idx >= num_windows || bucket_idx == 0)
    return;

  extern __shared__ char shared_mem[];
  auto *shared_sums = reinterpret_cast<ProjectiveType *>(shared_mem);

  ProjectiveType local_sum;
  ProjectivePoint::point_at_infinity(local_sum);

  // Each thread sums a subset of block contributions
  for (uint32_t block = threadIdx.x; block < num_blocks_per_window;
       block += blockDim.x) {
    uint32_t idx =
        (window_idx * num_blocks_per_window + block) * num_buckets + bucket_idx;
    const ProjectiveType &contrib = all_block_buckets[idx];
    if (!ProjectivePoint::is_infinity(contrib)) {
      if (ProjectivePoint::is_infinity(local_sum)) {
        ProjectivePoint::point_copy(local_sum, contrib);
      } else {
        ProjectiveType temp;
        ProjectivePoint::projective_add(temp, local_sum, contrib);
        ProjectivePoint::point_copy(local_sum, temp);
      }
    }
  }

  shared_sums[threadIdx.x] = local_sum;
  __syncthreads();

  // Tree reduction
  for (uint32_t s = blockDim.x / 2; s > 0; s >>= 1) {
    if (threadIdx.x < s &&
        !ProjectivePoint::is_infinity(shared_sums[threadIdx.x + s])) {
      if (ProjectivePoint::is_infinity(shared_sums[threadIdx.x])) {
        ProjectivePoint::point_copy(shared_sums[threadIdx.x],
                                    shared_sums[threadIdx.x + s]);
      } else {
        ProjectiveType temp;
        ProjectivePoint::projective_add(temp, shared_sums[threadIdx.x],
                                        shared_sums[threadIdx.x + s]);
        ProjectivePoint::point_copy(shared_sums[threadIdx.x], temp);
      }
    }
    __syncthreads();
  }

  if (threadIdx.x == 0) {
    uint32_t out_idx = window_idx * num_buckets + bucket_idx;
    ProjectivePoint::point_copy(all_final_buckets[out_idx], shared_sums[0]);
  }
}

// Kernel: Compute window sums for ALL windows in parallel
// Grid: num_windows blocks
// Each block computes the window sum: sum(i * bucket[i]) for i=1..n
template <typename ProjectiveType>
__global__ void kernel_compute_window_sums(
    ProjectiveType *__restrict__ window_sums, // [num_windows]
    const ProjectiveType
        *__restrict__ all_final_buckets, // [num_windows * NUM_BUCKETS]
    uint32_t num_windows, uint32_t num_buckets) {
  using ProjectivePoint = Projective<ProjectiveType>;

  const uint32_t window_idx = blockIdx.x;
  if (window_idx >= num_windows)
    return;

  extern __shared__ char shared_mem[];
  auto *work = reinterpret_cast<ProjectiveType *>(shared_mem);

  const uint32_t tid = threadIdx.x;
  const uint32_t n = num_buckets - 1;

  // Load buckets for this window
  const ProjectiveType *my_buckets =
      all_final_buckets + window_idx * num_buckets;

  if (tid < n) {
    ProjectivePoint::point_copy(work[tid], my_buckets[tid + 1]);
  }
  __syncthreads();

  // Suffix sum
  for (uint32_t stride = 1; stride < n; stride *= 2) {
    ProjectiveType temp;
    if (tid < n) {
      if (tid + stride < n &&
          !ProjectivePoint::is_infinity(work[tid + stride])) {
        if (ProjectivePoint::is_infinity(work[tid])) {
          ProjectivePoint::point_copy(temp, work[tid + stride]);
        } else {
          ProjectivePoint::projective_add(temp, work[tid], work[tid + stride]);
        }
      } else {
        ProjectivePoint::point_copy(temp, work[tid]);
      }
    }
    __syncthreads();
    if (tid < n) {
      ProjectivePoint::point_copy(work[tid], temp);
    }
    __syncthreads();
  }

  // Reduction
  for (uint32_t stride = (n + 1) / 2; stride > 0;
       stride = (stride > 1) ? (stride + 1) / 2 : 0) {
    if (tid < stride && tid + stride < n) {
      if (!ProjectivePoint::is_infinity(work[tid + stride])) {
        if (ProjectivePoint::is_infinity(work[tid])) {
          ProjectivePoint::point_copy(work[tid], work[tid + stride]);
        } else {
          ProjectiveType temp;
          ProjectivePoint::projective_add(temp, work[tid], work[tid + stride]);
          ProjectivePoint::point_copy(work[tid], temp);
        }
      }
    }
    __syncthreads();
    if (stride == 1)
      break;
  }

  if (tid == 0) {
    ProjectivePoint::point_copy(window_sums[window_idx], work[0]);
  }
}

// ============================================================================
// CPU Horner Combination
// ============================================================================

// Combines window sums using Horner's method on the CPU. A single CPU core
// native 64-bit multiply is much faster than a single GPU thread for this
// workload. The CPU path takes ~0.1 ms; a <<<1,1>>> GPU kernel takes ~10-12 ms.
//
// Horner evaluation (MSB-first):
//   acc = window_sums[0]
//   for w = 1 .. num_windows-1:
//     acc = acc * 2^window_size + window_sums[w]
template <typename ProjectiveType>
void horner_combine_cpu(ProjectiveType &result,
                        const ProjectiveType *window_sums, uint32_t num_windows,
                        uint32_t window_size) {
  using ProjectivePoint = Projective<ProjectiveType>;

  ProjectiveType acc;
  ProjectivePoint::point_at_infinity(acc);

  for (uint32_t w = 0; w < num_windows; w++) {
    const ProjectiveType &ws = window_sums[w];
    ProjectiveType temp;

    if (!ProjectivePoint::is_infinity(ws)) {
      if (ProjectivePoint::is_infinity(acc)) {
        ProjectivePoint::point_copy(acc, ws);
      } else {
        for (uint32_t i = 0; i < window_size; i++) {
          ProjectivePoint::projective_double(temp, acc);
          ProjectivePoint::point_copy(acc, temp);
        }
        ProjectivePoint::projective_add(temp, acc, ws);
        ProjectivePoint::point_copy(acc, temp);
      }
    } else if (!ProjectivePoint::is_infinity(acc)) {
      for (uint32_t i = 0; i < window_size; i++) {
        ProjectivePoint::projective_double(temp, acc);
        ProjectivePoint::point_copy(acc, temp);
      }
    }
  }

  ProjectivePoint::point_copy(result, acc);
}

// ============================================================================
// Pippenger MSM Implementation Functions
// ============================================================================

// Template MSM with BigInt scalars - ALL WINDOWS PARALLEL
// Result is written directly to a host pointer -- no device round-trip needed.
// d_scratch: caller-provided device buffer for intermediate bucket arrays and
// window sums. The caller is responsible for allocating and freeing this
// buffer.
//
// Scratch layout (all ProjectiveType elements):
//   d_all_block_buckets  [num_windows * num_blocks * bucket_count]
//   d_all_final_buckets  [num_windows * bucket_count]
//   d_window_sums        [num_windows]
//
// d_signed_digits is allocated internally (stream-ordered) and freed before
// the host memcpy, so it does not appear in the caller's scratch buffer.
template <typename AffineType, typename ProjectiveType>
void point_msm_pippenger_impl_async(cudaStream_t stream, uint32_t gpu_index,
                                    ProjectiveType *h_result,
                                    const AffineType *d_points,
                                    const Scalar *d_scalars, uint32_t n,
                                    uint32_t threads_per_block,
                                    uint32_t window_size, uint32_t bucket_count,
                                    ProjectiveType *d_scratch) {
  using ProjectivePoint = Projective<ProjectiveType>;

  if (n == 0) {
    ProjectivePoint::point_at_infinity(*h_result);
    return;
  }

  PANIC_IF_FALSE(h_result != nullptr && d_points != nullptr &&
                     d_scalars != nullptr && d_scratch != nullptr,
                 "point_msm_pippenger_impl_async: null pointer argument");

  cuda_set_device(gpu_index);

  // Compute number of windows. We use (scalar_bits + window_size) / window_size
  // instead of the usual ceil formula so that there is always at least one
  // partial window at the top. This guarantees the preprocessing kernel's carry
  // propagation never overflows the digit array, regardless of window size.
  const uint32_t total_bits = Scalar::NUM_BITS;
  const uint32_t num_windows = (total_bits + window_size) / window_size;

  Phase1KernelLaunchParams<AffineType> launch_params(n, threads_per_block,
                                                     bucket_count, gpu_index);

  // Scratch layout
  const size_t num_blocks = launch_params.num_blocks_per_window;
  const size_t all_block_buckets_size =
      static_cast<size_t>(num_windows) * num_blocks * bucket_count;
  const size_t all_final_buckets_size =
      static_cast<size_t>(num_windows) * bucket_count;
  const size_t total_scratch =
      all_block_buckets_size + all_final_buckets_size + num_windows;

  ProjectiveType *d_all_block_buckets = d_scratch;
  ProjectiveType *d_all_final_buckets = d_scratch + all_block_buckets_size;
  ProjectiveType *d_window_sums = d_all_final_buckets + all_final_buckets_size;

  const uint32_t clear_blocks = CEIL_DIV(total_scratch, KERNEL_THREADS_MAX);
  PANIC_IF_FALSE(clear_blocks * KERNEL_THREADS_MAX >= total_scratch,
                 "kernel_clear_buckets: insufficient threads (%zu) to clear "
                 "buffer (%zu elements)",
                 static_cast<size_t>(clear_blocks) * KERNEL_THREADS_MAX,
                 total_scratch);
  kernel_clear_buckets<ProjectiveType>
      <<<clear_blocks, KERNEL_THREADS_MAX, 0, stream>>>(d_scratch,
                                                        total_scratch);
  check_cuda_error(cudaGetLastError());

  // Preprocessing: convert scalars to signed-digit form.
  // Allocated stream-ordered; freed before the CPU phase once Phase 1 is done.
  int8_t *d_signed_digits = nullptr;
  const size_t signed_digits_bytes =
      static_cast<size_t>(num_windows) * n * sizeof(int8_t);
  cudaMallocAsync(&d_signed_digits, signed_digits_bytes, stream);
  check_cuda_error(cudaGetLastError());

  constexpr uint32_t preprocess_threads = 128;
  const uint32_t preprocess_blocks = CEIL_DIV(n, preprocess_threads);
  kernel_preprocess_signed_digits<<<preprocess_blocks, preprocess_threads, 0,
                                    stream>>>(d_signed_digits, d_scalars, n,
                                              num_windows, window_size);
  check_cuda_error(cudaGetLastError());

  // Phase 1: Accumulate ALL windows in parallel.
  const uint32_t total_accum_blocks =
      num_windows * launch_params.num_blocks_per_window;
  PANIC_IF_FALSE(
      static_cast<size_t>(total_accum_blocks) * bucket_count <=
          all_block_buckets_size,
      "kernel_accumulate_all_windows: max write index (%zu) exceeds buffer "
      "(%zu)",
      static_cast<size_t>(total_accum_blocks) * bucket_count,
      all_block_buckets_size);
  kernel_accumulate_all_windows<AffineType, ProjectiveType>
      <<<total_accum_blocks, launch_params.adjusted_threads_per_block,
         launch_params.accum_shared_mem, stream>>>(
          d_all_block_buckets, d_points, d_signed_digits, n, num_windows,
          launch_params.num_blocks_per_window, bucket_count);
  check_cuda_error(cudaGetLastError());

  // d_signed_digits is no longer needed after Phase 1.
  cudaFreeAsync(d_signed_digits, stream);
  check_cuda_error(cudaGetLastError());

  // Phase 2: Reduce ALL windows' buckets in parallel.
  const uint32_t total_reduce_blocks = num_windows * bucket_count;
  Phase2KernelLaunchParams<ProjectiveType> reduce_params(
      launch_params.num_blocks_per_window, gpu_index);
  PANIC_IF_FALSE(
      total_reduce_blocks <= all_final_buckets_size,
      "kernel_reduce_all_windows: blocks (%u) exceeds output buffer (%zu)",
      total_reduce_blocks, all_final_buckets_size);
  kernel_reduce_all_windows<ProjectiveType>
      <<<total_reduce_blocks, reduce_params.adjusted_threads,
         reduce_params.shared_mem, stream>>>(
          d_all_final_buckets, d_all_block_buckets, num_windows,
          launch_params.num_blocks_per_window, bucket_count);
  check_cuda_error(cudaGetLastError());

  // Phase 3: Compute window sums in parallel.
  const uint32_t combine_threads = ((bucket_count - 1) + 31) & ~31u;
  const size_t combine_shared_mem =
      safe_mul_sizeof<ProjectiveType>(static_cast<size_t>(combine_threads));
  PANIC_IF_FALSE(num_windows * bucket_count <= all_final_buckets_size,
                 "kernel_compute_window_sums: max read index (%zu) exceeds "
                 "input buffer (%zu)",
                 static_cast<size_t>(num_windows) * bucket_count,
                 all_final_buckets_size);
  kernel_compute_window_sums<ProjectiveType>
      <<<num_windows, combine_threads, combine_shared_mem, stream>>>(
          d_window_sums, d_all_final_buckets, num_windows, bucket_count);
  check_cuda_error(cudaGetLastError());

  // Phase 4: CPU Horner combine, result written directly to host pointer.
  std::vector<ProjectiveType> h_window_sums(num_windows);
  cuda_memcpy_async_to_cpu(
      h_window_sums.data(), d_window_sums,
      safe_mul_sizeof<ProjectiveType>(static_cast<size_t>(num_windows)), stream,
      gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  horner_combine_cpu(*h_result, h_window_sums.data(), num_windows, window_size);
}

// ============================================================================
// Dynamic Window Size Selection
// ============================================================================

// Select optimal window size for G1 MSM based on input count.
//
// Signed-digit preprocessing keeps the same window size as unsigned Pippenger
// but halves the bucket count: bucket_count = 2^(c-1) + 1 instead of 2^c.
// Fewer buckets speed up Phase 2 (cross-block reduce) and Phase 3 (window sum
// suffix-scan), with no correction term overhead.
//
// n = bucket_count - 1 must be a power of 2 for kernel_compute_window_sums:
//   c=4 → half=8,  bc=9,  n=8=2^3  ✓
//   c=5 → half=16, bc=17, n=16=2^4 ✓
//   c=6 → half=32, bc=33, n=32=2^5 ✓
inline void get_g1_window_params(uint32_t n, uint32_t &window_size,
                                 uint32_t &bucket_count) {
  // Signed-digit: same c as original unsigned Pippenger, but bucket_count
  // = 2^(c-1)+1 instead of 2^c. This halves Phase 2/3 work at no extra cost.
  if (n <= MSM_G1_SMALL_THRESHOLD) {
    window_size = 4;
    bucket_count = (1u << 3) + 1; // 9 = 2^3+1
  } else if (n <= MSM_G1_MEDIUM_THRESHOLD) {
    window_size = 5;
    bucket_count = (1u << 4) + 1; // 17 = 2^4+1
  } else {
    window_size = 6;
    bucket_count = (1u << 5) + 1; // 33 = 2^5+1
  }
}

// Select optimal window size for G2 MSM.
//
// G2 Phase 1 is memory-bandwidth bound: only 1 block fits per SM (shared mem
// limit). With c=5, bc=17 only 16 threads are active in the bucket reduce
// (half-warp), causing regression vs the original bc=32 (31 active).
//
// c=6, bc=33 gives exactly 32 active threads (full first warp, same as c=6
// G1), keeps Phase 1 cost identical to the original bc=32, and reduces windows
// from 64 → 54 (15.6% fewer). 54×6=324 > 320 so the last window is partial
// and carry never overflows — no extra window needed.
inline void get_g2_window_params(uint32_t n, uint32_t &window_size,
                                 uint32_t &bucket_count) {
  (void)n;
  window_size = 6;
  bucket_count = (1u << 5) + 1; // 33 = 2^5+1
}

// ============================================================================
// Scratch Size Computation
// ============================================================================
// Computes the exact scratch buffer size (in bytes) needed by
// point_msm_pippenger_impl_async for a given input count n. The formula must
// stay in sync with the scratch partitioning inside that function:
//   all_block_buckets:  num_windows * num_blocks * bucket_count
//   all_final_buckets:  num_windows * bucket_count
//   window_sums:        num_windows
//
// d_signed_digits is allocated internally (stream-ordered) and is NOT included
// here; callers only need to provide the ProjectiveType scratch buffer.
template <typename AffineType, typename ProjectiveType>
size_t pippenger_scratch_size(uint32_t n, uint32_t gpu_index) {
  if (n == 0)
    return 0;

  uint32_t window_size, bucket_count;
  if constexpr (std::is_same_v<AffineType, G1Affine>) {
    get_g1_window_params(n, window_size, bucket_count);
  } else {
    get_g2_window_params(n, window_size, bucket_count);
  }

  const uint32_t threads_per_block = msm_threads_per_block<AffineType>(n);
  const uint32_t num_windows = (Scalar::NUM_BITS + window_size) / window_size;

  Phase1KernelLaunchParams<AffineType> launch_params(n, threads_per_block,
                                                     bucket_count, gpu_index);

  const size_t num_blocks =
      static_cast<size_t>(launch_params.num_blocks_per_window);
  const size_t all_block_buckets_elems =
      static_cast<size_t>(num_windows) * num_blocks * bucket_count;
  const size_t all_final_buckets_elems =
      static_cast<size_t>(num_windows) * bucket_count;
  const size_t total_elems =
      all_block_buckets_elems + all_final_buckets_elems + num_windows;

  return safe_mul_sizeof<ProjectiveType>(total_elems);
}

// Non-template wrappers so callers outside this TU (c_wrapper.cu, tests, etc.)
// can compute the correct scratch size without access to template internals.
size_t pippenger_scratch_size_g1(uint32_t n, uint32_t gpu_index) {
  return pippenger_scratch_size<G1Affine, G1Projective>(n, gpu_index);
}

size_t pippenger_scratch_size_g2(uint32_t n, uint32_t gpu_index) {
  return pippenger_scratch_size<G2Point, G2ProjectivePoint>(n, gpu_index);
}

// MSM with BigInt scalars for G1 (projective coordinates internally)
void point_msm_g1_pippenger_async(cudaStream_t stream, uint32_t gpu_index,
                                  G1Projective *h_result,
                                  const G1Affine *d_points,
                                  const Scalar *d_scalars, uint32_t n,
                                  G1Projective *d_scratch) {
  uint32_t window_size, bucket_count;
  get_g1_window_params(n, window_size, bucket_count);

  point_msm_pippenger_impl_async<G1Affine, G1Projective>(
      stream, gpu_index, h_result, d_points, d_scalars, n,
      msm_threads_per_block<G1Affine>(n), window_size, bucket_count, d_scratch);
}

// MSM with BigInt scalars for G2 (projective coordinates internally)
// Uses larger window size to reduce Horner doublings (G2 ops are 2x more
// expensive)
void point_msm_g2_pippenger_async(cudaStream_t stream, uint32_t gpu_index,
                                  G2ProjectivePoint *h_result,
                                  const G2Point *d_points,
                                  const Scalar *d_scalars, uint32_t n,
                                  G2ProjectivePoint *d_scratch) {
  uint32_t window_size, bucket_count;
  get_g2_window_params(n, window_size, bucket_count);

  point_msm_pippenger_impl_async<G2Point, G2ProjectivePoint>(
      stream, gpu_index, h_result, d_points, d_scalars, n,
      msm_threads_per_block<G2Point>(n), window_size, bucket_count, d_scratch);
}
