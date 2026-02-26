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
    // - bucket_counts: [bucket_count] * sizeof(uint32_t)
    // - bucket_offsets: [bucket_count] * sizeof(uint32_t)
    // - sorted_points: [threads_per_block] * sizeof(AffineType)
    // - sorted_buckets: [threads_per_block] * sizeof(uint32_t)
    constexpr size_t per_thread_shared_mem =
        sizeof(AffineType) + sizeof(uint32_t); // sorted_points + sorted_buckets
    const size_t fixed_shared_mem =
        2 * bucket_count * sizeof(uint32_t); // bucket_counts + bucket_offsets

    // Query the actual per-block shared memory limit from the device
    const uint32_t max_shared_mem_per_block =
        cuda_get_max_shared_memory_per_block(gpu_index);

    // Calculate maximum threads that fit within shared memory limit
    const size_t available_shared_mem =
        (max_shared_mem_per_block > fixed_shared_mem)
            ? (max_shared_mem_per_block - fixed_shared_mem)
            : 0;
    const uint32_t max_threads_for_shared_mem =
        available_shared_mem / per_thread_shared_mem;

    // Cap threads_per_block to respect shared memory limit
    adjusted_threads_per_block =
        std::min(requested_threads_per_block, max_threads_for_shared_mem);

    PANIC_IF_FALSE(adjusted_threads_per_block > 0,
                   "Phase1KernelLaunchParams: insufficient shared memory for "
                   "kernel launch (max_shared=%u, fixed=%zu)",
                   max_shared_mem_per_block, fixed_shared_mem);

    // Calculate number of blocks per window
    num_blocks_per_window = CEIL_DIV(n, adjusted_threads_per_block);

    // Calculate actual shared memory requirement
    accum_shared_mem =
        fixed_shared_mem + adjusted_threads_per_block * per_thread_shared_mem;
  }
};

// Phase 2: Helper structure for reduce_all_windows kernel launch parameters
template <typename ProjectiveType> struct Phase2KernelLaunchParams {
  uint32_t adjusted_threads;
  size_t shared_mem;

  Phase2KernelLaunchParams(uint32_t requested_threads, uint32_t gpu_index) {
    // Query the actual per-block shared memory limit from the device
    const uint32_t max_shared_mem_per_block =
        cuda_get_max_shared_memory_per_block(gpu_index);

    // Calculate maximum threads that fit within shared memory limit
    const uint32_t max_threads_for_shared =
        max_shared_mem_per_block / sizeof(ProjectiveType);

    // Cap threads to respect shared memory limit
    uint32_t threads = std::min(requested_threads, max_threads_for_shared);
    threads = std::min(threads, static_cast<uint32_t>(KERNEL_THREADS_MAX));

    // Round up to nearest power of 2 (required for tree reduction)
    uint32_t pow2_threads = 1;
    while (pow2_threads < threads)
      pow2_threads *= 2;

    // After rounding to power of 2, verify shared memory doesn't exceed device
    // limit
    if (safe_mul_sizeof<ProjectiveType>(static_cast<size_t>(pow2_threads)) >
        max_shared_mem_per_block) {
      pow2_threads /= 2;
    }
    adjusted_threads = pow2_threads;

    // Calculate actual shared memory requirement
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

// Kernel: Accumulate ALL windows in parallel using SORT-THEN-REDUCE
// Grid: (num_windows * num_blocks_per_window) blocks
// Each block processes points for ONE window
// Uses counting sort by bucket, then parallel tree reduction per bucket
// Uses mixed addition (affine + projective) to save 3 field muls per add
template <typename AffineType, typename ProjectiveType>
__global__ void kernel_accumulate_all_windows(
    ProjectiveType *__restrict__ all_block_buckets, // [num_windows * num_blocks
                                                    // * bucket_count]
    const AffineType *__restrict__ points, const Scalar *__restrict__ scalars,
    uint32_t num_points, uint32_t num_windows, uint32_t num_blocks_per_window,
    uint32_t window_size, uint32_t bucket_count) {
  using ProjectivePoint = Projective<ProjectiveType>;

  const uint32_t window_idx = blockIdx.x / num_blocks_per_window;
  const uint32_t block_within_window = blockIdx.x % num_blocks_per_window;

  if (window_idx >= num_windows)
    return;

  // Output offset for this block's buckets
  uint32_t bucket_offset =
      (window_idx * num_blocks_per_window + block_within_window) * bucket_count;
  ProjectiveType *my_buckets = all_block_buckets + bucket_offset;

  // Shared memory layout (register-based optimization):
  // - bucket_counts: [bucket_count] for counting sort
  // - bucket_offsets: [bucket_count] for prefix sums
  // - sorted_points: [blockDim.x] for sorted points (AFFINE - smaller!)
  // - sorted_buckets: [blockDim.x] for sorted bucket indices
  // NOTE: shared_buckets removed - using register-based accumulation instead
  extern __shared__ char shared_mem[];
  auto *bucket_counts_arr = reinterpret_cast<uint32_t *>(shared_mem);
  auto *bucket_offsets = bucket_counts_arr + bucket_count;
  // Store affine points instead of projective - saves shared memory
  auto *sorted_points =
      reinterpret_cast<AffineType *>(bucket_offsets + bucket_count);
  auto *sorted_buckets =
      reinterpret_cast<uint32_t *>(sorted_points + blockDim.x);

  // Initialize bucket counts
  if (threadIdx.x < bucket_count) {
    bucket_counts_arr[threadIdx.x] = 0;
  }
  __syncthreads();

  // Each thread loads its affine point and computes bucket index
  // No conversion to projective here - we keep points affine
  uint32_t point_idx = threadIdx.x + block_within_window * blockDim.x;
  AffineType my_point;
  uint32_t my_bucket = 0;
  bool valid = point_idx < num_points;

  if (valid) {
    uint32_t scalar_window = num_windows - 1 - window_idx;
    my_bucket =
        extract_window_bigint(scalars[point_idx], scalar_window, window_size);
    my_point = points[point_idx]; // Keep as affine!
  }

  // Count points per bucket (atomic within block)
  if (valid && my_bucket > 0) {
    atomicAdd(&bucket_counts_arr[my_bucket], 1);
  }
  __syncthreads();

  // Compute prefix sums for bucket offsets
  if (threadIdx.x == 0) {
    uint32_t offset = 0;
    for (uint32_t b = 0; b < bucket_count; b++) {
      bucket_offsets[b] = offset;
      offset += bucket_counts_arr[b];
      bucket_counts_arr[b] = 0; // Reset for scatter phase
    }
  }
  __syncthreads();

  // Scatter affine points to sorted positions
  if (valid && my_bucket > 0) {
    uint32_t pos =
        bucket_offsets[my_bucket] + atomicAdd(&bucket_counts_arr[my_bucket], 1);
    sorted_points[pos] = my_point; // Store affine point directly
    sorted_buckets[pos] = my_bucket;
  }
  __syncthreads();

  // Parallel tree reduction within each bucket using MIXED ADDITION
  // Each thread is assigned to reduce points in one bucket
  // REGISTER-BASED: Accumulate in registers, write directly to global memory
  for (uint32_t bucket = threadIdx.x + 1; bucket < bucket_count;
       bucket += blockDim.x) {
    uint32_t start = bucket_offsets[bucket];
    uint32_t count = bucket_counts_arr[bucket];

    if (count == 0) {
      // Empty bucket - write infinity point
      ProjectivePoint::point_at_infinity(my_buckets[bucket]);
      continue;
    }

    // Tree reduction for this bucket using mixed addition
    // Accumulate in registers (compiler will optimize this)
    ProjectiveType sum;
    // Initialize sum from first affine point
    const AffineType &first_point = sorted_points[start];
    if (first_point.infinity) {
      ProjectivePoint::point_at_infinity(sum);
    } else {
      ProjectivePoint::affine_to_projective(sum, first_point);
    }

    // Use mixed addition for remaining points (saves 3 muls per add!)
    for (uint32_t i = 1; i < count; i++) {
      const AffineType &pt = sorted_points[start + i];
      if (!pt.infinity) {
        if (ProjectivePoint::is_infinity(sum)) {
          ProjectivePoint::affine_to_projective(sum, pt);
        } else {
          ProjectiveType temp;
          // MIXED ADDITION: projective + affine (saves 3 field muls)
          ProjectivePoint::mixed_add(temp, sum, pt);
          ProjectivePoint::point_copy(sum, temp);
        }
      }
    }

    // Write directly from registers to global memory (no shared memory
    // intermediate)
    ProjectivePoint::point_copy(my_buckets[bucket], sum);
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

  // Thread 0 writes final bucket value
  if (threadIdx.x == 0) {
    uint32_t out_idx = window_idx * num_buckets + bucket_idx;
    ProjectivePoint::point_copy(all_final_buckets[out_idx], shared_sums[0]);
  }
}

// Kernel: Compute window sums for ALL windows in parallel
// Grid: num_windows blocks
// Each block computes the window sum: sum(i * bucket[i]) for i=1..15
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

  // Thread 0 writes window sum
  if (tid == 0) {
    ProjectivePoint::point_copy(window_sums[window_idx], work[0]);
  }
}

// ============================================================================
// CPU Horner Combination + GPU Result Upload
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

  // Process from MSB (window 0) to LSB (window num_windows-1)
  for (uint32_t w = 0; w < num_windows; w++) {
    const ProjectiveType &ws = window_sums[w];
    ProjectiveType temp;

    if (!ProjectivePoint::is_infinity(ws)) {
      if (ProjectivePoint::is_infinity(acc)) {
        ProjectivePoint::point_copy(acc, ws);
      } else {
        // acc = acc * 2^window_size + ws
        for (uint32_t i = 0; i < window_size; i++) {
          ProjectivePoint::projective_double(temp, acc);
          ProjectivePoint::point_copy(acc, temp);
        }
        ProjectivePoint::projective_add(temp, acc, ws);
        ProjectivePoint::point_copy(acc, temp);
      }
    } else if (!ProjectivePoint::is_infinity(acc)) {
      // Window sum is infinity but accumulator is not -- still shift left
      for (uint32_t i = 0; i < window_size; i++) {
        ProjectivePoint::projective_double(temp, acc);
        ProjectivePoint::point_copy(acc, temp);
      }
    }
  }

  ProjectivePoint::point_copy(result, acc);
}

// Tiny kernel: writes a point passed by value (via kernel args) to a device
// pointer. CUDA copies kernel arguments to GPU-accessible memory before
// launch, so the host-side source variable can safely go out of scope after
// the launch call returns -- no second stream sync needed.
template <typename ProjectiveType>
__global__ void kernel_write_point(ProjectiveType *__restrict__ dst,
                                   ProjectiveType value) {
  *dst = value;
}

// ============================================================================
// Pippenger MSM Implementation Functions
// ============================================================================

// Template MSM with BigInt scalars - ALL WINDOWS PARALLEL
// d_scratch: caller-provided device buffer for intermediate bucket arrays and
// window sums. The caller is responsible for allocating and freeing this
// buffer.
template <typename AffineType, typename ProjectiveType>
void point_msm_pippenger_impl_async(
    cudaStream_t stream, uint32_t gpu_index, ProjectiveType *d_result,
    const AffineType *d_points, const Scalar *d_scalars, uint32_t n,
    uint32_t threads_per_block, uint32_t window_size, uint32_t bucket_count,
    ProjectiveType *d_scratch, uint64_t &size_tracker,
    bool gpu_memory_allocated) {
  using ProjectivePoint = Projective<ProjectiveType>;

  if (n == 0) {
    cuda_set_device(gpu_index);
    kernel_clear_buckets<ProjectiveType><<<1, 1, 0, stream>>>(d_result, 1);
    check_cuda_error(cudaGetLastError());
    return;
  }

  PANIC_IF_FALSE(d_result != nullptr && d_points != nullptr &&
                     d_scalars != nullptr && d_scratch != nullptr,
                 "point_msm_pippenger_impl_async: null pointer argument");

  cuda_set_device(gpu_index);

  // Calculate number of windows based on scalar bit width
  const uint32_t total_bits = Scalar::NUM_BITS;
  const uint32_t num_windows = CEIL_DIV(total_bits, window_size);

  // Calculate kernel launch parameters respecting shared memory limits
  Phase1KernelLaunchParams<AffineType> launch_params(n, threads_per_block,
                                                     bucket_count, gpu_index);

  // Scratch space layout for ALL-WINDOWS-PARALLEL:
  // - all_block_buckets: [num_windows * num_blocks * bucket_count]
  // - all_final_buckets: [num_windows * bucket_count]
  // - window_sums: [num_windows]
  // Compute element counts in size_t (64-bit) so that intermediate products
  // of uint32_t inputs don't silently wrap at 2^32 before reaching the
  // explicit overflow check below (which multiplies by sizeof(ProjectiveType))
  const size_t all_block_buckets_size = static_cast<size_t>(num_windows) *
                                        launch_params.num_blocks_per_window *
                                        bucket_count;
  const size_t all_final_buckets_size =
      static_cast<size_t>(num_windows) * bucket_count;
  const size_t total_scratch =
      all_block_buckets_size + all_final_buckets_size + num_windows;

  // Partition the caller-provided scratch buffer into sub-regions
  ProjectiveType *d_all_block_buckets = d_scratch;
  ProjectiveType *d_all_final_buckets = d_scratch + all_block_buckets_size;
  ProjectiveType *d_window_sums = d_all_final_buckets + all_final_buckets_size;

  // Clear all scratch space
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

  // Phase 1: Accumulate ALL windows in parallel (SINGLE kernel launch!)
  const uint32_t total_accum_blocks =
      num_windows * launch_params.num_blocks_per_window;
  PANIC_IF_FALSE(
      total_accum_blocks * bucket_count <= all_block_buckets_size,
      "kernel_accumulate_all_windows: max write index (%zu) exceeds buffer "
      "(%zu)",
      static_cast<size_t>(total_accum_blocks) * bucket_count,
      all_block_buckets_size);
  kernel_accumulate_all_windows<AffineType, ProjectiveType>
      <<<total_accum_blocks, launch_params.adjusted_threads_per_block,
         launch_params.accum_shared_mem, stream>>>(
          d_all_block_buckets, d_points, d_scalars, n, num_windows,
          launch_params.num_blocks_per_window, window_size, bucket_count);
  check_cuda_error(cudaGetLastError());

  // Phase 2: Reduce ALL windows' buckets in parallel (SINGLE kernel launch!)
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

  // Phase 3: Compute window sums in parallel (SINGLE kernel launch!)
  // Round up to next multiple of 32 (warp size) for efficient scheduling.
  // The kernel already has `if (tid < n)` bounds checks for the excess threads.
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

  // Phase 4: CPU Horner combine with kernel-arg upload
  //
  // The Horner loop is inherently sequential. A
  // single CPU core much faster than a single GPU thread for
  // this workload, so we run the Horner on the CPU.
  std::vector<ProjectiveType> h_window_sums(num_windows);
  cuda_memcpy_async_to_cpu(
      h_window_sums.data(), d_window_sums,
      safe_mul_sizeof<ProjectiveType>(static_cast<size_t>(num_windows)), stream,
      gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  ProjectiveType h_result;
  horner_combine_cpu(h_result, h_window_sums.data(), num_windows, window_size);

  // Upload result to device via kernel argument. We do this so we don't need a
  // sync to ensure h_result is still there during copy. This will take the data
  // we need and protect it from the function end of life
  kernel_write_point<ProjectiveType><<<1, 1, 0, stream>>>(d_result, h_result);
  check_cuda_error(cudaGetLastError());
}

// ============================================================================
// Dynamic Window Size Selection
// ============================================================================

// Select optimal window size for G1 MSM based on input count
// Trade-off: larger windows = fewer Horner doublings but more bucket work
// Optimal window size grows with log(n) approximately
inline void get_g1_window_params(uint32_t n, uint32_t &window_size,
                                 uint32_t &bucket_count) {
  if (n <= MSM_G1_SMALL_THRESHOLD) {
    window_size = 4;
    bucket_count = (1u << 4); // 2^window_size
  } else if (n <= MSM_G1_MEDIUM_THRESHOLD) {
    window_size = 5;
    bucket_count = (1u << 5);
  } else {
    window_size = 6;
    bucket_count = (1u << 6);
  }
}

// Select optimal window size for G2 MSM based on input count
// G2 has 2x more expensive field ops, but empirical testing shows
// that the 5-bit fixed window size is optimal - larger windows cause
// too much bucket overhead that exceeds the Horner doubling savings
inline void get_g2_window_params(uint32_t n, uint32_t &window_size,
                                 uint32_t &bucket_count) {
  (void)n;                            // Fixed window size works best for G2
  window_size = MSM_G2_WINDOW_SIZE;   // 5-bit windows
  bucket_count = MSM_G2_BUCKET_COUNT; // 32 buckets
}

// ============================================================================
// Scratch Size Computation
// ============================================================================
// Computes the exact scratch buffer size (in bytes) needed by
// point_msm_pippenger_impl_async for a given input count n. The formula must
// stay in sync with the scratch partitioning inside that function:
//   all_block_buckets: num_windows * num_blocks_per_window * bucket_count
//   all_final_buckets: num_windows * bucket_count
//   window_sums:       num_windows
// Factoring this into a helper avoids duplicating the formula in every caller
// and prevents the buffer-underallocation bug that occurs when callers use
// ad-hoc estimates.
template <typename AffineType, typename ProjectiveType>
size_t pippenger_scratch_size(uint32_t n, uint32_t gpu_index) {
  if (n == 0)
    return 0;

  uint32_t window_size, bucket_count;
  // Use the same window parameter selection as the MSM entry points
  if constexpr (std::is_same_v<AffineType, G1Affine>) {
    get_g1_window_params(n, window_size, bucket_count);
  } else {
    get_g2_window_params(n, window_size, bucket_count);
  }

  const uint32_t threads_per_block = msm_threads_per_block<AffineType>(n);
  const uint32_t num_windows = CEIL_DIV(Scalar::NUM_BITS, window_size);

  // Phase1KernelLaunchParams computes the adjusted threads per block
  // respecting shared memory limits, which determines num_blocks_per_window
  Phase1KernelLaunchParams<AffineType> launch_params(n, threads_per_block,
                                                     bucket_count, gpu_index);

  const size_t all_block_buckets_elems = static_cast<size_t>(num_windows) *
                                         launch_params.num_blocks_per_window *
                                         bucket_count;
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
                                  G1Projective *d_result,
                                  const G1Affine *d_points,
                                  const Scalar *d_scalars, uint32_t n,
                                  G1Projective *d_scratch,
                                  uint64_t &size_tracker,
                                  bool gpu_memory_allocated) {
  uint32_t window_size, bucket_count;
  get_g1_window_params(n, window_size, bucket_count);

  point_msm_pippenger_impl_async<G1Affine, G1Projective>(
      stream, gpu_index, d_result, d_points, d_scalars, n,
      msm_threads_per_block<G1Affine>(n), window_size, bucket_count, d_scratch,
      size_tracker, gpu_memory_allocated);
}

// MSM with BigInt scalars for G2 (projective coordinates internally)
// Uses larger window size to reduce Horner doublings (G2 ops are 2x more
// expensive)
void point_msm_g2_pippenger_async(cudaStream_t stream, uint32_t gpu_index,
                                  G2ProjectivePoint *d_result,
                                  const G2Point *d_points,
                                  const Scalar *d_scalars, uint32_t n,
                                  G2ProjectivePoint *d_scratch,
                                  uint64_t &size_tracker,
                                  bool gpu_memory_allocated) {
  uint32_t window_size, bucket_count;
  get_g2_window_params(n, window_size, bucket_count);

  point_msm_pippenger_impl_async<G2Point, G2ProjectivePoint>(
      stream, gpu_index, d_result, d_points, d_scalars, n,
      msm_threads_per_block<G2Point>(n), window_size, bucket_count, d_scratch,
      size_tracker, gpu_memory_allocated);
}
