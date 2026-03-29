// C wrapper functions for Rust FFI
// These functions provide a C-compatible interface to the C++ functions

#include "checked_arithmetic.h"
#include "curve.h"
#include "device.h"
#include "msm.h"
#include "bls12_446_params.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <cstring>

#include "../../tfhe-cuda-backend/cuda/src/utils/helper_profile.cuh"

// C++ helper functions (not exported, used internally)
// These can call template functions since they have C++ linkage
static void convert_g1_points_to_montgomery(cudaStream_t stream, uint32_t gpu_index, G1Affine* d_points, uint32_t n) {
    point_to_montgomery_batch_async<G1Affine>(stream, gpu_index, d_points, n);
}

static void convert_g2_points_to_montgomery(cudaStream_t stream, uint32_t gpu_index, G2Affine* d_points, uint32_t n) {
    point_to_montgomery_batch_async<G2Affine>(stream, gpu_index, d_points, n);
}

extern "C" {

void affine_to_projective_g1_wrapper(G1Projective* proj, const G1Affine* affine) {
    affine_to_projective(*proj, *affine);
}

void affine_to_projective_g2_wrapper(G2Projective* proj, const G2Affine* affine) {
    affine_to_projective(*proj, *affine);
}

void projective_to_affine_g1_wrapper(G1Affine* affine, const G1Projective* proj) {
    projective_to_affine_g1(*affine, *proj);
}

void projective_to_affine_g2_wrapper(G2Affine* affine, const G2Projective* proj) {
    projective_to_affine_g2(*affine, *proj);
}

void g1_point_at_infinity_wrapper(G1Affine* point) {
    g1_point_at_infinity(*point);
}

void g2_point_at_infinity_wrapper(G2Affine* point) {
    g2_point_at_infinity(*point);
}

void g1_projective_point_at_infinity_wrapper(G1Projective* point) {
    g1_projective_point_at_infinity(*point);
}

void g2_projective_point_at_infinity_wrapper(G2Projective* point) {
    g2_projective_point_at_infinity(*point);
}

bool g1_is_infinity_wrapper(const G1Affine* point) {
    return g1_is_infinity(*point);
}

bool g2_is_infinity_wrapper(const G2Affine* point) {
    return g2_is_infinity(*point);
}

// Unmanaged MSM wrapper for G1 (points/scalars/scratch on device, result on host)
// Points MUST be in Montgomery form. Caller provides scratch buffer.
// Zero internal allocations — this is a thin validation + dispatch layer.
void g1_msm_unmanaged_wrapper_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    G1Projective* h_result,
    const G1Affine* d_points,
    const Scalar* d_scalars,
    uint32_t n,
    G1Projective* d_scratch
) {
    PUSH_RANGE("G1 MSM UNMANAGED");
    PANIC_IF_FALSE(n > 0, "G1 MSM error: n must be positive, got %u", n);
    PANIC_IF_FALSE(stream != nullptr, "G1 MSM error: stream is null");
    PANIC_IF_FALSE(h_result != nullptr, "G1 MSM error: h_result is null");
    PANIC_IF_FALSE(d_points != nullptr, "G1 MSM error: d_points is null");
    PANIC_IF_FALSE(d_scalars != nullptr, "G1 MSM error: d_scalars is null");
    PANIC_IF_FALSE(d_scratch != nullptr, "G1 MSM error: d_scratch is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "G1 MSM error: invalid gpu_index=%u (gpu_count=%d)", gpu_index,
                   cuda_get_number_of_gpus());

    point_msm_g1_async(stream, gpu_index, h_result, d_points, d_scalars, n,
                       d_scratch);
    check_cuda_error(cudaGetLastError());
    POP_RANGE();
}

// Unmanaged MSM wrapper for G2 (points/scalars/scratch on device, result on host)
// Points MUST be in Montgomery form. Caller provides scratch buffer.
// Zero internal allocations — this is a thin validation + dispatch layer.
void g2_msm_unmanaged_wrapper_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    G2Projective* h_result,
    const G2Affine* d_points,
    const Scalar* d_scalars,
    uint32_t n,
    G2Projective* d_scratch
) {
    PUSH_RANGE("G2 MSM UNMANAGED");
    PANIC_IF_FALSE(n > 0, "G2 MSM error: n must be positive, got %u", n);
    PANIC_IF_FALSE(stream != nullptr, "G2 MSM error: stream is null");
    PANIC_IF_FALSE(h_result != nullptr, "G2 MSM error: h_result is null");
    PANIC_IF_FALSE(d_points != nullptr, "G2 MSM error: d_points is null");
    PANIC_IF_FALSE(d_scalars != nullptr, "G2 MSM error: d_scalars is null");
    PANIC_IF_FALSE(d_scratch != nullptr, "G2 MSM error: d_scratch is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "G2 MSM error: invalid gpu_index=%u (gpu_count=%d)", gpu_index,
                   cuda_get_number_of_gpus());

    point_msm_g2_async(stream, gpu_index, h_result, d_points, d_scalars, n,
                       d_scratch);
    check_cuda_error(cudaGetLastError());
    POP_RANGE();
}

// Scratch size query wrappers (needed for bindgen `.*_wrapper` allowlist)
size_t pippenger_scratch_size_g1_wrapper(uint32_t n, uint32_t gpu_index) {
    return pippenger_scratch_size_g1(n, gpu_index);
}

size_t pippenger_scratch_size_g2_wrapper(uint32_t n, uint32_t gpu_index) {
    return pippenger_scratch_size_g2(n, gpu_index);
}

// Managed MSM wrapper for G1 (handles memory management internally)
// This allocates device memory, copies data, runs MSM, and copies result back
void g1_msm_managed_wrapper(
    cudaStream_t stream,
    uint32_t gpu_index,
    G1Projective* result,
    const G1Affine* points,
    const Scalar* scalars,
    uint32_t n,
    bool points_in_montgomery,
    uint64_t* size_tracker
) {
    PUSH_RANGE("G1 MSM MANAGED");
    uint64_t& size_tracker_local = *size_tracker;
    PANIC_IF_FALSE(n > 0, "G1 MSM error: n must be positive, got %u", n);
    PANIC_IF_FALSE(result != nullptr, "G1 MSM error: result is null");
    PANIC_IF_FALSE(stream != nullptr, "G1 MSM error: stream is null");
    PANIC_IF_FALSE(points != nullptr, "G1 MSM error: points is null");
    PANIC_IF_FALSE(scalars != nullptr, "G1 MSM error: scalars is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "G1 MSM error: invalid gpu_index=%u (gpu_count=%d)", gpu_index,
                   cuda_get_number_of_gpus());

    cuda_set_device(gpu_index);

    // Compute buffer sizes with overflow checking.
    size_t points_bytes = safe_mul_sizeof<G1Affine>(static_cast<size_t>(n));
    size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));

    // TODO: We should migrate to _unmanaged_ methods and have scratch/cleanup functions as tfhe-cuda-backend
    auto* d_points = static_cast<G1Affine*>(cuda_malloc_with_size_tracking_async(points_bytes, stream, gpu_index, size_tracker_local, true));
    auto* d_scalars = static_cast<Scalar*>(cuda_malloc_with_size_tracking_async(scalars_bytes, stream, gpu_index, size_tracker_local, true));

    // Always copy points to GPU first
    cuda_memcpy_with_size_tracking_async_to_gpu(d_points, points, points_bytes, stream, gpu_index, true);
    cuda_memcpy_with_size_tracking_async_to_gpu(d_scalars, scalars, scalars_bytes, stream, gpu_index, true);

    // Convert to Montgomery form on GPU if not already in Montgomery form
    if (!points_in_montgomery) {
        convert_g1_points_to_montgomery(stream, gpu_index, d_points, n);
        check_cuda_error(cudaGetLastError());
    }

    // Allocate scratch buffer sized to match the pippenger internal partitioning
    size_t scratch_bytes = pippenger_scratch_size_g1(n, gpu_index);
    auto* d_scratch = static_cast<G1Projective*>(cuda_malloc_with_size_tracking_async(
        scratch_bytes, stream, gpu_index, size_tracker_local, true));

    PANIC_IF_FALSE(d_points && d_scalars && d_scratch,
                   "G1 MSM error: device memory allocation failed");

    // Result written directly to host pointer -- no device round-trip needed
    point_msm_g1_async(stream, gpu_index, result, d_points, d_scalars, n,
                       d_scratch);
    check_cuda_error(cudaGetLastError());

    cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);

    // Sync for the async frees above.
    cuda_synchronize_stream(stream, gpu_index);
    POP_RANGE();
}


// Managed MSM wrapper for G2 (handles memory management internally)
// This allocates device memory, copies data, runs MSM, and copies result back
void g2_msm_managed_wrapper(
    cudaStream_t stream,
    uint32_t gpu_index,
    G2Projective* result,
    const G2Affine* points,
    const Scalar* scalars,
    uint32_t n,
    bool points_in_montgomery,
    uint64_t* size_tracker
) {
    PUSH_RANGE("G2 MSM MANAGED");
    uint64_t& size_tracker_local = *size_tracker;
    PANIC_IF_FALSE(n > 0, "G2 MSM error: n must be positive, got %u", n);
    PANIC_IF_FALSE(result != nullptr, "G2 MSM error: result is null");
    PANIC_IF_FALSE(stream != nullptr, "G2 MSM error: stream is null");
    PANIC_IF_FALSE(points != nullptr, "G2 MSM error: points is null");
    PANIC_IF_FALSE(scalars != nullptr, "G2 MSM error: scalars is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "G2 MSM error: invalid gpu_index=%u (gpu_count=%d)", gpu_index,
                   cuda_get_number_of_gpus());

    cuda_set_device(gpu_index);

    // Compute buffer sizes with overflow checking.
    size_t points_bytes = safe_mul_sizeof<G2Affine>(static_cast<size_t>(n));
    size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));

    // TODO: We should migrate to _unmanaged_ methods and have scratch/cleanup functions as tfhe-cuda-backend
    auto* d_points = static_cast<G2Affine*>(cuda_malloc_with_size_tracking_async(points_bytes, stream, gpu_index, size_tracker_local, true));
    auto* d_scalars = static_cast<Scalar*>(cuda_malloc_with_size_tracking_async(scalars_bytes, stream, gpu_index, size_tracker_local, true));

    cuda_memcpy_with_size_tracking_async_to_gpu(d_points, points, points_bytes, stream, gpu_index, true);
    cuda_memcpy_with_size_tracking_async_to_gpu(d_scalars, scalars, scalars_bytes, stream, gpu_index, true);

    if (!points_in_montgomery) {
        convert_g2_points_to_montgomery(stream, gpu_index, d_points, n);
        check_cuda_error(cudaGetLastError());
    }

    // Allocate scratch buffer sized to match the pippenger internal partitioning
    size_t scratch_bytes = pippenger_scratch_size_g2(n, gpu_index);
    auto* d_scratch = static_cast<G2Projective*>(cuda_malloc_with_size_tracking_async(
        scratch_bytes, stream, gpu_index, size_tracker_local, true));

    PANIC_IF_FALSE(d_points && d_scalars && d_scratch,
                   "G2 MSM error: device memory allocation failed");

    // Result written directly to host pointer -- no device round-trip needed
    point_msm_g2_async(stream, gpu_index, result, d_points, d_scalars, n,
                       d_scratch);
    check_cuda_error(cudaGetLastError());

    cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);

    // Sync for the async frees above.
    cuda_synchronize_stream(stream, gpu_index);
    POP_RANGE();
}

// ============================================================================
// G1 MSM scratch/cleanup/async pattern
// ============================================================================
// Pre-allocates device buffers once, then reuses them across multiple MSM calls.
// This eliminates per-call malloc/free overhead from the managed wrapper path.
//
//   scratch_zk_g1_msm   — allocate device buffers for up to max_n points
//   zk_g1_msm_async     — copy host data, convert to Montgomery, run MSM
//   cleanup_zk_g1_msm   — free device buffers, delete context

struct zk_g1_msm_mem {
    G1Affine*      d_points;       // device buffer for G1 affine points
    Scalar*        d_scalars;      // device buffer for scalars
    G1Projective*  d_scratch;      // Pippenger scratch buffer
    uint32_t       capacity;       // max number of points this context can handle

    // For split launch/finalize: host buffer for Pippenger window sums.
    // Allocated during scratch, populated by the async D2H copy in
    // zk_g1_msm_cached_launch_async, consumed by zk_g1_msm_finalize.
    G1Projective*  h_window_sums;  // pinned host memory for window sums
    uint32_t       max_num_windows; // capacity of h_window_sums
    uint32_t       num_windows;    // set during launch, used by finalize
    uint32_t       window_size;    // set during launch, used by finalize
};

void scratch_zk_g1_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g1_msm_mem** mem,
    uint32_t max_n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr, "scratch_zk_g1_msm: mem is null");
    PANIC_IF_FALSE(max_n > 0, "scratch_zk_g1_msm: max_n must be positive");
    PANIC_IF_FALSE(stream != nullptr, "scratch_zk_g1_msm: stream is null");
    PANIC_IF_FALSE(size_tracker != nullptr, "scratch_zk_g1_msm: size_tracker is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "scratch_zk_g1_msm: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());

    *mem = new zk_g1_msm_mem;
    (*mem)->capacity = max_n;

    uint64_t& tracker = *size_tracker;

    size_t points_bytes = safe_mul_sizeof<G1Affine>(static_cast<size_t>(max_n));
    size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(max_n));
    size_t scratch_bytes = pippenger_scratch_size_g1(max_n, gpu_index);

    (*mem)->d_points = static_cast<G1Affine*>(
        cuda_malloc_with_size_tracking_async(
            points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
    (*mem)->d_scalars = static_cast<Scalar*>(
        cuda_malloc_with_size_tracking_async(
            scalars_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
    (*mem)->d_scratch = static_cast<G1Projective*>(
        cuda_malloc_with_size_tracking_async(
            scratch_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

    // Allocate pinned host buffer for window sums (used by launch/finalize split).
    // Pinned memory is required for the async D2H copy to be truly async.
    const uint32_t max_num_windows = CEIL_DIV(Scalar::NUM_BITS, MSM_G1_WINDOW_SIZE);
    (*mem)->max_num_windows = max_num_windows;
    (*mem)->num_windows = 0;
    (*mem)->window_size = 0;

    size_t window_sums_bytes = safe_mul_sizeof<G1Projective>(
        static_cast<size_t>(max_num_windows));
    check_cuda_error(
        cudaMallocHost(&(*mem)->h_window_sums, window_sums_bytes));
}

void cleanup_zk_g1_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g1_msm_mem** mem,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                   "cleanup_zk_g1_msm: mem is null");
    PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_g1_msm: stream is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "cleanup_zk_g1_msm: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());

    cuda_drop_with_size_tracking_async(
        (*mem)->d_points, stream, gpu_index, allocate_gpu_memory);
    cuda_drop_with_size_tracking_async(
        (*mem)->d_scalars, stream, gpu_index, allocate_gpu_memory);
    cuda_drop_with_size_tracking_async(
        (*mem)->d_scratch, stream, gpu_index, allocate_gpu_memory);

    // Free the pinned host buffer for window sums
    if ((*mem)->h_window_sums != nullptr) {
        check_cuda_error(cudaFreeHost((*mem)->h_window_sums));
    }

    delete *mem;
    *mem = nullptr;

    cuda_synchronize_stream(stream, gpu_index);
}

void zk_g1_msm_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g1_msm_mem* mem,
    G1Projective* h_result,
    const G1Affine* h_points,
    const Scalar* h_scalars,
    uint32_t n,
    bool points_in_montgomery
) {
    PUSH_RANGE("G1 MSM ASYNC (SCRATCH)");
    PANIC_IF_FALSE(mem != nullptr, "zk_g1_msm_async: mem is null");
    PANIC_IF_FALSE(n > 0, "zk_g1_msm_async: n must be positive, got %u", n);
    PANIC_IF_FALSE(n <= mem->capacity,
                   "zk_g1_msm_async: n=%u exceeds pre-allocated capacity=%u",
                   n, mem->capacity);
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
    cuda_memcpy_async_to_gpu(mem->d_points, h_points, points_bytes,
                             stream, gpu_index);
    cuda_memcpy_async_to_gpu(mem->d_scalars, h_scalars, scalars_bytes,
                             stream, gpu_index);

    // Convert points to Montgomery form on device if needed
    if (!points_in_montgomery) {
        convert_g1_points_to_montgomery(stream, gpu_index, mem->d_points, n);
        check_cuda_error(cudaGetLastError());
    }

    // Run MSM using pre-allocated scratch buffer (zero internal allocations).
    // point_msm_g1_async expects Montgomery-form points.
    point_msm_g1_async(stream, gpu_index, h_result, mem->d_points,
                       mem->d_scalars, n, mem->d_scratch);
    check_cuda_error(cudaGetLastError());
    POP_RANGE();
}

// ============================================================================
// Cached G1 base points on device
// ============================================================================
// For verify workloads that reuse the same CRS/PublicParams across many calls,
// we cache the G1 base points on device in Montgomery form.
// This avoids repeated CPU-side conversion and H2D copies per MSM call.
//
//   scratch_zk_cached_g1_points — allocate, copy H2D, convert to Montgomery
//   cleanup_zk_cached_g1_points — free device buffer, delete context
//   zk_g1_msm_cached_async     — MSM using cached device points (scalars-only H2D)

struct zk_cached_g1_points {
    G1Affine*  d_points;   // device buffer, Montgomery form
    uint32_t   n;          // number of points
    uint32_t   gpu_index;  // GPU this buffer lives on
};

void scratch_zk_cached_g1_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_cached_g1_points** mem,
    const G1Affine* h_points,
    uint32_t n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr, "scratch_zk_cached_g1_points: mem is null");
    PANIC_IF_FALSE(h_points != nullptr, "scratch_zk_cached_g1_points: h_points is null");
    PANIC_IF_FALSE(n > 0, "scratch_zk_cached_g1_points: n must be positive");
    PANIC_IF_FALSE(stream != nullptr, "scratch_zk_cached_g1_points: stream is null");
    PANIC_IF_FALSE(size_tracker != nullptr, "scratch_zk_cached_g1_points: size_tracker is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "scratch_zk_cached_g1_points: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());

    *mem = new zk_cached_g1_points;
    (*mem)->n = n;
    (*mem)->gpu_index = gpu_index;

    uint64_t& tracker = *size_tracker;
    size_t points_bytes = safe_mul_sizeof<G1Affine>(static_cast<size_t>(n));

    (*mem)->d_points = static_cast<G1Affine*>(
        cuda_malloc_with_size_tracking_async(
            points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

    // Copy host points to device, then convert to Montgomery form in-place
    cuda_memcpy_async_to_gpu((*mem)->d_points, h_points, points_bytes,
                             stream, gpu_index);
    convert_g1_points_to_montgomery(stream, gpu_index, (*mem)->d_points, n);
    check_cuda_error(cudaGetLastError());

    // Ensure points are fully resident and converted before returning,
    // so the cache is immediately usable by any stream.
    cuda_synchronize_stream(stream, gpu_index);
}

void cleanup_zk_cached_g1_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_cached_g1_points** mem,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                   "cleanup_zk_cached_g1_points: mem is null");
    PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_cached_g1_points: stream is null");

    cuda_drop_with_size_tracking_async(
        (*mem)->d_points, stream, gpu_index, allocate_gpu_memory);

    delete *mem;
    *mem = nullptr;

    cuda_synchronize_stream(stream, gpu_index);
}

void zk_g1_msm_cached_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g1_msm_mem* msm_mem,
    G1Projective* h_result,
    const zk_cached_g1_points* cached,
    uint32_t point_offset,
    const Scalar* h_scalars,
    uint32_t n
) {
    PUSH_RANGE("G1 MSM CACHED");
    PANIC_IF_FALSE(msm_mem != nullptr, "zk_g1_msm_cached_async: msm_mem is null");
    PANIC_IF_FALSE(cached != nullptr, "zk_g1_msm_cached_async: cached is null");
    PANIC_IF_FALSE(n > 0, "zk_g1_msm_cached_async: n must be positive, got %u", n);
    PANIC_IF_FALSE(n <= msm_mem->capacity,
                   "zk_g1_msm_cached_async: n=%u exceeds msm_mem capacity=%u",
                   n, msm_mem->capacity);
    PANIC_IF_FALSE(static_cast<uint64_t>(point_offset) + n <= cached->n,
                   "zk_g1_msm_cached_async: point_offset=%u + n=%u exceeds cached points=%u",
                   point_offset, n, cached->n);
    PANIC_IF_FALSE(stream != nullptr, "zk_g1_msm_cached_async: stream is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "zk_g1_msm_cached_async: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());
    PANIC_IF_FALSE(gpu_index == cached->gpu_index,
                   "zk_g1_msm_cached_async: gpu_index=%u but cached points are on gpu=%u",
                   gpu_index, cached->gpu_index);
    PANIC_IF_FALSE(h_result != nullptr, "zk_g1_msm_cached_async: h_result is null");
    PANIC_IF_FALSE(h_scalars != nullptr, "zk_g1_msm_cached_async: h_scalars is null");

    // Only scalars need H2D transfer — points are already on device in Montgomery form
    size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
    cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes,
                             stream, gpu_index);

    // Cached points are already in Montgomery form, which is what Pippenger expects.
    // The scratch buffer from msm_mem was sized for msm_mem->capacity >= n, and
    // pippenger_scratch_size is monotonically non-decreasing, so it is sufficient.
    point_msm_g1_async(stream, gpu_index, h_result,
                       cached->d_points + point_offset,
                       msm_mem->d_scalars, n, msm_mem->d_scratch);
    check_cuda_error(cudaGetLastError());
    POP_RANGE();
}

// ============================================================================
// G2 MSM scratch/cleanup/async pattern
// ============================================================================
// Pre-allocates device buffers once, then reuses them across multiple MSM calls.
// This eliminates per-call malloc/free overhead from the managed wrapper path.
//
//   scratch_zk_g2_msm   — allocate device buffers for up to max_n points
//   zk_g2_msm_async     — copy host data, convert to Montgomery, run MSM
//   cleanup_zk_g2_msm   — free device buffers, delete context

struct zk_g2_msm_mem {
    G2Affine*      d_points;       // device buffer for G2 affine points
    Scalar*        d_scalars;      // device buffer for scalars
    G2Projective*  d_scratch;      // Pippenger scratch buffer
    uint32_t       capacity;       // max number of points this context can handle

    // For split launch/finalize: host buffer for Pippenger window sums.
    // Allocated during scratch, populated by the async D2H copy in
    // zk_g2_msm_cached_launch_async, consumed by zk_g2_msm_finalize.
    G2Projective*  h_window_sums;  // pinned host memory for window sums
    uint32_t       max_num_windows; // capacity of h_window_sums
    uint32_t       num_windows;    // set during launch, used by finalize
    uint32_t       window_size;    // set during launch, used by finalize
};

void scratch_zk_g2_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g2_msm_mem** mem,
    uint32_t max_n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr, "scratch_zk_g2_msm: mem is null");
    PANIC_IF_FALSE(max_n > 0, "scratch_zk_g2_msm: max_n must be positive");
    PANIC_IF_FALSE(stream != nullptr, "scratch_zk_g2_msm: stream is null");
    PANIC_IF_FALSE(size_tracker != nullptr, "scratch_zk_g2_msm: size_tracker is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "scratch_zk_g2_msm: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());

    *mem = new zk_g2_msm_mem;
    (*mem)->capacity = max_n;

    uint64_t& tracker = *size_tracker;

    size_t points_bytes = safe_mul_sizeof<G2Affine>(static_cast<size_t>(max_n));
    size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(max_n));
    size_t scratch_bytes = pippenger_scratch_size_g2(max_n, gpu_index);

    (*mem)->d_points = static_cast<G2Affine*>(
        cuda_malloc_with_size_tracking_async(
            points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
    (*mem)->d_scalars = static_cast<Scalar*>(
        cuda_malloc_with_size_tracking_async(
            scalars_bytes, stream, gpu_index, tracker, allocate_gpu_memory));
    (*mem)->d_scratch = static_cast<G2Projective*>(
        cuda_malloc_with_size_tracking_async(
            scratch_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

    // Allocate pinned host buffer for window sums (used by launch/finalize split).
    // Pinned memory is required for the async D2H copy to be truly async.
    // Window count is constant for G2 (fixed window size), but we compute it
    // from the constants rather than hardcoding.
    const uint32_t max_num_windows = CEIL_DIV(Scalar::NUM_BITS, MSM_G2_WINDOW_SIZE);
    (*mem)->max_num_windows = max_num_windows;
    (*mem)->num_windows = 0;
    (*mem)->window_size = 0;

    size_t window_sums_bytes = safe_mul_sizeof<G2Projective>(
        static_cast<size_t>(max_num_windows));
    check_cuda_error(
        cudaMallocHost(&(*mem)->h_window_sums, window_sums_bytes));
}

void cleanup_zk_g2_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g2_msm_mem** mem,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                   "cleanup_zk_g2_msm: mem is null");
    PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_g2_msm: stream is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "cleanup_zk_g2_msm: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());

    cuda_drop_with_size_tracking_async(
        (*mem)->d_points, stream, gpu_index, allocate_gpu_memory);
    cuda_drop_with_size_tracking_async(
        (*mem)->d_scalars, stream, gpu_index, allocate_gpu_memory);
    cuda_drop_with_size_tracking_async(
        (*mem)->d_scratch, stream, gpu_index, allocate_gpu_memory);

    // Free the pinned host buffer for window sums
    if ((*mem)->h_window_sums != nullptr) {
        check_cuda_error(cudaFreeHost((*mem)->h_window_sums));
    }

    delete *mem;
    *mem = nullptr;

    cuda_synchronize_stream(stream, gpu_index);
}

void zk_g2_msm_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g2_msm_mem* mem,
    G2Projective* h_result,
    const G2Affine* h_points,
    const Scalar* h_scalars,
    uint32_t n,
    bool points_in_montgomery
) {
    PUSH_RANGE("G2 MSM ASYNC (SCRATCH)");
    PANIC_IF_FALSE(mem != nullptr, "zk_g2_msm_async: mem is null");
    PANIC_IF_FALSE(n > 0, "zk_g2_msm_async: n must be positive, got %u", n);
    PANIC_IF_FALSE(n <= mem->capacity,
                   "zk_g2_msm_async: n=%u exceeds pre-allocated capacity=%u",
                   n, mem->capacity);
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
    cuda_memcpy_async_to_gpu(mem->d_points, h_points, points_bytes,
                             stream, gpu_index);
    cuda_memcpy_async_to_gpu(mem->d_scalars, h_scalars, scalars_bytes,
                             stream, gpu_index);

    // Convert points to Montgomery form on device if needed
    if (!points_in_montgomery) {
        convert_g2_points_to_montgomery(stream, gpu_index, mem->d_points, n);
        check_cuda_error(cudaGetLastError());
    }

    // Run MSM using pre-allocated scratch buffer (zero internal allocations).
    // point_msm_g2_async expects Montgomery-form points.
    point_msm_g2_async(stream, gpu_index, h_result, mem->d_points,
                       mem->d_scalars, n, mem->d_scratch);
    check_cuda_error(cudaGetLastError());
    POP_RANGE();
}

// ============================================================================
// Cached G2 base points on device
// ============================================================================
// For verify workloads that reuse the same CRS/PublicParams across many calls,
// we cache the G2 base points (g_hat_list) on device in Montgomery form.
// This avoids repeated CPU-side conversion and H2D copies per MSM call.
//
//   scratch_zk_cached_g2_points — allocate, copy H2D, convert to Montgomery
//   cleanup_zk_cached_g2_points — free device buffer, delete context
//   zk_g2_msm_cached_async     — MSM using cached device points (scalars-only H2D)

struct zk_cached_g2_points {
    G2Affine*  d_points;   // device buffer, Montgomery form
    uint32_t   n;          // number of points
    uint32_t   gpu_index;  // GPU this buffer lives on
};

void scratch_zk_cached_g2_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_cached_g2_points** mem,
    const G2Affine* h_points,
    uint32_t n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr, "scratch_zk_cached_g2_points: mem is null");
    PANIC_IF_FALSE(h_points != nullptr, "scratch_zk_cached_g2_points: h_points is null");
    PANIC_IF_FALSE(n > 0, "scratch_zk_cached_g2_points: n must be positive");
    PANIC_IF_FALSE(stream != nullptr, "scratch_zk_cached_g2_points: stream is null");
    PANIC_IF_FALSE(size_tracker != nullptr, "scratch_zk_cached_g2_points: size_tracker is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "scratch_zk_cached_g2_points: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());

    *mem = new zk_cached_g2_points;
    (*mem)->n = n;
    (*mem)->gpu_index = gpu_index;

    uint64_t& tracker = *size_tracker;
    size_t points_bytes = safe_mul_sizeof<G2Affine>(static_cast<size_t>(n));

    (*mem)->d_points = static_cast<G2Affine*>(
        cuda_malloc_with_size_tracking_async(
            points_bytes, stream, gpu_index, tracker, allocate_gpu_memory));

    // Copy host points to device, then convert to Montgomery form in-place
    cuda_memcpy_async_to_gpu((*mem)->d_points, h_points, points_bytes,
                             stream, gpu_index);
    convert_g2_points_to_montgomery(stream, gpu_index, (*mem)->d_points, n);
    check_cuda_error(cudaGetLastError());

    // Ensure points are fully resident and converted before returning,
    // so the cache is immediately usable by any stream.
    cuda_synchronize_stream(stream, gpu_index);
}

void cleanup_zk_cached_g2_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_cached_g2_points** mem,
    bool allocate_gpu_memory
) {
    PANIC_IF_FALSE(mem != nullptr && *mem != nullptr,
                   "cleanup_zk_cached_g2_points: mem is null");
    PANIC_IF_FALSE(stream != nullptr, "cleanup_zk_cached_g2_points: stream is null");

    cuda_drop_with_size_tracking_async(
        (*mem)->d_points, stream, gpu_index, allocate_gpu_memory);

    delete *mem;
    *mem = nullptr;

    cuda_synchronize_stream(stream, gpu_index);
}

void zk_g2_msm_cached_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g2_msm_mem* msm_mem,
    G2Projective* h_result,
    const zk_cached_g2_points* cached,
    uint32_t point_offset,
    const Scalar* h_scalars,
    uint32_t n
) {
    PUSH_RANGE("G2 MSM CACHED");
    PANIC_IF_FALSE(msm_mem != nullptr, "zk_g2_msm_cached_async: msm_mem is null");
    PANIC_IF_FALSE(cached != nullptr, "zk_g2_msm_cached_async: cached is null");
    PANIC_IF_FALSE(n > 0, "zk_g2_msm_cached_async: n must be positive, got %u", n);
    PANIC_IF_FALSE(n <= msm_mem->capacity,
                   "zk_g2_msm_cached_async: n=%u exceeds msm_mem capacity=%u",
                   n, msm_mem->capacity);
    PANIC_IF_FALSE(static_cast<uint64_t>(point_offset) + n <= cached->n,
                   "zk_g2_msm_cached_async: point_offset=%u + n=%u exceeds cached points=%u",
                   point_offset, n, cached->n);
    PANIC_IF_FALSE(stream != nullptr, "zk_g2_msm_cached_async: stream is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "zk_g2_msm_cached_async: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());
    PANIC_IF_FALSE(gpu_index == cached->gpu_index,
                   "zk_g2_msm_cached_async: gpu_index=%u but cached points are on gpu=%u",
                   gpu_index, cached->gpu_index);
    PANIC_IF_FALSE(h_result != nullptr, "zk_g2_msm_cached_async: h_result is null");
    PANIC_IF_FALSE(h_scalars != nullptr, "zk_g2_msm_cached_async: h_scalars is null");

    // Only scalars need H2D transfer — points are already on device in Montgomery form
    size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
    cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes,
                             stream, gpu_index);

    // Cached points are already in Montgomery form, which is what Pippenger expects.
    // The scratch buffer from msm_mem was sized for msm_mem->capacity >= n, and
    // pippenger_scratch_size is monotonically non-decreasing, so it is sufficient.
    point_msm_g2_async(stream, gpu_index, h_result,
                       cached->d_points + point_offset,
                       msm_mem->d_scalars, n, msm_mem->d_scratch);
    check_cuda_error(cudaGetLastError());
    POP_RANGE();
}

// ============================================================================
// Split launch/finalize for pipelined G2 MSM
// ============================================================================
// These two functions split the MSM into a truly async GPU launch and a
// CPU-side finalize step. Between launch and finalize the caller can do
// CPU work (e.g., pairings) while the GPU kernels execute concurrently.
//
// Flow:
//   1. zk_g2_msm_cached_launch_async — H2D scalars, GPU phases 1-3, async D2H
//      of window sums. Returns immediately (stream NOT synchronized).
//   2. (caller does CPU work here while GPU is busy)
//   3. zk_g2_msm_finalize — syncs stream, runs CPU Horner combine, writes result.

// Launches G2 MSM asynchronously using cached device base points. Only scalars
// are transferred H2D. The MSM kernels and D2H copy of window sums are queued
// on `stream` but NOT synchronized — the caller must call
// `zk_g2_msm_finalize()` after any desired CPU overlap to get the final result.
void zk_g2_msm_cached_launch_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    zk_g2_msm_mem* msm_mem,
    const zk_cached_g2_points* cached,
    uint32_t point_offset,
    const Scalar* h_scalars,
    uint32_t n
) {
    PUSH_RANGE("G2 MSM CACHED LAUNCH");
    PANIC_IF_FALSE(msm_mem != nullptr, "zk_g2_msm_cached_launch_async: msm_mem is null");
    PANIC_IF_FALSE(cached != nullptr, "zk_g2_msm_cached_launch_async: cached is null");
    PANIC_IF_FALSE(n > 0, "zk_g2_msm_cached_launch_async: n must be positive, got %u", n);
    PANIC_IF_FALSE(n <= msm_mem->capacity,
                   "zk_g2_msm_cached_launch_async: n=%u exceeds msm_mem capacity=%u",
                   n, msm_mem->capacity);
    PANIC_IF_FALSE(static_cast<uint64_t>(point_offset) + n <= cached->n,
                   "zk_g2_msm_cached_launch_async: point_offset=%u + n=%u exceeds cached points=%u",
                   point_offset, n, cached->n);
    PANIC_IF_FALSE(stream != nullptr, "zk_g2_msm_cached_launch_async: stream is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "zk_g2_msm_cached_launch_async: invalid gpu_index=%u (gpu_count=%d)",
                   gpu_index, cuda_get_number_of_gpus());
    PANIC_IF_FALSE(gpu_index == cached->gpu_index,
                   "zk_g2_msm_cached_launch_async: gpu_index=%u but cached points are on gpu=%u",
                   gpu_index, cached->gpu_index);
    PANIC_IF_FALSE(h_scalars != nullptr, "zk_g2_msm_cached_launch_async: h_scalars is null");
    PANIC_IF_FALSE(msm_mem->h_window_sums != nullptr,
                   "zk_g2_msm_cached_launch_async: h_window_sums is null (scratch not allocated?)");

    // H2D transfer: only scalars (points are already cached on device)
    size_t scalars_bytes = safe_mul_sizeof<Scalar>(static_cast<size_t>(n));
    cuda_memcpy_async_to_gpu(msm_mem->d_scalars, h_scalars, scalars_bytes,
                             stream, gpu_index);

    // Launch Pippenger phases 1-3 + async D2H of window sums into msm_mem.
    // num_windows and window_size are written to msm_mem for finalize.
    point_msm_g2_launch_async(
        stream, gpu_index, msm_mem->h_window_sums,
        cached->d_points + point_offset, msm_mem->d_scalars, n,
        msm_mem->d_scratch,
        msm_mem->num_windows, msm_mem->window_size);
    check_cuda_error(cudaGetLastError());
    POP_RANGE();
}

// Synchronizes the stream and runs the CPU Horner combine on the window sums
// that were copied D2H during the launch phase. Writes the final MSM result
// to `h_result`.
void zk_g2_msm_finalize(
    cudaStream_t stream,
    uint32_t gpu_index,
    const zk_g2_msm_mem* msm_mem,
    G2Projective* h_result
) {
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

void g1_from_montgomery_wrapper(G1Affine* result, const G1Affine* point) {
    PANIC_IF_FALSE(result != nullptr, "g1_from_montgomery error: result is null");
    PANIC_IF_FALSE(point != nullptr, "g1_from_montgomery error: point is null");
    PANIC_IF_FALSE(result != point,
                   "Output and input pointers must be different for out-of-place operations");
    if (point->infinity) {
        g1_point_at_infinity(*result);
        return;
    }
    fp_from_montgomery(result->x, point->x);
    fp_from_montgomery(result->y, point->y);
    result->infinity = false;
}

void g2_from_montgomery_wrapper(G2Affine* result, const G2Affine* point) {
    PANIC_IF_FALSE(result != nullptr, "g2_from_montgomery error: result is null");
    PANIC_IF_FALSE(point != nullptr, "g2_from_montgomery error: point is null");
    PANIC_IF_FALSE(result != point,
                   "Output and input pointers must be different for out-of-place operations");
    if (point->infinity) {
        g2_point_at_infinity(*result);
        return;
    }
    fp_from_montgomery(result->x.c0, point->x.c0);
    fp_from_montgomery(result->x.c1, point->x.c1);
    fp_from_montgomery(result->y.c0, point->y.c0);
    fp_from_montgomery(result->y.c1, point->y.c1);
    result->infinity = false;
}

void fp_to_montgomery_wrapper(Fp* result, const Fp* value) {
    PANIC_IF_FALSE(result != nullptr, "fp_to_montgomery error: result is null");
    PANIC_IF_FALSE(value != nullptr, "fp_to_montgomery error: value is null");
    PANIC_IF_FALSE(result != value,
                   "Output and input pointers must be different for out-of-place operations");
    fp_to_montgomery(*result, *value);
}

void fp_from_montgomery_wrapper(Fp* result, const Fp* value) {
    PANIC_IF_FALSE(result != nullptr, "fp_from_montgomery error: result is null");
    PANIC_IF_FALSE(value != nullptr, "fp_from_montgomery error: value is null");
    PANIC_IF_FALSE(result != value,
                   "Output and input pointers must be different for out-of-place operations");
    fp_from_montgomery(*result, *value);
}

void g1_projective_from_montgomery_normalized_wrapper(G1Projective* result, const G1Projective* point) {
    PANIC_IF_FALSE(result != nullptr, "g1_projective_from_montgomery error: result is null");
    PANIC_IF_FALSE(point != nullptr, "g1_projective_from_montgomery error: point is null");
    PANIC_IF_FALSE(result != point,
                   "Output and input pointers must be different for out-of-place operations");

    // Copy the point first (since inplace modifies the input)
    *result = *point;
    // Normalize and convert from Montgomery to normal form in a single pass.
    // This avoids the redundant from_montgomery -> to_montgomery round-trip
    // that occurred when calling point_from_montgomery_inplace then
    // normalize_projective_g1 separately.
    normalize_from_montgomery_g1(*result);
}

void g2_projective_from_montgomery_normalized_wrapper(G2Projective* result, const G2Projective* point) {
    PANIC_IF_FALSE(result != nullptr, "g2_projective_from_montgomery error: result is null");
    PANIC_IF_FALSE(point != nullptr, "g2_projective_from_montgomery error: point is null");
    PANIC_IF_FALSE(result != point,
                   "Output and input pointers must be different for out-of-place operations");

    // Copy the point first (since inplace modifies the input)
    *result = *point;
    // Normalize and convert from Montgomery to normal form in a single pass.
    // This avoids the redundant from_montgomery -> to_montgomery round-trip
    // that occurred when calling point_from_montgomery_inplace then
    // normalize_projective_g2 separately.
    normalize_from_montgomery_g2(*result);
}

// Point validation wrappers - check if point is on the curve
bool is_on_curve_g1_wrapper(const G1Affine* point) {
    PANIC_IF_FALSE(point != nullptr, "is_on_curve_g1 error: point is null");
    return is_on_curve_g1(*point);
}

bool is_on_curve_g2_wrapper(const G2Affine* point) {
    PANIC_IF_FALSE(point != nullptr, "is_on_curve_g2 error: point is null");
    return is_on_curve_g2(*point);
}

// Scalar modulus accessor - returns the scalar field modulus (group order)
// Output is always 5 x 64-bit limbs (40 bytes) regardless of internal LIMB_BITS
void scalar_modulus_limbs_wrapper(uint64_t* limbs) {
    PANIC_IF_FALSE(limbs != nullptr, "scalar_modulus_limbs error: limbs is null");
    const UNSIGNED_LIMB modulus[ZP_LIMBS] = BLS12_446_SCALAR_MODULUS_LIMBS;
    // Byte layout is identical for little-endian regardless of limb size
    std::memcpy(limbs, modulus, 5 * sizeof(uint64_t));
}

} // extern "C"
