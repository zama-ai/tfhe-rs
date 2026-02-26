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

// Unmanaged MSM wrapper for G1 (assumes all data is already on device)
// Points MUST be in Montgomery form. Caller provides scratch buffer and
// controls allocation tracking via gpu_memory_allocated.
// Zero internal allocations — this is a thin validation + dispatch layer.
void g1_msm_unmanaged_wrapper_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    G1Projective* d_result,
    const G1Affine* d_points,
    const Scalar* d_scalars,
    uint32_t n,
    G1Projective* d_scratch,
    bool gpu_memory_allocated,
    uint64_t* size_tracker
) {
    PANIC_IF_FALSE(size_tracker != nullptr, "G1 MSM error: size_tracker is null");
    uint64_t& size_tracker_ref = *size_tracker;
    PANIC_IF_FALSE(n > 0, "G1 MSM error: n must be positive, got %u", n);
    PANIC_IF_FALSE(stream != nullptr, "G1 MSM error: stream is null");
    PANIC_IF_FALSE(d_result != nullptr, "G1 MSM error: d_result is null");
    PANIC_IF_FALSE(d_points != nullptr, "G1 MSM error: d_points is null");
    PANIC_IF_FALSE(d_scalars != nullptr, "G1 MSM error: d_scalars is null");
    PANIC_IF_FALSE(d_scratch != nullptr, "G1 MSM error: d_scratch is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "G1 MSM error: invalid gpu_index=%u (gpu_count=%d)", gpu_index,
                   cuda_get_number_of_gpus());

    point_msm_g1_async(stream, gpu_index, d_result, d_points, d_scalars, n,
                       d_scratch, size_tracker_ref, gpu_memory_allocated);
    check_cuda_error(cudaGetLastError());
}

// Unmanaged MSM wrapper for G2 (assumes all data is already on device)
// Points MUST be in Montgomery form. Caller provides scratch buffer and
// controls allocation tracking via gpu_memory_allocated.
// Zero internal allocations — this is a thin validation + dispatch layer.
void g2_msm_unmanaged_wrapper_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    G2Projective* d_result,
    const G2Affine* d_points,
    const Scalar* d_scalars,
    uint32_t n,
    G2Projective* d_scratch,
    bool gpu_memory_allocated,
    uint64_t* size_tracker
) {
    PANIC_IF_FALSE(size_tracker != nullptr, "G2 MSM error: size_tracker is null");
    uint64_t& size_tracker_ref = *size_tracker;
    PANIC_IF_FALSE(n > 0, "G2 MSM error: n must be positive, got %u", n);
    PANIC_IF_FALSE(stream != nullptr, "G2 MSM error: stream is null");
    PANIC_IF_FALSE(d_result != nullptr, "G2 MSM error: d_result is null");
    PANIC_IF_FALSE(d_points != nullptr, "G2 MSM error: d_points is null");
    PANIC_IF_FALSE(d_scalars != nullptr, "G2 MSM error: d_scalars is null");
    PANIC_IF_FALSE(d_scratch != nullptr, "G2 MSM error: d_scratch is null");
    PANIC_IF_FALSE(gpu_index < static_cast<uint32_t>(cuda_get_number_of_gpus()),
                   "G2 MSM error: invalid gpu_index=%u (gpu_count=%d)", gpu_index,
                   cuda_get_number_of_gpus());

    point_msm_g2_async(stream, gpu_index, d_result, d_points, d_scalars, n,
                       d_scratch, size_tracker_ref, gpu_memory_allocated);
    check_cuda_error(cudaGetLastError());
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
    uint64_t& size_tracker_ref = *size_tracker;
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
    auto* d_points = static_cast<G1Affine*>(cuda_malloc_with_size_tracking_async(points_bytes, stream, gpu_index, size_tracker_ref, true));
    auto* d_scalars = static_cast<Scalar*>(cuda_malloc_with_size_tracking_async(scalars_bytes, stream, gpu_index, size_tracker_ref, true));
    auto* d_result = static_cast<G1Projective*>(cuda_malloc_with_size_tracking_async(sizeof(G1Projective), stream, gpu_index, size_tracker_ref, true));

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
        scratch_bytes, stream, gpu_index, size_tracker_ref, true));

    PANIC_IF_FALSE(d_points && d_scalars && d_result && d_scratch,
                   "G1 MSM error: device memory allocation failed");

    point_msm_g1_async(stream, gpu_index, d_result, d_points, d_scalars, n,
                       d_scratch, size_tracker_ref, true);
    check_cuda_error(cudaGetLastError());

    cuda_memcpy_async_to_cpu(result, d_result, sizeof(G1Projective), stream, gpu_index);

    cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);

    // Sync for the D2H memcpy of the result and the async frees above.
    cuda_synchronize_stream(stream, gpu_index);
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
    uint64_t& size_tracker_ref = *size_tracker;
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
    auto* d_points = static_cast<G2Affine*>(cuda_malloc_with_size_tracking_async(points_bytes, stream, gpu_index, size_tracker_ref, true));
    auto* d_scalars = static_cast<Scalar*>(cuda_malloc_with_size_tracking_async(scalars_bytes, stream, gpu_index, size_tracker_ref, true));
    auto* d_result = static_cast<G2Projective*>(cuda_malloc_with_size_tracking_async(sizeof(G2Projective), stream, gpu_index, size_tracker_ref, true));

    cuda_memcpy_with_size_tracking_async_to_gpu(d_points, points, points_bytes, stream, gpu_index, true);
    cuda_memcpy_with_size_tracking_async_to_gpu(d_scalars, scalars, scalars_bytes, stream, gpu_index, true);

    if (!points_in_montgomery) {
        convert_g2_points_to_montgomery(stream, gpu_index, d_points, n);
        check_cuda_error(cudaGetLastError());
    }

    // Allocate scratch buffer sized to match the pippenger internal partitioning
    size_t scratch_bytes = pippenger_scratch_size_g2(n, gpu_index);
    auto* d_scratch = static_cast<G2Projective*>(cuda_malloc_with_size_tracking_async(
        scratch_bytes, stream, gpu_index, size_tracker_ref, true));

    PANIC_IF_FALSE(d_points && d_scalars && d_result && d_scratch,
                   "G2 MSM error: device memory allocation failed");

    point_msm_g2_async(stream, gpu_index, d_result, d_points, d_scalars, n,
                       d_scratch, size_tracker_ref, true);
    check_cuda_error(cudaGetLastError());

    cuda_memcpy_async_to_cpu(result, d_result, sizeof(G2Projective), stream, gpu_index);

    cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);

    // Sync for the D2H memcpy of the result and the async frees above.
    cuda_synchronize_stream(stream, gpu_index);
}

void g1_from_montgomery_wrapper(G1Affine* result, const G1Affine* point) {
    PANIC_IF_FALSE(result != nullptr, "g1_from_montgomery error: result is null");
    PANIC_IF_FALSE(point != nullptr, "g1_from_montgomery error: point is null");
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
    fp_to_montgomery(*result, *value);
}

void fp_from_montgomery_wrapper(Fp* result, const Fp* value) {
    PANIC_IF_FALSE(result != nullptr, "fp_from_montgomery error: result is null");
    PANIC_IF_FALSE(value != nullptr, "fp_from_montgomery error: value is null");
    fp_from_montgomery(*result, *value);
}

void g1_projective_from_montgomery_normalized_wrapper(G1Projective* result, const G1Projective* point) {
    PANIC_IF_FALSE(result != nullptr, "g1_projective_from_montgomery error: result is null");
    PANIC_IF_FALSE(point != nullptr, "g1_projective_from_montgomery error: point is null");

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
