#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Type definitions for FFI - these mirror the CUDA types in cuda/include/
// but are defined here as plain C structs for bindgen compatibility.
//
// Name mapping between FFI types and CUDA internals:
//   FFI (api.h)         CUDA (curve.h)
//   G1Point          -> G1Affine
//   G2Point          -> G2Affine
//   G1ProjectivePoint -> G1Projective (typedef G1Projective = G1ProjectivePoint)
//   G2ProjectivePoint -> G2Projective (typedef G2Projective = G2ProjectivePoint)

// Forward declare cudaStream_t as opaque pointer for FFI
typedef struct CUstream_st* cudaStream_t;

// Field element: 7 limbs of 64 bits each (448 bits for BLS12-446)
typedef struct Fp {
    uint64_t limb[7];
} Fp;

// Extension field Fp2: two Fp elements
typedef struct Fp2 {
    Fp c0;
    Fp c1;
} Fp2;

// Scalar: 5 limbs of 64 bits each (320 bits)
typedef struct BigInt {
    uint64_t limb[5];
} BigInt;

typedef BigInt Scalar;

// G1 affine point (x, y in Fp)
typedef struct G1Point {
    Fp x;
    Fp y;
    bool infinity;
} G1Point;

// G2 affine point (x, y in Fp2)
typedef struct G2Point {
    Fp2 x;
    Fp2 y;
    bool infinity;
} G2Point;

// G1 projective point (X, Y, Z in Fp)
typedef struct G1ProjectivePoint {
    Fp X;
    Fp Y;
    Fp Z;
} G1ProjectivePoint;

// G2 projective point (X, Y, Z in Fp2)
typedef struct G2ProjectivePoint {
    Fp2 X;
    Fp2 Y;
    Fp2 Z;
} G2ProjectivePoint;

// C-compatible wrapper functions for Rust FFI

// G1 affine to projective conversion
void affine_to_projective_g1_wrapper(G1ProjectivePoint* proj, const G1Point* affine);

// G2 affine to projective conversion
void affine_to_projective_g2_wrapper(G2ProjectivePoint* proj, const G2Point* affine);

// G1 projective to affine conversion
void projective_to_affine_g1_wrapper(G1Point* affine, const G1ProjectivePoint* proj);

// G2 projective to affine conversion
void projective_to_affine_g2_wrapper(G2Point* affine, const G2ProjectivePoint* proj);

// G1 point at infinity
void g1_point_at_infinity_wrapper(G1Point* point);

// G2 point at infinity
void g2_point_at_infinity_wrapper(G2Point* point);

// G1 projective point at infinity
void g1_projective_point_at_infinity_wrapper(G1ProjectivePoint* point);

// G2 projective point at infinity
void g2_projective_point_at_infinity_wrapper(G2ProjectivePoint* point);

// Check if G1 point is at infinity
bool g1_is_infinity_wrapper(const G1Point* point);

// Check if G2 point is at infinity
bool g2_is_infinity_wrapper(const G2Point* point);

// Unmanaged MSM wrappers (points/scalars/scratch on device, result on host)
// Points MUST be in Montgomery form. Caller provides a scratch buffer.
// Zero internal allocations — all device memory is caller-provided.
void g1_msm_unmanaged_wrapper_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    G1ProjectivePoint* h_result,
    const G1Point* d_points,
    const Scalar* d_scalars,
    uint32_t n,
    G1ProjectivePoint* d_scratch
);

void g2_msm_unmanaged_wrapper_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    G2ProjectivePoint* h_result,
    const G2Point* d_points,
    const Scalar* d_scalars,
    uint32_t n,
    G2ProjectivePoint* d_scratch
);

// Scratch size queries for Pippenger MSM
// Returns the exact scratch buffer size in bytes needed for a given input count.
size_t pippenger_scratch_size_g1_wrapper(uint32_t n, uint32_t gpu_index);
size_t pippenger_scratch_size_g2_wrapper(uint32_t n, uint32_t gpu_index);

// G1 MSM scratch/cleanup/async pattern
// Pre-allocates device buffers once for reuse across multiple MSM calls,
// eliminating per-call malloc/free overhead from the managed wrapper path.
struct zk_g1_msm_mem;

void scratch_zk_g1_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g1_msm_mem** mem,
    uint32_t max_n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
);

void cleanup_zk_g1_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g1_msm_mem** mem,
    bool allocate_gpu_memory
);

void zk_g1_msm_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g1_msm_mem* mem,
    G1ProjectivePoint* h_result,
    const G1Point* h_points,
    const Scalar* h_scalars,
    uint32_t n,
    bool points_in_montgomery
);

// Cached G1 base points on device in Montgomery form.
// Allocated once per CRS, reused across many MSM calls in the verify path.
struct zk_cached_g1_points;

void scratch_zk_cached_g1_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_cached_g1_points** mem,
    const G1Point* h_points,
    uint32_t n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
);

void cleanup_zk_cached_g1_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_cached_g1_points** mem,
    bool allocate_gpu_memory
);

// MSM variant that uses device-resident cached base points (scalars-only H2D).
// Requires a pre-allocated zk_g1_msm_mem for scalar buffer and Pippenger scratch.
void zk_g1_msm_cached_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g1_msm_mem* msm_mem,
    G1ProjectivePoint* h_result,
    const struct zk_cached_g1_points* cached,
    uint32_t point_offset,
    const Scalar* h_scalars,
    uint32_t n
);

// Split launch/finalize for pipelined G1 MSM.
// Allows GPU MSM kernels to overlap with CPU work.
//   1. zk_g1_msm_cached_launch_async — queues GPU work, returns immediately
//   2. zk_g1_msm_finalize — syncs stream, runs CPU Horner, writes result

// Launches G1 MSM using cached device base points. Queues H2D scalar copy,
// GPU Pippenger phases, and D2H window-sum copy on `stream`. Does NOT
// synchronize — call zk_g1_msm_finalize() when the result is needed.
void zk_g1_msm_cached_launch_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g1_msm_mem* msm_mem,
    const struct zk_cached_g1_points* cached,
    uint32_t point_offset,
    const Scalar* h_scalars,
    uint32_t n
);

// Synchronizes the stream and runs CPU Horner combine on the window sums
// that were D2H-copied during the launch phase. Writes final result to h_result.
void zk_g1_msm_finalize(
    cudaStream_t stream,
    uint32_t gpu_index,
    const struct zk_g1_msm_mem* msm_mem,
    G1ProjectivePoint* h_result
);

// G2 MSM scratch/cleanup/async pattern
// Pre-allocates device buffers once for reuse across multiple MSM calls,
// eliminating per-call malloc/free overhead from the managed wrapper path.
struct zk_g2_msm_mem;

void scratch_zk_g2_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g2_msm_mem** mem,
    uint32_t max_n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
);

void cleanup_zk_g2_msm(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g2_msm_mem** mem,
    bool allocate_gpu_memory
);

void zk_g2_msm_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g2_msm_mem* mem,
    G2ProjectivePoint* h_result,
    const G2Point* h_points,
    const Scalar* h_scalars,
    uint32_t n,
    bool points_in_montgomery
);

// Cached G2 base points on device in Montgomery form.
// Allocated once per CRS, reused across many MSM calls in the verify path.
struct zk_cached_g2_points;

void scratch_zk_cached_g2_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_cached_g2_points** mem,
    const G2Point* h_points,
    uint32_t n,
    uint64_t* size_tracker,
    bool allocate_gpu_memory
);

void cleanup_zk_cached_g2_points(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_cached_g2_points** mem,
    bool allocate_gpu_memory
);

// MSM variant that uses device-resident cached base points (scalars-only H2D).
// Requires a pre-allocated zk_g2_msm_mem for scalar buffer and Pippenger scratch.
void zk_g2_msm_cached_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g2_msm_mem* msm_mem,
    G2ProjectivePoint* h_result,
    const struct zk_cached_g2_points* cached,
    uint32_t point_offset,
    const Scalar* h_scalars,
    uint32_t n
);

// Split launch/finalize for pipelined G2 MSM.
// Allows GPU MSM kernels to overlap with CPU work (e.g., pairings).
//   1. zk_g2_msm_cached_launch_async — queues GPU work, returns immediately
//   2. zk_g2_msm_finalize — syncs stream, runs CPU Horner, writes result

// Launches G2 MSM using cached device base points. Queues H2D scalar copy,
// GPU Pippenger phases, and D2H window-sum copy on `stream`. Does NOT
// synchronize — call zk_g2_msm_finalize() when the result is needed.
void zk_g2_msm_cached_launch_async(
    cudaStream_t stream,
    uint32_t gpu_index,
    struct zk_g2_msm_mem* msm_mem,
    const struct zk_cached_g2_points* cached,
    uint32_t point_offset,
    const Scalar* h_scalars,
    uint32_t n
);

// Synchronizes the stream and runs CPU Horner combine on the window sums
// that were D2H-copied during the launch phase. Writes final result to h_result.
void zk_g2_msm_finalize(
    cudaStream_t stream,
    uint32_t gpu_index,
    const struct zk_g2_msm_mem* msm_mem,
    G2ProjectivePoint* h_result
);

// Managed MSM wrappers with BigInt scalars (320-bit scalars)
// Handles memory allocation and transfers internally.
void g1_msm_managed_wrapper(
    cudaStream_t stream,
    uint32_t gpu_index,
    G1ProjectivePoint* result,
    const G1Point* points,
    const Scalar* scalars,
    uint32_t n,
    bool points_in_montgomery,
    uint64_t* size_tracker
);

void g2_msm_managed_wrapper(
    cudaStream_t stream,
    uint32_t gpu_index,
    G2ProjectivePoint* result,
    const G2Point* points,
    const Scalar* scalars,
    uint32_t n,
    bool points_in_montgomery,
    uint64_t* size_tracker
);

// Montgomery conversion helpers
void g1_from_montgomery_wrapper(G1Point* result, const G1Point* point);
void g2_from_montgomery_wrapper(G2Point* result, const G2Point* point);
void fp_to_montgomery_wrapper(Fp* result, const Fp* value);
void fp_from_montgomery_wrapper(Fp* result, const Fp* value);

// Projective point from Montgomery and normalize (divides by Z to get Z=1 form)
void g1_projective_from_montgomery_normalized_wrapper(G1ProjectivePoint* result, const G1ProjectivePoint* point);
void g2_projective_from_montgomery_normalized_wrapper(G2ProjectivePoint* result, const G2ProjectivePoint* point);

// Point validation - check if point is on the curve
bool is_on_curve_g1_wrapper(const G1Point* point);
bool is_on_curve_g2_wrapper(const G2Point* point);

// Scalar modulus accessor - returns the scalar field modulus (group order)
void scalar_modulus_limbs_wrapper(uint64_t* limbs);

// Global MSM cache for CRS base points (singleton).
// Populated once per CRS key, lives until reset() or process exit.
uint32_t zk_msm_cache_acquire(
    const G1Point* g1_points, uint32_t n_g1,
    const G2Point* g2_points, uint32_t n_g2,
    const uintptr_t key[4]);
const struct zk_cached_g1_points* zk_msm_cache_get_g1(uint32_t gpu_index);
const struct zk_cached_g2_points* zk_msm_cache_get_g2(uint32_t gpu_index);
uint32_t zk_msm_cache_num_gpus(void);
void zk_msm_cache_release(void);
void zk_msm_cache_reset(void);

#ifdef __cplusplus
}
#endif
