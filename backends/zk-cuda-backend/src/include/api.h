#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Type definitions for FFI - these mirror the CUDA types in cuda/include/
// but are defined here as plain C structs for bindgen compatibility.

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

// Unmanaged MSM wrappers (assumes all data is already on device)
// If points_in_montgomery is false, a temporary copy will be made and converted.
// For best performance, provide points already in Montgomery form to avoid allocation overhead.
void g1_msm_unmanaged_wrapper(
    cudaStream_t stream,
    uint32_t gpu_index,
    G1ProjectivePoint* d_result,
    const G1Point* d_points,
    const Scalar* d_scalars,
    G1ProjectivePoint* d_scratch,
    uint32_t n,
    bool points_in_montgomery,
    uint64_t* size_tracker
);

void g2_msm_unmanaged_wrapper(
    cudaStream_t stream,
    uint32_t gpu_index,
    G2ProjectivePoint* d_result,
    const G2Point* d_points,
    const Scalar* d_scalars,
    G2ProjectivePoint* d_scratch,
    uint32_t n,
    bool points_in_montgomery,
    uint64_t* size_tracker
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

#ifdef __cplusplus
}
#endif
