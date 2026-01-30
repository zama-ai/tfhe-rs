//! FFI bindings to the C++ library
//!
//! This module contains the raw FFI bindings to the C++ CUDA library.
//! These are low-level bindings that should generally not be used directly.

use std::os::raw::c_uint;

// Fp structure: 7 limbs of 64 bits each (56 bytes)
// MONTGOMERY CONVENTION: All Fp values in internal computations are in Montgomery form.
// Use fp_to_montgomery() when importing and fp_from_montgomery() when exporting.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Fp {
    pub limb: [u64; 7],
}

impl Fp {
    /// Create a new Fp from limbs (in normal form - must convert to Montgomery for computation)
    pub fn new(limbs: [u64; 7]) -> Self {
        Self { limb: limbs }
    }

    /// Create a new Fp from a BigInt-like structure (in normal form)
    /// This is a convenience method for compatibility with tfhe-zk-pok's BigInt<7>
    pub fn from_bigint<const N: usize>(bigint: &[u64; N]) -> Self {
        let mut limbs = [0u64; 7];
        let copy_len = N.min(7);
        limbs[..copy_len].copy_from_slice(&bigint[..copy_len]);
        Self { limb: limbs }
    }
}

// Fp2 structure: two Fp elements
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

// G1 affine point
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct G1Point {
    pub x: Fp,
    pub y: Fp,
    pub infinity: bool,
}

// G2 affine point
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct G2Point {
    pub x: Fp2,
    pub y: Fp2,
    pub infinity: bool,
}

// G1 projective point
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct G1ProjectivePoint {
    pub X: Fp,
    pub Y: Fp,
    pub Z: Fp,
}

// G2 projective point
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct G2ProjectivePoint {
    pub X: Fp2,
    pub Y: Fp2,
    pub Z: Fp2,
}

// BigInt structure: 5 limbs of 64 bits each (320 bits total)
// Compatible with tfhe_zk_pok::curve_api::bls12_446::zp (BigInt<5>)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BigInt {
    pub limb: [u64; 5],
}

// Scalar type: alias for BigInt (matches C++ Scalar = BigInt<ZP_LIMBS>)
pub type Scalar = BigInt;

// Opaque CUDA stream type
#[repr(C)]
pub struct cudaStream_t {
    _private: [u8; 0],
}

extern "C" {
    pub fn affine_to_projective_g1_wrapper(proj: *mut G1ProjectivePoint, affine: *const G1Point);
    pub fn affine_to_projective_g2_wrapper(proj: *mut G2ProjectivePoint, affine: *const G2Point);
    pub fn projective_to_affine_g1_wrapper(affine: *mut G1Point, proj: *const G1ProjectivePoint);
    pub fn projective_to_affine_g2_wrapper(affine: *mut G2Point, proj: *const G2ProjectivePoint);

    pub fn g1_point_at_infinity_wrapper(point: *mut G1Point);
    pub fn g2_point_at_infinity_wrapper(point: *mut G2Point);
    pub fn g1_projective_point_at_infinity_wrapper(point: *mut G1ProjectivePoint);
    pub fn g2_projective_point_at_infinity_wrapper(point: *mut G2ProjectivePoint);

    pub fn g1_is_infinity_wrapper(point: *const G1Point) -> bool;
    pub fn g2_is_infinity_wrapper(point: *const G2Point) -> bool;

    // Unmanaged MSM functions (assumes all data is already on device)
    // If points_in_montgomery is false, a temporary copy will be made and converted.
    // For best performance, provide points already in Montgomery form to avoid allocation overhead.
    pub fn g1_msm_unmanaged_wrapper(
        stream: *mut cudaStream_t,
        gpu_index: c_uint,
        d_result: *mut G1ProjectivePoint,
        d_points: *const G1Point,
        d_scalars: *const Scalar,
        d_scratch: *mut G1ProjectivePoint,
        n: c_uint,
        points_in_montgomery: bool,
        size_tracker: *mut u64,
    );

    pub fn g2_msm_unmanaged_wrapper(
        stream: *mut cudaStream_t,
        gpu_index: c_uint,
        d_result: *mut G2ProjectivePoint,
        d_points: *const G2Point,
        d_scalars: *const Scalar,
        d_scratch: *mut G2ProjectivePoint,
        n: c_uint,
        points_in_montgomery: bool,
        size_tracker: *mut u64,
    );

    pub fn g1_msm_managed_wrapper(
        result: *mut G1ProjectivePoint,
        stream: *mut std::ffi::c_void,
        points: *const G1Point,
        scalars: *const Scalar,
        n: c_uint,
        gpu_index: c_uint,
        points_in_montgomery: bool,
        size_tracker: *mut u64,
    );

    pub fn g2_msm_managed_wrapper(
        result: *mut G2ProjectivePoint,
        stream: *mut std::ffi::c_void,
        points: *const G2Point,
        scalars: *const Scalar,
        n: c_uint,
        gpu_index: c_uint,
        points_in_montgomery: bool,
        size_tracker: *mut u64,
    );

    pub fn g1_from_montgomery_wrapper(result: *mut G1Point, point: *const G1Point);
    pub fn g2_from_montgomery_wrapper(result: *mut G2Point, point: *const G2Point);
    pub fn fp_to_montgomery_wrapper(result: *mut Fp, value: *const Fp);
    pub fn fp_from_montgomery_wrapper(result: *mut Fp, value: *const Fp);

    pub fn g1_projective_from_montgomery_normalized_wrapper(
        result: *mut G1ProjectivePoint,
        point: *const G1ProjectivePoint,
    );
    pub fn g2_projective_from_montgomery_normalized_wrapper(
        result: *mut G2ProjectivePoint,
        point: *const G2ProjectivePoint,
    );

    // Point validation - check if point is on the curve
    pub fn is_on_curve_g1_wrapper(point: *const G1Point) -> bool;
    pub fn is_on_curve_g2_wrapper(point: *const G2Point) -> bool;

    // Scalar modulus accessor - returns the scalar field modulus (group order)
    pub fn scalar_modulus_limbs_wrapper(limbs: *mut u64);
}
