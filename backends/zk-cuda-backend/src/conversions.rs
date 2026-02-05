//! Conversion functions for zk-cuda-backend types
//!
//! This module provides conversion functions that work with generic arkworks types.
//! Concrete conversion functions for tfhe-zk-pok types should be implemented in
//! tfhe-zk-pok itself to avoid circular dependencies.

use crate::bindings::{Fp, G1ProjectivePoint, G2ProjectivePoint};
use crate::types::{G1Affine, G1Projective, G2Affine, G2Projective, FP_LIMBS};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

// Verify at compile time that the bindgen-generated Fp matches FP_LIMBS.
// If this fails, the Fp struct layout has changed and all limb conversions are wrong.
const _: () = assert!(
    std::mem::size_of::<Fp>() == FP_LIMBS * std::mem::size_of::<u64>(),
    "Fp size must equal FP_LIMBS * 8 bytes"
);

/// Convert a G1Affine point from Montgomery form to normal form.
#[must_use = "Montgomery conversion returns a new point without modifying the input"]
pub fn g1_affine_from_montgomery(g1_mont: &G1Affine) -> G1Affine {
    let mut result = G1Affine::infinity();
    if !g1_mont.is_infinity() {
        // SAFETY: Both pointers are valid `repr(C)` pointers to stack-allocated `G1Point`
        // structs — `result.inner_mut()` provides exclusive write access and
        // `g1_mont.inner()` provides shared read access, both valid for the duration of
        // the call.
        unsafe {
            crate::bindings::g1_from_montgomery_wrapper(result.inner_mut(), g1_mont.inner());
        }
    }
    result
}

/// Convert a G2Affine point from Montgomery form to normal form.
#[must_use = "Montgomery conversion returns a new point without modifying the input"]
pub fn g2_affine_from_montgomery(g2_mont: &G2Affine) -> G2Affine {
    let mut result = G2Affine::infinity();
    if !g2_mont.is_infinity() {
        // SAFETY: Both pointers are valid `repr(C)` pointers to stack-allocated `G2Point`
        // structs — `result.inner_mut()` provides exclusive write access and
        // `g2_mont.inner()` provides shared read access, both valid for the duration of
        // the call.
        unsafe {
            crate::bindings::g2_from_montgomery_wrapper(result.inner_mut(), g2_mont.inner());
        }
    }
    result
}

/// Extract an Fp from an arkworks field element.
///
/// arkworks `BigInt<N>` is a newtype around `[u64; N]`, accessed via `as_ref()`.
/// This function is only called with BLS12-446 Fq fields (7 limbs), so the
/// `try_into` is guaranteed to succeed at all current call sites.
fn field_to_fp<F: PrimeField>(f: &F) -> Fp {
    let bigint = f.into_bigint();
    let limbs = bigint.as_ref();
    // BLS12-446 Fq uses BigInt<7>, so as_ref() always returns a 7-element slice.
    Fp {
        limb: limbs.try_into().unwrap_or_else(|_| {
            panic!(
                "field_to_fp: expected {FP_LIMBS} limbs (BLS12-446 Fq), got {}",
                limbs.len()
            )
        }),
    }
}

/// Convert from any arkworks G1Affine (implementing AffineRepr) to zk-cuda-backend's G1Affine
///
/// arkworks stores field elements in Montgomery form internally, but xy() normalizes them.
/// We extract the normalized coordinates and pass them to zk-cuda-backend in normal form.
/// zk-cuda-backend will convert them to Montgomery form before MSM computation.
pub fn g1_affine_from_arkworks<A: AffineRepr>(affine: &A) -> G1Affine
where
    A::BaseField: PrimeField,
{
    if affine.is_zero() {
        return G1Affine::infinity();
    }

    // xy() returns normalized coordinates (converted from Montgomery to normal form).
    // The is_zero() check above guarantees the point is not at infinity, so xy()
    // always returns Some here.
    let (x_ref, y_ref) = affine
        .xy()
        .expect("non-identity affine point must have coordinates");

    // into_bigint() on normalized Fq gives us the normal form representation
    // which is what zk-cuda-backend expects (it will convert to Montgomery)
    let x = field_to_fp(&x_ref);
    let y = field_to_fp(&y_ref);

    G1Affine::new(x, y, false)
}

/// Convert from zk-cuda-backend's G1Projective to the FFI projective point
///
/// Returns the (X, Y, Z) coordinates as a G1ProjectivePoint.
/// The actual construction of arkworks types should be done by the caller.
pub fn g1_projective_to_ffi(proj: &G1Projective) -> G1ProjectivePoint {
    G1ProjectivePoint {
        X: proj.X(),
        Y: proj.Y(),
        Z: proj.Z(),
    }
}

/// Convert from zk-cuda-backend's G2Projective to the FFI projective point
///
/// Returns the (X, Y, Z) coordinates as a G2ProjectivePoint.
/// The actual construction of arkworks types should be done by the caller.
pub fn g2_projective_to_ffi(proj: &G2Projective) -> G2ProjectivePoint {
    G2ProjectivePoint {
        X: proj.X(),
        Y: proj.Y(),
        Z: proj.Z(),
    }
}
