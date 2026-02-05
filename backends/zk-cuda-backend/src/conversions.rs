//! Conversion functions for zk-cuda-backend types
//!
//! This module provides conversion functions that work with generic arkworks types.
//! Concrete conversion functions for tfhe-zk-pok types should be implemented in
//! tfhe-zk-pok itself to avoid circular dependencies.

use crate::bindings::{Fp, G1ProjectivePoint, G2ProjectivePoint};
use crate::types::{
    G1Affine, G1Affine as ZkG1Affine, G1Projective as ZkG1Projective, G2Affine,
    G2Projective as ZkG2Projective,
};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};

// Helper function to convert G1Affine from Montgomery form to normal form
pub fn g1_affine_from_montgomery(g1_mont: &G1Affine) -> G1Affine {
    let mut result = G1Affine::infinity();
    if !g1_mont.is_infinity() {
        unsafe {
            crate::bindings::g1_from_montgomery_wrapper(result.inner_mut(), g1_mont.inner());
        }
    }
    result
}

// Helper function to convert G2Affine from Montgomery form to normal form
pub fn g2_affine_from_montgomery(g2_mont: &G2Affine) -> G2Affine {
    let mut result = G2Affine::infinity();
    if !g2_mont.is_infinity() {
        unsafe {
            crate::bindings::g2_from_montgomery_wrapper(result.inner_mut(), g2_mont.inner());
        }
    }
    result
}

// Helper to extract an Fp from an arkworks field element.
// arkworks BigInt<N> is a newtype around [u64; N], accessed via as_ref().
fn field_to_fp<F: PrimeField>(f: &F) -> Fp {
    let bigint = f.into_bigint();
    Fp {
        limb: bigint
            .as_ref()
            .try_into()
            .expect("BLS12-446 Fq must have exactly 7 limbs"),
    }
}

/// Convert from any arkworks G1Affine (implementing AffineRepr) to zk-cuda-backend's G1Affine
///
/// arkworks stores field elements in Montgomery form internally, but xy() normalizes them.
/// We extract the normalized coordinates and pass them to zk-cuda-backend in normal form.
/// zk-cuda-backend will convert them to Montgomery form before MSM computation.
pub fn g1_affine_from_arkworks<A: AffineRepr>(affine: &A) -> ZkG1Affine
where
    A::BaseField: PrimeField,
{
    if affine.is_zero() {
        return ZkG1Affine::infinity();
    }

    // Extract coordinates from arkworks affine point
    // xy() returns normalized coordinates (converted from Montgomery to normal form)
    let zero = A::BaseField::zero();
    let xy = affine.xy().unwrap_or((zero, zero));

    // into_bigint() on normalized Fq gives us the normal form representation
    // which is what zk-cuda-backend expects (it will convert to Montgomery)
    let x = field_to_fp(&xy.0);
    let y = field_to_fp(&xy.1);

    ZkG1Affine::new(x, y, false)
}

/// Convert from zk-cuda-backend's G1Projective to the FFI projective point
///
/// Returns the (X, Y, Z) coordinates as a G1ProjectivePoint.
/// The actual construction of arkworks types should be done by the caller.
pub fn g1_projective_to_ffi(proj: &ZkG1Projective) -> G1ProjectivePoint {
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
pub fn g2_projective_to_ffi(proj: &ZkG2Projective) -> G2ProjectivePoint {
    G2ProjectivePoint {
        X: proj.X(),
        Y: proj.Y(),
        Z: proj.Z(),
    }
}
