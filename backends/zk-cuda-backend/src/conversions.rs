//! Conversion functions for zk-cuda-backend types
//!
//! This module provides conversion functions that work with generic arkworks types.
//! Concrete conversion functions for tfhe-zk-pok types should be implemented in
//! tfhe-zk-pok itself to avoid circular dependencies.

use crate::types::{
    G1Affine, G1Affine as ZkG1Affine, G1Projective as ZkG1Projective, G2Affine,
    G2Projective as ZkG2Projective,
};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};

/// Type alias for Fp2 field element represented as limbs (c0, c1)
pub type Fp2Limbs = ([u64; 7], [u64; 7]);

/// Type alias for G2 projective point coordinates (X, Y, Z) as Fp2 limbs
pub type G2ProjectiveLimbs = (Fp2Limbs, Fp2Limbs, Fp2Limbs);

// Helper function to convert G1Affine from Montgomery form to normal form
pub fn g1_affine_from_montgomery(g1_mont: &G1Affine) -> G1Affine {
    let mut result = G1Affine::infinity();
    if !g1_mont.is_infinity() {
        unsafe {
            crate::ffi::g1_from_montgomery_wrapper(result.inner_mut(), g1_mont.inner());
        }
    }
    result
}

// Helper function to convert G2Affine from Montgomery form to normal form
pub fn g2_affine_from_montgomery(g2_mont: &G2Affine) -> G2Affine {
    let mut result = G2Affine::infinity();
    if !g2_mont.is_infinity() {
        unsafe {
            crate::ffi::g2_from_montgomery_wrapper(result.inner_mut(), g2_mont.inner());
        }
    }
    result
}

// Helper to extract limbs from an arkworks field element
fn field_to_limbs<F: PrimeField>(f: &F) -> [u64; 7] {
    let bigint = f.into_bigint();
    let mut limbs = [0u64; 7];
    for (i, limb) in bigint.as_ref().iter().take(7).enumerate() {
        limbs[i] = *limb;
    }
    limbs
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
    let x_limbs = field_to_limbs(&xy.0);
    let y_limbs = field_to_limbs(&xy.1);

    ZkG1Affine::new(x_limbs, y_limbs, false)
}

/// Convert from zk-cuda-backend's G1Projective to raw limbs
///
/// Returns (X, Y, Z) coordinates as 7-limb arrays.
/// The actual construction of arkworks types should be done by the caller.
pub fn g1_projective_to_limbs(proj: &ZkG1Projective) -> ([u64; 7], [u64; 7], [u64; 7]) {
    (proj.X(), proj.Y(), proj.Z())
}

/// Convert from zk-cuda-backend's G2Projective to raw limbs
///
/// Returns ((X.c0, X.c1), (Y.c0, Y.c1), (Z.c0, Z.c1)) coordinates as 7-limb arrays.
/// The actual construction of arkworks types should be done by the caller.
pub fn g2_projective_to_limbs(proj: &ZkG2Projective) -> G2ProjectiveLimbs {
    (proj.X(), proj.Y(), proj.Z())
}
