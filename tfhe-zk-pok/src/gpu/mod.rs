//! GPU acceleration module
//!
//! This module provides GPU-accelerated operations using zk-cuda-backend
//! and integration tests for verifying correctness.

#[cfg(test)]
mod tests;

use crate::curve_446::{Fq, Fq2};
use crate::curve_api::bls12_446::{G1Affine, G2Affine, Zp};
use ark_ec::CurveGroup;
use ark_ff::{MontFp, PrimeField};
use zk_cuda_backend::{G1Affine as ZkG1Affine, G2Affine as ZkG2Affine, Scalar as ZkScalar};

// Compile-time assertions to verify transmute safety between wrapper types and inner arkworks
// types. These ensure that G1Affine/G2Affine wrappers are truly repr(transparent) around their
// inner types.
const _: () = {
    assert!(
        std::mem::size_of::<G1Affine>() == std::mem::size_of::<crate::curve_446::g1::G1Affine>()
    );
    assert!(
        std::mem::align_of::<G1Affine>() == std::mem::align_of::<crate::curve_446::g1::G1Affine>()
    );
    assert!(
        std::mem::size_of::<G2Affine>() == std::mem::size_of::<crate::curve_446::g2::G2Affine>()
    );
    assert!(
        std::mem::align_of::<G2Affine>() == std::mem::align_of::<crate::curve_446::g2::G2Affine>()
    );
};

/// Convert from tfhe-zk-pok's G1Affine wrapper to zk-cuda-backend's G1Affine
///
/// This delegates to the `From<&G1Affine>` implementation in `curve_api::bls12_446`.
pub fn g1_affine_to_zk_cuda(affine: &G1Affine) -> ZkG1Affine {
    ZkG1Affine::from(affine)
}

/// Convert from zk-cuda-backend's G1Affine to tfhe-zk-pok's G1Affine
pub fn g1_affine_from_zk_cuda(affine: &ZkG1Affine) -> G1Affine {
    use crate::curve_api::bls12_446::G1;
    use crate::curve_api::CurveGroupOps;

    if affine.is_infinity() {
        return G1::ZERO.normalize();
    }

    let x_limbs = affine.x();
    let y_limbs = affine.y();

    let x = Fq::from_sign_and_limbs(true, &x_limbs);
    let y = Fq::from_sign_and_limbs(true, &y_limbs);

    use crate::curve_446::g1::G1Projective;
    let one = MontFp!("1");
    let proj = G1Projective::new_unchecked(x, y, one);
    let inner = <G1Projective as CurveGroup>::into_affine(proj);

    // SAFETY: G1Affine is repr(transparent)
    unsafe { core::mem::transmute(inner) }
}

/// Convert from tfhe-zk-pok's G2Affine wrapper to zk-cuda-backend's G2Affine
///
/// This delegates to the `From<&G2Affine>` implementation in `curve_api::bls12_446`.
pub fn g2_affine_to_zk_cuda(affine: &G2Affine) -> ZkG2Affine {
    ZkG2Affine::from(affine)
}

/// Convert from zk-cuda-backend's G2Affine to tfhe-zk-pok's G2Affine
pub fn g2_affine_from_zk_cuda(affine: &ZkG2Affine) -> G2Affine {
    use crate::curve_api::bls12_446::G2;
    use crate::curve_api::CurveGroupOps;

    if affine.is_infinity() {
        return G2::ZERO.normalize();
    }

    let (x_c0, x_c1) = affine.x();
    let (y_c0, y_c1) = affine.y();

    let x0 = Fq::from_sign_and_limbs(true, &x_c0);
    let x1 = Fq::from_sign_and_limbs(true, &x_c1);
    let y0 = Fq::from_sign_and_limbs(true, &y_c0);
    let y1 = Fq::from_sign_and_limbs(true, &y_c1);

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    use crate::curve_446::g2::G2Projective;
    let one = MontFp!("1");
    let zero = MontFp!("0");
    let one_fq2 = Fq2::new(one, zero);
    let proj = G2Projective::new_unchecked(x, y, one_fq2);
    let inner = <G2Projective as CurveGroup>::into_affine(proj);

    // SAFETY: G2Affine is repr(transparent)
    unsafe { core::mem::transmute(inner) }
}

/// Convert Zp scalar to zk-cuda-backend Scalar
pub fn zp_to_zk_scalar(zp: &Zp) -> ZkScalar {
    let limbs = zp.inner.into_bigint().0;
    ZkScalar::from(limbs)
}
