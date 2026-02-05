//! GPU acceleration module for tfhe-zk-pok
//!
//! This module provides GPU-accelerated operations using zk-cuda-backend,
//! type conversions between tfhe-zk-pok and zk-cuda-backend types,
//! and GPU-accelerated prove/verify entry points for pke (v1) and pke_v2.

#[cfg(test)]
mod tests;

pub(crate) mod pke;
pub(crate) mod pke_v2;

pub use pke::{prove_gpu as prove_pke_gpu, verify_gpu as verify_pke_gpu};
pub use pke_v2::{prove_gpu as prove_pke_v2_gpu, verify_gpu as verify_pke_v2_gpu};

use crate::curve_446::{Fq, Fq2};
use crate::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};
use crate::curve_api::CurveGroupOps;
use ark_ec::CurveGroup;
use ark_ff::{MontFp, PrimeField};
use tfhe_cuda_backend::cuda_bind::{
    cuda_create_stream, cuda_destroy_stream, cuda_get_number_of_gpus,
};
use zk_cuda_backend::{G1Affine as ZkG1Affine, G2Affine as ZkG2Affine, Scalar as ZkScalar};

// ---------------------------------------------------------------------------
// Compile-time assertions to verify transmute safety between wrapper types and inner arkworks
// types. These ensure that G1Affine/G2Affine wrappers are truly repr(transparent) around their
// inner types.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// GPU helpers
// ---------------------------------------------------------------------------

/// Returns the number of available GPUs. Panics if no GPU is found.
pub(crate) fn get_num_gpus() -> u32 {
    let num_gpus = unsafe { cuda_get_number_of_gpus() };
    assert!(num_gpus > 0, "No GPU available");
    num_gpus as u32
}

/// Selects a GPU for MSM based on the rayon thread index, distributing work
/// across all available GPUs. Returns `None` (meaning GPU 0) when only one GPU
/// is present.
#[inline]
pub(crate) fn select_gpu_for_msm() -> Option<u32> {
    let num_gpus = get_num_gpus();
    if num_gpus <= 1 {
        return None;
    }
    let thread_idx = rayon::current_thread_index().unwrap_or(0);
    Some((thread_idx % num_gpus as usize) as u32)
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

/// Extract normal-form limbs from an Fq2 element for the CUDA backend.
#[inline]
fn fq2_to_normal_limbs(fq2: &Fq2) -> ([u64; 7], [u64; 7]) {
    let c0_bigint = fq2.c0.into_bigint();
    let c1_bigint = fq2.c1.into_bigint();
    (c0_bigint.0, c1_bigint.0)
}

/// Reconstruct an Fq2 from sign and limb arrays for both components.
fn fq2_from_fq_sign_and_limbs(sign: bool, c0_limbs: &[u64; 7], c1_limbs: &[u64; 7]) -> Fq2 {
    Fq2::new(
        Fq::from_sign_and_limbs(sign, c0_limbs),
        Fq::from_sign_and_limbs(sign, c1_limbs),
    )
}

/// Convert a tfhe-zk-pok G1Affine to a zk-cuda-backend G1Affine (normal form).
pub fn g1_affine_to_zk_cuda(affine: &G1Affine) -> ZkG1Affine {
    use ark_ec::AffineRepr;
    use ark_ff::Zero;

    if affine.inner.is_zero() {
        return ZkG1Affine::infinity();
    }
    let zero = <Fq as Zero>::zero();
    let xy = affine.inner.xy().unwrap_or((zero, zero));
    let x_limbs = xy.0.into_bigint().0;
    let y_limbs = xy.1.into_bigint().0;
    ZkG1Affine::new(x_limbs, y_limbs, affine.inner.infinity)
}

/// Convert a zk-cuda-backend G1Affine back to a tfhe-zk-pok G1Affine.
pub fn g1_affine_from_zk_cuda(affine: &ZkG1Affine) -> G1Affine {
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
    G1Affine { inner }
}

/// Convert a tfhe-zk-pok G2Affine to a zk-cuda-backend G2Affine (normal form).
pub fn g2_affine_to_zk_cuda(affine: &G2Affine) -> ZkG2Affine {
    use ark_ec::AffineRepr;
    use ark_ff::Zero;

    if affine.inner.is_zero() {
        return ZkG2Affine::infinity();
    }
    let zero = <Fq2 as Zero>::zero();
    let xy = affine.inner.xy().unwrap_or((zero, zero));
    let (x_c0_limbs, x_c1_limbs) = fq2_to_normal_limbs(&xy.0);
    let (y_c0_limbs, y_c1_limbs) = fq2_to_normal_limbs(&xy.1);
    ZkG2Affine::new(
        (x_c0_limbs, x_c1_limbs),
        (y_c0_limbs, y_c1_limbs),
        affine.inner.infinity,
    )
}

/// Convert a zk-cuda-backend G2Affine back to a tfhe-zk-pok G2Affine.
pub fn g2_affine_from_zk_cuda(affine: &ZkG2Affine) -> G2Affine {
    if affine.is_infinity() {
        return G2::ZERO.normalize();
    }

    let (x_c0, x_c1) = affine.x();
    let (y_c0, y_c1) = affine.y();
    let x = Fq2::new(
        Fq::from_sign_and_limbs(true, &x_c0),
        Fq::from_sign_and_limbs(true, &x_c1),
    );
    let y = Fq2::new(
        Fq::from_sign_and_limbs(true, &y_c0),
        Fq::from_sign_and_limbs(true, &y_c1),
    );

    use crate::curve_446::g2::G2Projective;
    let one = MontFp!("1");
    let zero = MontFp!("0");
    let one_fq2 = Fq2::new(one, zero);
    let proj = G2Projective::new_unchecked(x, y, one_fq2);
    let inner = <G2Projective as CurveGroup>::into_affine(proj);
    G2Affine { inner }
}

/// Convert a Zp scalar to a zk-cuda-backend Scalar.
pub fn zp_to_zk_scalar(zp: &Zp) -> ZkScalar {
    let limbs = zp.inner.into_bigint().0;
    ZkScalar::from(limbs)
}

// ---------------------------------------------------------------------------
// GPU MSM functions
// ---------------------------------------------------------------------------

/// GPU-accelerated multi-scalar multiplication for G1. The `gpu_index` parameter
/// selects which GPU device to use; `None` defaults to GPU 0.
pub(crate) fn g1_msm_gpu(bases: &[G1Affine], scalars: &[Zp], gpu_index: Option<u32>) -> G1 {
    use crate::curve_446::g1::G1Projective;

    // Convert points to zk-cuda-backend format (normal form)
    let gpu_bases: Vec<_> = bases
        .iter()
        .map(|b| zk_cuda_backend::g1_affine_from_arkworks(&b.inner))
        .collect();

    let gpu_scalars: Vec<_> = scalars
        .iter()
        .map(|s| zk_cuda_backend::Scalar::from(s.inner.into_bigint().0))
        .collect();

    let gpu_index = gpu_index.unwrap_or(0);
    let stream = unsafe { cuda_create_stream(gpu_index) };

    let (gpu_result, _size_tracker) =
        zk_cuda_backend::G1Projective::msm(&gpu_bases, &gpu_scalars, stream, gpu_index, false)
            .unwrap_or_else(|e| panic!("G1 GPU MSM failed: {e}"));

    unsafe { cuda_destroy_stream(stream, gpu_index) };

    // Convert result from Montgomery form back to arkworks types
    let normalized = gpu_result.from_montgomery_normalized();

    let z_limbs = normalized.Z();
    if z_limbs.iter().all(|&limb| limb == 0) {
        return G1::ZERO;
    }

    let x = Fq::from_sign_and_limbs(true, &normalized.X());
    let y = Fq::from_sign_and_limbs(true, &normalized.Y());
    let z = Fq::from_sign_and_limbs(true, &z_limbs);
    G1 {
        inner: G1Projective::new_unchecked(x, y, z),
    }
}

/// GPU-accelerated multi-scalar multiplication for G2. The `gpu_index` parameter
/// selects which GPU device to use; `None` defaults to GPU 0.
pub(crate) fn g2_msm_gpu(bases: &[G2Affine], scalars: &[Zp], gpu_index: Option<u32>) -> G2 {
    use crate::curve_446::g2::G2Projective;
    use ark_ec::AffineRepr;

    // Convert points to zk-cuda-backend format (normal form)
    let gpu_bases: Vec<_> = bases
        .iter()
        .map(|b| {
            if b.inner.is_zero() {
                return zk_cuda_backend::G2Affine::infinity();
            }
            let x_limbs = fq2_to_normal_limbs(&b.inner.x);
            let y_limbs = fq2_to_normal_limbs(&b.inner.y);
            zk_cuda_backend::G2Affine::new(x_limbs, y_limbs, false)
        })
        .collect();

    let gpu_scalars: Vec<_> = scalars
        .iter()
        .map(|s| zk_cuda_backend::Scalar::from(s.inner.into_bigint().0))
        .collect();

    let gpu_index = gpu_index.unwrap_or(0);
    let stream = unsafe { cuda_create_stream(gpu_index) };

    let (gpu_result, _size_tracker) =
        zk_cuda_backend::G2Projective::msm(&gpu_bases, &gpu_scalars, stream, gpu_index, false)
            .unwrap_or_else(|e| panic!("G2 GPU MSM failed: {e}"));

    unsafe { cuda_destroy_stream(stream, gpu_index) };

    // Convert result from Montgomery form back to arkworks types
    let normalized = gpu_result.from_montgomery_normalized();
    let (x_c0, x_c1) = normalized.X();
    let (y_c0, y_c1) = normalized.Y();
    let (z_c0, z_c1) = normalized.Z();

    let z_is_zero = z_c0.iter().all(|&limb| limb == 0) && z_c1.iter().all(|&limb| limb == 0);
    if z_is_zero {
        return G2::ZERO;
    }

    let x = fq2_from_fq_sign_and_limbs(true, &x_c0, &x_c1);
    let y = fq2_from_fq_sign_and_limbs(true, &y_c0, &y_c1);
    let z = fq2_from_fq_sign_and_limbs(true, &z_c0, &z_c1);
    G2 {
        inner: G2Projective::new_unchecked(x, y, z),
    }
}
