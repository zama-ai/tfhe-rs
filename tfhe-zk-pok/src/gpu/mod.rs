//! GPU acceleration module for tfhe-zk-pok
//!
//! This module provides GPU-accelerated operations using zk-cuda-backend,
//! type conversions between tfhe-zk-pok and zk-cuda-backend types,
//! and GPU MSM helper functions used by `proofs::pke::gpu` and
//! `proofs::pke_v2::gpu`.

#[cfg(test)]
mod tests;

use crate::curve_446::{Fq, Fq2};
use crate::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};
use crate::curve_api::CurveGroupOps;
use ark_ec::CurveGroup;
use ark_ff::{BigInt, MontFp, PrimeField};
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
///
/// The result is cached after the first call since GPU count cannot change
/// during execution.
pub(crate) fn get_num_gpus() -> u32 {
    static NUM_GPUS: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *NUM_GPUS.get_or_init(|| {
        // SAFETY: cuda_get_number_of_gpus is a pure query with no preconditions
        let num_gpus = unsafe { cuda_get_number_of_gpus() };
        assert!(num_gpus > 0, "No GPU available");
        num_gpus
            .try_into()
            .expect("cuda_get_number_of_gpus returned negative value")
    })
}

/// Selects a GPU for MSM based on the rayon thread index, distributing work
/// across all available GPUs. Returns `None` (meaning GPU 0) when only one GPU
/// is present.
#[inline]
pub fn select_gpu_for_msm() -> Option<u32> {
    let num_gpus = get_num_gpus();
    if num_gpus <= 1 {
        return None;
    }
    let thread_idx = rayon::current_thread_index().unwrap_or(0);
    Some(
        (thread_idx % num_gpus as usize)
            .try_into()
            .expect("GPU index fits in u32"),
    )
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

/// Convert an Fq element (arkworks) to a zk-cuda-backend Fp (normal form limbs).
#[inline]
fn fq_to_cuda_fp(fq: &Fq) -> zk_cuda_backend::Fp {
    zk_cuda_backend::Fp::new(fq.into_bigint().0)
}

/// Convert a zk-cuda-backend Fp (normal form limbs) back to an arkworks Fq.
#[inline]
fn fq_from_cuda_fp(fp: &zk_cuda_backend::Fp) -> Fq {
    Fq::from_bigint(BigInt::new(fp.limb)).expect("invalid Fq element from CUDA Fp limbs")
}

/// Convert an Fq2 element (arkworks) to a zk-cuda-backend Fp2 (normal form).
#[inline]
fn fq2_to_cuda_fp2(fq2: &Fq2) -> zk_cuda_backend::bindings::Fp2 {
    zk_cuda_backend::bindings::Fp2 {
        c0: fq_to_cuda_fp(&fq2.c0),
        c1: fq_to_cuda_fp(&fq2.c1),
    }
}

/// Convert a zk-cuda-backend Fp2 back to an arkworks Fq2.
#[inline]
fn fq2_from_cuda_fp2(fp2: &zk_cuda_backend::bindings::Fp2) -> Fq2 {
    Fq2::new(fq_from_cuda_fp(&fp2.c0), fq_from_cuda_fp(&fp2.c1))
}

/// Convert a tfhe-zk-pok G1Affine to a zk-cuda-backend G1Affine (normal form).
///
/// # Panics
///
/// Panics if the input point is non-identity but has no coordinates (malformed arkworks point).
pub fn g1_affine_to_zk_cuda(affine: &G1Affine) -> ZkG1Affine {
    use ark_ec::AffineRepr;

    if affine.inner.is_zero() {
        return ZkG1Affine::infinity();
    }
    let xy = affine
        .inner
        .xy()
        .expect("non-identity point must have coordinates");
    let x = fq_to_cuda_fp(&xy.0);
    let y = fq_to_cuda_fp(&xy.1);
    ZkG1Affine::new(x, y, affine.inner.infinity)
}

/// Convert a zk-cuda-backend G1Affine back to a tfhe-zk-pok G1Affine.
///
/// # Panics
///
/// Panics if the Fp limbs from the zk-cuda-backend point do not represent a valid `Fq` element
/// (i.e., the value is not in the base field).
pub fn g1_affine_from_zk_cuda(affine: &ZkG1Affine) -> G1Affine {
    if affine.is_infinity() {
        return G1::ZERO.normalize();
    }

    let x = fq_from_cuda_fp(&affine.x());
    let y = fq_from_cuda_fp(&affine.y());

    use crate::curve_446::g1::G1Projective;
    let one = MontFp!("1");
    let proj = G1Projective::new_unchecked(x, y, one);
    let inner = <G1Projective as CurveGroup>::into_affine(proj);
    G1Affine { inner }
}

/// Convert a tfhe-zk-pok G2Affine to a zk-cuda-backend G2Affine (normal form).
///
/// # Panics
///
/// Panics if the input point is non-identity but has no coordinates (malformed arkworks point).
pub fn g2_affine_to_zk_cuda(affine: &G2Affine) -> ZkG2Affine {
    use ark_ec::AffineRepr;

    if affine.inner.is_zero() {
        return ZkG2Affine::infinity();
    }
    let xy = affine
        .inner
        .xy()
        .expect("non-identity point must have coordinates");
    let x = fq2_to_cuda_fp2(&xy.0);
    let y = fq2_to_cuda_fp2(&xy.1);
    ZkG2Affine::new(x, y, affine.inner.infinity)
}

/// Convert a zk-cuda-backend G2Affine back to a tfhe-zk-pok G2Affine.
///
/// # Panics
///
/// Panics if the Fp limbs from the zk-cuda-backend point do not represent valid `Fq` elements
/// (i.e., the values are not in the base field).
pub fn g2_affine_from_zk_cuda(affine: &ZkG2Affine) -> G2Affine {
    if affine.is_infinity() {
        return G2::ZERO.normalize();
    }

    let x = fq2_from_cuda_fp2(&affine.x());
    let y = fq2_from_cuda_fp2(&affine.y());

    use crate::curve_446::g2::G2Projective;
    let one = MontFp!("1");
    let zero = MontFp!("0");
    let one_fq2 = Fq2::new(one, zero);
    let proj = G2Projective::new_unchecked(x, y, one_fq2);
    let inner = <G2Projective as CurveGroup>::into_affine(proj);
    G2Affine { inner }
}

/// Convert a Zp scalar to a zk-cuda-backend Scalar.
///
/// # Panics
///
/// This function does not panic. The `into_bigint` conversion on arkworks `Fp` types is
/// infallible, and `ZkScalar::from` accepts any 5-limb array.
pub fn zp_to_zk_scalar(zp: &Zp) -> ZkScalar {
    let limbs = zp.inner.into_bigint().0;
    ZkScalar::from(limbs)
}

// ---------------------------------------------------------------------------
// GPU MSM functions
// ---------------------------------------------------------------------------

/// GPU-accelerated multi-scalar multiplication for G1. The `gpu_index` parameter
/// selects which GPU device to use; `None` defaults to GPU 0.
///
/// # Panics
///
/// - If `gpu_index` is `Some(i)` where `i >= number of available GPUs`.
/// - If `bases` and `scalars` have different lengths (checked inside the backend).
/// - If the GPU MSM call fails.
pub fn g1_msm_gpu(bases: &[G1Affine], scalars: &[Zp], gpu_index: Option<u32>) -> G1 {
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
    let num_gpus = get_num_gpus();
    assert!(
        gpu_index < num_gpus,
        "gpu_index {gpu_index} exceeds available GPUs ({num_gpus})",
    );
    // SAFETY: gpu_index was validated by the assert above
    let stream = unsafe { cuda_create_stream(gpu_index) };

    let result =
        zk_cuda_backend::G1Projective::msm(&gpu_bases, &gpu_scalars, stream, gpu_index, false);

    // SAFETY: stream was created by cuda_create_stream above with the same gpu_index and is not
    // used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let (gpu_result, _size_tracker) = result.unwrap_or_else(|e| panic!("G1 GPU MSM failed: {e}"));

    // Convert result from Montgomery form back to arkworks types
    let normalized = gpu_result.from_montgomery_normalized();

    let z_fp = normalized.Z();
    if z_fp.limb.iter().all(|&limb| limb == 0) {
        return G1::ZERO;
    }

    let x = fq_from_cuda_fp(&normalized.X());
    let y = fq_from_cuda_fp(&normalized.Y());
    let z = fq_from_cuda_fp(&z_fp);
    G1 {
        inner: G1Projective::new_unchecked(x, y, z),
    }
}

/// GPU-accelerated multi-scalar multiplication for G2. The `gpu_index` parameter
/// selects which GPU device to use; `None` defaults to GPU 0.
///
/// # Panics
///
/// - If `gpu_index` is `Some(i)` where `i >= number of available GPUs`.
/// - If `bases` and `scalars` have different lengths (checked inside the backend).
/// - If the GPU MSM call fails.
pub fn g2_msm_gpu(bases: &[G2Affine], scalars: &[Zp], gpu_index: Option<u32>) -> G2 {
    use crate::curve_446::g2::G2Projective;
    use ark_ec::AffineRepr;

    // Convert points to zk-cuda-backend format (normal form)
    let gpu_bases: Vec<_> = bases
        .iter()
        .map(|b| {
            if b.inner.is_zero() {
                return zk_cuda_backend::G2Affine::infinity();
            }
            let x = fq2_to_cuda_fp2(&b.inner.x);
            let y = fq2_to_cuda_fp2(&b.inner.y);
            zk_cuda_backend::G2Affine::new(x, y, false)
        })
        .collect();

    let gpu_scalars: Vec<_> = scalars
        .iter()
        .map(|s| zk_cuda_backend::Scalar::from(s.inner.into_bigint().0))
        .collect();

    let gpu_index = gpu_index.unwrap_or(0);
    let num_gpus = get_num_gpus();
    assert!(
        gpu_index < num_gpus,
        "gpu_index {gpu_index} exceeds available GPUs ({num_gpus})",
    );
    // SAFETY: gpu_index was validated by the assert above
    let stream = unsafe { cuda_create_stream(gpu_index) };

    let result =
        zk_cuda_backend::G2Projective::msm(&gpu_bases, &gpu_scalars, stream, gpu_index, false);

    // SAFETY: stream was created by cuda_create_stream above with the same gpu_index and is not
    // used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let (gpu_result, _size_tracker) = result.unwrap_or_else(|e| panic!("G2 GPU MSM failed: {e}"));

    // Convert result from Montgomery form back to arkworks types
    let normalized = gpu_result.from_montgomery_normalized();
    let x_fp2 = normalized.X();
    let y_fp2 = normalized.Y();
    let z_fp2 = normalized.Z();

    let z_is_zero =
        z_fp2.c0.limb.iter().all(|&limb| limb == 0) && z_fp2.c1.limb.iter().all(|&limb| limb == 0);
    if z_is_zero {
        return G2::ZERO;
    }

    let x = fq2_from_cuda_fp2(&x_fp2);
    let y = fq2_from_cuda_fp2(&y_fp2);
    let z = fq2_from_cuda_fp2(&z_fp2);
    G2 {
        inner: G2Projective::new_unchecked(x, y, z),
    }
}
