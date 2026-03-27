//! GPU acceleration module for tfhe-zk-pok
//!
//! This module provides GPU-accelerated operations using zk-cuda-backend,
//! type conversions between tfhe-zk-pok and zk-cuda-backend types,
//! and GPU MSM helper functions used by the `pke` and `pke_v2` submodules.

pub mod pke_v2;

#[cfg(test)]
mod tests;

use std::cell::Cell;

use crate::curve_446::{Fq, Fq2};
use crate::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};
use crate::curve_api::CurveGroupOps;
use ark_ec::CurveGroup;
use ark_ff::{BigInt, MontFp, PrimeField};
use tfhe_cuda_backend::cuda_bind::cuda_get_number_of_gpus;
use zk_cuda_backend::{G1Affine as CudaG1Affine, G2Affine as CudaG2Affine, Scalar as CudaScalar};

thread_local! {
    static GPU_AFFINITY: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Run `f` with all GPU MSM operations pinned to `gpu_idx`.
///
/// While active, `select_gpu_for_msm()` returns `gpu_idx` instead of
/// the rayon-thread-based default, and `run_in_pool` is bypassed
/// (the caller is responsible for providing an appropriately-sized
/// thread pool).
pub fn with_gpu_affinity<R>(gpu_idx: u32, f: impl FnOnce() -> R) -> R {
    struct ResetOnDrop;
    impl Drop for ResetOnDrop {
        fn drop(&mut self) {
            GPU_AFFINITY.set(None);
        }
    }
    GPU_AFFINITY.set(Some(gpu_idx));
    let _guard = ResetOnDrop;
    f()
}

/// Set GPU affinity for the current thread directly.
///
/// Intended for use with `rayon::ThreadPool::broadcast` to pin all pool
/// threads to a specific GPU. Pass `None` to clear.
pub fn set_gpu_affinity(gpu_idx: Option<u32>) {
    GPU_AFFINITY.set(gpu_idx);
}

pub(crate) fn current_gpu_affinity() -> Option<u32> {
    GPU_AFFINITY.get()
}

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

/// Selects a GPU for MSM operations.
///
/// If GPU affinity is set (via `with_gpu_affinity`), returns that GPU index
/// unconditionally. Otherwise falls back to distributing work across GPUs
/// based on the rayon thread index. Returns `0` when only one GPU is present.
#[inline]
pub fn select_gpu_for_msm() -> u32 {
    if let Some(idx) = GPU_AFFINITY.get() {
        return idx;
    }
    let num_gpus = get_num_gpus();
    if num_gpus <= 1 {
        return 0;
    }
    let thread_idx = rayon::current_thread_index().unwrap_or(0);
    let num_gpus_usize: usize = num_gpus.try_into().expect("GPU count fits in usize");
    (thread_idx % num_gpus_usize)
        .try_into()
        .expect("GPU index fits in u32")
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
/// Panics if the input point is non-infinity but has no coordinates (malformed arkworks point).
pub fn g1_affine_to_cuda(affine: &G1Affine) -> CudaG1Affine {
    use ark_ec::AffineRepr;

    if affine.inner.is_zero() {
        return CudaG1Affine::infinity();
    }
    let xy = affine
        .inner
        .xy()
        .expect("non-infinity point must have coordinates");
    let x = fq_to_cuda_fp(&xy.0);
    let y = fq_to_cuda_fp(&xy.1);
    CudaG1Affine::new(x, y, affine.inner.infinity)
}

/// Convert a zk-cuda-backend G1Affine back to a tfhe-zk-pok G1Affine.
///
/// # Panics
///
/// Panics if the Fp limbs from the zk-cuda-backend point do not represent a valid `Fq` element
/// (i.e., the value is not in the base field).
pub fn g1_affine_from_cuda(affine: &CudaG1Affine) -> G1Affine {
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
/// Panics if the input point is non-infinity but has no coordinates (malformed arkworks point).
pub fn g2_affine_to_cuda(affine: &G2Affine) -> CudaG2Affine {
    use ark_ec::AffineRepr;

    if affine.inner.is_zero() {
        return CudaG2Affine::infinity();
    }
    let xy = affine
        .inner
        .xy()
        .expect("non-infinity point must have coordinates");
    let x = fq2_to_cuda_fp2(&xy.0);
    let y = fq2_to_cuda_fp2(&xy.1);
    CudaG2Affine::new(x, y, affine.inner.infinity)
}

/// Convert a zk-cuda-backend G2Affine back to a tfhe-zk-pok G2Affine.
///
/// # Panics
///
/// Panics if the Fp limbs from the zk-cuda-backend point do not represent valid `Fq` elements
/// (i.e., the values are not in the base field).
pub fn g2_affine_from_cuda(affine: &CudaG2Affine) -> G2Affine {
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

/// Convert a tfhe-zk-pok Zp scalar to a zk-cuda-backend Scalar.
pub fn zp_to_cuda_scalar(zp: &Zp) -> CudaScalar {
    let limbs = zp.inner.into_bigint().0;
    CudaScalar::from(limbs)
}

// ---------------------------------------------------------------------------
// GPU MSM functions
// ---------------------------------------------------------------------------

/// GPU-accelerated multi-scalar multiplication for G1.
///
/// # Panics
///
/// - If `gpu_index >= number of available GPUs`.
/// - If `bases` and `scalars` have different lengths (checked inside the backend).
/// - If the GPU MSM call fails.
#[must_use]
pub fn g1_msm_gpu(bases: &[G1Affine], scalars: &[Zp], gpu_index: u32) -> G1 {
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

    let num_gpus = get_num_gpus();
    assert!(
        gpu_index < num_gpus,
        "gpu_index {gpu_index} exceeds available GPUs ({num_gpus})",
    );
    let stream = tfhe_cuda_backend::CudaStream::new(gpu_index);

    let result = zk_cuda_backend::G1Projective::msm(
        &gpu_bases,
        &gpu_scalars,
        stream.ptr(),
        gpu_index,
        false,
    );

    let gpu_result = result.unwrap_or_else(|e| panic!("G1 GPU MSM failed: {e}"));

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

/// G2 MSM on a caller-provided stream (no stream create/destroy).
///
/// # Panics
///
/// - If `gpu_index >= number of available GPUs`.
/// - If `bases` and `scalars` have different lengths (checked inside the backend).
/// - If the GPU MSM call fails.
#[must_use]
pub fn g2_msm_gpu_on_stream(
    bases: &[G2Affine],
    scalars: &[Zp],
    stream: *mut std::ffi::c_void,
    gpu_index: u32,
) -> G2 {
    use crate::curve_446::g2::G2Projective;
    use ark_ec::AffineRepr;

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

    let num_gpus = get_num_gpus();
    assert!(
        gpu_index < num_gpus,
        "gpu_index {gpu_index} exceeds available GPUs ({num_gpus})",
    );

    let result =
        zk_cuda_backend::G2Projective::msm(&gpu_bases, &gpu_scalars, stream, gpu_index, false);

    let gpu_result = result.unwrap_or_else(|e| panic!("G2 GPU MSM failed: {e}"));

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

/// G2 MSM that creates and destroys its own CUDA stream.
#[must_use]
pub fn g2_msm_gpu(bases: &[G2Affine], scalars: &[Zp], gpu_index: u32) -> G2 {
    let num_gpus = get_num_gpus();
    assert!(
        gpu_index < num_gpus,
        "gpu_index {gpu_index} exceeds available GPUs ({num_gpus})",
    );
    let stream = tfhe_cuda_backend::CudaStream::new(gpu_index);
    g2_msm_gpu_on_stream(bases, scalars, stream.ptr(), gpu_index)
}

/// Per-GPU cached base-point handles from the C++ singleton cache.
///
/// The C++ `ZkMsmCache` singleton owns the device memory and manages its
/// lifecycle. These pointers are immutable and valid as long as this struct
/// is alive. Drop calls `zk_msm_cache_release` to decrement the C++ ref
/// count — the cache is only eligible for eviction (by a different CRS key)
/// once all `CachedMsmResources` instances are dropped.
///
/// Callers index into `cached_g1` / `cached_g2` by gpu_index to get the
/// device pointer for a specific GPU.
pub(crate) struct CachedMsmResources {
    pub cached_g1: Vec<*const std::ffi::c_void>,
    pub cached_g2: Vec<*const std::ffi::c_void>,
    pub num_gpus: u32,
    pub size_tracker: u64,
}

impl Drop for CachedMsmResources {
    fn drop(&mut self) {
        // SAFETY: zk_msm_cache_release is a simple atomic decrement inside
        // the C++ singleton — no CUDA calls unless this is the last reference
        // AND the cache is being evicted, which only happens inside a
        // subsequent zk_msm_cache_acquire.
        unsafe {
            zk_cuda_backend::bindings::zk_msm_cache_release();
        }
    }
}

// SAFETY: The raw pointers point to immutable device memory (base points in
// Montgomery form) inside the C++ singleton cache. The cache is thread-safe
// (protected by a mutex on the C++ side) and the memory is never modified
// after initial setup. Multiple threads can safely read these concurrently.
unsafe impl Send for CachedMsmResources {}
unsafe impl Sync for CachedMsmResources {}

/// Acquire cached base-point pointers for the given CRS point lists.
///
/// Delegates to the C++ `ZkMsmCache` singleton. On cache miss (first call
/// or CRS change), uploads both g_list and g_hat_list to **every available
/// GPU** in Montgomery form. On cache hit, returns immediately.
///
/// Only immutable base points are cached. Callers are responsible for
/// creating their own CUDA streams and MSM scratch buffers for each call.
pub(crate) fn acquire_cached_msm_resources(
    g_list: &[G1Affine],
    g_hat_list: &[G2Affine],
) -> CachedMsmResources {
    let ffi_g1: Vec<zk_cuda_backend::bindings::G1Point> = g_list
        .iter()
        .map(|p| {
            let cuda = g1_affine_to_cuda(p);
            zk_cuda_backend::bindings::G1Point {
                x: cuda.x(),
                y: cuda.y(),
                infinity: cuda.is_infinity(),
            }
        })
        .collect();

    let ffi_g2: Vec<zk_cuda_backend::bindings::G2Point> = g_hat_list
        .iter()
        .map(|p| {
            let cuda = g2_affine_to_cuda(p);
            zk_cuda_backend::bindings::G2Point {
                x: cuda.x(),
                y: cuda.y(),
                infinity: cuda.is_infinity(),
            }
        })
        .collect();

    // Cache key: content-based hash of the first G1 and G2 points.
    // We cannot use pointer identity because Rust may reuse freed addresses
    // for new allocations, causing the cache to return stale GPU data from a
    // previously uploaded (and now-freed) CRS.
    let key: [usize; 4] = {
        use std::hash::{Hash, Hasher};
        let mut h = std::hash::DefaultHasher::new();
        if let Some(p) = ffi_g1.first() {
            p.x.limb.hash(&mut h);
            p.y.limb.hash(&mut h);
        }
        let h1 = h.finish() as usize;
        let mut h = std::hash::DefaultHasher::new();
        if let Some(p) = ffi_g2.first() {
            p.x.c0.limb.hash(&mut h);
            p.x.c1.limb.hash(&mut h);
        }
        let h2 = h.finish() as usize;
        [h1, g_list.len(), h2, g_hat_list.len()]
    };

    let n_g1: u32 = g_list.len().try_into().expect("g_list length fits in u32");
    let n_g2: u32 = g_hat_list
        .len()
        .try_into()
        .expect("g_hat_list length fits in u32");

    let g1_ptr = if ffi_g1.is_empty() {
        std::ptr::null()
    } else {
        ffi_g1.as_ptr()
    };
    let g2_ptr = if ffi_g2.is_empty() {
        std::ptr::null()
    } else {
        ffi_g2.as_ptr()
    };

    // SAFETY: g1_ptr/g2_ptr are either null or valid pointers to n_g1/n_g2
    // G1Point/G2Point structs. key is a valid 4-element array. The C++ side
    // is internally thread-safe (mutex-protected).
    let mut size_tracker: u64 = 0;
    let num_gpus = unsafe {
        zk_cuda_backend::bindings::zk_msm_cache_acquire(
            g1_ptr,
            n_g1,
            g2_ptr,
            n_g2,
            key.as_ptr(),
            &mut size_tracker,
        )
    };

    let cached_g1: Vec<*const std::ffi::c_void> = (0..num_gpus)
        .map(|i| {
            // SAFETY: cache is populated (zk_msm_cache_acquire just returned),
            // and i < num_gpus.
            unsafe { zk_cuda_backend::bindings::zk_msm_cache_get_g1(i) as *const std::ffi::c_void }
        })
        .collect();
    let cached_g2: Vec<*const std::ffi::c_void> = (0..num_gpus)
        .map(|i| {
            // SAFETY: same as above.
            unsafe { zk_cuda_backend::bindings::zk_msm_cache_get_g2(i) as *const std::ffi::c_void }
        })
        .collect();

    CachedMsmResources {
        cached_g1,
        cached_g2,
        num_gpus,
        size_tracker,
    }
}

/// G1 MSM using cached device base points and pre-allocated scratch.
/// Only scalars are transferred H2D.
#[must_use]
pub(crate) fn g1_msm_cached_on_stream(
    msm_mem: *mut std::ffi::c_void,
    cached: *const std::ffi::c_void,
    point_offset: u32,
    scalars: &[Zp],
    stream: *mut std::ffi::c_void,
    gpu_index: u32,
) -> G1 {
    use crate::curve_446::g1::G1Projective;

    let scalars_ffi: Vec<zk_cuda_backend::bindings::Scalar> = scalars
        .iter()
        .map(|s| zk_cuda_backend::bindings::Scalar {
            limb: s.inner.into_bigint().0,
        })
        .collect();
    let n: u32 = scalars_ffi
        .len()
        .try_into()
        .expect("GPU MSM: scalar count too large for u32");

    let mut result = zk_cuda_backend::bindings::G1ProjectivePoint::default();
    let cuda_stream = stream as zk_cuda_backend::bindings::cudaStream_t;

    // SAFETY: `msm_mem` was allocated by `scratch_zk_g1_msm` for >= n points.
    // `cached` is a valid handle from `scratch_zk_cached_g1_points`.
    // `scalars_ffi` is a valid host array with `n` elements.
    // The function synchronizes internally before writing to `result`.
    unsafe {
        zk_cuda_backend::bindings::zk_g1_msm_cached_async(
            cuda_stream,
            gpu_index,
            msm_mem as *mut _,
            &mut result,
            cached as *const _,
            point_offset,
            scalars_ffi.as_ptr(),
            n,
        );
    }

    let gpu_result = zk_cuda_backend::G1Projective::new(result.X, result.Y, result.Z);
    let normalized = gpu_result.from_montgomery_normalized();
    let x_fp = normalized.X();
    let y_fp = normalized.Y();
    let z_fp = normalized.Z();

    if z_fp.limb.iter().all(|&l| l == 0) {
        return G1::ZERO;
    }

    let x = fq_from_cuda_fp(&x_fp);
    let y = fq_from_cuda_fp(&y_fp);
    let z = fq_from_cuda_fp(&z_fp);
    G1 {
        inner: G1Projective::new_unchecked(x, y, z),
    }
}

/// G2 MSM using cached device base points and pre-allocated scratch.
/// Only scalars are transferred H2D.
#[must_use]
pub(crate) fn g2_msm_cached_on_stream(
    msm_mem: *mut std::ffi::c_void,
    cached: *const std::ffi::c_void,
    point_offset: u32,
    scalars: &[Zp],
    stream: *mut std::ffi::c_void,
    gpu_index: u32,
) -> G2 {
    use crate::curve_446::g2::G2Projective;

    let scalars_ffi: Vec<zk_cuda_backend::bindings::Scalar> = scalars
        .iter()
        .map(|s| zk_cuda_backend::bindings::Scalar {
            limb: s.inner.into_bigint().0,
        })
        .collect();
    let n: u32 = scalars_ffi
        .len()
        .try_into()
        .expect("GPU MSM: scalar count too large for u32");

    let mut result = zk_cuda_backend::bindings::G2ProjectivePoint::default();
    let cuda_stream = stream as zk_cuda_backend::bindings::cudaStream_t;

    // SAFETY: `msm_mem` was allocated by `scratch_zk_g2_msm` for >= n points.
    // `cached` is a valid handle from `scratch_zk_cached_g2_points`.
    // `scalars_ffi` is a valid host array with `n` elements.
    // The function synchronizes internally before writing to `result`.
    unsafe {
        zk_cuda_backend::bindings::zk_g2_msm_cached_async(
            cuda_stream,
            gpu_index,
            msm_mem as *mut _,
            &mut result,
            cached as *const _,
            point_offset,
            scalars_ffi.as_ptr(),
            n,
        );
    }

    let gpu_result = zk_cuda_backend::G2Projective::new(result.X, result.Y, result.Z);
    let normalized = gpu_result.from_montgomery_normalized();
    let x_fp2 = normalized.X();
    let y_fp2 = normalized.Y();
    let z_fp2 = normalized.Z();

    let z_is_zero = z_fp2.c0.limb.iter().all(|&l| l == 0) && z_fp2.c1.limb.iter().all(|&l| l == 0);
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
