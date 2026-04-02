//! GPU acceleration module for tfhe-zk-pok
//!
//! This module provides GPU-accelerated operations using zk-cuda-backend,
//! type conversions between tfhe-zk-pok and zk-cuda-backend types,
//! and GPU MSM helper functions used by the `pke` and `pke_v2` submodules.

pub mod pke_v2;

#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::sync::{Arc, Mutex};

use crate::curve_446::{Fq, Fq2};
use crate::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};
use crate::curve_api::CurveGroupOps;
use ark_ec::CurveGroup;
use ark_ff::{BigInt, MontFp, PrimeField};
use tfhe_cuda_backend::cuda_bind::{
    cuda_create_stream, cuda_destroy_stream, cuda_get_number_of_gpus,
};
use zk_cuda_backend::{G1Affine as CudaG1Affine, G2Affine as CudaG2Affine, Scalar as CudaScalar};

// ---------------------------------------------------------------------------
// Thread-local GPU affinity
// ---------------------------------------------------------------------------

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

/// Returns the current thread's GPU affinity, if set.
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
// Send wrapper for raw CUDA stream pointers
// ---------------------------------------------------------------------------

/// Wrapper that marks a raw pointer as `Send`.
///
/// CUDA streams are thread-safe for submission from any host thread, so it is
/// sound to move a `*mut c_void` stream handle across threads.  This newtype
/// exists solely to satisfy Rust's `Send` requirement in `rayon::scope` closures
/// where we pre-create streams outside the scope and hand them to worker threads.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SendPtr(pub *mut std::ffi::c_void);

// SAFETY: CUDA stream handles are safe to use from any host thread.
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

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
// Type conversion helpers for caching
// ---------------------------------------------------------------------------

/// Convert a slice of G1Affine points to FFI G1Point format.
///
/// Same pattern as [`g2_points_to_ffi`] but for G1 (Fp coordinates instead of Fp2).
pub(crate) fn g1_points_to_ffi(points: &[G1Affine]) -> Vec<zk_cuda_backend::bindings::G1Point> {
    use ark_ec::AffineRepr;

    points
        .iter()
        .map(|b| {
            if b.inner.is_zero() {
                let mut point = zk_cuda_backend::bindings::G1Point::default();
                // SAFETY: `point` is a valid, zero-initialized G1Point with repr(C) layout.
                unsafe {
                    zk_cuda_backend::bindings::g1_point_at_infinity_wrapper(&mut point);
                }
                return point;
            }
            let x = fq_to_cuda_fp(&b.inner.x);
            let y = fq_to_cuda_fp(&b.inner.y);
            zk_cuda_backend::bindings::G1Point {
                x,
                y,
                infinity: false,
            }
        })
        .collect()
}

/// Convert a slice of G2Affine points to FFI G2Point format.
///
/// This extracts the conversion logic used by `g2_msm_gpu_on_stream` so that
/// callers who cache points on device can convert once and reuse the result.
pub(crate) fn g2_points_to_ffi(points: &[G2Affine]) -> Vec<zk_cuda_backend::bindings::G2Point> {
    use ark_ec::AffineRepr;

    points
        .iter()
        .map(|b| {
            if b.inner.is_zero() {
                let mut point = zk_cuda_backend::bindings::G2Point::default();
                // SAFETY: `point` is a valid, zero-initialized G2Point with repr(C) layout.
                unsafe {
                    zk_cuda_backend::bindings::g2_point_at_infinity_wrapper(&mut point);
                }
                return point;
            }
            let x = fq2_to_cuda_fp2(&b.inner.x);
            let y = fq2_to_cuda_fp2(&b.inner.y);
            zk_cuda_backend::bindings::G2Point {
                x,
                y,
                infinity: false,
            }
        })
        .collect()
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
    // SAFETY: gpu_index was validated by the assert above
    let stream = unsafe { cuda_create_stream(gpu_index) };

    let result =
        zk_cuda_backend::G1Projective::msm(&gpu_bases, &gpu_scalars, stream, gpu_index, false);

    // SAFETY: stream was created by cuda_create_stream above with the same gpu_index and is not
    // used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

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

/// GPU-accelerated multi-scalar multiplication for G2, using a caller-provided stream.
///
/// Unlike [`g2_msm_gpu`], this does NOT create or destroy a CUDA stream — the caller
/// owns the stream lifecycle. Uses the managed MSM API internally (the backend handles
/// device memory allocation, H2D transfers, Montgomery conversion, and cleanup).
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

/// GPU-accelerated multi-scalar multiplication for G2.
///
/// Creates and destroys a CUDA stream internally. For callers that manage their
/// own stream lifetime, use [`g2_msm_gpu_on_stream`] instead.
///
/// # Panics
///
/// - If `gpu_index >= number of available GPUs`.
/// - If `bases` and `scalars` have different lengths (checked inside the backend).
/// - If the GPU MSM call fails.
#[must_use]
pub fn g2_msm_gpu(bases: &[G2Affine], scalars: &[Zp], gpu_index: u32) -> G2 {
    let num_gpus = get_num_gpus();
    assert!(
        gpu_index < num_gpus,
        "gpu_index {gpu_index} exceeds available GPUs ({num_gpus})",
    );
    // SAFETY: gpu_index was validated by the assert above
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result = g2_msm_gpu_on_stream(bases, scalars, stream, gpu_index);
    // SAFETY: stream was created by cuda_create_stream above with the same gpu_index and is not
    // used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };
    result
}

// ---------------------------------------------------------------------------
// Persistent device cache for CRS base points
// ---------------------------------------------------------------------------

/// Persistent GPU cache for CRS base points (g_list and g_hat_list).
///
/// Holds both g_list and g_hat_list on **every available GPU** in Montgomery form.
/// Persists across prove/verify calls as long as the same CRS (identified
/// by data pointers + lengths) is used.
///
/// Only *immutable* base points are cached here. Mutable per-call resources
/// (CUDA streams, MSM scratch buffers) are created and destroyed by each
/// caller, avoiding races when multiple prove/verify calls run concurrently.
///
/// # Multi-GPU layout
///
/// ```text
///   GPU 0: cached_g1[0], cached_g2[0], mgmt_streams[0]
///   GPU 1: cached_g1[1], cached_g2[1], mgmt_streams[1]
///   ...
///   GPU N: cached_g1[N], cached_g2[N], mgmt_streams[N]
/// ```
///
/// Each GPU holds an independent copy of the CRS base points. Callers
/// select which GPU to use via `i % num_gpus` and index into the per-GPU
/// arrays to get the right device pointer.
struct DevicePointCache {
    /// Per-GPU opaque handles to zk_cached_g1_points (device memory, Montgomery form).
    /// Index = gpu_index. Null if g_list was empty.
    cached_g1: Vec<*mut std::ffi::c_void>,
    /// Per-GPU opaque handles to zk_cached_g2_points (device memory, Montgomery form).
    /// Index = gpu_index. Null if g_hat_list was empty.
    cached_g2: Vec<*mut std::ffi::c_void>,
    /// Per-GPU management streams used for initial H2D transfer and cleanup.
    /// Index = gpu_index.
    mgmt_streams: Vec<*mut std::ffi::c_void>,
    /// Number of GPUs these caches cover.
    num_gpus: u32,
    /// Cache key: (g1 data pointer, g1 element count, g2 data pointer, g2 element count)
    key: (usize, usize, usize, usize),
}

// SAFETY: All fields are stable device pointers. The cached point buffers
// are immutable after setup and safe to read from any thread. The
// management streams are only used during Drop (which runs when the last
// Arc reference is released).
unsafe impl Send for DevicePointCache {}
unsafe impl Sync for DevicePointCache {}

/// Frees all device resources when the last reference is dropped.
///
/// Because the cache is wrapped in `Arc`, this runs only when no caller
/// still holds a `CachedMsmResources` referencing it. This prevents the
/// use-after-free that occurs when a concurrent caller evicts the cache
/// while another caller still holds raw pointers to the device memory.
impl Drop for DevicePointCache {
    fn drop(&mut self) {
        for gpu_idx in 0..self.num_gpus as usize {
            let stream = self.mgmt_streams[gpu_idx];
            let cuda_stream = stream as zk_cuda_backend::bindings::cudaStream_t;
            let gpu_index: u32 = gpu_idx.try_into().expect("gpu index fits in u32");

            if !self.cached_g2[gpu_idx].is_null() {
                // SAFETY: cached_g2[gpu_idx] was allocated by scratch_zk_cached_g2_points
                // on mgmt_streams[gpu_idx]. This Drop runs only when no caller references
                // these pointers anymore (Arc strong count reached 0).
                let mut typed =
                    self.cached_g2[gpu_idx] as *mut zk_cuda_backend::bindings::zk_cached_g2_points;
                unsafe {
                    zk_cuda_backend::bindings::cleanup_zk_cached_g2_points(
                        cuda_stream,
                        gpu_index,
                        &mut typed,
                        true,
                    );
                }
            }

            if !self.cached_g1[gpu_idx].is_null() {
                // SAFETY: cached_g1[gpu_idx] was allocated by scratch_zk_cached_g1_points
                // on mgmt_streams[gpu_idx]. This Drop runs only when no caller references
                // these pointers anymore (Arc strong count reached 0).
                let mut typed =
                    self.cached_g1[gpu_idx] as *mut zk_cuda_backend::bindings::zk_cached_g1_points;
                unsafe {
                    zk_cuda_backend::bindings::cleanup_zk_cached_g1_points(
                        cuda_stream,
                        gpu_index,
                        &mut typed,
                        true,
                    );
                }
            }

            // SAFETY: mgmt_streams[gpu_idx] was created with cuda_create_stream(gpu_index).
            // All device resources using this stream have been freed above.
            unsafe {
                cuda_destroy_stream(stream, gpu_index);
            }
        }
    }
}

static DEVICE_CACHE: Mutex<Option<Arc<DevicePointCache>>> = Mutex::new(None);

/// Immutable base-point pointers from the persistent device cache.
///
/// Holds an `Arc<DevicePointCache>` that keeps the underlying device memory
/// alive for the lifetime of this struct. Even if the global `DEVICE_CACHE`
/// is evicted (replaced with a new CRS), the device memory backing these
/// pointers remains valid until this struct is dropped.
///
/// Callers index into `cached_g1` / `cached_g2` by gpu_index to get the
/// device pointer for a specific GPU.
pub(crate) struct CachedMsmResources {
    /// Per-GPU G1 cached-point handles. Index = gpu_index.
    pub cached_g1: Vec<*const std::ffi::c_void>,
    /// Per-GPU G2 cached-point handles. Index = gpu_index.
    pub cached_g2: Vec<*const std::ffi::c_void>,
    /// Number of GPUs these caches cover.
    pub num_gpus: u32,
    /// Ownership anchor: prevents the device memory behind cached_g1/cached_g2
    /// from being freed while this struct is alive. The Drop impl on
    /// DevicePointCache only runs when the last Arc reference is released.
    _owner: Arc<DevicePointCache>,
}

// SAFETY: The raw pointers point to immutable device memory (base points in
// Montgomery form) that is never modified after initial setup. The Arc
// guarantees the memory remains allocated while any CachedMsmResources exists.
// Multiple threads can safely read these concurrently.
unsafe impl Send for CachedMsmResources {}
unsafe impl Sync for CachedMsmResources {}

/// Acquire cached base-point pointers for the given CRS point lists.
///
/// On cache miss (first call or CRS change), uploads both g_list and
/// g_hat_list to **every available GPU** in Montgomery form. The FFI
/// conversion (arkworks -> C structs) happens once, then the same host
/// arrays are H2D-transferred to each GPU independently.
///
/// On cache hit, returns the existing per-GPU device pointers immediately.
///
/// Only immutable base points are cached. Callers are responsible for
/// creating their own CUDA streams and MSM scratch buffers for each call.
///
/// # Ownership model
///
/// The returned `CachedMsmResources` holds an `Arc` reference to the
/// underlying `DevicePointCache`. This guarantees the device memory
/// remains valid even if a concurrent caller evicts the global cache
/// (e.g., by calling with a different CRS). The device memory is freed
/// only when the last `Arc` reference is dropped.
pub(crate) fn acquire_cached_msm_resources(
    g_list: &[G1Affine],
    g_hat_list: &[G2Affine],
) -> CachedMsmResources {
    let key = (
        g_list.as_ptr() as usize,
        g_list.len(),
        g_hat_list.as_ptr() as usize,
        g_hat_list.len(),
    );
    let mut guard = DEVICE_CACHE.lock().expect("DEVICE_CACHE lock poisoned");

    // Return existing cache if the CRS identity matches (fast path: Arc::clone)
    if let Some(ref cache) = *guard {
        if cache.key == key {
            let owner = Arc::clone(cache);
            return CachedMsmResources {
                cached_g1: owner.cached_g1.iter().map(|p| *p as *const _).collect(),
                cached_g2: owner.cached_g2.iter().map(|p| *p as *const _).collect(),
                num_gpus: owner.num_gpus,
                _owner: owner,
            };
        }
    }

    // Evict old cache from the global slot. If any caller still holds an Arc
    // to the old cache, the device memory stays alive until they drop it.
    // If we hold the last reference, Drop runs immediately here.
    guard.take();

    let num_gpus = get_num_gpus();

    // Convert points to FFI format once — reused for every GPU's H2D transfer
    let ffi_g1_points = if g_list.is_empty() {
        None
    } else {
        Some(g1_points_to_ffi(g_list))
    };
    let ffi_g2_points = if g_hat_list.is_empty() {
        None
    } else {
        Some(g2_points_to_ffi(g_hat_list))
    };

    let n_g1: u32 = g_list.len().try_into().expect("g_list length fits in u32");
    let n_g2: u32 = g_hat_list
        .len()
        .try_into()
        .expect("g_hat_list length fits in u32");

    let mut cached_g1: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); num_gpus as usize];
    let mut cached_g2: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); num_gpus as usize];
    let mut mgmt_streams: Vec<*mut std::ffi::c_void> =
        vec![std::ptr::null_mut(); num_gpus as usize];

    for gpu_idx in 0..num_gpus {
        // SAFETY: gpu_idx < num_gpus, validated by the loop bound
        let stream = unsafe { cuda_create_stream(gpu_idx) };
        let cuda_stream = stream as zk_cuda_backend::bindings::cudaStream_t;
        mgmt_streams[gpu_idx as usize] = stream;

        // Upload G1 base points to this GPU
        if let Some(ref ffi_g1) = ffi_g1_points {
            let mut size_tracker: u64 = 0;
            let mut typed: *mut zk_cuda_backend::bindings::zk_cached_g1_points =
                std::ptr::null_mut();
            // SAFETY: stream is a valid CUDA stream on gpu_idx. ffi_g1 is a valid
            // array of n_g1 G1Points. typed receives the handle.
            unsafe {
                zk_cuda_backend::bindings::scratch_zk_cached_g1_points(
                    cuda_stream,
                    gpu_idx,
                    &mut typed,
                    ffi_g1.as_ptr(),
                    n_g1,
                    &mut size_tracker,
                    true,
                );
            }
            cached_g1[gpu_idx as usize] = typed as *mut std::ffi::c_void;
        }

        // Upload G2 base points to this GPU
        if let Some(ref ffi_g2) = ffi_g2_points {
            let mut size_tracker: u64 = 0;
            let mut typed: *mut zk_cuda_backend::bindings::zk_cached_g2_points =
                std::ptr::null_mut();
            // SAFETY: stream is a valid CUDA stream on gpu_idx. ffi_g2 is a valid
            // array of n_g2 G2Points. typed receives the handle.
            unsafe {
                zk_cuda_backend::bindings::scratch_zk_cached_g2_points(
                    cuda_stream,
                    gpu_idx,
                    &mut typed,
                    ffi_g2.as_ptr(),
                    n_g2,
                    &mut size_tracker,
                    true,
                );
            }
            cached_g2[gpu_idx as usize] = typed as *mut std::ffi::c_void;
        }
    }

    let owner = Arc::new(DevicePointCache {
        cached_g1,
        cached_g2,
        mgmt_streams,
        num_gpus,
        key,
    });

    let resources = CachedMsmResources {
        cached_g1: owner.cached_g1.iter().map(|p| *p as *const _).collect(),
        cached_g2: owner.cached_g2.iter().map(|p| *p as *const _).collect(),
        num_gpus: owner.num_gpus,
        _owner: Arc::clone(&owner),
    };

    *guard = Some(owner);
    resources
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

    // Convert from Montgomery form
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

    // Convert from Montgomery form
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
