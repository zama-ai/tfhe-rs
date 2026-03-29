//! GPU acceleration module for tfhe-zk-pok
//!
//! This module provides GPU-accelerated operations using zk-cuda-backend,
//! type conversions between tfhe-zk-pok and zk-cuda-backend types,
//! and GPU MSM helper functions used by the `pke` and `pke_v2` submodules.

pub mod pke_v2;

#[cfg(test)]
mod tests;

use std::sync::Mutex;

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
/// across all available GPUs. Returns `0` when only one GPU is present.
#[inline]
pub fn select_gpu_for_msm() -> u32 {
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

// ---------------------------------------------------------------------------
// Async (split launch/finalize) G2 MSM using cached device points
// ---------------------------------------------------------------------------

/// Opaque handle returned by [`g2_msm_cached_launch`] that keeps the host
/// scalar buffer alive until the caller is done with it.
///
/// The FFI function `zk_g2_msm_cached_launch_async` issues an async H2D copy
/// from the host scalars pointer.  With pageable host memory (a normal `Vec`)
/// the CUDA runtime *may* stage the copy through an internal pinned buffer and
/// return before the copy completes.  To prevent use-after-free the caller must
/// hold this handle — and the `Vec` it owns — until after
/// [`g2_msm_finalize`] synchronizes the stream.
#[allow(dead_code)]
pub(crate) struct MsmLaunchHandle {
    _scalars_ffi: Vec<zk_cuda_backend::bindings::Scalar>,
}

// SAFETY: The inner Vec is only read from the CUDA stream via a device-side
// copy.  Once the stream is synchronized in `g2_msm_finalize`, the Vec is no
// longer accessed by the GPU.  Moving the handle across threads is safe.
unsafe impl Send for MsmLaunchHandle {}
unsafe impl Sync for MsmLaunchHandle {}

/// Launches a G2 MSM using cached device base points.  Queues GPU work on
/// `stream` and returns immediately — the GPU kernels run asynchronously.
/// Call [`g2_msm_finalize`] when the result is needed.
///
/// # Strategy
///
/// The Horner combine step (merging Pippenger window sums into the final
/// result) is deliberately deferred to [`g2_msm_finalize`] rather than
/// executed on the GPU, because the algorithm is inherently sequential:
/// a single CPU core completes it in ~0.1 ms, while a <<<1,1>>> GPU
/// kernel takes ~10–12 ms due to launch overhead.  By splitting launch
/// from finalize, multiple GPU MSMs can overlap with CPU pairings.
///
/// # Panics
///
/// - If `scalars` is empty.
/// - If the scalar count does not fit in `u32`.
#[allow(dead_code)]
pub(crate) fn g2_msm_cached_launch(
    msm_mem: *mut std::ffi::c_void,
    cached: *const std::ffi::c_void,
    point_offset: u32,
    scalars: &[Zp],
    stream: *mut std::ffi::c_void,
    gpu_index: u32,
) -> MsmLaunchHandle {
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
    let cuda_stream = stream as zk_cuda_backend::bindings::cudaStream_t;

    // SAFETY: `msm_mem` was allocated by `scratch_zk_g2_msm` for this stream.
    // `cached` is a valid handle from `scratch_zk_cached_g2_points`.
    // `scalars_ffi` is a valid host array with `n` elements that will remain
    // live (owned by the returned `MsmLaunchHandle`) until the stream is synced.
    unsafe {
        zk_cuda_backend::bindings::zk_g2_msm_cached_launch_async(
            cuda_stream,
            gpu_index,
            msm_mem,
            cached,
            point_offset,
            scalars_ffi.as_ptr(),
            n,
        );
    }

    MsmLaunchHandle {
        _scalars_ffi: scalars_ffi,
    }
}

/// Synchronizes the stream and runs the CPU Horner combine on the window
/// sums that were D2H-copied during the launch phase.  Returns the MSM
/// result as an arkworks G2 point.
///
/// The caller should drop the corresponding [`MsmLaunchHandle`] only after
/// this function returns, since the stream sync here guarantees the async
/// H2D copy from launch has completed.
#[allow(dead_code)]
pub(crate) fn g2_msm_finalize(
    msm_mem: *const std::ffi::c_void,
    stream: *mut std::ffi::c_void,
    gpu_index: u32,
) -> G2 {
    use crate::curve_446::g2::G2Projective;

    let cuda_stream = stream as zk_cuda_backend::bindings::cudaStream_t;
    let mut result = zk_cuda_backend::bindings::G2ProjectivePoint::default();

    // SAFETY: `msm_mem` was allocated by `scratch_zk_g2_msm` and had a launch
    // issued on this stream.  `result` is a valid stack-allocated output buffer.
    // The finalize function synchronizes the stream internally before running
    // the Horner combine.
    unsafe {
        zk_cuda_backend::bindings::zk_g2_msm_finalize(cuda_stream, gpu_index, msm_mem, &mut result);
    }

    // Convert from Montgomery form (same as g2_msm_cached_on_stream)
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
/// Holds both g_list and g_hat_list on GPU device in Montgomery form,
/// plus pre-allocated MSM scratch buffers. Persists across prove/verify
/// calls as long as the same CRS (identified by data pointers + lengths)
/// is used. Either G1 or G2 side can be absent (null pointers + max_n=0)
/// when only one group is needed.
struct DevicePointCache {
    /// Opaque handle to zk_cached_g2_points (device memory, Montgomery form)
    cached_g2_points: *mut std::ffi::c_void,
    /// Pre-allocated G2 MSM scratch buffers (one per stream/MSM slot)
    g2_msm_mems: [*mut std::ffi::c_void; 3],
    /// Opaque handle to zk_cached_g1_points (device memory, Montgomery form)
    cached_g1_points: *mut std::ffi::c_void,
    /// Pre-allocated G1 MSM scratch buffers (one per stream/MSM slot)
    g1_msm_mems: [*mut std::ffi::c_void; 3],
    /// CUDA streams for MSM execution (persistent)
    streams: [*mut std::ffi::c_void; 3],
    /// GPU indices for each stream
    gpu_indices: [u32; 3],
    /// Cache key: (g1 data pointer, g1 element count, g2 data pointer, g2 element count)
    key: (usize, usize, usize, usize),
    /// Max G1 MSM size these scratch buffers support
    g1_max_n: u32,
    /// Max G2 MSM size these scratch buffers support
    g2_max_n: u32,
}

// SAFETY: All fields are stable device pointers or GPU indices. CUDA operations
// on these pointers are thread-safe when each stream is used by at most one thread.
unsafe impl Send for DevicePointCache {}

static DEVICE_CACHE: Mutex<Option<DevicePointCache>> = Mutex::new(None);

/// Frees all device resources held by the cache.
///
/// Must be called while holding the DEVICE_CACHE lock, before replacing
/// the cache entry. Cleanup functions synchronize internally.
fn evict_cache(cache: DevicePointCache) {
    let DevicePointCache {
        mut cached_g2_points,
        mut g2_msm_mems,
        mut cached_g1_points,
        mut g1_msm_mems,
        streams,
        gpu_indices,
        ..
    } = cache;

    // Free G2 MSM scratch buffers (each on its own stream)
    if !cached_g2_points.is_null() {
        for i in 0..3 {
            if !g2_msm_mems[i].is_null() {
                // SAFETY: g2_msm_mems[i] was allocated by scratch_zk_g2_msm on
                // streams[i]. No operations are in-flight since we hold the lock.
                unsafe {
                    zk_cuda_backend::bindings::cleanup_zk_g2_msm(
                        streams[i] as zk_cuda_backend::bindings::cudaStream_t,
                        gpu_indices[i],
                        &mut g2_msm_mems[i],
                        true,
                    );
                }
            }
        }

        // SAFETY: cached_g2_points was allocated by scratch_zk_cached_g2_points.
        // MSM scratch buffers were freed above so no operations reference them.
        unsafe {
            zk_cuda_backend::bindings::cleanup_zk_cached_g2_points(
                streams[0] as zk_cuda_backend::bindings::cudaStream_t,
                gpu_indices[0],
                &mut cached_g2_points,
                true,
            );
        }
    }

    // Free G1 MSM scratch buffers (each on its own stream)
    if !cached_g1_points.is_null() {
        for i in 0..3 {
            if !g1_msm_mems[i].is_null() {
                // SAFETY: g1_msm_mems[i] was allocated by scratch_zk_g1_msm on
                // streams[i]. No operations are in-flight since we hold the lock.
                unsafe {
                    zk_cuda_backend::bindings::cleanup_zk_g1_msm(
                        streams[i] as zk_cuda_backend::bindings::cudaStream_t,
                        gpu_indices[i],
                        &mut g1_msm_mems[i],
                        true,
                    );
                }
            }
        }

        // SAFETY: cached_g1_points was allocated by scratch_zk_cached_g1_points.
        // MSM scratch buffers were freed above so no operations reference them.
        unsafe {
            zk_cuda_backend::bindings::cleanup_zk_cached_g1_points(
                streams[0] as zk_cuda_backend::bindings::cudaStream_t,
                gpu_indices[0],
                &mut cached_g1_points,
                true,
            );
        }
    }

    // Destroy streams
    for i in 0..3 {
        // SAFETY: streams[i] was created with cuda_create_stream(gpu_indices[i]).
        // All device resources using these streams have been freed above.
        unsafe {
            cuda_destroy_stream(streams[i], gpu_indices[i]);
        }
    }
}

/// Resources cloned out of the persistent cache for use during a single
/// prove or verify call.
///
/// Device pointers are stable until the cache is evicted (which only happens
/// when the CRS changes -- never mid-call).
pub(crate) struct CachedMsmResources {
    pub cached_g1_points: *const std::ffi::c_void,
    pub cached_g2_points: *const std::ffi::c_void,
    pub g1_msm_mems: [*mut std::ffi::c_void; 3],
    pub g2_msm_mems: [*mut std::ffi::c_void; 3],
    pub streams: [SendPtr; 3],
    pub gpu_indices: [u32; 3],
}

// SAFETY: Device pointers are stable and CUDA streams are thread-safe
unsafe impl Send for CachedMsmResources {}
unsafe impl Sync for CachedMsmResources {}

/// Acquire cached MSM resources for the given CRS point lists.
///
/// Re-caches on device if the CRS changed or if the requested max MSM sizes
/// exceed current capacity. Pass `g1_max_n = 0` to skip G1 allocation (verify
/// path) or `g2_max_n = 0` to skip G2 allocation.
///
/// # Safety invariant
///
/// The returned `CachedMsmResources` contains raw device pointers that are only
/// valid as long as the cache entry is not evicted. Eviction happens only when a
/// subsequent call provides a different CRS (different data pointers or lengths).
/// Callers must ensure the CRS does not change while the returned resources are
/// in use (i.e., do not call `acquire_cached_msm_resources` with different lists
/// from another thread while GPU MSMs are in-flight).
pub(crate) fn acquire_cached_msm_resources(
    g_list: &[G1Affine],
    g_hat_list: &[G2Affine],
    g1_max_n: u32,
    g2_max_n: u32,
) -> CachedMsmResources {
    let key = (
        g_list.as_ptr() as usize,
        g_list.len(),
        g_hat_list.as_ptr() as usize,
        g_hat_list.len(),
    );
    let mut guard = DEVICE_CACHE.lock().expect("DEVICE_CACHE lock poisoned");

    // Return existing cache if the CRS identity and capacity match
    if let Some(ref cache) = *guard {
        if cache.key == key && cache.g1_max_n >= g1_max_n && cache.g2_max_n >= g2_max_n {
            return CachedMsmResources {
                cached_g1_points: cache.cached_g1_points,
                cached_g2_points: cache.cached_g2_points,
                g1_msm_mems: cache.g1_msm_mems,
                g2_msm_mems: cache.g2_msm_mems,
                streams: [
                    SendPtr(cache.streams[0]),
                    SendPtr(cache.streams[1]),
                    SendPtr(cache.streams[2]),
                ],
                gpu_indices: cache.gpu_indices,
            };
        }
    }

    // Evict old cache if present
    if let Some(old) = guard.take() {
        evict_cache(old);
    }

    // All 3 streams on GPU 0
    let gpu_index: u32 = 0;
    let gpu_indices = [gpu_index; 3];
    // SAFETY: gpu_index is 0, which is always valid (get_num_gpus() asserts >= 1 GPU).
    let streams: [*mut std::ffi::c_void; 3] = [
        unsafe { cuda_create_stream(gpu_index) },
        unsafe { cuda_create_stream(gpu_index) },
        unsafe { cuda_create_stream(gpu_index) },
    ];

    // --- G2 cache (if requested) ---
    let mut cached_g2_points: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut g2_msm_mems: [*mut std::ffi::c_void; 3] = [std::ptr::null_mut(); 3];

    if g2_max_n > 0 {
        let ffi_g2_points = g2_points_to_ffi(g_hat_list);
        let n_g2: u32 = g_hat_list
            .len()
            .try_into()
            .expect("g_hat_list length fits in u32");

        let mut size_tracker: u64 = 0;
        // SAFETY: streams[0] is a valid CUDA stream. ffi_g2_points is a valid
        // array of n_g2 G2Points. cached_g2_points receives the allocation.
        unsafe {
            zk_cuda_backend::bindings::scratch_zk_cached_g2_points(
                streams[0] as zk_cuda_backend::bindings::cudaStream_t,
                gpu_index,
                &mut cached_g2_points,
                ffi_g2_points.as_ptr(),
                n_g2,
                &mut size_tracker,
                true,
            );
        }

        for i in 0..3 {
            let mut tracker: u64 = 0;
            // SAFETY: streams[i] is valid. g2_msm_mems[i] is null and receives
            // the allocation. g2_max_n is the maximum MSM size.
            unsafe {
                zk_cuda_backend::bindings::scratch_zk_g2_msm(
                    streams[i] as zk_cuda_backend::bindings::cudaStream_t,
                    gpu_indices[i],
                    &mut g2_msm_mems[i],
                    g2_max_n,
                    &mut tracker,
                    true,
                );
            }
        }
    }

    // --- G1 cache (if requested) ---
    let mut cached_g1_points: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut g1_msm_mems: [*mut std::ffi::c_void; 3] = [std::ptr::null_mut(); 3];

    if g1_max_n > 0 {
        let ffi_g1_points = g1_points_to_ffi(g_list);
        let n_g1: u32 = g_list.len().try_into().expect("g_list length fits in u32");

        let mut size_tracker: u64 = 0;
        // SAFETY: streams[0] is a valid CUDA stream. ffi_g1_points is a valid
        // array of n_g1 G1Points. cached_g1_points receives the allocation.
        unsafe {
            zk_cuda_backend::bindings::scratch_zk_cached_g1_points(
                streams[0] as zk_cuda_backend::bindings::cudaStream_t,
                gpu_index,
                &mut cached_g1_points,
                ffi_g1_points.as_ptr(),
                n_g1,
                &mut size_tracker,
                true,
            );
        }

        for i in 0..3 {
            let mut tracker: u64 = 0;
            // SAFETY: streams[i] is valid. g1_msm_mems[i] is null and receives
            // the allocation. g1_max_n is the maximum MSM size.
            unsafe {
                zk_cuda_backend::bindings::scratch_zk_g1_msm(
                    streams[i] as zk_cuda_backend::bindings::cudaStream_t,
                    gpu_indices[i],
                    &mut g1_msm_mems[i],
                    g1_max_n,
                    &mut tracker,
                    true,
                );
            }
        }
    }

    let cache = DevicePointCache {
        cached_g2_points,
        g2_msm_mems,
        cached_g1_points,
        g1_msm_mems,
        streams,
        gpu_indices,
        key,
        g1_max_n,
        g2_max_n,
    };

    let resources = CachedMsmResources {
        cached_g1_points: cache.cached_g1_points,
        cached_g2_points: cache.cached_g2_points,
        g1_msm_mems: cache.g1_msm_mems,
        g2_msm_mems: cache.g2_msm_mems,
        streams: [
            SendPtr(cache.streams[0]),
            SendPtr(cache.streams[1]),
            SendPtr(cache.streams[2]),
        ],
        gpu_indices: cache.gpu_indices,
    };

    *guard = Some(cache);
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
            msm_mem,
            &mut result,
            cached,
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
            msm_mem,
            &mut result,
            cached,
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
