//! GPU acceleration module for tfhe-zk-pok
//!
//! This module provides GPU-accelerated operations using zk-cuda-backend,
//! type conversions between tfhe-zk-pok and zk-cuda-backend types,
//! and GPU MSM helper functions used by the `pke` and `pke_v2` submodules.

pub mod pke_v2;

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
    (thread_idx % num_gpus as usize)
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
/// Uses the scratch/async/cleanup pattern: device buffers are allocated once via
/// `scratch_zk_g2_msm`, the MSM is launched asynchronously with `zk_g2_msm_async`,
/// the stream is synchronized to wait for the result, and buffers are freed via
/// `cleanup_zk_g2_msm`. This is the building block for Phase 3 pipelining where
/// scratch allocation and cleanup will be hoisted out of per-call scope.
///
/// Unlike [`g2_msm_gpu`], this does NOT create or destroy a CUDA stream — the caller
/// owns the stream lifecycle. The stream must be valid for the duration of this call.
///
/// # Panics
///
/// - If `gpu_index >= number of available GPUs`.
/// - If `bases` and `scalars` have different lengths.
/// - If the stream pointer is null.
/// - If the input length does not fit in `u32`.
#[must_use]
pub fn g2_msm_gpu_on_stream(
    bases: &[G2Affine],
    scalars: &[Zp],
    stream: *mut std::ffi::c_void,
    gpu_index: u32,
) -> G2 {
    use crate::curve_446::g2::G2Projective;
    use ark_ec::AffineRepr;

    assert_eq!(
        bases.len(),
        scalars.len(),
        "GPU MSM: bases and scalars must have the same length"
    );
    assert!(!stream.is_null(), "GPU MSM: stream pointer is null");

    let num_gpus = get_num_gpus();
    assert!(
        gpu_index < num_gpus,
        "gpu_index {gpu_index} exceeds available GPUs ({num_gpus})",
    );

    if bases.is_empty() {
        return G2::ZERO;
    }

    // Convert points and scalars to FFI types (normal form).
    // The wrapper types are not #[repr(transparent)], so we extract the inner
    // FFI structs into separate Vecs — matching G2Projective::msm's approach.
    let points_ffi: Vec<zk_cuda_backend::bindings::G2Point> = bases
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
        .collect();

    let scalars_ffi: Vec<zk_cuda_backend::bindings::Scalar> = scalars
        .iter()
        .map(|s| {
            let limbs = s.inner.into_bigint().0;
            zk_cuda_backend::bindings::Scalar { limb: limbs }
        })
        .collect();

    let n: u32 = points_ffi
        .len()
        .try_into()
        .expect("GPU MSM: input length too large for u32");

    let cuda_stream = stream as zk_cuda_backend::bindings::cudaStream_t;

    // Allocate device buffers for MSM scratch space. Wrapped in an RAII guard
    // so that device memory is freed even if a panic occurs before cleanup.
    let mut mem: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut size_tracker: u64 = 0;
    // SAFETY: `cuda_stream` is a valid, non-null CUDA stream (asserted above). `mem` and
    // `size_tracker` are valid stack-allocated pointers. The C++ function allocates device
    // memory and writes the opaque handle to `mem`.
    unsafe {
        zk_cuda_backend::bindings::scratch_zk_g2_msm(
            cuda_stream,
            gpu_index,
            &mut mem,
            n,
            &mut size_tracker,
            true,
        );
    }

    // RAII guard: ensures cleanup_zk_g2_msm runs on all exit paths (including panics)
    struct ScratchGuard {
        mem: *mut std::ffi::c_void,
        stream: zk_cuda_backend::bindings::cudaStream_t,
        gpu_index: u32,
    }
    impl Drop for ScratchGuard {
        fn drop(&mut self) {
            if !self.mem.is_null() {
                // SAFETY: mem was allocated by scratch_zk_g2_msm on this stream/GPU
                unsafe {
                    zk_cuda_backend::bindings::cleanup_zk_g2_msm(
                        self.stream,
                        self.gpu_index,
                        &mut self.mem,
                        true,
                    );
                }
            }
        }
    }
    let mut guard = ScratchGuard {
        mem,
        stream: cuda_stream,
        gpu_index,
    };

    // Launch MSM: H2D transfers, Montgomery conversion, and Pippenger kernel.
    // Note: despite the "_async" name, the Pippenger implementation synchronizes
    // internally for its CPU Horner combine phase, so `result` is fully written
    // by the time this call returns.
    let mut result = zk_cuda_backend::bindings::G2ProjectivePoint::default();
    // SAFETY: `guard.mem` was allocated by `scratch_zk_g2_msm` above and is valid for
    // this stream. `result` is a valid stack-allocated output buffer. `points_ffi` and
    // `scalars_ffi` are valid host arrays with length `n`.
    unsafe {
        zk_cuda_backend::bindings::zk_g2_msm_async(
            cuda_stream,
            gpu_index,
            guard.mem,
            &mut result,
            points_ffi.as_ptr(),
            scalars_ffi.as_ptr(),
            n,
            false, // points are in normal form, not Montgomery
        );
    }

    // Cleanup device buffers via the guard. Setting mem to null prevents double-free
    // if the guard also runs (e.g., during unwind).
    // SAFETY: guard.mem was allocated by scratch_zk_g2_msm on this stream/GPU
    unsafe {
        zk_cuda_backend::bindings::cleanup_zk_g2_msm(cuda_stream, gpu_index, &mut guard.mem, true);
    }

    // Convert result from Montgomery form back to arkworks types
    let gpu_result = zk_cuda_backend::G2Projective::new(result.X, result.Y, result.Z);
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
