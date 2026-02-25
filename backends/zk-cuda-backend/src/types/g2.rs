//! G2 affine and projective point types for the BLS12-446 curve

use crate::bindings::{Fp2, G2Point, G2ProjectivePoint, Scalar as ScalarFFI};
use std::fmt;

use super::{fp_to_decimal_string, Scalar};

/// G2 affine point on the BLS12-446 curve
#[derive(Clone, Copy)]
pub struct G2Affine {
    inner: G2Point,
}

impl G2Affine {
    /// Create a new G2 affine point from coordinates (in normal form)
    /// Note: Coordinates must be converted to Montgomery form before use in computations
    pub fn new(x: Fp2, y: Fp2, infinity: bool) -> Self {
        Self {
            inner: G2Point { x, y, infinity },
        }
    }

    /// Create the point at infinity
    pub fn infinity() -> Self {
        let mut point = G2Point::default();
        // SAFETY: `point` is a valid, zero-initialized G2Point with repr(C) layout.
        // The FFI function only writes to the output pointer, which is valid for the
        // duration of this call since `point` is stack-allocated.
        unsafe {
            crate::bindings::g2_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Check if this point is at infinity
    #[inline]
    pub fn is_infinity(&self) -> bool {
        // SAFETY: `self.inner` is a valid G2Point with repr(C) layout that remains
        // valid for the duration of this call. The FFI function only reads from it.
        unsafe { crate::bindings::g2_is_infinity_wrapper(&self.inner) }
    }

    /// Get the x coordinate
    #[inline]
    pub fn x(&self) -> Fp2 {
        self.inner.x
    }

    /// Get the y coordinate
    #[inline]
    pub fn y(&self) -> Fp2 {
        self.inner.y
    }

    /// Get the inner FFI type (for internal use)
    pub(crate) fn inner(&self) -> &G2Point {
        &self.inner
    }

    /// Get a mutable reference to the inner FFI type (for internal use)
    pub(crate) fn inner_mut(&mut self) -> &mut G2Point {
        &mut self.inner
    }

    /// Convert to projective coordinates
    pub fn to_projective(&self) -> G2Projective {
        let mut proj = G2ProjectivePoint::default();
        // SAFETY: Both `proj` and `self.inner` are valid repr(C) structs.
        // `proj` is a mutable reference to stack-allocated memory, and `self.inner`
        // is a shared reference valid for the duration of this call.
        unsafe {
            crate::bindings::affine_to_projective_g2_wrapper(&mut proj, &self.inner);
        }
        G2Projective { inner: proj }
    }

    /// Check if the point is on the curve (satisfies y^2 = x^3 + b')
    /// Only available when the `validate_points` feature is enabled
    #[cfg(feature = "validate_points")]
    pub fn is_on_curve(&self) -> bool {
        // SAFETY: `self.inner` is a valid G2Point with repr(C) layout.
        // The FFI function only reads from the pointer.
        unsafe { crate::bindings::is_on_curve_g2_wrapper(&self.inner) }
    }
}

/// Displays coordinates in decimal. Assumes the point is in Montgomery form (e.g., from MSM
/// output).
impl fmt::Display for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "Infinity")
        } else {
            let normal = crate::conversions::g2_affine_from_montgomery(self);

            let x = normal.x();
            let y = normal.y();

            let x_c0_str = fp_to_decimal_string(&x.c0);
            let x_c1_str = fp_to_decimal_string(&x.c1);
            let y_c0_str = fp_to_decimal_string(&y.c0);
            let y_c1_str = fp_to_decimal_string(&y.c1);

            write!(
                f,
                "(x: ({}, {}), y: ({}, {}))",
                x_c0_str, x_c1_str, y_c0_str, y_c1_str
            )
        }
    }
}

impl fmt::Debug for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "G2Affine(infinity)")
        } else {
            write!(f, "G2Affine(x: {:?}, y: {:?})", self.x(), self.y())
        }
    }
}

impl PartialEq for G2Affine {
    fn eq(&self, other: &Self) -> bool {
        if self.is_infinity() && other.is_infinity() {
            return true;
        }
        if self.is_infinity() != other.is_infinity() {
            return false;
        }
        self.inner.x == other.inner.x && self.inner.y == other.inner.y
    }
}

impl Eq for G2Affine {}

/// G2 projective point on the BLS12-446 curve
#[derive(Clone, Copy)]
pub struct G2Projective {
    inner: G2ProjectivePoint,
}

impl G2Projective {
    /// Create a new G2 projective point from coordinates (in normal form)
    ///
    /// Parameters use uppercase (X, Y, Z) following standard mathematical notation
    /// for projective coordinates, distinguishing them from affine (x, y).
    ///
    /// Note: Coordinates must be converted to Montgomery form before use in computations
    #[allow(non_snake_case)]
    pub fn new(X: Fp2, Y: Fp2, Z: Fp2) -> Self {
        Self {
            inner: G2ProjectivePoint { X, Y, Z },
        }
    }

    /// Create the point at infinity (Z = 0)
    pub fn infinity() -> Self {
        let mut point = G2ProjectivePoint::default();
        // SAFETY: `point` is a valid, zero-initialized G2ProjectivePoint with repr(C) layout.
        // The FFI function only writes to the output pointer, which is valid since `point`
        // is stack-allocated.
        unsafe {
            crate::bindings::g2_projective_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Get the X coordinate (projective).
    ///
    /// Note: Projective coordinates use uppercase (X, Y, Z) following standard
    /// mathematical notation, distinguishing them from affine coordinates (x, y).
    #[inline]
    pub fn X(&self) -> Fp2 {
        self.inner.X
    }

    /// Get the Y coordinate (projective).
    ///
    /// Note: Projective coordinates use uppercase (X, Y, Z) following standard
    /// mathematical notation, distinguishing them from affine coordinates (x, y).
    #[inline]
    pub fn Y(&self) -> Fp2 {
        self.inner.Y
    }

    /// Get the Z coordinate (projective).
    ///
    /// Note: Projective coordinates use uppercase (X, Y, Z) following standard
    /// mathematical notation, distinguishing them from affine coordinates (x, y).
    #[inline]
    pub fn Z(&self) -> Fp2 {
        self.inner.Z
    }

    /// Get the inner FFI type (for internal use)
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &G2ProjectivePoint {
        &self.inner
    }

    /// Get a mutable reference to the inner FFI type (for internal use)
    #[allow(dead_code)]
    pub(crate) fn inner_mut(&mut self) -> &mut G2ProjectivePoint {
        &mut self.inner
    }

    /// Convert to affine coordinates
    pub fn to_affine(&self) -> G2Affine {
        let mut affine = G2Point::default();
        // SAFETY: Both `affine` and `self.inner` are valid repr(C) structs.
        // `affine` is a mutable reference to stack-allocated memory, and `self.inner`
        // is a shared reference valid for the duration of this call.
        unsafe {
            crate::bindings::projective_to_affine_g2_wrapper(&mut affine, &self.inner);
        }
        G2Affine { inner: affine }
    }

    /// Convert from Montgomery form to normal form (projective coordinates)
    #[must_use = "Montgomery conversion returns a new point without modifying the input"]
    pub fn from_montgomery_normalized(&self) -> Self {
        let mut result = Self::infinity();
        // SAFETY: Both `result.inner` and `self.inner` are valid repr(C) structs.
        // `result.inner` is a mutable reference, and `self.inner` is a shared reference.
        // The FFI function reads from `self.inner` and writes to `result.inner`.
        unsafe {
            crate::bindings::g2_projective_from_montgomery_normalized_wrapper(
                &mut result.inner,
                &self.inner,
            );
        }
        result
    }

    /// Compute multi-scalar multiplication with Scalar values (320-bit scalars): result =
    /// sum(scalars[i] * points[i])
    ///
    /// If `points_in_montgomery` is true, points are assumed to already be in Montgomery form,
    /// which avoids a costly conversion. For best performance, pass points in Montgomery form.
    ///
    /// The caller is responsible for creating and destroying the stream.
    ///
    /// Returns the result and the size_tracker (GPU memory allocated in bytes) if successful,
    /// or an error if MSM computation fails.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    #[must_use = "GPU MSM result must be handled"]
    pub fn msm(
        points: &[G2Affine],
        scalars: &[Scalar],
        stream: *mut std::ffi::c_void,
        gpu_index: u32,
        points_in_montgomery: bool,
    ) -> Result<(Self, u64), String> {
        assert_eq!(
            points.len(),
            scalars.len(),
            "GPU MSM: points and scalars must have the same length"
        );
        if points.is_empty() {
            return Ok((Self::infinity(), 0));
        }
        if stream.is_null() {
            return Err("GPU MSM: stream pointer is null".to_string());
        }
        let n: u32 = points
            .len()
            .try_into()
            .map_err(|_| format!("GPU MSM: input length too large for u32: {}", points.len()))?;
        let points_ffi: Vec<G2Point> = points.iter().map(|p| p.inner).collect();
        let scalars_ffi: Vec<ScalarFFI> = scalars.iter().map(|s| *s.inner()).collect();
        let mut result = G2ProjectivePoint::default();

        let mut size_tracker: u64 = 0;
        // NOTE: This method uses the managed API (g2_msm_managed_wrapper) which handles
        // memory allocation and transfers internally. For a pure-GPU verify/proof implementation
        // where all data is already on the device and memory is managed externally, use the
        // unmanaged API (g2_msm_unmanaged_wrapper_async) instead — it performs zero internal
        // allocations (caller provides d_scratch via pippenger_scratch_size_g2_wrapper).
        //
        // SAFETY:
        // - `stream` was validated as non-null above and must be a valid `cudaStream_t` obtained
        //   from `cuda_create_stream`. The raw pointer type is `*mut c_void` because CUDA streams
        //   are opaque pointers. If the stream is invalid (e.g., already destroyed or corrupted),
        //   the CUDA runtime will report an error through `cudaGetLastError()`.
        // - This function borrows the stream for the duration of the call; it does not take
        //   ownership. The caller remains responsible for destroying the stream after use.
        // - `gpu_index` is passed directly to CUDA; the C++ wrapper validates it
        // - `points_ffi` and `scalars_ffi` are valid Vec slices with matching length `n`
        // - `result` and `size_tracker` are valid stack-allocated outputs
        // - The managed wrapper handles all device memory allocation/deallocation internally
        // - Failure: The C++ managed wrapper validates all inputs via PANIC_IF_FALSE and checks
        //   CUDA errors via cudaGetLastError() after each kernel launch.
        // - Success: The C++ managed wrapper calls cuda_synchronize_stream before returning,
        //   ensuring `result` contains the final MSM output.
        unsafe {
            crate::bindings::g2_msm_managed_wrapper(
                stream as crate::bindings::cudaStream_t,
                gpu_index,
                &mut result,
                points_ffi.as_ptr(),
                scalars_ffi.as_ptr(),
                n,
                points_in_montgomery,
                &mut size_tracker,
            );
        }

        Ok((Self { inner: result }, size_tracker))
    }
}

/// Converts to affine and displays. Assumes coordinates are in Montgomery form.
impl fmt::Display for G2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let affine = self.to_affine();
        write!(f, "{}", affine)
    }
}

impl fmt::Debug for G2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "G2Projective(X: {:?}, Y: {:?}, Z: {:?})",
            self.X(),
            self.Y(),
            self.Z()
        )
    }
}

/// **WARNING**: This compares raw projective coordinates (X, Y, Z), NOT geometric
/// equivalence. In projective coordinates, `(X, Y, Z)` and `(λX, λY, λZ)` represent
/// the same point but will compare as unequal. Use `to_affine()` for geometric equality.
impl PartialEq for G2Projective {
    fn eq(&self, other: &Self) -> bool {
        let self_inf = self.inner.Z == Fp2::default();
        let other_inf = other.inner.Z == Fp2::default();
        if self_inf && other_inf {
            return true;
        }
        if self_inf != other_inf {
            return false;
        }
        self.inner.X == other.inner.X
            && self.inner.Y == other.inner.Y
            && self.inner.Z == other.inner.Z
    }
}

impl Eq for G2Projective {}
