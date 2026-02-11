//! G1 affine and projective point types for the BLS12-446 curve

use crate::bindings::{Fp, G1Point, G1ProjectivePoint, Scalar as ScalarFFI};
use std::fmt;

use super::{fp_to_decimal_string, Scalar};

fn zero_g1_point() -> G1Point {
    G1Point {
        x: Fp::default(),
        y: Fp::default(),
        infinity: false,
    }
}

/// G1 affine point on the BLS12-446 curve
#[derive(Clone, Copy)]
pub struct G1Affine {
    inner: G1Point,
}

impl G1Affine {
    /// Create a new G1 affine point from coordinates (in normal form)
    /// Note: Coordinates must be converted to Montgomery form before use in computations
    pub fn new(x: Fp, y: Fp, infinity: bool) -> Self {
        Self {
            inner: G1Point { x, y, infinity },
        }
    }

    /// Create the point at infinity
    pub fn infinity() -> Self {
        let mut point = zero_g1_point();
        point.infinity = true;
        // SAFETY: `point` is a valid, zero-initialized G1Point with repr(C) layout.
        // The FFI function only writes to the output pointer, which is valid for the
        // duration of this call since `point` is stack-allocated.
        unsafe {
            crate::bindings::g1_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Check if this point is at infinity
    #[inline]
    pub fn is_infinity(&self) -> bool {
        // SAFETY: `self.inner` is a valid G1Point with repr(C) layout that remains
        // valid for the duration of this call. The FFI function only reads from it.
        unsafe { crate::bindings::g1_is_infinity_wrapper(&self.inner) }
    }

    /// Get the x coordinate
    #[inline]
    pub fn x(&self) -> Fp {
        self.inner.x
    }

    /// Get the y coordinate
    #[inline]
    pub fn y(&self) -> Fp {
        self.inner.y
    }

    /// Get the inner FFI type (for internal use)
    pub(crate) fn inner(&self) -> &G1Point {
        &self.inner
    }

    /// Get a mutable reference to the inner FFI type (for internal use)
    pub(crate) fn inner_mut(&mut self) -> &mut G1Point {
        &mut self.inner
    }

    /// Convert to projective coordinates
    pub fn to_projective(&self) -> G1Projective {
        let mut proj = G1ProjectivePoint::default();
        // SAFETY: Both `proj` and `self.inner` are valid repr(C) structs.
        // `proj` is a mutable reference to stack-allocated memory, and `self.inner`
        // is a shared reference valid for the duration of this call.
        unsafe {
            crate::bindings::affine_to_projective_g1_wrapper(&mut proj, &self.inner);
        }
        G1Projective { inner: proj }
    }

    /// Check if the point is on the curve (satisfies y^2 = x^3 + b)
    /// Only available when the `validate_points` feature is enabled
    #[cfg(feature = "validate_points")]
    pub fn is_on_curve(&self) -> bool {
        // SAFETY: `self.inner` is a valid G1Point with repr(C) layout.
        // The FFI function only reads from the pointer.
        unsafe { crate::bindings::is_on_curve_g1_wrapper(&self.inner) }
    }
}

impl fmt::Display for G1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "Infinity")
        } else {
            // Convert from Montgomery to normal form
            let normal = crate::conversions::g1_affine_from_montgomery(self);

            let x_str = fp_to_decimal_string(&normal.x());
            let y_str = fp_to_decimal_string(&normal.y());

            write!(f, "({}, {})", x_str, y_str)
        }
    }
}

impl Default for G1Affine {
    fn default() -> Self {
        Self::infinity()
    }
}

impl fmt::Debug for G1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "G1Affine(infinity)")
        } else {
            write!(f, "G1Affine(x: {:?}, y: {:?})", self.x(), self.y())
        }
    }
}

impl PartialEq for G1Affine {
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

impl Eq for G1Affine {}

/// G1 projective point on the BLS12-446 curve
///
/// Projective infinity is Z=0, which is all zeros — the derived Default produces this.
#[derive(Clone, Copy, Default)]
pub struct G1Projective {
    inner: G1ProjectivePoint,
}

impl G1Projective {
    /// Create a new G1 projective point from coordinates (in normal form)
    ///
    /// Parameters use uppercase (X, Y, Z) following standard mathematical notation
    /// for projective coordinates, distinguishing them from affine (x, y).
    ///
    /// Note: Coordinates must be converted to Montgomery form before use in computations
    #[allow(non_snake_case)]
    pub fn new(X: Fp, Y: Fp, Z: Fp) -> Self {
        Self {
            inner: G1ProjectivePoint { X, Y, Z },
        }
    }

    /// Create the point at infinity (Z = 0)
    pub fn infinity() -> Self {
        let mut point = G1ProjectivePoint::default();
        // SAFETY: `point` is a valid, zero-initialized G1ProjectivePoint with repr(C) layout.
        // The FFI function only writes to the output pointer, which is valid since `point`
        // is stack-allocated.
        unsafe {
            crate::bindings::g1_projective_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Get the X coordinate (projective).
    ///
    /// Note: Projective coordinates use uppercase (X, Y, Z) following standard
    /// mathematical notation, distinguishing them from affine coordinates (x, y).
    #[inline]
    pub fn X(&self) -> Fp {
        self.inner.X
    }

    /// Get the Y coordinate (projective).
    ///
    /// Note: Projective coordinates use uppercase (X, Y, Z) following standard
    /// mathematical notation, distinguishing them from affine coordinates (x, y).
    #[inline]
    pub fn Y(&self) -> Fp {
        self.inner.Y
    }

    /// Get the Z coordinate (projective).
    ///
    /// Note: Projective coordinates use uppercase (X, Y, Z) following standard
    /// mathematical notation, distinguishing them from affine coordinates (x, y).
    #[inline]
    pub fn Z(&self) -> Fp {
        self.inner.Z
    }

    /// Get the inner FFI type (for internal use)
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &G1ProjectivePoint {
        &self.inner
    }

    /// Get a mutable reference to the inner FFI type (for internal use)
    #[allow(dead_code)]
    pub(crate) fn inner_mut(&mut self) -> &mut G1ProjectivePoint {
        &mut self.inner
    }

    /// Convert to affine coordinates
    pub fn to_affine(&self) -> G1Affine {
        let mut affine = zero_g1_point();
        // SAFETY: Both `affine` and `self.inner` are valid repr(C) structs.
        // `affine` is a mutable reference to stack-allocated memory, and `self.inner`
        // is a shared reference valid for the duration of this call.
        unsafe {
            crate::bindings::projective_to_affine_g1_wrapper(&mut affine, &self.inner);
        }
        G1Affine { inner: affine }
    }

    /// Convert from Montgomery form to normal form (projective coordinates)
    #[must_use = "Montgomery conversion returns a new point without modifying the input"]
    pub fn from_montgomery_normalized(&self) -> Self {
        let mut result = Self::infinity();
        // SAFETY: Both `result.inner` and `self.inner` are valid repr(C) structs.
        // `result.inner` is a mutable reference, and `self.inner` is a shared reference.
        // The FFI function reads from `self.inner` and writes to `result.inner`.
        unsafe {
            crate::bindings::g1_projective_from_montgomery_normalized_wrapper(
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
    /// which avoids a costly CPU-side conversion loop. For best performance, pass points in
    /// Montgomery form.
    ///
    /// The caller is responsible for creating and destroying the stream.
    ///
    /// Returns the result and the size_tracker (GPU memory allocated in bytes) if successful,
    /// or an error if MSM computation fails.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    #[must_use = "GPU MSM result must be handled"]
    pub fn msm(
        points: &[G1Affine],
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
        let points_ffi: Vec<G1Point> = points.iter().map(|p| p.inner).collect();
        let scalars_ffi: Vec<ScalarFFI> = scalars.iter().map(|s| *s.inner()).collect();
        let mut result = G1ProjectivePoint::default();
        let mut size_tracker: u64 = 0;
        // NOTE: This method uses the managed API (g1_msm_managed_wrapper) which handles
        // memory allocation and transfers internally. For a pure-GPU verify/proof implementation
        // where all data is already on the device and memory is managed externally, consider
        // using the unmanaged API (g1_msm_unmanaged_wrapper) instead for better performance.
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
        unsafe {
            crate::bindings::g1_msm_managed_wrapper(
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

impl fmt::Display for G1Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let affine = self.to_affine();
        write!(f, "{}", affine)
    }
}

impl fmt::Debug for G1Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "G1Projective(X: {:?}, Y: {:?}, Z: {:?})",
            self.X(),
            self.Y(),
            self.Z()
        )
    }
}

/// **WARNING**: This compares raw projective coordinates (X, Y, Z), NOT geometric
/// equivalence. In projective coordinates, `(X, Y, Z)` and `(λX, λY, λZ)` represent
/// the same point but will compare as unequal. Use `to_affine()` for geometric equality.
impl PartialEq for G1Projective {
    fn eq(&self, other: &Self) -> bool {
        let self_inf = self.inner.Z == Fp::default();
        let other_inf = other.inner.Z == Fp::default();
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

impl Eq for G1Projective {}
