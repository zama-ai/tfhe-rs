//! Rust wrapper types for G1 and G2 points
//!
//! This module provides safe Rust wrappers around the FFI types,
//! with proper memory management and error handling.

use crate::ffi::{
    Fp, Fp2, G1Point, G1ProjectivePoint, G2Point, G2ProjectivePoint, Scalar as ScalarFFI,
};
use std::fmt;

// Helper functions for zero-initialized types
fn zero_g1_projective_point() -> G1ProjectivePoint {
    G1ProjectivePoint {
        X: Fp::default(),
        Y: Fp::default(),
        Z: Fp::default(),
    }
}

fn zero_g2_projective_point() -> G2ProjectivePoint {
    G2ProjectivePoint {
        X: Fp2::default(),
        Y: Fp2::default(),
        Z: Fp2::default(),
    }
}

fn zero_g1_point() -> G1Point {
    G1Point {
        x: Fp::default(),
        y: Fp::default(),
        infinity: false,
    }
}

fn zero_g2_point() -> G2Point {
    G2Point {
        x: Fp2::default(),
        y: Fp2::default(),
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
    pub fn new(x: [u64; 7], y: [u64; 7], infinity: bool) -> Self {
        Self {
            inner: G1Point {
                x: Fp { limb: x },
                y: Fp { limb: y },
                infinity,
            },
        }
    }

    /// Create the point at infinity
    pub fn infinity() -> Self {
        let mut point = zero_g1_point();
        point.infinity = true;
        unsafe {
            crate::ffi::g1_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Check if this point is at infinity
    pub fn is_infinity(&self) -> bool {
        unsafe { crate::ffi::g1_is_infinity_wrapper(&self.inner) }
    }

    /// Get the x coordinate
    pub fn x(&self) -> [u64; 7] {
        self.inner.x.limb
    }

    /// Get the y coordinate
    pub fn y(&self) -> [u64; 7] {
        self.inner.y.limb
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
        let mut proj = zero_g1_projective_point();
        unsafe {
            crate::ffi::affine_to_projective_g1_wrapper(&mut proj, &self.inner);
        }
        G1Projective { inner: proj }
    }

    /// Check if the point is on the curve (satisfies y^2 = x^3 + b)
    /// Only available when the `validate_points` feature is enabled
    #[cfg(feature = "validate_points")]
    pub fn is_on_curve(&self) -> bool {
        unsafe { crate::ffi::is_on_curve_g1_wrapper(&self.inner) }
    }
}

impl fmt::Display for G1Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "Infinity")
        } else {
            // Convert from Montgomery to normal form
            let normal = crate::conversions::g1_affine_from_montgomery(self);

            let x_str = fp_to_decimal_string(&normal.inner().x.limb);
            let y_str = fp_to_decimal_string(&normal.inner().y.limb);

            write!(f, "({}, {})", x_str, y_str)
        }
    }
}

/// Convert an Fp value (represented as limbs) to a decimal string
/// Assumes the limbs are in normal form (not Montgomery)
fn fp_to_decimal_string(limbs: &[u64; 7]) -> String {
    if limbs.iter().all(|&x| x == 0) {
        return "0".to_string();
    }

    let mut working = *limbs;
    let mut result = String::new();

    while !working.iter().all(|&x| x == 0) {
        let mut remainder = 0u64;
        for i in (0..7).rev() {
            let value = ((remainder as u128) << 64) | (working[i] as u128);
            working[i] = (value / 10) as u64;
            remainder = (value % 10) as u64;
        }
        result = format!("{}{}", remainder, result);
    }

    if result.is_empty() {
        "0".to_string()
    } else {
        result
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

/// G2 affine point on the BLS12-446 curve
#[derive(Clone, Copy)]
pub struct G2Affine {
    inner: G2Point,
}

impl G2Affine {
    /// Create a new G2 affine point from coordinates (in normal form)
    /// Note: Coordinates must be converted to Montgomery form before use in computations
    pub fn new(x: ([u64; 7], [u64; 7]), y: ([u64; 7], [u64; 7]), infinity: bool) -> Self {
        Self {
            inner: G2Point {
                x: Fp2 {
                    c0: Fp { limb: x.0 },
                    c1: Fp { limb: x.1 },
                },
                y: Fp2 {
                    c0: Fp { limb: y.0 },
                    c1: Fp { limb: y.1 },
                },
                infinity,
            },
        }
    }

    /// Create the point at infinity
    pub fn infinity() -> Self {
        let mut point = zero_g2_point();
        point.infinity = true;
        unsafe {
            crate::ffi::g2_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Check if this point is at infinity
    pub fn is_infinity(&self) -> bool {
        unsafe { crate::ffi::g2_is_infinity_wrapper(&self.inner) }
    }

    /// Get the x coordinate as (c0, c1)
    pub fn x(&self) -> ([u64; 7], [u64; 7]) {
        (self.inner.x.c0.limb, self.inner.x.c1.limb)
    }

    /// Get the y coordinate as (c0, c1)
    pub fn y(&self) -> ([u64; 7], [u64; 7]) {
        (self.inner.y.c0.limb, self.inner.y.c1.limb)
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
        let mut proj = zero_g2_projective_point();
        unsafe {
            crate::ffi::affine_to_projective_g2_wrapper(&mut proj, &self.inner);
        }
        G2Projective { inner: proj }
    }

    /// Check if the point is on the curve (satisfies y^2 = x^3 + b')
    /// Only available when the `validate_points` feature is enabled
    #[cfg(feature = "validate_points")]
    pub fn is_on_curve(&self) -> bool {
        unsafe { crate::ffi::is_on_curve_g2_wrapper(&self.inner) }
    }
}

impl fmt::Display for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "Infinity")
        } else {
            let normal = crate::conversions::g2_affine_from_montgomery(self);

            let (x_c0, x_c1) = normal.x();
            let (y_c0, y_c1) = normal.y();

            let x_c0_str = fp_to_decimal_string(&x_c0);
            let x_c1_str = fp_to_decimal_string(&x_c1);
            let y_c0_str = fp_to_decimal_string(&y_c0);
            let y_c1_str = fp_to_decimal_string(&y_c1);

            write!(
                f,
                "(x: ({}, {}), y: ({}, {}))",
                x_c0_str, x_c1_str, y_c0_str, y_c1_str
            )
        }
    }
}

impl Default for G2Affine {
    fn default() -> Self {
        Self::infinity()
    }
}

impl fmt::Debug for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "G2Affine(infinity)")
        } else {
            let (x0, x1) = self.x();
            let (y0, y1) = self.y();
            write!(
                f,
                "G2Affine(x: ({:?}, {:?}), y: ({:?}, {:?}))",
                x0, x1, y0, y1
            )
        }
    }
}

/// G1 projective point on the BLS12-446 curve
#[derive(Clone, Copy)]
pub struct G1Projective {
    inner: G1ProjectivePoint,
}

impl G1Projective {
    /// Create a new G1 projective point from coordinates (in normal form)
    /// Note: Coordinates must be converted to Montgomery form before use in computations
    pub fn new(X: [u64; 7], Y: [u64; 7], Z: [u64; 7]) -> Self {
        Self {
            inner: G1ProjectivePoint {
                X: Fp { limb: X },
                Y: Fp { limb: Y },
                Z: Fp { limb: Z },
            },
        }
    }

    /// Create the point at infinity (Z = 0)
    pub fn infinity() -> Self {
        let mut point = zero_g1_projective_point();
        unsafe {
            crate::ffi::g1_projective_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Get the X coordinate
    pub fn X(&self) -> [u64; 7] {
        self.inner.X.limb
    }

    /// Get the Y coordinate
    pub fn Y(&self) -> [u64; 7] {
        self.inner.Y.limb
    }

    /// Get the Z coordinate
    pub fn Z(&self) -> [u64; 7] {
        self.inner.Z.limb
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
        unsafe {
            crate::ffi::projective_to_affine_g1_wrapper(&mut affine, &self.inner);
        }
        G1Affine { inner: affine }
    }

    /// Convert from Montgomery form to normal form (projective coordinates)
    pub fn from_montgomery_normalized(&self) -> Self {
        let mut result = Self::infinity();
        unsafe {
            crate::ffi::g1_projective_from_montgomery_normalized_wrapper(
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
            "points and scalars must have the same length: {} != {}",
            points.len(),
            scalars.len()
        );
        if points.is_empty() {
            return Ok((Self::infinity(), 0));
        }
        assert!(
            points.len() <= u32::MAX as usize,
            "MSM input length too large for u32: {}",
            points.len()
        );
        let n = points.len() as u32;
        let points_ffi: Vec<G1Point> = points.iter().map(|p| p.inner).collect();
        let scalars_ffi: Vec<ScalarFFI> = scalars.iter().map(|s| *s.inner()).collect();
        let mut result = zero_g1_projective_point();
        let mut size_tracker: u64 = 0;
        // NOTE: This method uses the managed API (g1_msm_managed_wrapper) which handles
        // memory allocation and transfers internally. For a pure-GPU verify/proof implementation
        // where all data is already on the device and memory is managed externally, consider
        // using the unmanaged API (g1_msm_unmanaged_wrapper) instead for better performance.
        unsafe {
            crate::ffi::g1_msm_managed_wrapper(
                &mut result,
                stream as crate::ffi::cudaStream_t,
                points_ffi.as_ptr(),
                scalars_ffi.as_ptr(),
                n,
                gpu_index,
                points_in_montgomery,
                std::ptr::addr_of_mut!(size_tracker),
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

impl Default for G1Projective {
    fn default() -> Self {
        Self::infinity()
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

/// G2 projective point on the BLS12-446 curve
#[derive(Clone, Copy)]
pub struct G2Projective {
    inner: G2ProjectivePoint,
}

impl G2Projective {
    /// Create a new G2 projective point from coordinates (in normal form)
    /// Note: Coordinates must be converted to Montgomery form before use in computations
    pub fn new(X: ([u64; 7], [u64; 7]), Y: ([u64; 7], [u64; 7]), Z: ([u64; 7], [u64; 7])) -> Self {
        Self {
            inner: G2ProjectivePoint {
                X: Fp2 {
                    c0: Fp { limb: X.0 },
                    c1: Fp { limb: X.1 },
                },
                Y: Fp2 {
                    c0: Fp { limb: Y.0 },
                    c1: Fp { limb: Y.1 },
                },
                Z: Fp2 {
                    c0: Fp { limb: Z.0 },
                    c1: Fp { limb: Z.1 },
                },
            },
        }
    }

    /// Create the point at infinity (Z = 0)
    pub fn infinity() -> Self {
        let mut point = zero_g2_projective_point();
        unsafe {
            crate::ffi::g2_projective_point_at_infinity_wrapper(&mut point);
        }
        Self { inner: point }
    }

    /// Get the X coordinate as (c0, c1)
    pub fn X(&self) -> ([u64; 7], [u64; 7]) {
        (self.inner.X.c0.limb, self.inner.X.c1.limb)
    }

    /// Get the Y coordinate as (c0, c1)
    pub fn Y(&self) -> ([u64; 7], [u64; 7]) {
        (self.inner.Y.c0.limb, self.inner.Y.c1.limb)
    }

    /// Get the Z coordinate as (c0, c1)
    pub fn Z(&self) -> ([u64; 7], [u64; 7]) {
        (self.inner.Z.c0.limb, self.inner.Z.c1.limb)
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
        let mut affine = zero_g2_point();
        unsafe {
            crate::ffi::projective_to_affine_g2_wrapper(&mut affine, &self.inner);
        }
        G2Affine { inner: affine }
    }

    /// Convert from Montgomery form to normal form (projective coordinates)
    pub fn from_montgomery_normalized(&self) -> Self {
        let mut result = Self::infinity();
        unsafe {
            crate::ffi::g2_projective_from_montgomery_normalized_wrapper(
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
            "points and scalars must have the same length: {} != {}",
            points.len(),
            scalars.len()
        );
        if points.is_empty() {
            return Ok((Self::infinity(), 0));
        }

        assert!(
            points.len() <= u32::MAX as usize,
            "MSM input length too large for u32: {}",
            points.len()
        );
        let n = points.len() as u32;
        let points_ffi: Vec<G2Point> = points.iter().map(|p| p.inner).collect();
        let scalars_ffi: Vec<ScalarFFI> = scalars.iter().map(|s| *s.inner()).collect();
        let mut result = zero_g2_projective_point();

        let mut size_tracker: u64 = 0;
        // NOTE: This method uses the managed API (g2_msm_managed_wrapper) which handles
        // memory allocation and transfers internally. For a pure-GPU verify/proof implementation
        // where all data is already on the device and memory is managed externally, consider
        // using the unmanaged API (g2_msm_unmanaged_wrapper) instead for better performance.
        unsafe {
            crate::ffi::g2_msm_managed_wrapper(
                &mut result,
                stream as crate::ffi::cudaStream_t,
                points_ffi.as_ptr(),
                scalars_ffi.as_ptr(),
                n,
                gpu_index,
                points_in_montgomery,
                std::ptr::addr_of_mut!(size_tracker),
            );
        }

        Ok((Self { inner: result }, size_tracker))
    }
}

impl fmt::Display for G2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let affine = self.to_affine();
        write!(f, "{}", affine)
    }
}

impl Default for G2Projective {
    fn default() -> Self {
        Self::infinity()
    }
}

impl fmt::Debug for G2Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (X0, X1) = self.X();
        let (Y0, Y1) = self.Y();
        let (Z0, Z1) = self.Z();
        write!(
            f,
            "G2Projective(X: ({:?}, {:?}), Y: ({:?}, {:?}), Z: ({:?}, {:?}))",
            X0, X1, Y0, Y1, Z0, Z1
        )
    }
}

/// Scalar type for BLS12-446 (320-bit integers, 5 limbs)
/// This matches the C++ Scalar type (BigInt<ZP_LIMBS>)
#[derive(Clone, Copy)]
pub struct Scalar {
    inner: ScalarFFI,
}

/// Get the scalar field modulus from C++ via FFI
fn scalar_modulus_limbs() -> [u64; 5] {
    let mut limbs = [0u64; 5];
    unsafe {
        crate::ffi::scalar_modulus_limbs_wrapper(limbs.as_mut_ptr());
    }
    limbs
}

/// Scalar field modulus (group order) - initialized once from C++
/// Uses OnceLock to ensure thread-safe one-time initialization
static SCALAR_MODULUS: std::sync::OnceLock<[u64; 5]> = std::sync::OnceLock::new();

fn get_scalar_modulus() -> &'static [u64; 5] {
    SCALAR_MODULUS.get_or_init(scalar_modulus_limbs)
}

impl Scalar {
    /// Create a new scalar from limbs
    pub fn new(limbs: [u64; 5]) -> Self {
        Self {
            inner: ScalarFFI { limb: limbs },
        }
    }

    /// Create a scalar from a single u64 value
    pub fn from_u64(value: u64) -> Self {
        Self {
            inner: ScalarFFI {
                limb: [value, 0, 0, 0, 0],
            },
        }
    }

    /// Get the limbs of the scalar
    pub fn limbs(&self) -> [u64; 5] {
        self.inner.limb
    }

    /// Get the inner FFI type (for internal use)
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &ScalarFFI {
        &self.inner
    }

    /// Get a mutable reference to the inner FFI type (for internal use)
    #[allow(dead_code)]
    pub(crate) fn inner_mut(&mut self) -> &mut ScalarFFI {
        &mut self.inner
    }

    /// Check if this scalar is less than the modulus (valid range)
    pub fn is_valid(&self) -> bool {
        let modulus = get_scalar_modulus();
        // Compare limbs from most significant to least significant
        for i in (0..5).rev() {
            if self.inner.limb[i] < modulus[i] {
                return true;
            }
            if self.inner.limb[i] > modulus[i] {
                return false;
            }
        }
        // Equal to modulus, which is out of range (should be < r)
        false
    }

    /// Reduce scalar modulo curve order if needed
    /// This is a simple reduction that works when scalar < 2*r
    /// For scalars >= 2*r, multiple subtractions may be needed
    pub fn reduce_if_needed(&self) -> Self {
        if self.is_valid() {
            return *self;
        }

        // Subtract modulus
        let modulus = get_scalar_modulus();
        let mut result = [0u64; 5];
        let mut borrow: u64 = 0;
        for i in 0..5 {
            let (diff, b1) = self.inner.limb[i].overflowing_sub(modulus[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }

        Self::new(result)
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({:?})", self.limbs())
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({:?})", self.limbs())
    }
}

impl From<[u64; 5]> for Scalar {
    fn from(limbs: [u64; 5]) -> Self {
        Self::new(limbs)
    }
}

impl From<Scalar> for [u64; 5] {
    fn from(scalar: Scalar) -> Self {
        scalar.limbs()
    }
}
