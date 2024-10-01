use super::f128;

/// Computes $\operatorname{fl}(a+b)$ and $\operatorname{err}(a+b)$.  
/// Assumes $|a| \geq |b|$.
#[inline(always)]
fn quick_two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    (s, b - (s - a))
}

/// Computes $\operatorname{fl}(a-b)$ and $\operatorname{err}(a-b)$.  
/// Assumes $|a| \geq |b|$.
#[allow(dead_code)]
#[inline(always)]
fn quick_two_diff(a: f64, b: f64) -> (f64, f64) {
    let s = a - b;
    (s, (a - s) - b)
}

/// Computes $\operatorname{fl}(a+b)$ and $\operatorname{err}(a+b)$.
#[inline(always)]
fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    let bb = s - a;
    (s, (a - (s - bb)) + (b - bb))
}

/// Computes $\operatorname{fl}(a-b)$ and $\operatorname{err}(a-b)$.
#[inline(always)]
fn two_diff(a: f64, b: f64) -> (f64, f64) {
    let s = a - b;
    let bb = s - a;
    (s, (a - (s - bb)) - (b + bb))
}

#[inline(always)]
fn two_prod(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    (p, f64::mul_add(a, b, -p))
}

use core::{
    cmp::Ordering,
    convert::From,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

impl From<f64> for f128 {
    #[inline(always)]
    fn from(value: f64) -> Self {
        Self(value, 0.0)
    }
}

impl Add<f128> for f128 {
    type Output = f128;

    #[inline(always)]
    fn add(self, rhs: f128) -> Self::Output {
        f128::add_f128_f128(self, rhs)
    }
}

impl Add<f64> for f128 {
    type Output = f128;

    #[inline(always)]
    fn add(self, rhs: f64) -> Self::Output {
        f128::add_f128_f64(self, rhs)
    }
}

impl Add<f128> for f64 {
    type Output = f128;

    #[inline(always)]
    fn add(self, rhs: f128) -> Self::Output {
        f128::add_f64_f128(self, rhs)
    }
}

impl AddAssign<f64> for f128 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: f64) {
        *self = *self + rhs
    }
}

impl AddAssign<f128> for f128 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: f128) {
        *self = *self + rhs
    }
}

impl Sub<f128> for f128 {
    type Output = f128;

    #[inline(always)]
    fn sub(self, rhs: f128) -> Self::Output {
        f128::sub_f128_f128(self, rhs)
    }
}

impl Sub<f64> for f128 {
    type Output = f128;

    #[inline(always)]
    fn sub(self, rhs: f64) -> Self::Output {
        f128::sub_f128_f64(self, rhs)
    }
}

impl Sub<f128> for f64 {
    type Output = f128;

    #[inline(always)]
    fn sub(self, rhs: f128) -> Self::Output {
        f128::sub_f64_f128(self, rhs)
    }
}

impl SubAssign<f64> for f128 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: f64) {
        *self = *self - rhs
    }
}

impl SubAssign<f128> for f128 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: f128) {
        *self = *self - rhs
    }
}

impl Mul<f128> for f128 {
    type Output = f128;

    #[inline(always)]
    fn mul(self, rhs: f128) -> Self::Output {
        f128::mul_f128_f128(self, rhs)
    }
}

impl Mul<f64> for f128 {
    type Output = f128;

    #[inline(always)]
    fn mul(self, rhs: f64) -> Self::Output {
        f128::mul_f128_f64(self, rhs)
    }
}

impl Mul<f128> for f64 {
    type Output = f128;

    #[inline(always)]
    fn mul(self, rhs: f128) -> Self::Output {
        f128::mul_f64_f128(self, rhs)
    }
}

impl MulAssign<f64> for f128 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: f64) {
        *self = *self * rhs
    }
}

impl MulAssign<f128> for f128 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: f128) {
        *self = *self * rhs
    }
}

impl Div<f128> for f128 {
    type Output = f128;

    #[inline(always)]
    fn div(self, rhs: f128) -> Self::Output {
        f128::div_f128_f128(self, rhs)
    }
}

impl Div<f64> for f128 {
    type Output = f128;

    #[inline(always)]
    fn div(self, rhs: f64) -> Self::Output {
        f128::div_f128_f64(self, rhs)
    }
}

impl Div<f128> for f64 {
    type Output = f128;

    #[inline(always)]
    fn div(self, rhs: f128) -> Self::Output {
        f128::div_f64_f128(self, rhs)
    }
}

impl DivAssign<f64> for f128 {
    #[inline(always)]
    fn div_assign(&mut self, rhs: f64) {
        *self = *self / rhs
    }
}

impl DivAssign<f128> for f128 {
    #[inline(always)]
    fn div_assign(&mut self, rhs: f128) {
        *self = *self / rhs
    }
}

impl Neg for f128 {
    type Output = f128;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl PartialEq<f128> for f128 {
    #[inline(always)]
    fn eq(&self, other: &f128) -> bool {
        matches!((self.0 == other.0, self.1 == other.1), (true, true))
    }
}

impl PartialEq<f64> for f128 {
    #[inline(always)]
    fn eq(&self, other: &f64) -> bool {
        (*self).eq(&f128(*other, 0.0))
    }
}

impl PartialEq<f128> for f64 {
    #[inline(always)]
    fn eq(&self, other: &f128) -> bool {
        (*other).eq(self)
    }
}

impl PartialOrd<f128> for f128 {
    #[inline(always)]
    fn partial_cmp(&self, other: &f128) -> Option<Ordering> {
        let first_cmp = self.0.partial_cmp(&other.0);
        let second_cmp = self.1.partial_cmp(&other.1);

        match first_cmp {
            Some(Ordering::Equal) => second_cmp,
            _ => first_cmp,
        }
    }
}

impl PartialOrd<f64> for f128 {
    #[inline(always)]
    fn partial_cmp(&self, other: &f64) -> Option<Ordering> {
        (*self).partial_cmp(&f128(*other, 0.0))
    }
}

impl PartialOrd<f128> for f64 {
    #[inline(always)]
    fn partial_cmp(&self, other: &f128) -> Option<Ordering> {
        f128(*self, 0.0).partial_cmp(other)
    }
}

impl f128 {
    /// Adds `a` and `b` and returns the result.
    #[inline(always)]
    pub fn add_f64_f64(a: f64, b: f64) -> Self {
        let (s, e) = two_sum(a, b);
        Self(s, e)
    }

    /// Adds `a` and `b` and returns the result.
    #[inline(always)]
    pub fn add_f128_f64(a: f128, b: f64) -> Self {
        let (s1, s2) = two_sum(a.0, b);
        let s2 = s2 + a.1;
        let (s1, s2) = quick_two_sum(s1, s2);
        Self(s1, s2)
    }

    /// Adds `a` and `b` and returns the result.
    #[inline(always)]
    pub fn add_f64_f128(a: f64, b: f128) -> Self {
        Self::add_f128_f64(b, a)
    }

    /// Adds `a` and `b` and returns the result.  
    /// This function has a slightly higher error bound than [`Self::add_f128_f128`]
    #[inline(always)]
    pub fn add_estimate_f128_f128(a: f128, b: f128) -> Self {
        let (s, e) = two_sum(a.0, b.0);
        let e = e + (a.1 + b.1);
        let (s, e) = quick_two_sum(s, e);
        Self(s, e)
    }

    /// Adds `a` and `b` and returns the result.
    #[inline(always)]
    pub fn add_f128_f128(a: f128, b: f128) -> Self {
        let (s1, s2) = two_sum(a.0, b.0);
        let (t1, t2) = two_sum(a.1, b.1);

        let s2 = s2 + t1;
        let (s1, s2) = quick_two_sum(s1, s2);
        let s2 = s2 + t2;
        let (s1, s2) = quick_two_sum(s1, s2);
        Self(s1, s2)
    }

    /// Subtracts `b` from `a` and returns the result.
    #[inline(always)]
    pub fn sub_f64_f64(a: f64, b: f64) -> Self {
        let (s, e) = two_diff(a, b);
        Self(s, e)
    }

    /// Subtracts `b` from `a` and returns the result.
    #[inline(always)]
    pub fn sub_f128_f64(a: f128, b: f64) -> Self {
        let (s1, s2) = two_diff(a.0, b);
        let s2 = s2 + a.1;
        let (s1, s2) = quick_two_sum(s1, s2);
        Self(s1, s2)
    }

    /// Subtracts `b` from `a` and returns the result.
    #[inline(always)]
    pub fn sub_f64_f128(a: f64, b: f128) -> Self {
        let (s1, s2) = two_diff(a, b.0);
        let s2 = s2 - b.1;
        let (s1, s2) = quick_two_sum(s1, s2);
        Self(s1, s2)
    }

    /// Subtracts `b` from `a` and returns the result.
    /// This function has a slightly higher error bound than [`Self::sub_f128_f128`]
    #[inline(always)]
    pub fn sub_estimate_f128_f128(a: f128, b: f128) -> Self {
        let (s, e) = two_diff(a.0, b.0);
        let e = e + a.1;
        let e = e - b.1;
        let (s, e) = quick_two_sum(s, e);
        Self(s, e)
    }

    /// Subtracts `b` from `a` and returns the result.
    #[inline(always)]
    pub fn sub_f128_f128(a: f128, b: f128) -> Self {
        let (s1, s2) = two_diff(a.0, b.0);
        let (t1, t2) = two_diff(a.1, b.1);

        let s2 = s2 + t1;
        let (s1, s2) = quick_two_sum(s1, s2);
        let s2 = s2 + t2;
        let (s1, s2) = quick_two_sum(s1, s2);
        Self(s1, s2)
    }

    /// Multiplies `a` and `b` and returns the result.
    #[inline(always)]
    pub fn mul_f64_f64(a: f64, b: f64) -> Self {
        let (p, e) = two_prod(a, b);
        Self(p, e)
    }

    /// Multiplies `a` and `b` and returns the result.
    #[inline(always)]
    pub fn mul_f128_f64(a: f128, b: f64) -> Self {
        let (p1, p2) = two_prod(a.0, b);
        let p2 = p2 + (a.1 * b);
        let (p1, p2) = quick_two_sum(p1, p2);
        Self(p1, p2)
    }

    /// Multiplies `a` and `b` and returns the result.
    #[inline(always)]
    pub fn mul_f64_f128(a: f64, b: f128) -> Self {
        Self::mul_f128_f64(b, a)
    }

    /// Multiplies `a` and `b` and returns the result.
    #[inline(always)]
    pub fn mul_f128_f128(a: f128, b: f128) -> Self {
        let (p1, p2) = two_prod(a.0, b.0);
        let p2 = p2 + (a.0 * b.1 + a.1 * b.0);
        let (p1, p2) = quick_two_sum(p1, p2);
        Self(p1, p2)
    }

    /// Squares `self` and returns the result.
    #[inline(always)]
    pub fn sqr(self) -> Self {
        let (p1, p2) = two_prod(self.0, self.0);
        let p2 = p2 + 2.0 * (self.0 * self.1);
        let (p1, p2) = quick_two_sum(p1, p2);
        Self(p1, p2)
    }

    /// Divides `a` by `b` and returns the result.
    #[inline(always)]
    pub fn div_f64_f64(a: f64, b: f64) -> Self {
        let q1 = a / b;

        // Compute  a - q1 * b
        let (p1, p2) = two_prod(q1, b);
        let (s, e) = two_diff(a, p1);
        let e = e - p2;

        // get next approximation
        let q2 = (s + e) / b;

        let (s, e) = quick_two_sum(q1, q2);
        f128(s, e)
    }

    /// Divides `a` by `b` and returns the result.
    #[inline(always)]
    pub fn div_f128_f64(a: f128, b: f64) -> Self {
        // approximate quotient
        let q1 = a.0 / b;

        // Compute a - q1 * b
        let (p1, p2) = two_prod(q1, b);
        let (s, e) = two_diff(a.0, p1);
        let e = e + a.1;
        let e = e - p2;

        // get next approximation
        let q2 = (s + e) / b;

        // renormalize
        let (r0, r1) = quick_two_sum(q1, q2);
        Self(r0, r1)
    }

    /// Divides `a` by `b` and returns the result.
    #[inline(always)]
    pub fn div_f64_f128(a: f64, b: f128) -> Self {
        Self::div_f128_f128(a.into(), b)
    }

    /// Divides `a` by `b` and returns the result.
    /// This function has a slightly higher error bound than [`Self::div_f128_f128`]
    #[inline(always)]
    pub fn div_estimate_f128_f128(a: f128, b: f128) -> Self {
        // approximate quotient
        let q1 = a.0 / b.0;

        // compute a - q1 * b
        let r = b * q1;
        let (s1, s2) = two_diff(a.0, r.0);
        let s2 = s2 - r.1;
        let s2 = s2 + a.1;

        // get next approximation
        let q2 = (s1 + s2) / b.0;

        // renormalize
        let (r0, r1) = quick_two_sum(q1, q2);
        Self(r0, r1)
    }

    /// Divides `a` by `b` and returns the result.
    #[inline(always)]
    pub fn div_f128_f128(a: f128, b: f128) -> Self {
        // approximate quotient
        let q1 = a.0 / b.0;

        let r = a - b * q1;

        let q2 = r.0 / b.0;
        let r = r - q2 * b;

        let q3 = r.0 / b.0;

        let (q1, q2) = quick_two_sum(q1, q2);
        Self(q1, q2) + q3
    }

    /// Casts `self` to an `f64`.
    #[inline(always)]
    pub fn to_f64(self) -> f64 {
        self.0
    }

    /// Checks if `self` is `NaN`.
    #[inline(always)]
    pub fn is_nan(self) -> bool {
        !matches!((self.0.is_nan(), self.1.is_nan()), (false, false))
    }

    /// Returns the absolute value of `self`.
    #[inline(always)]
    pub fn abs(self) -> Self {
        if self.0 < 0.0 {
            -self
        } else {
            self
        }
    }

    fn sincospi_taylor(self) -> (Self, Self) {
        let mut sinc = Self::PI;
        let mut cos = f128(1.0, 0.0);

        let sqr = self.sqr();
        let mut pow = f128(1.0, 0.0);
        for (s, c) in Self::SINPI_TAYLOR
            .iter()
            .copied()
            .zip(Self::COSPI_TAYLOR.iter().copied())
        {
            pow *= sqr;
            sinc += s * pow;
            cos += c * pow;
        }

        (sinc * self, cos)
    }

    /// Takes an input in `(-1.0, 1.0)`, and returns the sine and cosine of `self`.
    pub fn sincospi(self) -> (Self, Self) {
        #[allow(clippy::manual_range_contains)]
        if self > 1.0 || self < -1.0 {
            panic!("only inputs in [-1, 1] are currently supported, received: {self:?}");
        }
        // approximately reduce modulo 1/2
        let p = (self.0 * 2.0).round();
        let r = self - p * 0.5;

        // approximately reduce modulo 1/16
        let q = (r.0 * 16.0).round();
        let r = r - q * (1.0 / 16.0);

        let p = p as isize;
        let q = q as isize;

        let q_abs = q.unsigned_abs();

        let (sin_r, cos_r) = r.sincospi_taylor();

        let (s, c) = if q == 0 {
            (sin_r, cos_r)
        } else {
            let u = Self::COS_K_PI_OVER_16_TABLE[q_abs - 1];
            let v = Self::SIN_K_PI_OVER_16_TABLE[q_abs - 1];
            if q > 0 {
                (u * sin_r + v * cos_r, u * cos_r - v * sin_r)
            } else {
                (u * sin_r - v * cos_r, u * cos_r + v * sin_r)
            }
        };

        if p == 0 {
            (s, c)
        } else if p == 1 {
            (c, -s)
        } else if p == -1 {
            (-c, s)
        } else {
            (-s, -c)
        }
    }
}

#[allow(clippy::approx_constant)]
impl f128 {
    pub const PI: Self = f128(3.141592653589793, 1.2246467991473532e-16);

    const SINPI_TAYLOR: &'static [Self; 9] = &[
        f128(-5.16771278004997, 2.2665622825789447e-16),
        f128(2.5501640398773455, -7.931006345326556e-17),
        f128(-0.5992645293207921, 2.845026112698218e-17),
        f128(0.08214588661112823, -3.847292805297656e-18),
        f128(-0.0073704309457143504, -3.328281165603432e-19),
        f128(0.00046630280576761255, 1.0704561733683463e-20),
        f128(-2.1915353447830217e-5, 1.4648526682685598e-21),
        f128(7.952054001475513e-7, 1.736540361519021e-23),
        f128(-2.2948428997269873e-8, -7.376346207041088e-26),
    ];

    const COSPI_TAYLOR: &'static [Self; 9] = &[
        f128(-4.934802200544679, -3.1326477543698557e-16),
        f128(4.0587121264167685, -2.6602000824298645e-16),
        f128(-1.3352627688545895, 3.1815237892149862e-18),
        f128(0.2353306303588932, -1.2583065576724427e-18),
        f128(-0.02580689139001406, 1.170191067939226e-18),
        f128(0.0019295743094039231, -9.669517939986956e-20),
        f128(-0.0001046381049248457, -2.421206183964864e-21),
        f128(4.303069587032947e-6, -2.864010082936791e-22),
        f128(-1.3878952462213771e-7, -7.479362090417238e-24),
    ];

    const SIN_K_PI_OVER_16_TABLE: &'static [Self; 4] = &[
        f128(0.19509032201612828, -7.991079068461731e-18),
        f128(0.3826834323650898, -1.0050772696461588e-17),
        f128(0.5555702330196022, 4.709410940561677e-17),
        f128(0.7071067811865476, -4.833646656726457e-17),
    ];

    const COS_K_PI_OVER_16_TABLE: &'static [Self; 4] = &[
        f128(0.9807852804032304, 1.8546939997825006e-17),
        f128(0.9238795325112867, 1.7645047084336677e-17),
        f128(0.8314696123025452, 1.4073856984728024e-18),
        f128(0.7071067811865476, -4.833646656726457e-17),
    ];
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg_attr(docsrs, doc(cfg(any(target_arch = "x86", target_arch = "x86_64"))))]
pub mod x86 {
    #[cfg(feature = "nightly")]
    use pulp::{b8, f64x8, x86::V4};
    use pulp::{f64x4, x86::V3, Simd};

    #[inline(always)]
    pub(crate) fn quick_two_sum_f64x4(simd: V3, a: f64x4, b: f64x4) -> (f64x4, f64x4) {
        let s = simd.add_f64x4(a, b);
        (s, simd.sub_f64x4(b, simd.sub_f64x4(s, a)))
    }

    #[inline(always)]
    pub(crate) fn two_sum_f64x4(simd: V3, a: f64x4, b: f64x4) -> (f64x4, f64x4) {
        let sign_bit = simd.splat_f64x4(-0.0);
        let cmp = simd.cmp_gt_f64x4(
            simd.andnot_f64x4(sign_bit, a),
            simd.andnot_f64x4(sign_bit, b),
        );
        let (a, b) = (simd.select_f64x4(cmp, a, b), simd.select_f64x4(cmp, b, a));

        quick_two_sum_f64x4(simd, a, b)
    }

    #[inline(always)]
    pub(crate) fn two_diff_f64x4(simd: V3, a: f64x4, b: f64x4) -> (f64x4, f64x4) {
        two_sum_f64x4(simd, a, simd.neg_f64s(b))
    }

    #[inline(always)]
    pub(crate) fn two_prod_f64x4(simd: V3, a: f64x4, b: f64x4) -> (f64x4, f64x4) {
        let p = simd.mul_f64x4(a, b);
        (p, simd.mul_sub_f64x4(a, b, p))
    }

    #[cfg(feature = "nightly")]
    #[inline(always)]
    pub(crate) fn quick_two_sum_f64x8(simd: V4, a: f64x8, b: f64x8) -> (f64x8, f64x8) {
        let s = simd.add_f64x8(a, b);
        (s, simd.sub_f64x8(b, simd.sub_f64x8(s, a)))
    }

    #[inline(always)]
    #[cfg(feature = "nightly")]
    pub(crate) fn two_sum_f64x8(simd: V4, a: f64x8, b: f64x8) -> (f64x8, f64x8) {
        let sign_bit = simd.splat_f64x8(-0.0);
        let cmp = simd.cmp_gt_f64x8(
            simd.andnot_f64x8(sign_bit, a),
            simd.andnot_f64x8(sign_bit, b),
        );
        let (a, b) = (simd.select_f64x8(cmp, a, b), simd.select_f64x8(cmp, b, a));

        quick_two_sum_f64x8(simd, a, b)
    }

    #[inline(always)]
    #[cfg(feature = "nightly")]
    pub(crate) fn two_diff_f64x8(simd: V4, a: f64x8, b: f64x8) -> (f64x8, f64x8) {
        two_sum_f64x8(simd, a, simd.neg_f64s(b))
    }

    #[cfg(feature = "nightly")]
    #[inline(always)]
    pub(crate) fn two_prod_f64x8(simd: V4, a: f64x8, b: f64x8) -> (f64x8, f64x8) {
        let p = simd.mul_f64x8(a, b);
        (p, simd.mul_sub_f64x8(a, b, p))
    }

    #[cfg(feature = "nightly")]
    #[inline(always)]
    pub(crate) fn quick_two_sum_f64x16(simd: V4, a: f64x16, b: f64x16) -> (f64x16, f64x16) {
        let s = simd.add_f64x16(a, b);
        (s, simd.sub_f64x16(b, simd.sub_f64x16(s, a)))
    }

    #[inline(always)]
    #[cfg(feature = "nightly")]
    pub(crate) fn two_sum_f64x16(simd: V4, a: f64x16, b: f64x16) -> (f64x16, f64x16) {
        let sign_bit = simd.splat_f64x16(-0.0);
        let cmp = simd.cmp_gt_f64x16(
            simd.andnot_f64x16(sign_bit, a),
            simd.andnot_f64x16(sign_bit, b),
        );
        let (a, b) = (simd.select_f64x16(cmp, a, b), simd.select_f64x16(cmp, b, a));

        quick_two_sum_f64x16(simd, a, b)
    }

    #[inline(always)]
    #[cfg(feature = "nightly")]
    pub(crate) fn two_diff_f64x16(simd: V4, a: f64x16, b: f64x16) -> (f64x16, f64x16) {
        two_sum_f64x16(
            simd,
            a,
            f64x16 {
                lo: simd.neg_f64s(b.lo),
                hi: simd.neg_f64s(b.hi),
            },
        )
    }

    #[cfg(feature = "nightly")]
    #[inline(always)]
    pub(crate) fn two_prod_f64x16(simd: V4, a: f64x16, b: f64x16) -> (f64x16, f64x16) {
        let p = simd.mul_f64x16(a, b);
        (p, simd.mul_sub_f64x16(a, b, p))
    }

    #[cfg(feature = "nightly")]
    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    pub struct f64x16 {
        pub lo: f64x8,
        pub hi: f64x8,
    }

    #[cfg(feature = "nightly")]
    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    pub struct b16 {
        pub lo: b8,
        pub hi: b8,
    }

    #[cfg(feature = "nightly")]
    unsafe impl bytemuck::Zeroable for f64x16 {}
    #[cfg(feature = "nightly")]
    unsafe impl bytemuck::Pod for f64x16 {}

    pub trait V3F128Ext {
        fn add_estimate_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4);
        fn sub_estimate_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4);
        fn add_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4);
        fn sub_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4);
        fn mul_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4);
    }

    #[cfg(feature = "nightly")]
    pub trait V4F128Ext {
        fn add_estimate_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8);
        fn sub_estimate_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8);
        fn add_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8);
        fn sub_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8);
        fn mul_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8);

        fn add_estimate_f128x16(
            self,
            a0: f64x16,
            a1: f64x16,
            b0: f64x16,
            b1: f64x16,
        ) -> (f64x16, f64x16);
        fn sub_estimate_f128x16(
            self,
            a0: f64x16,
            a1: f64x16,
            b0: f64x16,
            b1: f64x16,
        ) -> (f64x16, f64x16);
        fn add_f128x16(self, a0: f64x16, a1: f64x16, b0: f64x16, b1: f64x16) -> (f64x16, f64x16);
        fn sub_f128x16(self, a0: f64x16, a1: f64x16, b0: f64x16, b1: f64x16) -> (f64x16, f64x16);
        fn mul_f128x16(self, a0: f64x16, a1: f64x16, b0: f64x16, b1: f64x16) -> (f64x16, f64x16);

        fn splat_f64x16(self, value: f64) -> f64x16;
        fn add_f64x16(self, a: f64x16, b: f64x16) -> f64x16;
        fn sub_f64x16(self, a: f64x16, b: f64x16) -> f64x16;
        fn mul_f64x16(self, a: f64x16, b: f64x16) -> f64x16;
        fn mul_add_f64x16(self, a: f64x16, b: f64x16, c: f64x16) -> f64x16;
        fn mul_sub_f64x16(self, a: f64x16, b: f64x16, c: f64x16) -> f64x16;
        fn andnot_f64x16(self, a: f64x16, b: f64x16) -> f64x16;
        fn cmp_gt_f64x16(self, a: f64x16, b: f64x16) -> b16;
        fn select_f64x16(self, mask: b16, if_true: f64x16, if_false: f64x16) -> f64x16;
    }

    impl V3F128Ext for V3 {
        #[inline(always)]
        fn add_estimate_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4) {
            let (s, e) = two_sum_f64x4(self, a0, b0);
            let e = self.add_f64x4(e, self.add_f64x4(a1, b1));
            quick_two_sum_f64x4(self, s, e)
        }

        #[inline(always)]
        fn sub_estimate_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4) {
            let (s, e) = two_diff_f64x4(self, a0, b0);
            let e = self.add_f64x4(e, a1);
            let e = self.sub_f64x4(e, b1);
            quick_two_sum_f64x4(self, s, e)
        }

        #[inline(always)]
        fn add_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4) {
            let (s1, s2) = two_sum_f64x4(self, a0, b0);
            let (t1, t2) = two_sum_f64x4(self, a1, b1);

            let s2 = self.add_f64x4(s2, t1);
            let (s1, s2) = quick_two_sum_f64x4(self, s1, s2);
            let s2 = self.add_f64x4(s2, t2);
            let (s1, s2) = quick_two_sum_f64x4(self, s1, s2);
            (s1, s2)
        }

        #[inline(always)]
        fn sub_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4) {
            let (s1, s2) = two_diff_f64x4(self, a0, b0);
            let (t1, t2) = two_diff_f64x4(self, a1, b1);

            let s2 = self.add_f64x4(s2, t1);
            let (s1, s2) = quick_two_sum_f64x4(self, s1, s2);
            let s2 = self.add_f64x4(s2, t2);
            let (s1, s2) = quick_two_sum_f64x4(self, s1, s2);
            (s1, s2)
        }

        #[inline(always)]
        fn mul_f128x4(self, a0: f64x4, a1: f64x4, b0: f64x4, b1: f64x4) -> (f64x4, f64x4) {
            let (p1, p2) = two_prod_f64x4(self, a0, b0);
            let p2 = self.mul_add_f64x4(a0, b1, self.mul_add_f64x4(a1, b0, p2));
            quick_two_sum_f64x4(self, p1, p2)
        }
    }

    #[cfg(feature = "nightly")]
    impl V4F128Ext for V4 {
        #[inline(always)]
        fn add_estimate_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8) {
            let (s, e) = two_sum_f64x8(self, a0, b0);
            let e = self.add_f64x8(e, self.add_f64x8(a1, b1));
            quick_two_sum_f64x8(self, s, e)
        }

        #[inline(always)]
        fn sub_estimate_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8) {
            let (s, e) = two_diff_f64x8(self, a0, b0);
            let e = self.add_f64x8(e, a1);
            let e = self.sub_f64x8(e, b1);
            quick_two_sum_f64x8(self, s, e)
        }

        #[inline(always)]
        fn add_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8) {
            let (s1, s2) = two_sum_f64x8(self, a0, b0);
            let (t1, t2) = two_sum_f64x8(self, a1, b1);

            let s2 = self.add_f64x8(s2, t1);
            let (s1, s2) = quick_two_sum_f64x8(self, s1, s2);
            let s2 = self.add_f64x8(s2, t2);
            let (s1, s2) = quick_two_sum_f64x8(self, s1, s2);
            (s1, s2)
        }

        #[inline(always)]
        fn sub_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8) {
            let (s1, s2) = two_diff_f64x8(self, a0, b0);
            let (t1, t2) = two_diff_f64x8(self, a1, b1);

            let s2 = self.add_f64x8(s2, t1);
            let (s1, s2) = quick_two_sum_f64x8(self, s1, s2);
            let s2 = self.add_f64x8(s2, t2);
            let (s1, s2) = quick_two_sum_f64x8(self, s1, s2);
            (s1, s2)
        }

        #[inline(always)]
        fn mul_f128x8(self, a0: f64x8, a1: f64x8, b0: f64x8, b1: f64x8) -> (f64x8, f64x8) {
            let (p1, p2) = two_prod_f64x8(self, a0, b0);
            let p2 = self.mul_add_f64x8(a0, b1, self.mul_add_f64x8(a1, b0, p2));
            quick_two_sum_f64x8(self, p1, p2)
        }

        #[inline(always)]
        fn add_estimate_f128x16(
            self,
            a0: f64x16,
            a1: f64x16,
            b0: f64x16,
            b1: f64x16,
        ) -> (f64x16, f64x16) {
            let (s, e) = two_sum_f64x16(self, a0, b0);
            let e = self.add_f64x16(e, self.add_f64x16(a1, b1));
            quick_two_sum_f64x16(self, s, e)
        }

        #[inline(always)]
        fn sub_estimate_f128x16(
            self,
            a0: f64x16,
            a1: f64x16,
            b0: f64x16,
            b1: f64x16,
        ) -> (f64x16, f64x16) {
            let (s, e) = two_diff_f64x16(self, a0, b0);
            let e = self.add_f64x16(e, a1);
            let e = self.sub_f64x16(e, b1);
            quick_two_sum_f64x16(self, s, e)
        }

        #[inline(always)]
        fn add_f128x16(self, a0: f64x16, a1: f64x16, b0: f64x16, b1: f64x16) -> (f64x16, f64x16) {
            let (s1, s2) = two_sum_f64x16(self, a0, b0);
            let (t1, t2) = two_sum_f64x16(self, a1, b1);

            let s2 = self.add_f64x16(s2, t1);
            let (s1, s2) = quick_two_sum_f64x16(self, s1, s2);
            let s2 = self.add_f64x16(s2, t2);
            let (s1, s2) = quick_two_sum_f64x16(self, s1, s2);
            (s1, s2)
        }

        #[inline(always)]
        fn sub_f128x16(self, a0: f64x16, a1: f64x16, b0: f64x16, b1: f64x16) -> (f64x16, f64x16) {
            let (s1, s2) = two_diff_f64x16(self, a0, b0);
            let (t1, t2) = two_diff_f64x16(self, a1, b1);

            let s2 = self.add_f64x16(s2, t1);
            let (s1, s2) = quick_two_sum_f64x16(self, s1, s2);
            let s2 = self.add_f64x16(s2, t2);
            let (s1, s2) = quick_two_sum_f64x16(self, s1, s2);
            (s1, s2)
        }

        #[inline(always)]
        fn mul_f128x16(self, a0: f64x16, a1: f64x16, b0: f64x16, b1: f64x16) -> (f64x16, f64x16) {
            let (p1, p2) = two_prod_f64x16(self, a0, b0);
            let p2 = self.mul_add_f64x16(a0, b1, self.mul_add_f64x16(a1, b0, p2));
            quick_two_sum_f64x16(self, p1, p2)
        }

        #[inline(always)]
        fn add_f64x16(self, a: f64x16, b: f64x16) -> f64x16 {
            f64x16 {
                lo: self.add_f64x8(a.lo, b.lo),
                hi: self.add_f64x8(a.hi, b.hi),
            }
        }

        #[inline(always)]
        fn sub_f64x16(self, a: f64x16, b: f64x16) -> f64x16 {
            f64x16 {
                lo: self.sub_f64x8(a.lo, b.lo),
                hi: self.sub_f64x8(a.hi, b.hi),
            }
        }

        #[inline(always)]
        fn mul_f64x16(self, a: f64x16, b: f64x16) -> f64x16 {
            f64x16 {
                lo: self.mul_f64x8(a.lo, b.lo),
                hi: self.mul_f64x8(a.hi, b.hi),
            }
        }

        #[inline(always)]
        fn mul_add_f64x16(self, a: f64x16, b: f64x16, c: f64x16) -> f64x16 {
            f64x16 {
                lo: self.mul_add_f64x8(a.lo, b.lo, c.lo),
                hi: self.mul_add_f64x8(a.hi, b.hi, c.hi),
            }
        }

        #[inline(always)]
        fn mul_sub_f64x16(self, a: f64x16, b: f64x16, c: f64x16) -> f64x16 {
            f64x16 {
                lo: self.mul_sub_f64x8(a.lo, b.lo, c.lo),
                hi: self.mul_sub_f64x8(a.hi, b.hi, c.hi),
            }
        }

        #[inline(always)]
        fn andnot_f64x16(self, a: f64x16, b: f64x16) -> f64x16 {
            f64x16 {
                lo: self.andnot_f64x8(a.lo, b.lo),
                hi: self.andnot_f64x8(a.hi, b.hi),
            }
        }

        #[inline(always)]
        fn cmp_gt_f64x16(self, a: f64x16, b: f64x16) -> b16 {
            b16 {
                lo: self.cmp_gt_f64x8(a.lo, b.lo),
                hi: self.cmp_gt_f64x8(a.hi, b.hi),
            }
        }

        #[inline(always)]
        fn select_f64x16(self, mask: b16, if_true: f64x16, if_false: f64x16) -> f64x16 {
            f64x16 {
                lo: self.select_f64x8(mask.lo, if_true.lo, if_false.lo),
                hi: self.select_f64x8(mask.hi, if_true.hi, if_false.hi),
            }
        }

        #[inline(always)]
        fn splat_f64x16(self, value: f64) -> f64x16 {
            f64x16 {
                lo: self.splat_f64x8(value),
                hi: self.splat_f64x8(value),
            }
        }
    }
}

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;
    use more_asserts::assert_le;
    use rug::{ops::Pow, Float, Integer};

    const PREC: u32 = 1024;

    fn float_to_f128(value: &Float) -> f128 {
        let x0: f64 = value.to_f64();
        let diff = value.clone() - x0;
        let x1 = diff.to_f64();
        f128(x0, x1)
    }

    fn f128_to_float(value: f128) -> Float {
        Float::with_val(PREC, value.0) + Float::with_val(PREC, value.1)
    }

    #[test]
    fn test_add() {
        let mut rng = rug::rand::RandState::new();
        rng.seed(&Integer::from(0u64));

        for _ in 0..100 {
            let a = Float::with_val(PREC, Float::random_normal(&mut rng));
            let b = Float::with_val(PREC, Float::random_normal(&mut rng));

            let a_f128 = float_to_f128(&a);
            let b_f128 = float_to_f128(&b);
            let a = f128_to_float(a_f128);
            let b = f128_to_float(b_f128);

            let sum = Float::with_val(PREC, &a + &b);
            let sum_rug_f128 = float_to_f128(&sum);
            let sum_f128 = a_f128 + b_f128;
            let sum_estimate_f128 = f128::add_estimate_f128_f128(a_f128, b_f128);

            assert_le!(
                (sum_f128 - sum_rug_f128).abs(),
                2.0f64.powi(-104) * sum_f128.abs()
            );

            assert_le!(
                (sum_estimate_f128 - sum_rug_f128).abs(),
                2.0f64.powi(-101) * sum_f128.abs()
            );
        }
    }

    #[test]
    fn test_sub() {
        let mut rng = rug::rand::RandState::new();
        rng.seed(&Integer::from(1u64));

        for _ in 0..100 {
            let a = Float::with_val(PREC, Float::random_normal(&mut rng));
            let b = Float::with_val(PREC, Float::random_normal(&mut rng));

            let a_f128 = float_to_f128(&a);
            let b_f128 = float_to_f128(&b);
            let a = f128_to_float(a_f128);
            let b = f128_to_float(b_f128);

            let diff = Float::with_val(PREC, &a - &b);
            let diff_rug_f128 = float_to_f128(&diff);
            let diff_f128 = a_f128 - b_f128;
            let diff_estimate_f128 = f128::sub_estimate_f128_f128(a_f128, b_f128);

            assert_le!(
                (diff_f128 - diff_rug_f128).abs(),
                2.0f64.powi(-104) * diff_f128.abs()
            );

            assert_le!(
                (diff_estimate_f128 - diff_rug_f128).abs(),
                2.0f64.powi(-101) * diff_f128.abs()
            );
        }
    }

    #[test]
    fn test_mul() {
        let mut rng = rug::rand::RandState::new();
        rng.seed(&Integer::from(2u64));

        for _ in 0..100 {
            let a = Float::with_val(PREC, Float::random_normal(&mut rng));
            let b = Float::with_val(PREC, Float::random_normal(&mut rng));

            let a_f128 = float_to_f128(&a);
            let b_f128 = float_to_f128(&b);
            let a = f128_to_float(a_f128);
            let b = f128_to_float(b_f128);

            let prod = Float::with_val(PREC, &a * &b);
            let prod_rug_f128 = float_to_f128(&prod);
            let prod_f128 = a_f128 * b_f128;

            assert_le!(
                (prod_f128 - prod_rug_f128).abs(),
                2.0f64.powi(-104) * prod_f128.abs()
            );
        }
    }

    #[test]
    fn test_div() {
        let mut rng = rug::rand::RandState::new();
        rng.seed(&Integer::from(3u64));

        for _ in 0..100 {
            let a = Float::with_val(PREC, Float::random_normal(&mut rng));
            let b = Float::with_val(PREC, Float::random_normal(&mut rng));

            let a_f128 = float_to_f128(&a);
            let b_f128 = float_to_f128(&b);
            let a = f128_to_float(a_f128);
            let b = f128_to_float(b_f128);

            let quot = Float::with_val(PREC, &a / &b);
            let quot_rug_f128 = float_to_f128(&quot);
            let quot_f128 = a_f128 / b_f128;

            assert_le!(
                (quot_f128 - quot_rug_f128).abs(),
                2.0f64.powi(-104) * quot_f128.abs()
            );
        }
    }

    #[test]
    fn test_sincos_taylor() {
        let mut rng = rug::rand::RandState::new();
        rng.seed(&Integer::from(4u64));

        for _ in 0..10000 {
            let a = (Float::with_val(PREC, Float::random_bits(&mut rng)) * 2.0 - 1.0) / 32;
            let a_f128 = float_to_f128(&a);
            let a = f128_to_float(a_f128);

            let sin = Float::with_val(PREC, a.clone().sin_pi());
            let cos = Float::with_val(PREC, a.clone().cos_pi());
            let sin_rug_f128 = float_to_f128(&sin);
            let cos_rug_f128 = float_to_f128(&cos);
            let (sin_f128, cos_f128) = a_f128.sincospi_taylor();
            assert_le!(
                (cos_f128 - cos_rug_f128).abs(),
                2.0f64.powi(-103) * cos_f128.abs()
            );
            assert_le!(
                (sin_f128 - sin_rug_f128).abs(),
                2.0f64.powi(-103) * sin_f128.abs()
            );
        }
    }

    #[test]
    fn test_sincos() {
        let mut rng = rug::rand::RandState::new();
        rng.seed(&Integer::from(5u64));

        #[track_caller]
        fn test_sincos(a: Float) {
            let a_f128 = float_to_f128(&a);
            let a = f128_to_float(a_f128);

            let sin = Float::with_val(PREC, a.clone().sin_pi());
            let cos = Float::with_val(PREC, a.cos_pi());
            let sin_rug_f128 = float_to_f128(&sin);
            let cos_rug_f128 = float_to_f128(&cos);
            let (sin_f128, cos_f128) = a_f128.sincospi();
            assert_le!(
                (cos_f128 - cos_rug_f128).abs(),
                2.0f64.powi(-103) * cos_f128.abs()
            );
            assert_le!(
                (sin_f128 - sin_rug_f128).abs(),
                2.0f64.powi(-103) * sin_f128.abs()
            );
        }

        test_sincos(Float::with_val(PREC, 0.00));
        test_sincos(Float::with_val(PREC, 0.25));
        test_sincos(Float::with_val(PREC, 0.50));
        test_sincos(Float::with_val(PREC, 0.75));
        test_sincos(Float::with_val(PREC, 1.00));

        for _ in 0..10000 {
            test_sincos(Float::with_val(PREC, Float::random_bits(&mut rng)) * 2.0 - 1.0);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn generate_constants() {
        let pi = Float::with_val(PREC, rug::float::Constant::Pi);

        println!();
        println!("###############################################################################");
        println!("impl f128 {{");
        println!("    pub const PI: Self = {:?};", float_to_f128(&pi));

        println!();
        println!("    const SINPI_TAYLOR: &'static [Self; 9] = &[");
        let mut factorial = 1_u64;
        for i in 1..10 {
            let k = 2 * i + 1;
            factorial *= (k - 1) * k;
            println!(
                "        {:?},",
                (-1.0f64).powi(i as i32) * float_to_f128(&(pi.clone().pow(k) / factorial)),
            );
        }
        println!("    ];");

        println!();
        println!("    const COSPI_TAYLOR: &'static [Self; 9] = &[");
        let mut factorial = 1_u64;
        for i in 1..10 {
            let k = 2 * i;
            factorial *= (k - 1) * k;
            println!(
                "        {:?},",
                (-1.0f64).powi(i as i32) * float_to_f128(&(pi.clone().pow(k) / factorial)),
            );
        }
        println!("    ];");

        println!();
        println!("    const SIN_K_PI_OVER_16_TABLE: &'static [Self; 4] = &[");
        for k in 1..5 {
            let x: Float = Float::with_val(PREC, k as f64 / 16.0);
            println!("        {:?},", float_to_f128(&x.clone().sin_pi()),);
        }
        println!("    ];");

        println!();
        println!("    const COS_K_PI_OVER_16_TABLE: &'static [Self; 4] = &[");
        for k in 1..5 {
            let x: Float = Float::with_val(PREC, k as f64 / 16.0);
            println!("        {:?},", float_to_f128(&x.clone().cos_pi()),);
        }
        println!("    ];");

        println!("}}");
        println!("###############################################################################");
        assert_eq!(float_to_f128(&pi), f128::PI);
    }
}
