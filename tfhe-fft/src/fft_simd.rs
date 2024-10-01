use crate::c64;
use core::{fmt::Debug, marker::PhantomData};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct c64x2(c64, c64);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct c64x4(c64, c64, c64, c64);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const __ASSERT_POD: () = {
    #[allow(unknown_lints)]
    #[allow(clippy::extra_unused_type_parameters)]
    const fn assert_pod_zeroable<T: bytemuck::Pod + bytemuck::Zeroable>() {}

    // c64 is Pod and Zeroable
    assert_pod_zeroable::<c64>();

    // no padding
    assert!(core::mem::size_of::<c64x2>() == core::mem::size_of::<c64>() * 2);
    #[cfg(feature = "nightly")]
    assert!(core::mem::size_of::<c64x4>() == core::mem::size_of::<c64>() * 4);
};

// SAFETY: c64 is Zeroable
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe impl bytemuck::Zeroable for c64x2 {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
unsafe impl bytemuck::Zeroable for c64x4 {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// SAFETY: c64 is Pod, c64x2, c64x4 are all repr(C) and have no padding
unsafe impl bytemuck::Pod for c64x2 {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
unsafe impl bytemuck::Pod for c64x4 {}

pub trait Pod: Copy + Debug + bytemuck::Pod {}
impl<T: Copy + Debug + bytemuck::Pod> Pod for T {}

// cos(-pi/8)
pub const H1X: f64 = 0.9238795325112867f64;
// sin(-pi/8)
pub const H1Y: f64 = -0.38268343236508984f64;

struct AssertC64Vec<T>(PhantomData<T>);
impl<T> AssertC64Vec<T> {
    pub const VALID: () = {
        assert!(core::mem::size_of::<T>() % core::mem::size_of::<c64>() == 0);
    };
}

pub trait FftSimd<c64xN: Pod>: Copy + Debug {
    fn try_new() -> Option<Self>;
    #[inline(always)]
    fn vectorize(self, f: impl pulp::NullaryFnOnce<Output = ()>) {
        f.call()
    }

    #[inline(always)]
    fn lane_count(self) -> usize {
        #[allow(clippy::let_unit_value)]
        let _ = AssertC64Vec::<c64xN>::VALID;
        core::mem::size_of::<c64xN>() / core::mem::size_of::<c64>()
    }

    fn splat_f64(self, value: f64) -> c64xN;
    fn splat(self, value: c64) -> c64xN;
    fn xor(self, a: c64xN, b: c64xN) -> c64xN;
    fn swap_re_im(self, xy: c64xN) -> c64xN;
    fn add(self, a: c64xN, b: c64xN) -> c64xN;
    fn sub(self, a: c64xN, b: c64xN) -> c64xN;
    fn real_mul(self, a: c64xN, b: c64xN) -> c64xN;
    fn mul(self, a: c64xN, b: c64xN) -> c64xN;

    // implemented only when `self.lane_count() == 2`
    fn catlo(self, a: c64xN, b: c64xN) -> c64xN {
        let _ = a;
        let _ = b;
        unimplemented!()
    }
    fn cathi(self, a: c64xN, b: c64xN) -> c64xN {
        let _ = a;
        let _ = b;
        unimplemented!()
    }

    // implemented only when `self.lane_count() == 4`
    fn transpose(self, a: c64xN, b: c64xN, c: c64xN, d: c64xN) -> (c64xN, c64xN, c64xN, c64xN) {
        let _ = a;
        let _ = b;
        let _ = c;
        let _ = d;
        unimplemented!()
    }
}

pub trait FftSimdExt<c64xN: Pod>: FftSimd<c64xN> {
    #[inline(always)]
    fn conj(self, xy: c64xN) -> c64xN {
        let mask = self.splat(c64 { re: 0.0, im: -0.0 });
        self.xor(xy, mask)
    }

    #[inline(always)]
    fn mul_j(self, fwd: bool, xy: c64xN) -> c64xN {
        if fwd {
            self.swap_re_im(self.conj(xy))
        } else {
            self.conj(self.swap_re_im(xy))
        }
    }

    #[inline(always)]
    fn mul_exp_pi_over_8(self, fwd: bool, xy: c64xN) -> c64xN {
        let r = self.splat_f64(core::f64::consts::FRAC_1_SQRT_2);
        self.real_mul(r, self.add(xy, self.mul_j(fwd, xy)))
    }

    #[inline(always)]
    fn mul_exp_neg_pi_over_8(self, fwd: bool, xy: c64xN) -> c64xN {
        self.mul_exp_pi_over_8(!fwd, xy)
    }

    #[inline(always)]
    fn mul_exp_pi_over_16(self, fwd: bool, xy: c64xN) -> c64xN {
        if fwd {
            self.mul(self.splat(c64 { re: H1X, im: H1Y }), xy)
        } else {
            self.mul(self.splat(c64 { re: H1X, im: -H1Y }), xy)
        }
    }

    #[inline(always)]
    fn mul_exp_17pi_over_16(self, fwd: bool, xy: c64xN) -> c64xN {
        if fwd {
            self.mul(self.splat(c64 { re: -H1Y, im: -H1X }), xy)
        } else {
            self.mul(self.splat(c64 { re: -H1Y, im: H1X }), xy)
        }
    }

    #[inline(always)]
    fn mul_exp_neg_pi_over_16(self, fwd: bool, xy: c64xN) -> c64xN {
        self.mul_exp_pi_over_16(!fwd, xy)
    }

    #[inline(always)]
    fn mul_exp_neg_17pi_over_16(self, fwd: bool, xy: c64xN) -> c64xN {
        self.mul_exp_17pi_over_16(!fwd, xy)
    }
}

impl<c64xN: Pod, T: FftSimd<c64xN>> FftSimdExt<c64xN> for T {}

#[derive(Copy, Clone, Debug)]
pub struct Scalar;

impl FftSimd<c64> for Scalar {
    #[inline(always)]
    fn try_new() -> Option<Self> {
        Some(Scalar)
    }

    #[inline(always)]
    fn splat_f64(self, value: f64) -> c64 {
        c64 {
            re: value,
            im: value,
        }
    }

    #[inline(always)]
    fn splat(self, value: c64) -> c64 {
        value
    }

    #[inline(always)]
    fn xor(self, a: c64, b: c64) -> c64 {
        let a: u128 = pulp::cast(a);
        let b: u128 = pulp::cast(b);
        pulp::cast(a ^ b)
    }

    #[inline(always)]
    fn swap_re_im(self, xy: c64) -> c64 {
        c64 {
            re: xy.im,
            im: xy.re,
        }
    }

    #[inline(always)]
    fn add(self, a: c64, b: c64) -> c64 {
        a + b
    }

    #[inline(always)]
    fn sub(self, a: c64, b: c64) -> c64 {
        a - b
    }

    #[inline(always)]
    fn real_mul(self, a: c64, b: c64) -> c64 {
        c64 {
            re: a.re * b.re,
            im: a.im * b.im,
        }
    }

    #[inline(always)]
    fn mul(self, a: c64, b: c64) -> c64 {
        let ab = a;
        let xy = b;

        let a = ab.re;
        let b = ab.im;
        let x = xy.re;
        let y = xy.im;

        c64 {
            re: f64::mul_add(a, x, -b * y),
            im: f64::mul_add(a, y, b * x),
        }
    }
}

// https://stackoverflow.com/a/42792940
pub fn sincospi64(mut a: f64) -> (f64, f64) {
    let fma = f64::mul_add;

    // must be evaluated with IEEE-754 semantics
    let az = a * 0.0;

    // for |a| >= 2**53, cospi(a) = 1.0, but cospi(Inf) = NaN
    a = if a.abs() < 9007199254740992.0f64 {
        a
    } else {
        az
    };

    // reduce argument to primary approximation interval (-0.25, 0.25)
    let mut r = (a + a).round();
    let i = r as i64;
    let t = f64::mul_add(-0.5, r, a);

    // compute core approximations
    let s = t * t;

    // approximate cos(pi*x) for x in [-0.25,0.25]

    r = -1.0369917389758117e-4;
    r = fma(r, s, 1.9294935641298806e-3);
    r = fma(r, s, -2.5806887942825395e-2);
    r = fma(r, s, 2.3533063028328211e-1);
    r = fma(r, s, -1.3352627688538006e+0);
    r = fma(r, s, 4.0587121264167623e+0);
    r = fma(r, s, -4.9348022005446790e+0);
    let mut c = fma(r, s, 1.0000000000000000e+0);

    // approximate sin(pi*x) for x in [-0.25,0.25]
    r = 4.6151442520157035e-4;
    r = fma(r, s, -7.3700183130883555e-3);
    r = fma(r, s, 8.2145868949323936e-2);
    r = fma(r, s, -5.9926452893214921e-1);
    r = fma(r, s, 2.5501640398732688e+0);
    r = fma(r, s, -5.1677127800499516e+0);
    let s = s * t;
    r *= s;

    let mut s = fma(t, 3.1415926535897931e+0, r);
    // map results according to quadrant

    if (i & 2) != 0 {
        s = 0.0 - s; // must be evaluated with IEEE-754 semantics
        c = 0.0 - c; // must be evaluated with IEEE-754 semantics
    }
    if (i & 1) != 0 {
        let t = 0.0 - s; // must be evaluated with IEEE-754 semantics
        s = c;
        c = t;
    }
    // IEEE-754: sinPi(+n) is +0 and sinPi(-n) is -0 for positive integers n
    if a == a.floor() {
        s = az
    }
    (s, c)
}

pub fn init_wt(r: usize, n: usize, w: &mut [c64], w_inv: &mut [c64]) {
    if n < r {
        return;
    }

    let nr = n / r;
    let theta = -2.0 / n as f64;

    for wi in w.iter_mut() {
        wi.re = f64::NAN;
        wi.im = f64::NAN;
    }

    for p in 0..nr {
        for k in 1..r {
            let (s, c) = sincospi64(theta * (k * p) as f64);
            let z = c64::new(c, s);
            w[p + k * nr] = z;
            w[n + r * p + k] = z;
            w_inv[p + k * nr] = z.conj();
            w_inv[n + r * p + k] = z.conj();
        }
    }
}
