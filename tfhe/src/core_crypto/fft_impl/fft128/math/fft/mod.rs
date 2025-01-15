use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::PolynomialSize;
use crate::core_crypto::commons::utils::izip;
use core::any::TypeId;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use tfhe_fft::fft128::{f128, Plan};

#[derive(Clone)]
pub(crate) struct PlanWrapper(Plan);
impl core::ops::Deref for PlanWrapper {
    type Target = Plan;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::fmt::Debug for PlanWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        "[?]".fmt(f)
    }
}

/// Negacyclic Fast Fourier Transform. See [`Fft128View`] for transform functions.
///
/// This structure contains the twisting factors as well as the
/// FFT plan needed for the negacyclic convolution over the reals.
#[derive(Clone, Debug)]
pub struct Fft128 {
    plan: Arc<PlanWrapper>,
}

/// View type for [`Fft128`].
#[derive(Clone, Copy, Debug)]
pub struct Fft128View<'a> {
    pub(crate) plan: &'a PlanWrapper,
}

impl Fft128 {
    pub fn as_view(&self) -> Fft128View<'_> {
        Fft128View { plan: &self.plan }
    }
}

type PlanMap = RwLock<HashMap<usize, Arc<OnceLock<Arc<PlanWrapper>>>>>;
pub(crate) static PLANS: OnceLock<PlanMap> = OnceLock::new();
fn plans() -> &'static PlanMap {
    PLANS.get_or_init(|| RwLock::new(HashMap::new()))
}

impl Fft128 {
    /// Real polynomial of size `size`.
    pub fn new(size: PolynomialSize) -> Self {
        let global_plans = plans();

        let n = size.0;
        let get_plan = || {
            let plans = global_plans.read().unwrap();
            let plan = plans.get(&n).cloned();
            drop(plans);

            plan.map(|p| {
                p.get_or_init(|| Arc::new(PlanWrapper(Plan::new(n / 2))))
                    .clone()
            })
        };

        // could not find a plan of the given size, we lock the map again and try to insert it
        let mut plans = global_plans.write().unwrap();
        if let Entry::Vacant(v) = plans.entry(n) {
            v.insert(Arc::new(OnceLock::new()));
        }

        drop(plans);

        Self {
            plan: get_plan().unwrap(),
        }
    }
}

#[inline(always)]
fn to_signed_to_f128<Scalar: UnsignedInteger>(x: Scalar) -> f128 {
    if TypeId::of::<Scalar>() == TypeId::of::<u128>() {
        // we use bytemuck::cast instead of pulp::cast since it doesn't assert the check at compile
        // time
        u128_to_signed_to_f128(bytemuck::cast(x))
    } else {
        // convert to signed then to float
        let first_approx: f64 = x.into_signed().cast_into();

        // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS -
        // 1)`, which should fit in a `Scalar`
        //
        // we perform this step since converting back directly to a signed integer may overflow
        let sign_bit = first_approx.to_bits() & (1u64 << 63);
        let first_approx_roundtrip: Scalar = first_approx.abs().cast_into();

        // apply sign again to get a wraparound effect
        let first_approx_roundtrip_signed = if sign_bit == (1u64 << 63) {
            // negative
            first_approx_roundtrip.wrapping_neg()
        } else {
            // positive
            first_approx_roundtrip
        };

        let correction = x
            .wrapping_sub(first_approx_roundtrip_signed)
            .into_signed()
            .cast_into();

        f128(first_approx, correction)
    }
}

#[inline(always)]
fn f128_floor(x: f128) -> f128 {
    let f128(x0, x1) = x;
    let x0_floor = x0.floor();
    if x0_floor == x0 {
        f128::add_f64_f64(x0_floor, x1.floor())
    } else {
        f128(x0_floor, 0.0)
    }
}

#[inline(always)]
fn f128_round(x: f128) -> f128 {
    f128_floor(x + 0.5)
}

#[inline(always)]
pub fn u128_to_f64(x: u128) -> f64 {
    const A: f64 = (1u128 << 52) as f64;
    const B: f64 = (1u128 << 104) as f64;
    const C: f64 = (1u128 << 76) as f64;
    const D: f64 = u128::MAX as f64;
    if x < 1 << 104 {
        let l = f64::from_bits(A.to_bits() | ((x << 12) as u64 >> 12)) - A;
        let h = f64::from_bits(B.to_bits() | (x >> 52) as u64) - B;
        l + h
    } else {
        let l = f64::from_bits(C.to_bits() | ((x >> 12) as u64 >> 12) | (x as u64 & 0xFFFFFF)) - C;
        let h = f64::from_bits(D.to_bits() | (x >> 76) as u64) - D;
        l + h
    }
}

#[inline(always)]
fn i128_to_f64(x: i128) -> f64 {
    let sign = ((x >> 64) as u64) & (1u64 << 63);
    let abs = x.unsigned_abs();
    f64::from_bits(u128_to_f64(abs).to_bits() | sign)
}

#[inline(always)]
pub fn f64_to_u128(f: f64) -> u128 {
    let f = f.to_bits();
    if f < 1023 << 52 {
        // >= 0, < 1
        0
    } else {
        // >= 1, < max
        let m = (1 << 127) | ((f as u128) << 75); // Mantissa and the implicit 1-bit.
        let s = 1150 - (f >> 52); // Shift based on the exponent and bias.
        if s >= 128 {
            0
        } else {
            m >> s
        }
    }
}

#[inline(always)]
pub fn f64_to_i128(f: f64) -> i128 {
    let f = f.to_bits();

    let a = f & (!0 >> 1); // Remove sign bit.
    if a < 1023 << 52 {
        // >= 0, < 1
        0
    } else {
        // >= 1, < max
        let m = (1 << 127) | ((a as u128) << 75); // Mantissa and the implicit 1-bit.
        let s = 1150 - (a >> 52); // Shift based on the exponent and bias.
        let u = (m >> s) as i128; // Unsigned result.
        if (f as i64) < 0 {
            -u
        } else {
            u
        }
    }
}

#[inline(always)]
fn u128_to_signed_to_f128(x: u128) -> f128 {
    // convert to signed then to float
    let first_approx: f64 = i128_to_f64(x as _);

    // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS - 1)`,
    // which should fit in a `Scalar`
    //
    // we perform this step since converting back directly to a signed integer may overflow
    let sign_bit = first_approx.to_bits() & (1u64 << 63);
    let first_approx_roundtrip = f64_to_u128(first_approx.abs());

    // apply sign again to get a wraparound effect
    let first_approx_roundtrip_signed = if sign_bit == (1u64 << 63) {
        // negative
        first_approx_roundtrip.wrapping_neg()
    } else {
        // positive
        first_approx_roundtrip
    };

    let correction = i128_to_f64(x.wrapping_sub(first_approx_roundtrip_signed) as _);
    f128(first_approx, correction)
}

#[inline(always)]
fn u128_from_torus_f128(x: f128) -> u128 {
    let mut x = f128::sub_estimate_f128_f128(x, f128_floor(x));

    let normalization = 2.0f64.powi(128);
    x.0 *= normalization;
    x.1 *= normalization;

    let x = f128_round(x);

    let x0 = f64_to_u128(x.0);
    let x1 = f64_to_i128(x.1);

    x0.wrapping_add(x1 as _)
}

#[inline(always)]
fn from_torus_f128<Scalar: UnsignedInteger>(x: f128) -> Scalar {
    if TypeId::of::<Scalar>() == TypeId::of::<u128>() {
        // we use bytemuck::cast instead of pulp::cast since it doesn't assert the check at compile
        // time
        bytemuck::cast(u128_from_torus_f128(x))
    } else {
        let mut x = x - f128_floor(x);

        let normalization = 2.0f64.powi(Scalar::BITS as i32);
        x.0 *= normalization;
        x.1 *= normalization;

        let x = f128_round(x);

        let x0 = Scalar::cast_from(x.0);
        let x1 = Scalar::cast_from(Scalar::Signed::cast_from(x.1));

        x0.wrapping_add(x1)
    }
}

pub fn convert_forward_torus<Scalar: UnsignedTorus>(
    out_re0: &mut [f64],
    out_re1: &mut [f64],
    out_im0: &mut [f64],
    out_im1: &mut [f64],
    in_re: &[Scalar],
    in_im: &[Scalar],
) {
    let normalization = 2.0_f64.powi(-(Scalar::BITS as i32));

    for (out_re0, out_re1, out_im0, out_im1, &in_re, &in_im) in
        izip!(out_re0, out_re1, out_im0, out_im1, in_re, in_im)
    {
        let out_re = to_signed_to_f128(in_re);
        let out_im = to_signed_to_f128(in_im);

        let out_re = (out_re.0 * normalization, out_re.1 * normalization);
        let out_im = (out_im.0 * normalization, out_im.1 * normalization);

        *out_re0 = out_re.0;
        *out_re1 = out_re.1;
        *out_im0 = out_im.0;
        *out_im1 = out_im.1;
    }
}

pub fn convert_forward_integer<Scalar: UnsignedTorus>(
    out_re0: &mut [f64],
    out_re1: &mut [f64],
    out_im0: &mut [f64],
    out_im1: &mut [f64],
    in_re: &[Scalar],
    in_im: &[Scalar],
) {
    for (out_re0, out_re1, out_im0, out_im1, &in_re, &in_im) in
        izip!(out_re0, out_re1, out_im0, out_im1, in_re, in_im)
    {
        let out_re = to_signed_to_f128(in_re);
        let out_im = to_signed_to_f128(in_im);

        *out_re0 = out_re.0;
        *out_re1 = out_re.1;
        *out_im0 = out_im.0;
        *out_im1 = out_im.1;
    }
}

fn convert_add_backward_torus<Scalar: UnsignedTorus>(
    out_re: &mut [Scalar],
    out_im: &mut [Scalar],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    let norm = 1.0 / in_re0.len() as f64;
    for (out_re, out_im, in_re0, in_re1, in_im0, in_im1) in
        izip!(out_re, out_im, in_re0, in_re1, in_im0, in_im1)
    {
        let in_re = f128(*in_re0 * norm, *in_re1 * norm);
        let in_im = f128(*in_im0 * norm, *in_im1 * norm);

        *out_re = out_re.wrapping_add(from_torus_f128(in_re));
        *out_im = out_im.wrapping_add(from_torus_f128(in_im));
    }
}

fn convert_backward_torus<Scalar: UnsignedTorus>(
    out_re: &mut [Scalar],
    out_im: &mut [Scalar],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    let norm = 1.0 / in_re0.len() as f64;
    for (out_re, out_im, in_re0, in_re1, in_im0, in_im1) in
        izip!(out_re, out_im, in_re0, in_re1, in_im0, in_im1)
    {
        let in_re = f128(*in_re0 * norm, *in_re1 * norm);
        let in_im = f128(*in_im0 * norm, *in_im1 * norm);
        *out_re = from_torus_f128(in_re);
        *out_im = from_torus_f128(in_im);
    }
}

impl Fft128View<'_> {
    pub fn polynomial_size(self) -> PolynomialSize {
        PolynomialSize(2 * self.plan.fft_size())
    }

    /// Return the memory required for a backward negacyclic FFT.
    pub fn backward_scratch(self) -> Result<StackReq, SizeOverflow> {
        let one = StackReq::try_new_aligned::<f64>(
            self.polynomial_size().0 / 2,
            aligned_vec::CACHELINE_ALIGN,
        )?;
        StackReq::try_all_of([one; 4])
    }

    pub fn forward_as_torus<Scalar: UnsignedTorus>(
        self,
        fourier_re0: &mut [f64],
        fourier_re1: &mut [f64],
        fourier_im0: &mut [f64],
        fourier_im1: &mut [f64],
        standard: &[Scalar],
    ) {
        self.forward_with_conv(
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            standard,
            convert_forward_torus,
        );
    }

    pub fn forward_as_integer<Scalar: UnsignedTorus>(
        self,
        fourier_re0: &mut [f64],
        fourier_re1: &mut [f64],
        fourier_im0: &mut [f64],
        fourier_im1: &mut [f64],
        standard: &[Scalar],
    ) {
        self.forward_with_conv(
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            standard,
            convert_forward_integer,
        );
    }

    fn forward_with_conv<Scalar: UnsignedTorus>(
        self,
        fourier_re0: &mut [f64],
        fourier_re1: &mut [f64],
        fourier_im0: &mut [f64],
        fourier_im1: &mut [f64],
        standard: &[Scalar],
        conv_fn: impl Fn(&mut [f64], &mut [f64], &mut [f64], &mut [f64], &[Scalar], &[Scalar]),
    ) {
        let n = standard.len();
        debug_assert_eq!(n, 2 * fourier_re0.len());
        debug_assert_eq!(n, 2 * fourier_re1.len());
        debug_assert_eq!(n, 2 * fourier_im0.len());
        debug_assert_eq!(n, 2 * fourier_im1.len());

        let (standard_re, standard_im) = standard.split_at(n / 2);
        conv_fn(
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            standard_re,
            standard_im,
        );
        self.plan
            .fwd(fourier_re0, fourier_re1, fourier_im0, fourier_im1);
    }

    /// Perform an inverse negacyclic real FFT of `fourier` and stores the result in `standard`,
    /// viewed as torus elements.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn backward_as_torus<Scalar: UnsignedTorus>(
        self,
        standard: &mut [Scalar],
        fourier_re0: &[f64],
        fourier_re1: &[f64],
        fourier_im0: &[f64],
        fourier_im1: &[f64],
        stack: &mut PodStack,
    ) {
        self.backward_with_conv(
            standard,
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            convert_backward_torus,
            stack,
        );
    }

    /// Perform an inverse negacyclic real FFT of `fourier` and adds the result to `standard`,
    /// viewed as torus elements.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn add_backward_as_torus<Scalar: UnsignedTorus>(
        self,
        standard: &mut [Scalar],
        fourier_re0: &[f64],
        fourier_re1: &[f64],
        fourier_im0: &[f64],
        fourier_im1: &[f64],
        stack: &mut PodStack,
    ) {
        self.backward_with_conv(
            standard,
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            convert_add_backward_torus,
            stack,
        );
    }

    fn backward_with_conv<
        Scalar: UnsignedTorus,
        F: Fn(&mut [Scalar], &mut [Scalar], &[f64], &[f64], &[f64], &[f64]),
    >(
        self,
        standard: &mut [Scalar],
        fourier_re0: &[f64],
        fourier_re1: &[f64],
        fourier_im0: &[f64],
        fourier_im1: &[f64],
        conv_fn: F,
        stack: &mut PodStack,
    ) {
        let n = standard.len();
        debug_assert_eq!(n, 2 * fourier_re0.len());
        debug_assert_eq!(n, 2 * fourier_re1.len());
        debug_assert_eq!(n, 2 * fourier_im0.len());
        debug_assert_eq!(n, 2 * fourier_im1.len());

        let (tmp_re0, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_re0.iter().copied());
        let (tmp_re1, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_re1.iter().copied());
        let (tmp_im0, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_im0.iter().copied());
        let (tmp_im1, _) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_im1.iter().copied());

        self.plan.inv(tmp_re0, tmp_re1, tmp_im0, tmp_im1);

        let (standard_re, standard_im) = standard.split_at_mut(n / 2);
        conv_fn(standard_re, standard_im, tmp_re0, tmp_re1, tmp_im0, tmp_im1);
    }
}

#[cfg(test)]
mod tests;
