use crate::{c64, fft_simd::*};
use pulp::{aarch64::*, cast, Simd};

// Neon has 128 bits registers, so can process one c64 at once
impl FftSimd<c64> for Neon {
    #[inline(always)]
    fn try_new() -> Option<Self> {
        Self::try_new()
    }

    #[inline(always)]
    fn vectorize(self, f: impl pulp::NullaryFnOnce<Output = ()>) {
        self.vectorize(f)
    }

    #[inline(always)]
    fn splat_f64(self, value: f64) -> c64 {
        cast(self.splat_f64x2(value))
    }

    #[inline(always)]
    fn splat(self, value: c64) -> c64 {
        value
    }

    #[inline(always)]
    fn xor(self, a: c64, b: c64) -> c64 {
        cast(self.xor_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn swap_re_im(self, xy: c64) -> c64 {
        cast(self.neon.vextq_f64::<1>(cast(xy), cast(xy)))
    }

    #[inline(always)]
    fn add(self, a: c64, b: c64) -> c64 {
        cast(self.add_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn sub(self, a: c64, b: c64) -> c64 {
        cast(self.sub_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn real_mul(self, a: c64, b: c64) -> c64 {
        cast(self.mul_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn mul(self, a: c64, b: c64) -> c64 {
        cast(self.mul_c64s(cast(a), cast(b)))
    }
}

// Neon has 128 bits registers, so can process one c64 at once
impl FftSimd<c64> for NeonFcma {
    #[inline(always)]
    fn try_new() -> Option<Self> {
        Self::try_new()
    }

    #[inline(always)]
    fn vectorize(self, f: impl pulp::NullaryFnOnce<Output = ()>) {
        self.vectorize(f)
    }

    #[inline(always)]
    fn splat_f64(self, value: f64) -> c64 {
        cast(self.splat_f64x2(value))
    }

    #[inline(always)]
    fn splat(self, value: c64) -> c64 {
        value
    }

    #[inline(always)]
    fn xor(self, a: c64, b: c64) -> c64 {
        cast(self.xor_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn swap_re_im(self, xy: c64) -> c64 {
        cast(self.neon.vextq_f64::<1>(cast(xy), cast(xy)))
    }

    #[inline(always)]
    fn add(self, a: c64, b: c64) -> c64 {
        cast(self.add_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn sub(self, a: c64, b: c64) -> c64 {
        cast(self.sub_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn real_mul(self, a: c64, b: c64) -> c64 {
        cast(self.mul_f64x2(cast(a), cast(b)))
    }

    #[inline(always)]
    fn mul(self, a: c64, b: c64) -> c64 {
        cast(self.mul_c64s(cast(a), cast(b)))
    }
}
