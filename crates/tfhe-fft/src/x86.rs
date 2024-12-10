use crate::{c64, fft_simd::*};
use pulp::{cast, x86::*};

impl FftSimd<c64x2> for V3 {
    #[inline(always)]
    fn try_new() -> Option<Self> {
        Self::try_new()
    }
    #[inline(always)]
    fn vectorize(self, f: impl pulp::NullaryFnOnce<Output = ()>) {
        self.vectorize(f)
    }

    #[inline(always)]
    fn splat_f64(self, value: f64) -> c64x2 {
        cast(self.splat_f64x4(value))
    }

    #[inline(always)]
    fn splat(self, value: c64) -> c64x2 {
        let f128 = cast(value);
        cast(self.avx._mm256_broadcast_pd(&f128))
    }

    #[inline(always)]
    fn xor(self, a: c64x2, b: c64x2) -> c64x2 {
        cast(self.xor_f64x4(cast(a), cast(b)))
    }

    #[inline(always)]
    fn swap_re_im(self, xy: c64x2) -> c64x2 {
        cast(self.avx._mm256_permute_pd::<0b0101>(cast(xy)))
    }

    #[inline(always)]
    fn add(self, a: c64x2, b: c64x2) -> c64x2 {
        cast(self.add_f64x4(cast(a), cast(b)))
    }

    #[inline(always)]
    fn sub(self, a: c64x2, b: c64x2) -> c64x2 {
        cast(self.sub_f64x4(cast(a), cast(b)))
    }

    #[inline(always)]
    fn real_mul(self, a: c64x2, b: c64x2) -> c64x2 {
        cast(self.mul_f64x4(cast(a), cast(b)))
    }

    #[inline(always)]
    fn mul(self, a: c64x2, b: c64x2) -> c64x2 {
        let xy = cast(b);
        let yx = cast(self.swap_re_im(b));
        let ab = cast(a);
        let aa = cast(self.avx._mm256_unpacklo_pd(ab, ab));
        let bb = cast(self.avx._mm256_unpackhi_pd(ab, ab));
        cast(self.mul_subadd_f64x4(aa, xy, self.mul_f64x4(bb, yx)))
    }
    #[inline(always)]
    fn catlo(self, a: c64x2, b: c64x2) -> c64x2 {
        cast(
            self.avx
                ._mm256_permute2f128_pd::<0b0010_0000>(cast(a), cast(b)),
        )
    }

    #[inline(always)]
    fn cathi(self, a: c64x2, b: c64x2) -> c64x2 {
        cast(
            self.avx
                ._mm256_permute2f128_pd::<0b0011_0001>(cast(a), cast(b)),
        )
    }
}

#[cfg(feature = "nightly")]
impl FftSimd<c64x4> for V4 {
    #[inline(always)]
    fn try_new() -> Option<Self> {
        Self::try_new()
    }
    #[inline(always)]
    fn vectorize(self, f: impl pulp::NullaryFnOnce<Output = ()>) {
        self.vectorize(f)
    }

    #[inline(always)]
    fn splat_f64(self, value: f64) -> c64x4 {
        cast(self.splat_f64x8(value))
    }

    #[inline(always)]
    fn splat(self, value: c64) -> c64x4 {
        let f128 = cast(value);
        cast(self.avx512f._mm512_broadcast_f32x4(f128))
    }

    #[inline(always)]
    fn xor(self, a: c64x4, b: c64x4) -> c64x4 {
        cast(self.xor_f64x8(cast(a), cast(b)))
    }

    #[inline(always)]
    fn swap_re_im(self, xy: c64x4) -> c64x4 {
        cast(self.avx512f._mm512_permute_pd::<0b0101_0101>(cast(xy)))
    }

    #[inline(always)]
    fn add(self, a: c64x4, b: c64x4) -> c64x4 {
        cast(self.add_f64x8(cast(a), cast(b)))
    }

    #[inline(always)]
    fn sub(self, a: c64x4, b: c64x4) -> c64x4 {
        cast(self.sub_f64x8(cast(a), cast(b)))
    }

    #[inline(always)]
    fn real_mul(self, a: c64x4, b: c64x4) -> c64x4 {
        cast(self.mul_f64x8(cast(a), cast(b)))
    }

    #[inline(always)]
    fn mul(self, a: c64x4, b: c64x4) -> c64x4 {
        let xy = cast(b);
        let yx = cast(self.swap_re_im(b));
        let ab = cast(a);
        let aa = cast(self.avx512f._mm512_unpacklo_pd(ab, ab));
        let bb = cast(self.avx512f._mm512_unpackhi_pd(ab, ab));
        cast(self.mul_subadd_f64x8(aa, xy, self.mul_f64x8(bb, yx)))
    }

    #[inline(always)]
    fn transpose(self, r0: c64x4, r1: c64x4, r2: c64x4, r3: c64x4) -> (c64x4, c64x4, c64x4, c64x4) {
        let t0 = self
            .avx512f
            ._mm512_shuffle_f64x2::<0b1000_1000>(cast(r0), cast(r1));
        let t1 = self
            .avx512f
            ._mm512_shuffle_f64x2::<0b1101_1101>(cast(r0), cast(r1));
        let t2 = self
            .avx512f
            ._mm512_shuffle_f64x2::<0b1000_1000>(cast(r2), cast(r3));
        let t3 = self
            .avx512f
            ._mm512_shuffle_f64x2::<0b1101_1101>(cast(r2), cast(r3));

        let s0 = cast(self.avx512f._mm512_shuffle_f64x2::<0b1000_1000>(t0, t2));
        let s1 = cast(self.avx512f._mm512_shuffle_f64x2::<0b1101_1101>(t0, t2));
        let s2 = cast(self.avx512f._mm512_shuffle_f64x2::<0b1000_1000>(t1, t3));
        let s3 = cast(self.avx512f._mm512_shuffle_f64x2::<0b1101_1101>(t1, t3));

        (s0, s2, s1, s3)
    }
}
