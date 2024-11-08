pub mod f128_ops;

/// 128-bit floating point number.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct f128(pub f64, pub f64);

use aligned_vec::{avec, ABox};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use pulp::{as_arrays, as_arrays_mut, cast};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::fft128::f128_ops::x86::V3F128Ext;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use pulp::{f64x4, x86::V3};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
use crate::fft128::f128_ops::x86::{f64x16, V4F128Ext};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
use pulp::{f64x8, x86::V4};

trait FftSimdF128: Copy {
    type Reg: Copy + core::fmt::Debug;

    #[allow(dead_code)]
    fn splat(self, value: f64) -> Self::Reg;
    fn add(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg);
    fn sub(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg);
    fn mul(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
trait V3InterleaveExt {
    fn interleave2_f64x4(self, z0z0z1z1: [f64x4; 2]) -> [f64x4; 2];
    fn permute2_f64x4(self, w: [f64; 2]) -> f64x4;
    fn interleave1_f64x4(self, z0z1: [f64x4; 2]) -> [f64x4; 2];
    fn permute1_f64x4(self, w: [f64; 4]) -> f64x4;
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
trait V4InterleaveExt {
    fn interleave4_f64x8(self, z0z0z0z0z1z1z1z1: [f64x8; 2]) -> [f64x8; 2];
    fn permute4_f64x8(self, w: [f64; 2]) -> f64x8;
    fn interleave2_f64x8(self, z0z0z1z1: [f64x8; 2]) -> [f64x8; 2];
    fn permute2_f64x8(self, w: [f64; 4]) -> f64x8;
    fn interleave1_f64x8(self, z0z1: [f64x8; 2]) -> [f64x8; 2];
    fn permute1_f64x8(self, w: [f64; 8]) -> f64x8;
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl V3InterleaveExt for V3 {
    #[inline(always)]
    fn interleave2_f64x4(self, z0z0z1z1: [f64x4; 2]) -> [f64x4; 2] {
        let avx = self.avx;
        [
            cast(avx._mm256_permute2f128_pd::<0b0010_0000>(cast(z0z0z1z1[0]), cast(z0z0z1z1[1]))),
            cast(avx._mm256_permute2f128_pd::<0b0011_0001>(cast(z0z0z1z1[0]), cast(z0z0z1z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute2_f64x4(self, w: [f64; 2]) -> f64x4 {
        let avx = self.avx;
        let w00 = self.sse2._mm_set1_pd(w[0]);
        let w11 = self.sse2._mm_set1_pd(w[1]);
        cast(avx._mm256_insertf128_pd::<0b1>(avx._mm256_castpd128_pd256(w00), w11))
    }

    #[inline(always)]
    fn interleave1_f64x4(self, z0z1: [f64x4; 2]) -> [f64x4; 2] {
        let avx = self.avx;
        [
            cast(avx._mm256_unpacklo_pd(cast(z0z1[0]), cast(z0z1[1]))),
            cast(avx._mm256_unpackhi_pd(cast(z0z1[0]), cast(z0z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute1_f64x4(self, w: [f64; 4]) -> f64x4 {
        let avx = self.avx;
        let w0123 = pulp::cast(w);
        let w0101 = avx._mm256_permute2f128_pd::<0b0000_0000>(w0123, w0123);
        let w2323 = avx._mm256_permute2f128_pd::<0b0011_0011>(w0123, w0123);
        cast(avx._mm256_shuffle_pd::<0b1100>(w0101, w2323))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl V4InterleaveExt for V4 {
    #[inline(always)]
    fn interleave4_f64x8(self, z0z0z0z0z1z1z1z1: [f64x8; 2]) -> [f64x8; 2] {
        let avx = self.avx512f;
        let idx_0 = avx._mm512_setr_epi64(0x0, 0x1, 0x2, 0x3, 0x8, 0x9, 0xa, 0xb);
        let idx_1 = avx._mm512_setr_epi64(0x4, 0x5, 0x6, 0x7, 0xc, 0xd, 0xe, 0xf);
        [
            cast(avx._mm512_permutex2var_pd(
                cast(z0z0z0z0z1z1z1z1[0]),
                idx_0,
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
            cast(avx._mm512_permutex2var_pd(
                cast(z0z0z0z0z1z1z1z1[0]),
                idx_1,
                cast(z0z0z0z0z1z1z1z1[1]),
            )),
        ]
    }

    #[inline(always)]
    fn permute4_f64x8(self, w: [f64; 2]) -> f64x8 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let w01xxxxxx = avx._mm512_castpd128_pd512(w);
        let idx = avx._mm512_setr_epi64(0, 0, 0, 0, 1, 1, 1, 1);
        cast(avx._mm512_permutexvar_pd(idx, w01xxxxxx))
    }

    #[inline(always)]
    fn interleave2_f64x8(self, z0z0z1z1: [f64x8; 2]) -> [f64x8; 2] {
        let avx = self.avx512f;
        let idx_0 = avx._mm512_setr_epi64(0x0, 0x1, 0x8, 0x9, 0x4, 0x5, 0xc, 0xd);
        let idx_1 = avx._mm512_setr_epi64(0x2, 0x3, 0xa, 0xb, 0x6, 0x7, 0xe, 0xf);
        [
            cast(avx._mm512_permutex2var_pd(cast(z0z0z1z1[0]), idx_0, cast(z0z0z1z1[1]))),
            cast(avx._mm512_permutex2var_pd(cast(z0z0z1z1[0]), idx_1, cast(z0z0z1z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute2_f64x8(self, w: [f64; 4]) -> f64x8 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let w0123xxxx = avx._mm512_castpd256_pd512(w);
        let idx = avx._mm512_setr_epi64(0, 0, 2, 2, 1, 1, 3, 3);
        cast(avx._mm512_permutexvar_pd(idx, w0123xxxx))
    }

    #[inline(always)]
    fn interleave1_f64x8(self, z0z1: [f64x8; 2]) -> [f64x8; 2] {
        let avx = self.avx512f;
        [
            cast(avx._mm512_unpacklo_pd(cast(z0z1[0]), cast(z0z1[1]))),
            cast(avx._mm512_unpackhi_pd(cast(z0z1[0]), cast(z0z1[1]))),
        ]
    }

    #[inline(always)]
    fn permute1_f64x8(self, w: [f64; 8]) -> f64x8 {
        let avx = self.avx512f;
        let w = pulp::cast(w);
        let idx = avx._mm512_setr_epi64(0, 4, 1, 5, 2, 6, 3, 7);
        cast(avx._mm512_permutexvar_pd(idx, w))
    }
}

#[derive(Copy, Clone)]
struct Scalar;

impl FftSimdF128 for Scalar {
    type Reg = f64;

    #[inline(always)]
    fn splat(self, value: f64) -> Self::Reg {
        value
    }

    #[inline(always)]
    fn add(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let f128(o0, o1) = f128::add_estimate_f128_f128(f128(a.0, a.1), f128(b.0, b.1));
        (o0, o1)
    }

    #[inline(always)]
    fn sub(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let f128(o0, o1) = f128::sub_estimate_f128_f128(f128(a.0, a.1), f128(b.0, b.1));
        (o0, o1)
    }

    #[inline(always)]
    fn mul(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let f128(o0, o1) = f128(a.0, a.1) * f128(b.0, b.1);
        (o0, o1)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl FftSimdF128 for V3 {
    type Reg = f64x4;

    #[inline(always)]
    fn splat(self, value: f64) -> Self::Reg {
        cast(self.avx._mm256_set1_pd(value))
    }

    #[inline(always)]
    fn add(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self.add_estimate_f128x4(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }

    #[inline(always)]
    fn sub(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self.sub_estimate_f128x4(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }

    #[inline(always)]
    fn mul(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self.mul_f128x4(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl FftSimdF128 for V4 {
    type Reg = f64x8;

    #[inline(always)]
    fn splat(self, value: f64) -> Self::Reg {
        cast(self.avx512f._mm512_set1_pd(value))
    }

    #[inline(always)]
    fn add(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self.add_estimate_f128x8(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }

    #[inline(always)]
    fn sub(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self.sub_estimate_f128x8(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }

    #[inline(always)]
    fn mul(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self.mul_f128x8(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[derive(Copy, Clone, Debug)]
pub struct V4x2(pub V4);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
impl FftSimdF128 for V4x2 {
    type Reg = f64x16;

    #[inline(always)]
    fn splat(self, value: f64) -> Self::Reg {
        cast(self.0.splat_f64x16(value))
    }

    #[inline(always)]
    fn add(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self
            .0
            .add_estimate_f128x16(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }

    #[inline(always)]
    fn sub(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self
            .0
            .sub_estimate_f128x16(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }

    #[inline(always)]
    fn mul(self, a: (Self::Reg, Self::Reg), b: (Self::Reg, Self::Reg)) -> (Self::Reg, Self::Reg) {
        let result = self
            .0
            .mul_f128x16(cast(a.0), cast(a.1), cast(b.0), cast(b.1));
        (cast(result.0), cast(result.1))
    }
}
trait FftSimdF128Ext: FftSimdF128 {
    #[inline(always)]
    fn cplx_add(
        self,
        a_re: (Self::Reg, Self::Reg),
        a_im: (Self::Reg, Self::Reg),
        b_re: (Self::Reg, Self::Reg),
        b_im: (Self::Reg, Self::Reg),
    ) -> ((Self::Reg, Self::Reg), (Self::Reg, Self::Reg)) {
        (self.add(a_re, b_re), self.add(a_im, b_im))
    }

    #[inline(always)]
    fn cplx_sub(
        self,
        a_re: (Self::Reg, Self::Reg),
        a_im: (Self::Reg, Self::Reg),
        b_re: (Self::Reg, Self::Reg),
        b_im: (Self::Reg, Self::Reg),
    ) -> ((Self::Reg, Self::Reg), (Self::Reg, Self::Reg)) {
        (self.sub(a_re, b_re), self.sub(a_im, b_im))
    }

    /// `a * b`
    #[inline(always)]
    fn cplx_mul(
        self,
        a_re: (Self::Reg, Self::Reg),
        a_im: (Self::Reg, Self::Reg),
        b_re: (Self::Reg, Self::Reg),
        b_im: (Self::Reg, Self::Reg),
    ) -> ((Self::Reg, Self::Reg), (Self::Reg, Self::Reg)) {
        let a_re_x_b_re = self.mul(a_re, b_re);
        let a_re_x_b_im = self.mul(a_re, b_im);
        let a_im_x_b_re = self.mul(a_im, b_re);
        let a_im_x_b_im = self.mul(a_im, b_im);

        (
            self.sub(a_re_x_b_re, a_im_x_b_im),
            self.add(a_im_x_b_re, a_re_x_b_im),
        )
    }

    /// `a * conj(b)`
    #[inline(always)]
    fn cplx_mul_conj(
        self,
        a_re: (Self::Reg, Self::Reg),
        a_im: (Self::Reg, Self::Reg),
        b_re: (Self::Reg, Self::Reg),
        b_im: (Self::Reg, Self::Reg),
    ) -> ((Self::Reg, Self::Reg), (Self::Reg, Self::Reg)) {
        let a_re_x_b_re = self.mul(a_re, b_re);
        let a_re_x_b_im = self.mul(a_re, b_im);
        let a_im_x_b_re = self.mul(a_im, b_re);
        let a_im_x_b_im = self.mul(a_im, b_im);

        (
            self.add(a_re_x_b_re, a_im_x_b_im),
            self.sub(a_im_x_b_re, a_re_x_b_im),
        )
    }
}

impl<T: FftSimdF128> FftSimdF128Ext for T {}

#[doc(hidden)]
pub fn negacyclic_fwd_fft_scalar(
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    let n = data_re0.len();
    let mut t = n;
    let mut m = 1;
    let simd = Scalar;

    while m < n {
        t /= 2;

        for i in 0..m {
            let w1_re = (twid_re0[m + i], twid_re1[m + i]);
            let w1_im = (twid_im0[m + i], twid_im1[m + i]);

            let start = 2 * i * t;

            let data_re0 = &mut data_re0[start..][..2 * t];
            let data_re1 = &mut data_re1[start..][..2 * t];
            let data_im0 = &mut data_im0[start..][..2 * t];
            let data_im1 = &mut data_im1[start..][..2 * t];

            let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
            let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
            let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
            let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

            for (z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1) in
                izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1)
            {
                let (z0_re, z0_im) = ((*z0_re0, *z0_re1), (*z0_im0, *z0_im1));
                let (z1_re, z1_im) = ((*z1_re0, *z1_re1), (*z1_im0, *z1_im1));
                let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                ((*z0_re0, *z0_re1), (*z0_im0, *z0_im1)) =
                    simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                ((*z1_re0, *z1_re1), (*z1_im0, *z1_im1)) =
                    simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);
            }
        }

        m *= 2;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[doc(hidden)]
pub fn negacyclic_fwd_fft_avxfma(
    simd: V3,
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    struct Impl<'a> {
        simd: V3,
        data_re0: &'a mut [f64],
        data_re1: &'a mut [f64],
        data_im0: &'a mut [f64],
        data_im1: &'a mut [f64],
        twid_re0: &'a [f64],
        twid_re1: &'a [f64],
        twid_im0: &'a [f64],
        twid_im1: &'a [f64],
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                twid_re0,
                twid_re1,
                twid_im0,
                twid_im1,
            } = self;
            let n = data_re0.len();
            assert!(n >= 32);
            {
                let mut t = n;
                let mut m = 1;

                while m < n / 4 {
                    t /= 2;

                    let twid_re0 = &twid_re0[m..];
                    let twid_re1 = &twid_re1[m..];
                    let twid_im0 = &twid_im0[m..];
                    let twid_im1 = &twid_im1[m..];

                    let iter = izip!(
                        data_re0.chunks_mut(2 * t),
                        data_re1.chunks_mut(2 * t),
                        data_im0.chunks_mut(2 * t),
                        data_im1.chunks_mut(2 * t),
                        twid_re0,
                        twid_re1,
                        twid_im0,
                        twid_im1,
                    );
                    for (data_re0, data_re1, data_im0, data_im1, w1_re0, w1_re1, w1_im0, w1_im1) in
                        iter
                    {
                        let w1_re = (*w1_re0, *w1_re1);
                        let w1_im = (*w1_im0, *w1_im1);

                        let w1_re = (simd.splat(w1_re.0), simd.splat(w1_re.1));
                        let w1_im = (simd.splat(w1_im.0), simd.splat(w1_im.1));

                        let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
                        let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
                        let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
                        let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

                        let z0_re0 = as_arrays_mut::<4, _>(z0_re0).0;
                        let z0_re1 = as_arrays_mut::<4, _>(z0_re1).0;
                        let z0_im0 = as_arrays_mut::<4, _>(z0_im0).0;
                        let z0_im1 = as_arrays_mut::<4, _>(z0_im1).0;
                        let z1_re0 = as_arrays_mut::<4, _>(z1_re0).0;
                        let z1_re1 = as_arrays_mut::<4, _>(z1_re1).0;
                        let z1_im0 = as_arrays_mut::<4, _>(z1_im0).0;
                        let z1_im1 = as_arrays_mut::<4, _>(z1_im1).0;

                        let iter =
                            izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1);
                        for (
                            z0_re0_,
                            z0_re1_,
                            z0_im0_,
                            z0_im1_,
                            z1_re0_,
                            z1_re1_,
                            z1_im0_,
                            z1_im1_,
                        ) in iter
                        {
                            let mut z0_re0 = cast(*z0_re0_);
                            let mut z0_re1 = cast(*z0_re1_);
                            let mut z0_im0 = cast(*z0_im0_);
                            let mut z0_im1 = cast(*z0_im1_);
                            let mut z1_re0 = cast(*z1_re0_);
                            let mut z1_re1 = cast(*z1_re1_);
                            let mut z1_im0 = cast(*z1_im0_);
                            let mut z1_im1 = cast(*z1_im1_);

                            let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                            let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                            let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                            ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                                simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                            ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                                simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                            *z0_re0_ = cast(z0_re0);
                            *z0_re1_ = cast(z0_re1);
                            *z0_im0_ = cast(z0_im0);
                            *z0_im1_ = cast(z0_im1);
                            *z1_re0_ = cast(z1_re0);
                            *z1_re1_ = cast(z1_re1);
                            *z1_im0_ = cast(z1_im0);
                            *z1_im1_ = cast(z1_im1);
                        }
                    }

                    m *= 2;
                }
            }

            // m = n / 4
            // t = 2
            {
                let m = n / 4;

                let twid_re0 = as_arrays::<2, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<2, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<2, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<2, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<4, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<4, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<4, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<4, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (
                    z0z0z1z1_re0,
                    z0z0z1z1_re1,
                    z0z0z1z1_im0,
                    z0z0z1z1_im1,
                    w1_re0,
                    w1_re1,
                    w1_im0,
                    w1_im1,
                ) in iter
                {
                    // 0 1 2 3 | 4 5 6 7 -> 0 1 4 5 | 2 3 6 7
                    //
                    // is its own inverse since:
                    // 0 1 4 5 | 2 3 6 7 -> 0 1 2 3 | 4 5 6 7
                    let w1_re = (simd.permute2_f64x4(*w1_re0), simd.permute2_f64x4(*w1_re1));
                    let w1_im = (simd.permute2_f64x4(*w1_im0), simd.permute2_f64x4(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave2_f64x4(cast(*z0z0z1z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave2_f64x4(cast(*z0z0z1z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave2_f64x4(cast(*z0z0z1z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave2_f64x4(cast(*z0z0z1z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                    *z0z0z1z1_re0 = cast(simd.interleave2_f64x4([z0_re0, z1_re0]));
                    *z0z0z1z1_re1 = cast(simd.interleave2_f64x4([z0_re1, z1_re1]));
                    *z0z0z1z1_im0 = cast(simd.interleave2_f64x4([z0_im0, z1_im0]));
                    *z0z0z1z1_im1 = cast(simd.interleave2_f64x4([z0_im1, z1_im1]));
                }
            }

            // m = n / 2
            // t = 1
            {
                let m = n / 2;

                let twid_re0 = as_arrays::<4, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<4, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<4, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<4, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<4, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<4, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<4, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<4, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (z0z1_re0, z0z1_re1, z0z1_im0, z0z1_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (simd.permute1_f64x4(*w1_re0), simd.permute1_f64x4(*w1_re1));
                    let w1_im = (simd.permute1_f64x4(*w1_im0), simd.permute1_f64x4(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave1_f64x4(cast(*z0z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave1_f64x4(cast(*z0z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave1_f64x4(cast(*z0z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave1_f64x4(cast(*z0z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                    *z0z1_re0 = cast(simd.interleave1_f64x4([z0_re0, z1_re0]));
                    *z0z1_re1 = cast(simd.interleave1_f64x4([z0_re1, z1_re1]));
                    *z0z1_im0 = cast(simd.interleave1_f64x4([z0_im0, z1_im0]));
                    *z0z1_im1 = cast(simd.interleave1_f64x4([z0_im1, z1_im1]));
                }
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data_re0,
        data_re1,
        data_im0,
        data_im1,
        twid_re0,
        twid_re1,
        twid_im0,
        twid_im1,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[doc(hidden)]
pub fn negacyclic_fwd_fft_avx512(
    simd: V4,
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    struct Impl<'a> {
        simd: V4,
        data_re0: &'a mut [f64],
        data_re1: &'a mut [f64],
        data_im0: &'a mut [f64],
        data_im1: &'a mut [f64],
        twid_re0: &'a [f64],
        twid_re1: &'a [f64],
        twid_im0: &'a [f64],
        twid_im1: &'a [f64],
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                twid_re0,
                twid_re1,
                twid_im0,
                twid_im1,
            } = self;

            let n = data_re0.len();
            assert!(n >= 32);
            {
                let mut t = n;
                let mut m = 1;

                while m < n / 16 {
                    t /= 2;

                    let twid_re0 = &twid_re0[m..];
                    let twid_re1 = &twid_re1[m..];
                    let twid_im0 = &twid_im0[m..];
                    let twid_im1 = &twid_im1[m..];

                    let iter = izip!(
                        data_re0.chunks_mut(2 * t),
                        data_re1.chunks_mut(2 * t),
                        data_im0.chunks_mut(2 * t),
                        data_im1.chunks_mut(2 * t),
                        twid_re0,
                        twid_re1,
                        twid_im0,
                        twid_im1,
                    );
                    for (data_re0, data_re1, data_im0, data_im1, w1_re0, w1_re1, w1_im0, w1_im1) in
                        iter
                    {
                        let simd = V4x2(simd);

                        let w1_re = (*w1_re0, *w1_re1);
                        let w1_im = (*w1_im0, *w1_im1);

                        let w1_re = (simd.splat(w1_re.0), simd.splat(w1_re.1));
                        let w1_im = (simd.splat(w1_im.0), simd.splat(w1_im.1));

                        let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
                        let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
                        let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
                        let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

                        let z0_re0 = as_arrays_mut::<16, _>(z0_re0).0;
                        let z0_re1 = as_arrays_mut::<16, _>(z0_re1).0;
                        let z0_im0 = as_arrays_mut::<16, _>(z0_im0).0;
                        let z0_im1 = as_arrays_mut::<16, _>(z0_im1).0;
                        let z1_re0 = as_arrays_mut::<16, _>(z1_re0).0;
                        let z1_re1 = as_arrays_mut::<16, _>(z1_re1).0;
                        let z1_im0 = as_arrays_mut::<16, _>(z1_im0).0;
                        let z1_im1 = as_arrays_mut::<16, _>(z1_im1).0;

                        let iter =
                            izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1);
                        for (
                            z0_re0_,
                            z0_re1_,
                            z0_im0_,
                            z0_im1_,
                            z1_re0_,
                            z1_re1_,
                            z1_im0_,
                            z1_im1_,
                        ) in iter
                        {
                            let mut z0_re0: f64x16 = cast(*z0_re0_);
                            let mut z0_re1: f64x16 = cast(*z0_re1_);
                            let mut z0_im0: f64x16 = cast(*z0_im0_);
                            let mut z0_im1: f64x16 = cast(*z0_im1_);
                            let mut z1_re0: f64x16 = cast(*z1_re0_);
                            let mut z1_re1: f64x16 = cast(*z1_re1_);
                            let mut z1_im0: f64x16 = cast(*z1_im0_);
                            let mut z1_im1: f64x16 = cast(*z1_im1_);

                            let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                            let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                            let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                            ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                                simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                            ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                                simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                            *z0_re0_ = cast(z0_re0);
                            *z0_re1_ = cast(z0_re1);
                            *z0_im0_ = cast(z0_im0);
                            *z0_im1_ = cast(z0_im1);
                            *z1_re0_ = cast(z1_re0);
                            *z1_re1_ = cast(z1_re1);
                            *z1_im0_ = cast(z1_im0);
                            *z1_im1_ = cast(z1_im1);
                        }
                    }

                    m *= 2;
                }
            }

            {
                let m = n / 16;
                let t = 8;

                let twid_re0 = &twid_re0[m..];
                let twid_re1 = &twid_re1[m..];
                let twid_im0 = &twid_im0[m..];
                let twid_im1 = &twid_im1[m..];

                let iter = izip!(
                    data_re0.chunks_mut(2 * t),
                    data_re1.chunks_mut(2 * t),
                    data_im0.chunks_mut(2 * t),
                    data_im1.chunks_mut(2 * t),
                    twid_re0,
                    twid_re1,
                    twid_im0,
                    twid_im1,
                );
                for (data_re0, data_re1, data_im0, data_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (*w1_re0, *w1_re1);
                    let w1_im = (*w1_im0, *w1_im1);

                    let w1_re = (simd.splat(w1_re.0), simd.splat(w1_re.1));
                    let w1_im = (simd.splat(w1_im.0), simd.splat(w1_im.1));

                    let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
                    let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
                    let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
                    let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

                    let z0_re0 = as_arrays_mut::<8, _>(z0_re0).0;
                    let z0_re1 = as_arrays_mut::<8, _>(z0_re1).0;
                    let z0_im0 = as_arrays_mut::<8, _>(z0_im0).0;
                    let z0_im1 = as_arrays_mut::<8, _>(z0_im1).0;
                    let z1_re0 = as_arrays_mut::<8, _>(z1_re0).0;
                    let z1_re1 = as_arrays_mut::<8, _>(z1_re1).0;
                    let z1_im0 = as_arrays_mut::<8, _>(z1_im0).0;
                    let z1_im1 = as_arrays_mut::<8, _>(z1_im1).0;

                    let iter =
                        izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1);
                    for (z0_re0_, z0_re1_, z0_im0_, z0_im1_, z1_re0_, z1_re1_, z1_im0_, z1_im1_) in
                        iter
                    {
                        let mut z0_re0 = cast(*z0_re0_);
                        let mut z0_re1 = cast(*z0_re1_);
                        let mut z0_im0 = cast(*z0_im0_);
                        let mut z0_im1 = cast(*z0_im1_);
                        let mut z1_re0 = cast(*z1_re0_);
                        let mut z1_re1 = cast(*z1_re1_);
                        let mut z1_im0 = cast(*z1_im0_);
                        let mut z1_im1 = cast(*z1_im1_);

                        let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                        let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                        let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                        ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                            simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                        ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                            simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                        *z0_re0_ = cast(z0_re0);
                        *z0_re1_ = cast(z0_re1);
                        *z0_im0_ = cast(z0_im0);
                        *z0_im1_ = cast(z0_im1);
                        *z1_re0_ = cast(z1_re0);
                        *z1_re1_ = cast(z1_re1);
                        *z1_im0_ = cast(z1_im0);
                        *z1_im1_ = cast(z1_im1);
                    }
                }
            }

            // m = n / 8
            // t = 4
            {
                let m = n / 8;

                let twid_re0 = as_arrays::<2, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<2, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<2, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<2, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<8, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<8, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<8, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<8, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (z0z1_re0, z0z1_re1, z0z1_im0, z0z1_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (simd.permute4_f64x8(*w1_re0), simd.permute4_f64x8(*w1_re1));
                    let w1_im = (simd.permute4_f64x8(*w1_im0), simd.permute4_f64x8(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave4_f64x8(cast(*z0z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave4_f64x8(cast(*z0z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave4_f64x8(cast(*z0z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave4_f64x8(cast(*z0z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                    *z0z1_re0 = cast(simd.interleave4_f64x8([z0_re0, z1_re0]));
                    *z0z1_re1 = cast(simd.interleave4_f64x8([z0_re1, z1_re1]));
                    *z0z1_im0 = cast(simd.interleave4_f64x8([z0_im0, z1_im0]));
                    *z0z1_im1 = cast(simd.interleave4_f64x8([z0_im1, z1_im1]));
                }
            }

            // m = n / 4
            // t = 2
            {
                let m = n / 4;

                let twid_re0 = as_arrays::<4, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<4, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<4, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<4, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<8, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<8, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<8, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<8, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (z0z1_re0, z0z1_re1, z0z1_im0, z0z1_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (simd.permute2_f64x8(*w1_re0), simd.permute2_f64x8(*w1_re1));
                    let w1_im = (simd.permute2_f64x8(*w1_im0), simd.permute2_f64x8(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave2_f64x8(cast(*z0z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave2_f64x8(cast(*z0z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave2_f64x8(cast(*z0z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave2_f64x8(cast(*z0z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                    *z0z1_re0 = cast(simd.interleave2_f64x8([z0_re0, z1_re0]));
                    *z0z1_re1 = cast(simd.interleave2_f64x8([z0_re1, z1_re1]));
                    *z0z1_im0 = cast(simd.interleave2_f64x8([z0_im0, z1_im0]));
                    *z0z1_im1 = cast(simd.interleave2_f64x8([z0_im1, z1_im1]));
                }
            }

            // m = n / 2
            // t = 1
            {
                let m = n / 2;

                let twid_re0 = as_arrays::<8, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<8, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<8, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<8, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<8, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<8, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<8, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<8, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (z0z1_re0, z0z1_re1, z0z1_im0, z0z1_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (simd.permute1_f64x8(*w1_re0), simd.permute1_f64x8(*w1_re1));
                    let w1_im = (simd.permute1_f64x8(*w1_im0), simd.permute1_f64x8(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave1_f64x8(cast(*z0z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave1_f64x8(cast(*z0z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave1_f64x8(cast(*z0z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave1_f64x8(cast(*z0z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z1w_re, z1w_im) = simd.cplx_mul(z1_re, z1_im, w1_re, w1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1w_re, z1w_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_sub(z0_re, z0_im, z1w_re, z1w_im);

                    *z0z1_re0 = cast(simd.interleave1_f64x8([z0_re0, z1_re0]));
                    *z0z1_re1 = cast(simd.interleave1_f64x8([z0_re1, z1_re1]));
                    *z0z1_im0 = cast(simd.interleave1_f64x8([z0_im0, z1_im0]));
                    *z0z1_im1 = cast(simd.interleave1_f64x8([z0_im1, z1_im1]));
                }
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data_re0,
        data_re1,
        data_im0,
        data_im1,
        twid_re0,
        twid_re1,
        twid_im0,
        twid_im1,
    });
}

#[doc(hidden)]
pub fn negacyclic_fwd_fft(
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "nightly")]
        if let Some(simd) = V4::try_new() {
            return negacyclic_fwd_fft_avx512(
                simd, data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0,
                twid_im1,
            );
        }
        if let Some(simd) = V3::try_new() {
            return negacyclic_fwd_fft_avxfma(
                simd, data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0,
                twid_im1,
            );
        }
    }
    negacyclic_fwd_fft_scalar(
        data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1,
    )
}

#[doc(hidden)]
pub fn negacyclic_inv_fft(
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "nightly")]
        if let Some(simd) = V4::try_new() {
            return negacyclic_inv_fft_avx512(
                simd, data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0,
                twid_im1,
            );
        }
        if let Some(simd) = V3::try_new() {
            return negacyclic_inv_fft_avxfma(
                simd, data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0,
                twid_im1,
            );
        }
    }
    negacyclic_inv_fft_scalar(
        data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1,
    )
}

#[doc(hidden)]
pub fn negacyclic_inv_fft_scalar(
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    let n = data_re0.len();
    let mut t = 1;
    let mut m = n;
    let simd = Scalar;

    while m > 1 {
        m /= 2;

        for i in 0..m {
            let w1_re = (twid_re0[m + i], twid_re1[m + i]);
            let w1_im = (twid_im0[m + i], twid_im1[m + i]);

            let start = 2 * i * t;

            let data_re0 = &mut data_re0[start..][..2 * t];
            let data_re1 = &mut data_re1[start..][..2 * t];
            let data_im0 = &mut data_im0[start..][..2 * t];
            let data_im1 = &mut data_im1[start..][..2 * t];

            let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
            let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
            let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
            let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

            for (z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1) in
                izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1)
            {
                let (z0_re, z0_im) = ((*z0_re0, *z0_re1), (*z0_im0, *z0_im1));
                let (z1_re, z1_im) = ((*z1_re0, *z1_re1), (*z1_im0, *z1_im1));
                let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                ((*z0_re0, *z0_re1), (*z0_im0, *z0_im1)) =
                    simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                ((*z1_re0, *z1_re1), (*z1_im0, *z1_im1)) =
                    simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);
            }
        }

        t *= 2;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[doc(hidden)]
pub fn negacyclic_inv_fft_avxfma(
    simd: V3,
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    struct Impl<'a> {
        simd: V3,
        data_re0: &'a mut [f64],
        data_re1: &'a mut [f64],
        data_im0: &'a mut [f64],
        data_im1: &'a mut [f64],
        twid_re0: &'a [f64],
        twid_re1: &'a [f64],
        twid_im0: &'a [f64],
        twid_im1: &'a [f64],
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                twid_re0,
                twid_re1,
                twid_im0,
                twid_im1,
            } = self;
            let n = data_re0.len();
            assert!(n >= 32);
            let mut t = 1;
            let mut m = n;

            // m = n / 2
            // t = 1
            {
                m /= 2;

                let twid_re0 = as_arrays::<4, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<4, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<4, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<4, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<4, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<4, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<4, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<4, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (z0z1_re0, z0z1_re1, z0z1_im0, z0z1_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (simd.permute1_f64x4(*w1_re0), simd.permute1_f64x4(*w1_re1));
                    let w1_im = (simd.permute1_f64x4(*w1_im0), simd.permute1_f64x4(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave1_f64x4(cast(*z0z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave1_f64x4(cast(*z0z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave1_f64x4(cast(*z0z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave1_f64x4(cast(*z0z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                    *z0z1_re0 = cast(simd.interleave1_f64x4([z0_re0, z1_re0]));
                    *z0z1_re1 = cast(simd.interleave1_f64x4([z0_re1, z1_re1]));
                    *z0z1_im0 = cast(simd.interleave1_f64x4([z0_im0, z1_im0]));
                    *z0z1_im1 = cast(simd.interleave1_f64x4([z0_im1, z1_im1]));
                }

                t *= 2;
            }

            // m = n / 4
            // t = 2
            {
                m /= 2;

                let twid_re0 = as_arrays::<2, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<2, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<2, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<2, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<4, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<4, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<4, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<4, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (
                    z0z0z1z1_re0,
                    z0z0z1z1_re1,
                    z0z0z1z1_im0,
                    z0z0z1z1_im1,
                    w1_re0,
                    w1_re1,
                    w1_im0,
                    w1_im1,
                ) in iter
                {
                    let w1_re = (simd.permute2_f64x4(*w1_re0), simd.permute2_f64x4(*w1_re1));
                    let w1_im = (simd.permute2_f64x4(*w1_im0), simd.permute2_f64x4(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave2_f64x4(cast(*z0z0z1z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave2_f64x4(cast(*z0z0z1z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave2_f64x4(cast(*z0z0z1z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave2_f64x4(cast(*z0z0z1z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                    *z0z0z1z1_re0 = cast(simd.interleave2_f64x4([z0_re0, z1_re0]));
                    *z0z0z1z1_re1 = cast(simd.interleave2_f64x4([z0_re1, z1_re1]));
                    *z0z0z1z1_im0 = cast(simd.interleave2_f64x4([z0_im0, z1_im0]));
                    *z0z0z1z1_im1 = cast(simd.interleave2_f64x4([z0_im1, z1_im1]));
                }

                t *= 2;
            }

            while m > 1 {
                m /= 2;

                let twid_re0 = &twid_re0[m..];
                let twid_re1 = &twid_re1[m..];
                let twid_im0 = &twid_im0[m..];
                let twid_im1 = &twid_im1[m..];

                let iter = izip!(
                    data_re0.chunks_mut(2 * t),
                    data_re1.chunks_mut(2 * t),
                    data_im0.chunks_mut(2 * t),
                    data_im1.chunks_mut(2 * t),
                    twid_re0,
                    twid_re1,
                    twid_im0,
                    twid_im1,
                );
                for (data_re0, data_re1, data_im0, data_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (*w1_re0, *w1_re1);
                    let w1_im = (*w1_im0, *w1_im1);

                    let w1_re = (simd.splat(w1_re.0), simd.splat(w1_re.1));
                    let w1_im = (simd.splat(w1_im.0), simd.splat(w1_im.1));

                    let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
                    let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
                    let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
                    let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

                    let z0_re0 = as_arrays_mut::<4, _>(z0_re0).0;
                    let z0_re1 = as_arrays_mut::<4, _>(z0_re1).0;
                    let z0_im0 = as_arrays_mut::<4, _>(z0_im0).0;
                    let z0_im1 = as_arrays_mut::<4, _>(z0_im1).0;
                    let z1_re0 = as_arrays_mut::<4, _>(z1_re0).0;
                    let z1_re1 = as_arrays_mut::<4, _>(z1_re1).0;
                    let z1_im0 = as_arrays_mut::<4, _>(z1_im0).0;
                    let z1_im1 = as_arrays_mut::<4, _>(z1_im1).0;

                    let iter =
                        izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1);
                    for (z0_re0_, z0_re1_, z0_im0_, z0_im1_, z1_re0_, z1_re1_, z1_im0_, z1_im1_) in
                        iter
                    {
                        let mut z0_re0 = cast(*z0_re0_);
                        let mut z0_re1 = cast(*z0_re1_);
                        let mut z0_im0 = cast(*z0_im0_);
                        let mut z0_im1 = cast(*z0_im1_);
                        let mut z1_re0 = cast(*z1_re0_);
                        let mut z1_re1 = cast(*z1_re1_);
                        let mut z1_im0 = cast(*z1_im0_);
                        let mut z1_im1 = cast(*z1_im1_);

                        let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                        let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                        let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                        ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                            simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                        ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                            simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                        *z0_re0_ = cast(z0_re0);
                        *z0_re1_ = cast(z0_re1);
                        *z0_im0_ = cast(z0_im0);
                        *z0_im1_ = cast(z0_im1);
                        *z1_re0_ = cast(z1_re0);
                        *z1_re1_ = cast(z1_re1);
                        *z1_im0_ = cast(z1_im0);
                        *z1_im1_ = cast(z1_im1);
                    }
                }

                t *= 2;
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data_re0,
        data_re1,
        data_im0,
        data_im1,
        twid_re0,
        twid_re1,
        twid_im0,
        twid_im1,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly")]
#[doc(hidden)]
pub fn negacyclic_inv_fft_avx512(
    simd: V4,
    data_re0: &mut [f64],
    data_re1: &mut [f64],
    data_im0: &mut [f64],
    data_im1: &mut [f64],
    twid_re0: &[f64],
    twid_re1: &[f64],
    twid_im0: &[f64],
    twid_im1: &[f64],
) {
    struct Impl<'a> {
        simd: V4,
        data_re0: &'a mut [f64],
        data_re1: &'a mut [f64],
        data_im0: &'a mut [f64],
        data_im1: &'a mut [f64],
        twid_re0: &'a [f64],
        twid_re1: &'a [f64],
        twid_im0: &'a [f64],
        twid_im1: &'a [f64],
    }

    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self {
                simd,
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                twid_re0,
                twid_re1,
                twid_im0,
                twid_im1,
            } = self;

            let n = data_re0.len();
            assert!(n >= 32);
            let mut t = 1;
            let mut m = n;

            // m = n / 2
            // t = 1
            {
                m /= 2;

                let twid_re0 = as_arrays::<8, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<8, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<8, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<8, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<8, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<8, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<8, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<8, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (z0z1_re0, z0z1_re1, z0z1_im0, z0z1_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (simd.permute1_f64x8(*w1_re0), simd.permute1_f64x8(*w1_re1));
                    let w1_im = (simd.permute1_f64x8(*w1_im0), simd.permute1_f64x8(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave1_f64x8(cast(*z0z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave1_f64x8(cast(*z0z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave1_f64x8(cast(*z0z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave1_f64x8(cast(*z0z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                    *z0z1_re0 = cast(simd.interleave1_f64x8([z0_re0, z1_re0]));
                    *z0z1_re1 = cast(simd.interleave1_f64x8([z0_re1, z1_re1]));
                    *z0z1_im0 = cast(simd.interleave1_f64x8([z0_im0, z1_im0]));
                    *z0z1_im1 = cast(simd.interleave1_f64x8([z0_im1, z1_im1]));
                }

                t *= 2;
            }

            // m = n / 4
            // t = 2
            {
                m /= 2;

                let twid_re0 = as_arrays::<4, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<4, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<4, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<4, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<8, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<8, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<8, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<8, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (
                    z0z0z1z1_re0,
                    z0z0z1z1_re1,
                    z0z0z1z1_im0,
                    z0z0z1z1_im1,
                    w1_re0,
                    w1_re1,
                    w1_im0,
                    w1_im1,
                ) in iter
                {
                    let w1_re = (simd.permute2_f64x8(*w1_re0), simd.permute2_f64x8(*w1_re1));
                    let w1_im = (simd.permute2_f64x8(*w1_im0), simd.permute2_f64x8(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave2_f64x8(cast(*z0z0z1z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave2_f64x8(cast(*z0z0z1z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave2_f64x8(cast(*z0z0z1z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave2_f64x8(cast(*z0z0z1z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                    *z0z0z1z1_re0 = cast(simd.interleave2_f64x8([z0_re0, z1_re0]));
                    *z0z0z1z1_re1 = cast(simd.interleave2_f64x8([z0_re1, z1_re1]));
                    *z0z0z1z1_im0 = cast(simd.interleave2_f64x8([z0_im0, z1_im0]));
                    *z0z0z1z1_im1 = cast(simd.interleave2_f64x8([z0_im1, z1_im1]));
                }

                t *= 2;
            }

            // m = n / 8
            // t = 4
            {
                m /= 2;

                let twid_re0 = as_arrays::<2, _>(&twid_re0[m..]).0;
                let twid_re1 = as_arrays::<2, _>(&twid_re1[m..]).0;
                let twid_im0 = as_arrays::<2, _>(&twid_im0[m..]).0;
                let twid_im1 = as_arrays::<2, _>(&twid_im1[m..]).0;

                let data_re0 = as_arrays_mut::<8, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<8, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<8, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<8, _>(data_im1).0;

                let data_re0 = as_arrays_mut::<2, _>(data_re0).0;
                let data_re1 = as_arrays_mut::<2, _>(data_re1).0;
                let data_im0 = as_arrays_mut::<2, _>(data_im0).0;
                let data_im1 = as_arrays_mut::<2, _>(data_im1).0;

                let iter = izip!(
                    data_re0, data_re1, data_im0, data_im1, twid_re0, twid_re1, twid_im0, twid_im1
                );
                for (
                    z0z0z1z1_re0,
                    z0z0z1z1_re1,
                    z0z0z1z1_im0,
                    z0z0z1z1_im1,
                    w1_re0,
                    w1_re1,
                    w1_im0,
                    w1_im1,
                ) in iter
                {
                    let w1_re = (simd.permute4_f64x8(*w1_re0), simd.permute4_f64x8(*w1_re1));
                    let w1_im = (simd.permute4_f64x8(*w1_im0), simd.permute4_f64x8(*w1_im1));

                    let [mut z0_re0, mut z1_re0] = simd.interleave4_f64x8(cast(*z0z0z1z1_re0));
                    let [mut z0_re1, mut z1_re1] = simd.interleave4_f64x8(cast(*z0z0z1z1_re1));
                    let [mut z0_im0, mut z1_im0] = simd.interleave4_f64x8(cast(*z0z0z1z1_im0));
                    let [mut z0_im1, mut z1_im1] = simd.interleave4_f64x8(cast(*z0z0z1z1_im1));

                    let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                    let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                    let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                    ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                        simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                    ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                        simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                    *z0z0z1z1_re0 = cast(simd.interleave4_f64x8([z0_re0, z1_re0]));
                    *z0z0z1z1_re1 = cast(simd.interleave4_f64x8([z0_re1, z1_re1]));
                    *z0z0z1z1_im0 = cast(simd.interleave4_f64x8([z0_im0, z1_im0]));
                    *z0z0z1z1_im1 = cast(simd.interleave4_f64x8([z0_im1, z1_im1]));
                }

                t *= 2;
            }

            {
                m /= 2;

                let twid_re0 = &twid_re0[m..];
                let twid_re1 = &twid_re1[m..];
                let twid_im0 = &twid_im0[m..];
                let twid_im1 = &twid_im1[m..];

                let iter = izip!(
                    data_re0.chunks_mut(2 * t),
                    data_re1.chunks_mut(2 * t),
                    data_im0.chunks_mut(2 * t),
                    data_im1.chunks_mut(2 * t),
                    twid_re0,
                    twid_re1,
                    twid_im0,
                    twid_im1,
                );
                for (data_re0, data_re1, data_im0, data_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let w1_re = (*w1_re0, *w1_re1);
                    let w1_im = (*w1_im0, *w1_im1);

                    let w1_re = (simd.splat(w1_re.0), simd.splat(w1_re.1));
                    let w1_im = (simd.splat(w1_im.0), simd.splat(w1_im.1));

                    let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
                    let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
                    let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
                    let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

                    let z0_re0 = as_arrays_mut::<8, _>(z0_re0).0;
                    let z0_re1 = as_arrays_mut::<8, _>(z0_re1).0;
                    let z0_im0 = as_arrays_mut::<8, _>(z0_im0).0;
                    let z0_im1 = as_arrays_mut::<8, _>(z0_im1).0;
                    let z1_re0 = as_arrays_mut::<8, _>(z1_re0).0;
                    let z1_re1 = as_arrays_mut::<8, _>(z1_re1).0;
                    let z1_im0 = as_arrays_mut::<8, _>(z1_im0).0;
                    let z1_im1 = as_arrays_mut::<8, _>(z1_im1).0;

                    let iter =
                        izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1);
                    for (z0_re0_, z0_re1_, z0_im0_, z0_im1_, z1_re0_, z1_re1_, z1_im0_, z1_im1_) in
                        iter
                    {
                        let mut z0_re0 = cast(*z0_re0_);
                        let mut z0_re1 = cast(*z0_re1_);
                        let mut z0_im0 = cast(*z0_im0_);
                        let mut z0_im1 = cast(*z0_im1_);
                        let mut z1_re0 = cast(*z1_re0_);
                        let mut z1_re1 = cast(*z1_re1_);
                        let mut z1_im0 = cast(*z1_im0_);
                        let mut z1_im1 = cast(*z1_im1_);

                        let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                        let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                        let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                        ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                            simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                        ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                            simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                        *z0_re0_ = cast(z0_re0);
                        *z0_re1_ = cast(z0_re1);
                        *z0_im0_ = cast(z0_im0);
                        *z0_im1_ = cast(z0_im1);
                        *z1_re0_ = cast(z1_re0);
                        *z1_re1_ = cast(z1_re1);
                        *z1_im0_ = cast(z1_im0);
                        *z1_im1_ = cast(z1_im1);
                    }
                }
                t *= 2;
            }

            while m > 1 {
                m /= 2;

                let twid_re0 = &twid_re0[m..];
                let twid_re1 = &twid_re1[m..];
                let twid_im0 = &twid_im0[m..];
                let twid_im1 = &twid_im1[m..];

                let iter = izip!(
                    data_re0.chunks_mut(2 * t),
                    data_re1.chunks_mut(2 * t),
                    data_im0.chunks_mut(2 * t),
                    data_im1.chunks_mut(2 * t),
                    twid_re0,
                    twid_re1,
                    twid_im0,
                    twid_im1,
                );
                for (data_re0, data_re1, data_im0, data_im1, w1_re0, w1_re1, w1_im0, w1_im1) in iter
                {
                    let simd = V4x2(simd);
                    let w1_re = (*w1_re0, *w1_re1);
                    let w1_im = (*w1_im0, *w1_im1);

                    let w1_re = (simd.splat(w1_re.0), simd.splat(w1_re.1));
                    let w1_im = (simd.splat(w1_im.0), simd.splat(w1_im.1));

                    let (z0_re0, z1_re0) = data_re0.split_at_mut(t);
                    let (z0_re1, z1_re1) = data_re1.split_at_mut(t);
                    let (z0_im0, z1_im0) = data_im0.split_at_mut(t);
                    let (z0_im1, z1_im1) = data_im1.split_at_mut(t);

                    let z0_re0 = as_arrays_mut::<16, _>(z0_re0).0;
                    let z0_re1 = as_arrays_mut::<16, _>(z0_re1).0;
                    let z0_im0 = as_arrays_mut::<16, _>(z0_im0).0;
                    let z0_im1 = as_arrays_mut::<16, _>(z0_im1).0;
                    let z1_re0 = as_arrays_mut::<16, _>(z1_re0).0;
                    let z1_re1 = as_arrays_mut::<16, _>(z1_re1).0;
                    let z1_im0 = as_arrays_mut::<16, _>(z1_im0).0;
                    let z1_im1 = as_arrays_mut::<16, _>(z1_im1).0;

                    let iter =
                        izip!(z0_re0, z0_re1, z0_im0, z0_im1, z1_re0, z1_re1, z1_im0, z1_im1);
                    for (z0_re0_, z0_re1_, z0_im0_, z0_im1_, z1_re0_, z1_re1_, z1_im0_, z1_im1_) in
                        iter
                    {
                        let mut z0_re0 = cast(*z0_re0_);
                        let mut z0_re1 = cast(*z0_re1_);
                        let mut z0_im0 = cast(*z0_im0_);
                        let mut z0_im1 = cast(*z0_im1_);
                        let mut z1_re0 = cast(*z1_re0_);
                        let mut z1_re1 = cast(*z1_re1_);
                        let mut z1_im0 = cast(*z1_im0_);
                        let mut z1_im1 = cast(*z1_im1_);

                        let (z0_re, z0_im) = ((z0_re0, z0_re1), (z0_im0, z0_im1));
                        let (z1_re, z1_im) = ((z1_re0, z1_re1), (z1_im0, z1_im1));
                        let (z0mz1_re, z0mz1_im) = simd.cplx_sub(z0_re, z0_im, z1_re, z1_im);

                        ((z0_re0, z0_re1), (z0_im0, z0_im1)) =
                            simd.cplx_add(z0_re, z0_im, z1_re, z1_im);
                        ((z1_re0, z1_re1), (z1_im0, z1_im1)) =
                            simd.cplx_mul_conj(z0mz1_re, z0mz1_im, w1_re, w1_im);

                        *z0_re0_ = cast(z0_re0);
                        *z0_re1_ = cast(z0_re1);
                        *z0_im0_ = cast(z0_im0);
                        *z0_im1_ = cast(z0_im1);
                        *z1_re0_ = cast(z1_re0);
                        *z1_re1_ = cast(z1_re1);
                        *z1_im0_ = cast(z1_im0);
                        *z1_im1_ = cast(z1_im1);
                    }
                }

                t *= 2;
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        data_re0,
        data_re1,
        data_im0,
        data_im1,
        twid_re0,
        twid_re1,
        twid_im0,
        twid_im1,
    })
}

fn bitreverse(i: usize, n: usize) -> usize {
    let logn = n.trailing_zeros();
    let mut result = 0;
    for k in 0..logn {
        let kth_bit = (i >> k) & 1_usize;
        result |= kth_bit << (logn - k - 1);
    }
    result
}

#[doc(hidden)]
pub fn init_negacyclic_twiddles(
    twid_re0: &mut [f64],
    twid_re1: &mut [f64],
    twid_im0: &mut [f64],
    twid_im1: &mut [f64],
) {
    let n = twid_re0.len();
    let mut m = 1_usize;

    while m < n {
        for i in 0..m {
            let k = 2 * m + i;
            let pos = m + i;

            let theta_over_pi = f128(bitreverse(k, 2 * n) as f64 / (2 * n) as f64, 0.0);
            let (s, c) = theta_over_pi.sincospi();
            twid_re0[pos] = c.0;
            twid_re1[pos] = c.1;
            twid_im0[pos] = s.0;
            twid_im1[pos] = s.1;
        }
        m *= 2;
    }
}

/// 128-bit negacyclic FFT plan.
#[derive(Clone)]
pub struct Plan {
    twid_re0: ABox<[f64]>,
    twid_re1: ABox<[f64]>,
    twid_im0: ABox<[f64]>,
    twid_im1: ABox<[f64]>,
}

impl core::fmt::Debug for Plan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plan")
            .field("fft_size", &self.fft_size())
            .finish()
    }
}

impl Plan {
    /// Returns a new negacyclic FFT plan for the given vector size, following the algorithm in
    /// [Fast and Error-Free Negacyclic Integer Convolution using Extended Fourier Transform][paper]
    ///
    /// # Panics
    ///
    /// - Panics if `n` is not a power of two, or if it is less than `32`.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe_fft::fft128::Plan;
    /// let plan = Plan::new(32);
    /// ```
    ///
    /// [paper]: https://eprint.iacr.org/2021/480
    #[track_caller]
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two());
        assert!(n >= 32);

        let mut twid_re0 = avec![0.0f64; n].into_boxed_slice();
        let mut twid_re1 = avec![0.0f64; n].into_boxed_slice();
        let mut twid_im0 = avec![0.0f64; n].into_boxed_slice();
        let mut twid_im1 = avec![0.0f64; n].into_boxed_slice();

        init_negacyclic_twiddles(&mut twid_re0, &mut twid_re1, &mut twid_im0, &mut twid_im1);

        Self {
            twid_re0,
            twid_re1,
            twid_im0,
            twid_im1,
        }
    }

    /// Returns the vector size of the negacyclic FFT.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe_fft::fft128::Plan;
    /// let plan = Plan::new(32);
    /// assert_eq!(plan.fft_size(), 32);
    /// ```
    pub fn fft_size(&self) -> usize {
        self.twid_re0.len()
    }

    /// Performs a forward negacyclic FFT in place.
    ///
    /// # Note
    ///
    /// The values in `buf_re0`, `buf_re1`, `buf_im0`, `buf_im1` must be in standard order prior to
    /// calling this function. When this function returns, the values in `buf_re0`, `buf_re1`,
    /// `buf_im0`, `buf_im1` will contain the terms of the forward transform in bit-reversed
    /// order.
    #[track_caller]
    pub fn fwd(
        &self,
        buf_re0: &mut [f64],
        buf_re1: &mut [f64],
        buf_im0: &mut [f64],
        buf_im1: &mut [f64],
    ) {
        assert_eq!(buf_re0.len(), self.fft_size());
        assert_eq!(buf_re1.len(), self.fft_size());
        assert_eq!(buf_im0.len(), self.fft_size());
        assert_eq!(buf_im1.len(), self.fft_size());

        negacyclic_fwd_fft(
            buf_re0,
            buf_re1,
            buf_im0,
            buf_im1,
            &self.twid_re0,
            &self.twid_re1,
            &self.twid_im0,
            &self.twid_im1,
        );
    }

    /// Performs an inverse negacyclic FFT in place.
    ///
    /// # Note
    ///
    /// The values in `buf_re0`, `buf_re1`, `buf_im0`, `buf_im1` must be in bit-reversed order
    /// prior to calling this function. When this function returns, the values in `buf_re0`,
    /// `buf_re1`, `buf_im0`, `buf_im1` will contain the terms of the inverse transform in standard
    /// order.
    #[track_caller]
    pub fn inv(
        &self,
        buf_re0: &mut [f64],
        buf_re1: &mut [f64],
        buf_im0: &mut [f64],
        buf_im1: &mut [f64],
    ) {
        assert_eq!(buf_re0.len(), self.fft_size());
        assert_eq!(buf_re1.len(), self.fft_size());
        assert_eq!(buf_im0.len(), self.fft_size());
        assert_eq!(buf_im1.len(), self.fft_size());

        negacyclic_inv_fft(
            buf_re0,
            buf_re1,
            buf_im0,
            buf_im1,
            &self.twid_re0,
            &self.twid_re1,
            &self.twid_im0,
            &self.twid_im1,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rand::random;

    extern crate alloc;

    #[test]
    fn test_wrapper() {
        for n in [64, 128, 256, 512, 1024, 2048] {
            let mut lhs = vec![f128(0.0, 0.0); n];
            let mut rhs = vec![f128(0.0, 0.0); n];
            let mut result = vec![f128(0.0, 0.0); n];

            for x in &mut lhs {
                x.0 = random();
            }
            for x in &mut rhs {
                x.0 = random();
            }

            let mut full_convolution = vec![f128(0.0, 0.0); 2 * n];
            let mut negacyclic_convolution = vec![f128(0.0, 0.0); n];
            for i in 0..n {
                for j in 0..n {
                    full_convolution[i + j] += lhs[i] * rhs[j];
                }
            }
            for i in 0..n {
                negacyclic_convolution[i] = full_convolution[i] - full_convolution[i + n];
            }

            let mut lhs_fourier_re0 = vec![0.0; n / 2];
            let mut lhs_fourier_re1 = vec![0.0; n / 2];
            let mut lhs_fourier_im0 = vec![0.0; n / 2];
            let mut lhs_fourier_im1 = vec![0.0; n / 2];

            let mut rhs_fourier_re0 = vec![0.0; n / 2];
            let mut rhs_fourier_re1 = vec![0.0; n / 2];
            let mut rhs_fourier_im0 = vec![0.0; n / 2];
            let mut rhs_fourier_im1 = vec![0.0; n / 2];

            for i in 0..n / 2 {
                lhs_fourier_re0[i] = lhs[i].0;
                lhs_fourier_re1[i] = lhs[i].1;
                lhs_fourier_im0[i] = lhs[i + n / 2].0;
                lhs_fourier_im1[i] = lhs[i + n / 2].1;

                rhs_fourier_re0[i] = rhs[i].0;
                rhs_fourier_re1[i] = rhs[i].1;
                rhs_fourier_im0[i] = rhs[i + n / 2].0;
                rhs_fourier_im1[i] = rhs[i + n / 2].1;
            }

            let plan = Plan::new(n / 2);

            plan.fwd(
                &mut lhs_fourier_re0,
                &mut lhs_fourier_re1,
                &mut lhs_fourier_im0,
                &mut lhs_fourier_im1,
            );
            plan.fwd(
                &mut rhs_fourier_re0,
                &mut rhs_fourier_re1,
                &mut rhs_fourier_im0,
                &mut rhs_fourier_im1,
            );

            let factor = 2.0 / n as f64;
            let simd = Scalar;
            for i in 0..n / 2 {
                let (prod_re, prod_im) = simd.cplx_mul(
                    (lhs_fourier_re0[i], lhs_fourier_re1[i]),
                    (lhs_fourier_im0[i], lhs_fourier_im1[i]),
                    (rhs_fourier_re0[i], rhs_fourier_re1[i]),
                    (rhs_fourier_im0[i], rhs_fourier_im1[i]),
                );

                lhs_fourier_re0[i] = prod_re.0 * factor;
                lhs_fourier_re1[i] = prod_re.1 * factor;
                lhs_fourier_im0[i] = prod_im.0 * factor;
                lhs_fourier_im1[i] = prod_im.1 * factor;
            }

            plan.inv(
                &mut lhs_fourier_re0,
                &mut lhs_fourier_re1,
                &mut lhs_fourier_im0,
                &mut lhs_fourier_im1,
            );

            for i in 0..n / 2 {
                result[i] = f128(lhs_fourier_re0[i], lhs_fourier_re1[i]);
                result[i + n / 2] = f128(lhs_fourier_im0[i], lhs_fourier_im1[i]);
            }

            for i in 0..n {
                assert!((result[i] - negacyclic_convolution[i]).abs() < 1e-30 * n as f64);
            }
        }
    }

    #[test]
    fn test_product() {
        for n in [64, 128, 256, 512, 1024, 2048] {
            let mut lhs = vec![f128(0.0, 0.0); n];
            let mut rhs = vec![f128(0.0, 0.0); n];
            let mut result = vec![f128(0.0, 0.0); n];

            for x in &mut lhs {
                x.0 = random();
            }
            for x in &mut rhs {
                x.0 = random();
            }

            let mut full_convolution = vec![f128(0.0, 0.0); 2 * n];
            let mut negacyclic_convolution = vec![f128(0.0, 0.0); n];
            for i in 0..n {
                for j in 0..n {
                    full_convolution[i + j] += lhs[i] * rhs[j];
                }
            }
            for i in 0..n {
                negacyclic_convolution[i] = full_convolution[i] - full_convolution[i + n];
            }

            let mut twid_re0 = vec![0.0; n / 2];
            let mut twid_re1 = vec![0.0; n / 2];
            let mut twid_im0 = vec![0.0; n / 2];
            let mut twid_im1 = vec![0.0; n / 2];

            let mut lhs_fourier_re0 = vec![0.0; n / 2];
            let mut lhs_fourier_re1 = vec![0.0; n / 2];
            let mut lhs_fourier_im0 = vec![0.0; n / 2];
            let mut lhs_fourier_im1 = vec![0.0; n / 2];

            let mut rhs_fourier_re0 = vec![0.0; n / 2];
            let mut rhs_fourier_re1 = vec![0.0; n / 2];
            let mut rhs_fourier_im0 = vec![0.0; n / 2];
            let mut rhs_fourier_im1 = vec![0.0; n / 2];

            init_negacyclic_twiddles(&mut twid_re0, &mut twid_re1, &mut twid_im0, &mut twid_im1);

            for i in 0..n / 2 {
                lhs_fourier_re0[i] = lhs[i].0;
                lhs_fourier_re1[i] = lhs[i].1;
                lhs_fourier_im0[i] = lhs[i + n / 2].0;
                lhs_fourier_im1[i] = lhs[i + n / 2].1;

                rhs_fourier_re0[i] = rhs[i].0;
                rhs_fourier_re1[i] = rhs[i].1;
                rhs_fourier_im0[i] = rhs[i + n / 2].0;
                rhs_fourier_im1[i] = rhs[i + n / 2].1;
            }

            negacyclic_fwd_fft_scalar(
                &mut lhs_fourier_re0,
                &mut lhs_fourier_re1,
                &mut lhs_fourier_im0,
                &mut lhs_fourier_im1,
                &twid_re0,
                &twid_re1,
                &twid_im0,
                &twid_im1,
            );
            negacyclic_fwd_fft_scalar(
                &mut rhs_fourier_re0,
                &mut rhs_fourier_re1,
                &mut rhs_fourier_im0,
                &mut rhs_fourier_im1,
                &twid_re0,
                &twid_re1,
                &twid_im0,
                &twid_im1,
            );

            let factor = 2.0 / n as f64;
            let simd = Scalar;
            for i in 0..n / 2 {
                let (prod_re, prod_im) = simd.cplx_mul(
                    (lhs_fourier_re0[i], lhs_fourier_re1[i]),
                    (lhs_fourier_im0[i], lhs_fourier_im1[i]),
                    (rhs_fourier_re0[i], rhs_fourier_re1[i]),
                    (rhs_fourier_im0[i], rhs_fourier_im1[i]),
                );

                lhs_fourier_re0[i] = prod_re.0 * factor;
                lhs_fourier_re1[i] = prod_re.1 * factor;
                lhs_fourier_im0[i] = prod_im.0 * factor;
                lhs_fourier_im1[i] = prod_im.1 * factor;
            }

            negacyclic_inv_fft_scalar(
                &mut lhs_fourier_re0,
                &mut lhs_fourier_re1,
                &mut lhs_fourier_im0,
                &mut lhs_fourier_im1,
                &twid_re0,
                &twid_re1,
                &twid_im0,
                &twid_im1,
            );

            for i in 0..n / 2 {
                result[i] = f128(lhs_fourier_re0[i], lhs_fourier_re1[i]);
                result[i + n / 2] = f128(lhs_fourier_im0[i], lhs_fourier_im1[i]);
            }

            for i in 0..n {
                assert!((result[i] - negacyclic_convolution[i]).abs() < 1e-30 * n as f64);
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_product_avxfma() {
        if let Some(simd) = V3::try_new() {
            for n in [64, 128, 256, 512, 1024, 2048] {
                let mut lhs = vec![f128(0.0, 0.0); n];
                let mut rhs = vec![f128(0.0, 0.0); n];
                let mut result = vec![f128(0.0, 0.0); n];

                for x in &mut lhs {
                    x.0 = random();
                }
                for x in &mut rhs {
                    x.0 = random();
                }

                let mut full_convolution = vec![f128(0.0, 0.0); 2 * n];
                let mut negacyclic_convolution = vec![f128(0.0, 0.0); n];
                for i in 0..n {
                    for j in 0..n {
                        full_convolution[i + j] += lhs[i] * rhs[j];
                    }
                }
                for i in 0..n {
                    negacyclic_convolution[i] = full_convolution[i] - full_convolution[i + n];
                }

                let mut twid_re0 = vec![0.0; n / 2];
                let mut twid_re1 = vec![0.0; n / 2];
                let mut twid_im0 = vec![0.0; n / 2];
                let mut twid_im1 = vec![0.0; n / 2];

                let mut lhs_fourier_re0 = vec![0.0; n / 2];
                let mut lhs_fourier_re1 = vec![0.0; n / 2];
                let mut lhs_fourier_im0 = vec![0.0; n / 2];
                let mut lhs_fourier_im1 = vec![0.0; n / 2];

                let mut rhs_fourier_re0 = vec![0.0; n / 2];
                let mut rhs_fourier_re1 = vec![0.0; n / 2];
                let mut rhs_fourier_im0 = vec![0.0; n / 2];
                let mut rhs_fourier_im1 = vec![0.0; n / 2];

                init_negacyclic_twiddles(
                    &mut twid_re0,
                    &mut twid_re1,
                    &mut twid_im0,
                    &mut twid_im1,
                );

                for i in 0..n / 2 {
                    lhs_fourier_re0[i] = lhs[i].0;
                    lhs_fourier_re1[i] = lhs[i].1;
                    lhs_fourier_im0[i] = lhs[i + n / 2].0;
                    lhs_fourier_im1[i] = lhs[i + n / 2].1;

                    rhs_fourier_re0[i] = rhs[i].0;
                    rhs_fourier_re1[i] = rhs[i].1;
                    rhs_fourier_im0[i] = rhs[i + n / 2].0;
                    rhs_fourier_im1[i] = rhs[i + n / 2].1;
                }

                negacyclic_fwd_fft_avxfma(
                    simd,
                    &mut lhs_fourier_re0,
                    &mut lhs_fourier_re1,
                    &mut lhs_fourier_im0,
                    &mut lhs_fourier_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );
                negacyclic_fwd_fft_avxfma(
                    simd,
                    &mut rhs_fourier_re0,
                    &mut rhs_fourier_re1,
                    &mut rhs_fourier_im0,
                    &mut rhs_fourier_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );

                let factor = 2.0 / n as f64;
                let scalar = Scalar;
                for i in 0..n / 2 {
                    let (prod_re, prod_im) = scalar.cplx_mul(
                        (lhs_fourier_re0[i], lhs_fourier_re1[i]),
                        (lhs_fourier_im0[i], lhs_fourier_im1[i]),
                        (rhs_fourier_re0[i], rhs_fourier_re1[i]),
                        (rhs_fourier_im0[i], rhs_fourier_im1[i]),
                    );

                    lhs_fourier_re0[i] = prod_re.0 * factor;
                    lhs_fourier_re1[i] = prod_re.1 * factor;
                    lhs_fourier_im0[i] = prod_im.0 * factor;
                    lhs_fourier_im1[i] = prod_im.1 * factor;
                }

                negacyclic_inv_fft_avxfma(
                    simd,
                    &mut lhs_fourier_re0,
                    &mut lhs_fourier_re1,
                    &mut lhs_fourier_im0,
                    &mut lhs_fourier_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );

                for i in 0..n / 2 {
                    result[i] = f128(lhs_fourier_re0[i], lhs_fourier_re1[i]);
                    result[i + n / 2] = f128(lhs_fourier_im0[i], lhs_fourier_im1[i]);
                }

                for i in 0..n {
                    assert!((result[i] - negacyclic_convolution[i]).abs() < 1e-30 * n as f64);
                }
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly")]
    #[test]
    fn test_product_avx512() {
        if let Some(simd) = V4::try_new() {
            for n in [64, 128, 256, 512, 1024, 2048] {
                let mut lhs = vec![f128(0.0, 0.0); n];
                let mut rhs = vec![f128(0.0, 0.0); n];
                let mut result = vec![f128(0.0, 0.0); n];

                for x in &mut lhs {
                    x.0 = random();
                }
                for x in &mut rhs {
                    x.0 = random();
                }

                let mut full_convolution = vec![f128(0.0, 0.0); 2 * n];
                let mut negacyclic_convolution = vec![f128(0.0, 0.0); n];
                for i in 0..n {
                    for j in 0..n {
                        full_convolution[i + j] += lhs[i] * rhs[j];
                    }
                }
                for i in 0..n {
                    negacyclic_convolution[i] = full_convolution[i] - full_convolution[i + n];
                }

                let mut twid_re0 = vec![0.0; n / 2];
                let mut twid_re1 = vec![0.0; n / 2];
                let mut twid_im0 = vec![0.0; n / 2];
                let mut twid_im1 = vec![0.0; n / 2];

                let mut lhs_fourier_re0 = vec![0.0; n / 2];
                let mut lhs_fourier_re1 = vec![0.0; n / 2];
                let mut lhs_fourier_im0 = vec![0.0; n / 2];
                let mut lhs_fourier_im1 = vec![0.0; n / 2];

                let mut rhs_fourier_re0 = vec![0.0; n / 2];
                let mut rhs_fourier_re1 = vec![0.0; n / 2];
                let mut rhs_fourier_im0 = vec![0.0; n / 2];
                let mut rhs_fourier_im1 = vec![0.0; n / 2];

                init_negacyclic_twiddles(
                    &mut twid_re0,
                    &mut twid_re1,
                    &mut twid_im0,
                    &mut twid_im1,
                );

                for i in 0..n / 2 {
                    lhs_fourier_re0[i] = lhs[i].0;
                    lhs_fourier_re1[i] = lhs[i].1;
                    lhs_fourier_im0[i] = lhs[i + n / 2].0;
                    lhs_fourier_im1[i] = lhs[i + n / 2].1;

                    rhs_fourier_re0[i] = rhs[i].0;
                    rhs_fourier_re1[i] = rhs[i].1;
                    rhs_fourier_im0[i] = rhs[i + n / 2].0;
                    rhs_fourier_im1[i] = rhs[i + n / 2].1;
                }

                negacyclic_fwd_fft_avx512(
                    simd,
                    &mut lhs_fourier_re0,
                    &mut lhs_fourier_re1,
                    &mut lhs_fourier_im0,
                    &mut lhs_fourier_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );
                negacyclic_fwd_fft_avx512(
                    simd,
                    &mut rhs_fourier_re0,
                    &mut rhs_fourier_re1,
                    &mut rhs_fourier_im0,
                    &mut rhs_fourier_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );

                let factor = 2.0 / n as f64;
                let scalar = Scalar;
                for i in 0..n / 2 {
                    let (prod_re, prod_im) = scalar.cplx_mul(
                        (lhs_fourier_re0[i], lhs_fourier_re1[i]),
                        (lhs_fourier_im0[i], lhs_fourier_im1[i]),
                        (rhs_fourier_re0[i], rhs_fourier_re1[i]),
                        (rhs_fourier_im0[i], rhs_fourier_im1[i]),
                    );

                    lhs_fourier_re0[i] = prod_re.0 * factor;
                    lhs_fourier_re1[i] = prod_re.1 * factor;
                    lhs_fourier_im0[i] = prod_im.0 * factor;
                    lhs_fourier_im1[i] = prod_im.1 * factor;
                }

                negacyclic_inv_fft_avx512(
                    simd,
                    &mut lhs_fourier_re0,
                    &mut lhs_fourier_re1,
                    &mut lhs_fourier_im0,
                    &mut lhs_fourier_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );

                for i in 0..n / 2 {
                    result[i] = f128(lhs_fourier_re0[i], lhs_fourier_re1[i]);
                    result[i + n / 2] = f128(lhs_fourier_im0[i], lhs_fourier_im1[i]);
                }

                for i in 0..n {
                    assert!((result[i] - negacyclic_convolution[i]).abs() < 1e-30 * n as f64);
                }
            }
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(test)]
mod x86_tests {
    use super::*;
    use rand::random as rnd;

    #[test]
    fn test_interleaves_and_permutes_f64x4() {
        if let Some(simd) = V3::try_new() {
            let a = f64x4(rnd(), rnd(), rnd(), rnd());
            let b = f64x4(rnd(), rnd(), rnd(), rnd());

            assert_eq!(
                simd.interleave2_f64x4([a, b]),
                [f64x4(a.0, a.1, b.0, b.1), f64x4(a.2, a.3, b.2, b.3)],
            );
            assert_eq!(
                simd.interleave2_f64x4(simd.interleave2_f64x4([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd()];
            assert_eq!(simd.permute2_f64x4(w), f64x4(w[0], w[0], w[1], w[1]));

            assert_eq!(
                simd.interleave1_f64x4([a, b]),
                [f64x4(a.0, b.0, a.2, b.2), f64x4(a.1, b.1, a.3, b.3)],
            );
            assert_eq!(
                simd.interleave1_f64x4(simd.interleave1_f64x4([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd()];
            assert_eq!(simd.permute1_f64x4(w), f64x4(w[0], w[2], w[1], w[3]));
        }
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_interleaves_and_permutes_f64x8() {
        if let Some(simd) = V4::try_new() {
            let a = f64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());
            let b = f64x8(rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd());

            assert_eq!(
                simd.interleave4_f64x8([a, b]),
                [
                    f64x8(a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3),
                    f64x8(a.4, a.5, a.6, a.7, b.4, b.5, b.6, b.7),
                ],
            );
            assert_eq!(
                simd.interleave4_f64x8(simd.interleave4_f64x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd()];
            assert_eq!(
                simd.permute4_f64x8(w),
                f64x8(w[0], w[0], w[0], w[0], w[1], w[1], w[1], w[1]),
            );

            assert_eq!(
                simd.interleave2_f64x8([a, b]),
                [
                    f64x8(a.0, a.1, b.0, b.1, a.4, a.5, b.4, b.5),
                    f64x8(a.2, a.3, b.2, b.3, a.6, a.7, b.6, b.7),
                ],
            );
            assert_eq!(
                simd.interleave2_f64x8(simd.interleave2_f64x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute2_f64x8(w),
                f64x8(w[0], w[0], w[2], w[2], w[1], w[1], w[3], w[3]),
            );

            assert_eq!(
                simd.interleave1_f64x8([a, b]),
                [
                    f64x8(a.0, b.0, a.2, b.2, a.4, b.4, a.6, b.6),
                    f64x8(a.1, b.1, a.3, b.3, a.5, b.5, a.7, b.7),
                ],
            );
            assert_eq!(
                simd.interleave1_f64x8(simd.interleave1_f64x8([a, b])),
                [a, b],
            );
            let w = [rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd(), rnd()];
            assert_eq!(
                simd.permute1_f64x8(w),
                f64x8(w[0], w[4], w[1], w[5], w[2], w[6], w[3], w[7]),
            );
        }
    }
}
