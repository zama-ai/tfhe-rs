use crate::{
    c64,
    dif2::{split_2, split_mut_2},
    fft_simd::{FftSimd, FftSimdExt, Pod},
    fn_ptr, nat, RecursiveFft,
};

#[inline(always)]
pub fn split_4<T>(slice: &[T]) -> (&[T], &[T], &[T], &[T]) {
    let (slice01, slice23) = split_2(slice);
    let (slice0, slice1) = split_2(slice01);
    let (slice2, slice3) = split_2(slice23);
    (slice0, slice1, slice2, slice3)
}
#[inline(always)]
pub fn split_mut_4<T>(slice: &mut [T]) -> (&mut [T], &mut [T], &mut [T], &mut [T]) {
    let (slice01, slice23) = split_mut_2(slice);
    let (slice0, slice1) = split_mut_2(slice01);
    let (slice2, slice3) = split_mut_2(slice23);
    (slice0, slice1, slice2, slice3)
}

#[inline(always)]
fn stockham_core_1x2<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &[c64xN],
    y: &mut [c64xN],
    w_init: &[c64xN],
    _w: &[c64],
) {
    assert_eq!(s, 1);

    let y = pulp::as_arrays_mut::<4, _>(y).0;
    let (x0, x1, x2, x3) = split_4(x);
    let (_, w1, w2, w3) = split_4(w_init);

    for (x0, x1, x2, x3, y, w1, w2, w3) in izip!(x0, x1, x2, x3, y, w1, w2, w3) {
        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;

        let a = *x0;
        let b = *x1;
        let c = *x2;
        let d = *x3;

        let apc = simd.add(a, c);
        let amc = simd.sub(a, c);

        let bpd = simd.add(b, d);
        let jbmd = simd.mul_j(fwd, simd.sub(b, d));

        let aa = simd.add(apc, bpd);
        let bb = simd.mul(w1, simd.sub(amc, jbmd));
        let cc = simd.mul(w2, simd.sub(apc, bpd));
        let dd = simd.mul(w3, simd.add(amc, jbmd));

        let ab = simd.catlo(aa, bb);
        let cd = simd.catlo(cc, dd);
        y[0] = ab;
        y[1] = cd;

        let ab = simd.cathi(aa, bb);
        let cd = simd.cathi(cc, dd);
        y[2] = ab;
        y[3] = cd;
    }
}

#[inline(always)]
fn stockham_core_1x4<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &[c64xN],
    y: &mut [c64xN],
    w_init: &[c64xN],
    _w: &[c64],
) {
    assert_eq!(s, 1);

    let y = pulp::as_arrays_mut::<4, _>(y).0;
    let (x0, x1, x2, x3) = split_4(x);
    let (_, w1, w2, w3) = split_4(w_init);

    for (x0, x1, x2, x3, y, w1, w2, w3) in izip!(x0, x1, x2, x3, y, w1, w2, w3) {
        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;

        let a = *x0;
        let b = *x1;
        let c = *x2;
        let d = *x3;

        let apc = simd.add(a, c);
        let amc = simd.sub(a, c);

        let bpd = simd.add(b, d);
        let jbmd = simd.mul_j(fwd, simd.sub(b, d));

        let aaaa = simd.add(apc, bpd);
        let bbbb = simd.mul(w1, simd.sub(amc, jbmd));
        let cccc = simd.mul(w2, simd.sub(apc, bpd));
        let dddd = simd.mul(w3, simd.add(amc, jbmd));

        let (abcd0, abcd1, abcd2, abcd3) = simd.transpose(aaaa, bbbb, cccc, dddd);
        y[0] = abcd0;
        y[1] = abcd1;
        y[2] = abcd2;
        y[3] = abcd3;
    }
}

#[inline(always)]
fn stockham_core_generic<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &[c64xN],
    y: &mut [c64xN],
    _w_init: &[c64xN],
    w: &[c64],
) {
    assert_eq!(s % simd.lane_count(), 0);
    let simd_s = s / simd.lane_count();

    let w = pulp::as_arrays::<4, _>(w).0;

    let (x0, x1, x2, x3) = split_4(x);

    for (x0, x1, x2, x3, y, w) in izip!(
        x0.chunks_exact(simd_s),
        x1.chunks_exact(simd_s),
        x2.chunks_exact(simd_s),
        x3.chunks_exact(simd_s),
        y.chunks_exact_mut(4 * simd_s),
        w.chunks_exact(s),
    ) {
        let [_, w1, w2, w3] = w[0];

        let w1 = simd.splat(w1);
        let w2 = simd.splat(w2);
        let w3 = simd.splat(w3);

        let (y0, y1, y2, y3) = split_mut_4(y);

        for (x0, x1, x2, x3, y0, y1, y2, y3) in izip!(x0, x1, x2, x3, y0, y1, y2, y3) {
            let a = *x0;
            let b = *x1;
            let c = *x2;
            let d = *x3;

            let apc = simd.add(a, c);
            let amc = simd.sub(a, c);

            let bpd = simd.add(b, d);
            let jbmd = simd.mul_j(fwd, simd.sub(b, d));

            *y0 = simd.add(apc, bpd);
            *y1 = simd.mul(w1, simd.sub(amc, jbmd));
            *y2 = simd.mul(w2, simd.sub(apc, bpd));
            *y3 = simd.mul(w3, simd.add(amc, jbmd));
        }
    }
}

#[inline(always)]
fn stockham_core<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &[c64xN],
    y: &mut [c64xN],
    w_init: &[c64xN],
    w: &[c64],
) {
    // we create a fn pointer that will be force-inlined in release builds
    // but not in debug builds. this helps keep compile times low, since dead code
    // elimination handles this well in release builds. and the function pointer indirection
    // prevents inlining in debug builds.
    let stockham = if s == 1 && simd.lane_count() == 2 {
        stockham_core_1x2
    } else if s == 1 && simd.lane_count() == 4 {
        stockham_core_1x4
    } else {
        stockham_core_generic
    };
    stockham(simd, fwd, s, x, y, w_init, w);
}

#[inline(always)]
fn last_butterfly<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    x0: c64xN,
    x1: c64xN,
    x2: c64xN,
    x3: c64xN,
) -> (c64xN, c64xN, c64xN, c64xN) {
    let apc = simd.add(x0, x2);
    let amc = simd.sub(x0, x2);
    let bpd = simd.add(x1, x3);
    let jbmd = simd.mul_j(fwd, simd.sub(x1, x3));

    (
        simd.add(apc, bpd),
        simd.sub(amc, jbmd),
        simd.sub(apc, bpd),
        simd.add(amc, jbmd),
    )
}

#[inline(always)]
pub fn stockham_dif4_end<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    write_to_x: bool,
    s: usize,
    x: &mut [c64xN],
    y: &mut [c64xN],
) {
    assert_eq!(s % simd.lane_count(), 0);
    let (x0, x1, x2, x3) = split_mut_4(x);
    let (y0, y1, y2, y3) = split_mut_4(y);

    // we create a fn pointer that will be force-inlined in release builds
    // but not in debug builds. this helps keep compile times low, since dead code
    // elimination handles this well in release builds. and the function pointer indirection
    // prevents inlining in debug builds.
    let last_butterfly: fn(_, _, _, _, _, _) -> _ = last_butterfly;

    if write_to_x {
        for (x0, x1, x2, x3) in izip!(x0, x1, x2, x3) {
            (*x0, *x1, *x2, *x3) = last_butterfly(simd, fwd, *x0, *x1, *x2, *x3);
        }
    } else {
        for (x0, x1, x2, x3, y0, y1, y2, y3) in izip!(x0, x1, x2, x3, y0, y1, y2, y3) {
            (*y0, *y1, *y2, *y3) = last_butterfly(simd, fwd, *x0, *x1, *x2, *x3);
        }
    }
}

struct Dif4<N: nat::Nat>(N);
impl<N: nat::Nat> nat::Nat for Dif4<N> {
    const VALUE: usize = N::VALUE;
}

// size 2
impl RecursiveFft for Dif4<nat::N0> {
    #[inline(always)]
    fn fft_recurse_impl<c64xN: Pod>(
        simd: impl FftSimd<c64xN>,
        fwd: bool,
        write_to_x: bool,
        s: usize,
        x: &mut [c64xN],
        y: &mut [c64xN],
        _w_init: &[c64xN],
        _w: &[c64],
    ) {
        crate::dif2::stockham_dif2_end(simd, fwd, write_to_x, s, x, y);
    }
}

// size 4
impl RecursiveFft for Dif4<nat::N1> {
    #[inline(always)]
    fn fft_recurse_impl<c64xN: Pod>(
        simd: impl FftSimd<c64xN>,
        fwd: bool,
        write_to_x: bool,
        s: usize,
        x: &mut [c64xN],
        y: &mut [c64xN],
        _w_init: &[c64xN],
        _w: &[c64],
    ) {
        stockham_dif4_end(simd, fwd, write_to_x, s, x, y);
    }
}

impl<N: nat::Nat> RecursiveFft for Dif4<nat::Plus2<N>>
where
    Dif4<N>: RecursiveFft,
{
    #[inline(always)]
    fn fft_recurse_impl<c64xN: Pod>(
        simd: impl FftSimd<c64xN>,
        fwd: bool,
        write_to_x: bool,
        s: usize,
        x: &mut [c64xN],
        y: &mut [c64xN],
        w_init: &[c64xN],
        w: &[c64],
    ) {
        stockham_core(simd, fwd, s, x, y, w_init, w);
        Dif4::<N>::fft_recurse_impl(simd, fwd, !write_to_x, s * 4, y, x, w_init, w);
    }
}

pub(crate) fn fft_impl<c64xN: Pod>(simd: impl FftSimd<c64xN>) -> crate::FftImpl {
    let fwd = [
        fn_ptr::<true, Dif4<nat::N0>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N1>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N2>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N3>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N4>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N5>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N6>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N7>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N8>, _, _>(simd),
        fn_ptr::<true, Dif4<nat::N9>, _, _>(simd),
    ];
    let inv = [
        fn_ptr::<false, Dif4<nat::N0>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N1>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N2>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N3>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N4>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N5>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N6>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N7>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N8>, _, _>(simd),
        fn_ptr::<false, Dif4<nat::N9>, _, _>(simd),
    ];
    crate::FftImpl { fwd, inv }
}

pub fn fft_impl_dispatch(n: usize) -> [fn(&mut [c64], &mut [c64], &[c64], &[c64]); 2] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "nightly")]
        if let Some(simd) = pulp::x86::V4::try_new() {
            if n >= 4 * simd.lane_count() {
                return fft_impl(simd).make_fn_ptr(n);
            }
        }
        if let Some(simd) = pulp::x86::V3::try_new() {
            if n >= 4 * simd.lane_count() {
                return fft_impl(simd).make_fn_ptr(n);
            }
        }
    }
    fft_impl(crate::fft_simd::Scalar).make_fn_ptr(n)
}
