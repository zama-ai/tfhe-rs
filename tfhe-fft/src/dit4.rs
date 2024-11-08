use crate::{
    c64,
    dif4::{split_4, split_mut_4},
    fft_simd::{FftSimd, FftSimdExt, Pod},
    fn_ptr, nat, RecursiveFft,
};

#[inline(always)]
fn stockham_core_1x2<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &mut [c64xN],
    y: &[c64xN],
    w_init: &[c64xN],
    _w: &[c64],
) {
    assert_eq!(s, 1);

    let y = pulp::as_arrays::<4, _>(y).0;
    let (x0, x1, x2, x3) = split_mut_4(x);
    let (_, w1, w2, w3) = split_4(w_init);

    for (y, x0, x1, x2, x3, w1, w2, w3) in izip!(y, x0, x1, x2, x3, w1, w2, w3) {
        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;

        let ab0 = y[0];
        let cd0 = y[1];
        let ab1 = y[2];
        let cd1 = y[3];

        let a = simd.catlo(ab0, ab1);
        let b = simd.mul(w1, simd.cathi(ab0, ab1));
        let c = simd.mul(w2, simd.catlo(cd0, cd1));
        let d = simd.mul(w3, simd.cathi(cd0, cd1));

        let apc = simd.add(a, c);
        let amc = simd.sub(a, c);
        let bpd = simd.add(b, d);
        let jbmd = simd.mul_j(fwd, simd.sub(b, d));

        *x0 = simd.add(apc, bpd);
        *x1 = simd.sub(amc, jbmd);
        *x2 = simd.sub(apc, bpd);
        *x3 = simd.add(amc, jbmd);
    }
}

#[inline(always)]
fn stockham_core_1x4<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &mut [c64xN],
    y: &[c64xN],
    w_init: &[c64xN],
    _w: &[c64],
) {
    assert_eq!(s, 1);

    let y = pulp::as_arrays::<4, _>(y).0;
    let (x0, x1, x2, x3) = split_mut_4(x);
    let (_, w1, w2, w3) = split_4(w_init);

    for (y, x0, x1, x2, x3, w1, w2, w3) in izip!(y, x0, x1, x2, x3, w1, w2, w3) {
        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;

        let abcd0 = y[0];
        let abcd1 = y[1];
        let abcd2 = y[2];
        let abcd3 = y[3];

        let (a, b, c, d) = simd.transpose(abcd0, abcd1, abcd2, abcd3);

        let b = simd.mul(w1, b);
        let c = simd.mul(w2, c);
        let d = simd.mul(w3, d);

        let apc = simd.add(a, c);
        let amc = simd.sub(a, c);
        let bpd = simd.add(b, d);
        let jbmd = simd.mul_j(fwd, simd.sub(b, d));

        *x0 = simd.add(apc, bpd);
        *x1 = simd.sub(amc, jbmd);
        *x2 = simd.sub(apc, bpd);
        *x3 = simd.add(amc, jbmd);
    }
}

#[inline(always)]
fn stockham_core_generic<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &mut [c64xN],
    y: &[c64xN],
    _w_init: &[c64xN],
    w: &[c64],
) {
    assert_eq!(s % simd.lane_count(), 0);
    let simd_s = s / simd.lane_count();

    let w = pulp::as_arrays::<4, _>(w).0;

    let (x0, x1, x2, x3) = split_mut_4(x);
    for (x0, x1, x2, x3, y, w) in izip!(
        x0.chunks_exact_mut(simd_s),
        x1.chunks_exact_mut(simd_s),
        x2.chunks_exact_mut(simd_s),
        x3.chunks_exact_mut(simd_s),
        y.chunks_exact(4 * simd_s),
        w.chunks_exact(s),
    ) {
        let [_, w1, w2, w3] = w[0];

        let w1 = simd.splat(w1);
        let w2 = simd.splat(w2);
        let w3 = simd.splat(w3);

        let (y0, y1, y2, y3) = split_4(y);

        for (x0, x1, x2, x3, y0, y1, y2, y3) in izip!(x0, x1, x2, x3, y0, y1, y2, y3) {
            let a = *y0;
            let b = simd.mul(w1, *y1);
            let c = simd.mul(w2, *y2);
            let d = simd.mul(w3, *y3);

            let apc = simd.add(a, c);
            let amc = simd.sub(a, c);

            let bpd = simd.add(b, d);
            let jbmd = simd.mul_j(fwd, simd.sub(b, d));

            *x0 = simd.add(apc, bpd);
            *x1 = simd.sub(amc, jbmd);
            *x2 = simd.sub(apc, bpd);
            *x3 = simd.add(amc, jbmd);
        }
    }
}

#[inline(always)]
fn stockham_core<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    s: usize,
    x: &mut [c64xN],
    y: &[c64xN],
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
pub fn stockham_dit4_end<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    read_from_x: bool,
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

    if read_from_x {
        for (x0, x1, x2, x3) in izip!(x0, x1, x2, x3) {
            (*x0, *x1, *x2, *x3) = last_butterfly(simd, fwd, *x0, *x1, *x2, *x3);
        }
    } else {
        for (x0, x1, x2, x3, y0, y1, y2, y3) in izip!(x0, x1, x2, x3, y0, y1, y2, y3) {
            (*x0, *x1, *x2, *x3) = last_butterfly(simd, fwd, *y0, *y1, *y2, *y3);
        }
    }
}

struct Dit4<N: nat::Nat>(N);
impl<N: nat::Nat> nat::Nat for Dit4<N> {
    const VALUE: usize = N::VALUE;
}

// size 2
impl RecursiveFft for Dit4<nat::N0> {
    #[inline(always)]
    fn fft_recurse_impl<c64xN: Pod>(
        simd: impl FftSimd<c64xN>,
        fwd: bool,
        read_from_x: bool,
        s: usize,
        x: &mut [c64xN],
        y: &mut [c64xN],
        _w_init: &[c64xN],
        _w: &[c64],
    ) {
        crate::dit2::stockham_dit2_end(simd, fwd, read_from_x, s, x, y);
    }
}

// size 4
impl RecursiveFft for Dit4<nat::N1> {
    #[inline(always)]
    fn fft_recurse_impl<c64xN: Pod>(
        simd: impl FftSimd<c64xN>,
        fwd: bool,
        read_from_x: bool,
        s: usize,
        x: &mut [c64xN],
        y: &mut [c64xN],
        _w_init: &[c64xN],
        _w: &[c64],
    ) {
        stockham_dit4_end(simd, fwd, read_from_x, s, x, y);
    }
}

impl<N: nat::Nat> RecursiveFft for Dit4<nat::Plus2<N>>
where
    Dit4<N>: RecursiveFft,
{
    #[inline(always)]
    fn fft_recurse_impl<c64xN: Pod>(
        simd: impl FftSimd<c64xN>,
        fwd: bool,
        read_from_x: bool,
        s: usize,
        x: &mut [c64xN],
        y: &mut [c64xN],
        w_init: &[c64xN],
        w: &[c64],
    ) {
        Dit4::<N>::fft_recurse_impl(simd, fwd, !read_from_x, s * 4, y, x, w_init, w);
        stockham_core(simd, fwd, s, x, y, w_init, w);
    }
}

pub(crate) fn fft_impl<c64xN: Pod>(simd: impl FftSimd<c64xN>) -> crate::FftImpl {
    let fwd = [
        fn_ptr::<true, Dit4<nat::N0>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N1>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N2>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N3>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N4>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N5>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N6>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N7>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N8>, _, _>(simd),
        fn_ptr::<true, Dit4<nat::N9>, _, _>(simd),
    ];
    let inv = [
        fn_ptr::<false, Dit4<nat::N0>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N1>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N2>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N3>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N4>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N5>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N6>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N7>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N8>, _, _>(simd),
        fn_ptr::<false, Dit4<nat::N9>, _, _>(simd),
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
