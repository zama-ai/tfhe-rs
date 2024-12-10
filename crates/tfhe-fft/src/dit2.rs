use crate::{
    c64,
    dif2::{split_2, split_mut_2},
    fft_simd::{FftSimd, Pod},
    fn_ptr, nat, RecursiveFft,
};

#[inline(always)]
fn stockham_core_1x2<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    _fwd: bool,
    s: usize,
    x: &mut [c64xN],
    y: &[c64xN],
    w_init: &[c64xN],
    _w: &[c64],
) {
    assert_eq!(s, 1);

    let y = pulp::as_arrays::<2, _>(y).0;
    let (x0, x1) = split_mut_2(x);
    let (_, w1) = split_2(w_init);

    for (y, x0, x1, w1) in izip!(y, x0, x1, w1) {
        let ab0 = y[0];
        let ab1 = y[1];
        let w1 = *w1;

        let a = simd.catlo(ab0, ab1);
        let b = simd.mul(w1, simd.cathi(ab0, ab1));

        *x0 = simd.add(a, b);
        *x1 = simd.sub(a, b);
    }
}

#[inline(always)]
fn stockham_core_generic<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    _fwd: bool,
    s: usize,
    x: &mut [c64xN],
    y: &[c64xN],
    _w_init: &[c64xN],
    w: &[c64],
) {
    assert_eq!(s % simd.lane_count(), 0);
    let simd_s = s / simd.lane_count();

    let w = pulp::as_arrays::<2, _>(w).0;

    let (x0, x1) = split_mut_2(x);
    for (x0, x1, y, w) in izip!(
        x0.chunks_exact_mut(simd_s),
        x1.chunks_exact_mut(simd_s),
        y.chunks_exact(2 * simd_s),
        w.chunks_exact(s),
    ) {
        let [_, w1] = w[0];

        let w1 = simd.splat(w1);

        let (y0, y1) = split_2(y);

        for (x0, x1, y0, y1) in izip!(x0, x1, y0, y1) {
            let a = *y0;
            let b = simd.mul(w1, *y1);

            *x0 = simd.add(a, b);
            *x1 = simd.sub(a, b);
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
    } else {
        stockham_core_generic
    };
    stockham(simd, fwd, s, x, y, w_init, w);
}

#[inline(always)]
fn last_butterfly<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    _fwd: bool,
    x0: c64xN,
    x1: c64xN,
) -> (c64xN, c64xN) {
    (simd.add(x0, x1), simd.sub(x0, x1))
}

#[inline(always)]
pub fn stockham_dit2_end<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    read_from_x: bool,
    s: usize,
    x: &mut [c64xN],
    y: &mut [c64xN],
) {
    assert_eq!(s % simd.lane_count(), 0);
    let (x0, x1) = split_mut_2(x);
    let (y0, y1) = split_mut_2(y);

    // we create a fn pointer that will be force-inlined in release builds
    // but not in debug builds. this helps keep compile times low, since dead code
    // elimination handles this well in release builds. and the function pointer indirection
    // prevents inlining in debug builds.
    let last_butterfly: fn(_, _, _, _) -> _ = last_butterfly;

    if read_from_x {
        for (x0, x1) in izip!(x0, x1) {
            (*x0, *x1) = last_butterfly(simd, fwd, *x0, *x1);
        }
    } else {
        for (x0, x1, y0, y1) in izip!(x0, x1, y0, y1) {
            (*x0, *x1) = last_butterfly(simd, fwd, *y0, *y1);
        }
    }
}

struct Dit2<N: nat::Nat>(N);
impl<N: nat::Nat> nat::Nat for Dit2<N> {
    const VALUE: usize = N::VALUE;
}

/// size 2^3
impl RecursiveFft for Dit2<nat::N0> {
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
        stockham_dit2_end(simd, fwd, read_from_x, s, x, y);
    }
}

impl<N: nat::Nat> RecursiveFft for Dit2<nat::Plus1<N>>
where
    Dit2<N>: RecursiveFft,
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
        Dit2::<N>::fft_recurse_impl(simd, fwd, !read_from_x, s * 2, y, x, w_init, w);
        stockham_core(simd, fwd, s, x, y, w_init, w);
    }
}

pub(crate) fn fft_impl<c64xN: Pod>(simd: impl FftSimd<c64xN>) -> crate::FftImpl {
    // special case, for DIT2, fwd and inv are the same
    let ptrs = [
        fn_ptr::<true, Dit2<nat::N0>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N1>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N2>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N3>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N4>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N5>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N6>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N7>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N8>, _, _>(simd),
        fn_ptr::<true, Dit2<nat::N9>, _, _>(simd),
    ];
    crate::FftImpl {
        fwd: ptrs,
        inv: ptrs,
    }
}

pub fn fft_impl_dispatch(n: usize) -> [fn(&mut [c64], &mut [c64], &[c64], &[c64]); 2] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if let Some(simd) = pulp::x86::V3::try_new() {
            if n >= 2 * simd.lane_count() {
                return fft_impl(simd).make_fn_ptr(n);
            }
        }
    }
    fft_impl(crate::fft_simd::Scalar).make_fn_ptr(n)
}
