use crate::{
    c64,
    dif2::{split_2, split_mut_2},
    dif4::{split_4, split_mut_4},
    fft_simd::{FftSimd, FftSimdExt, Pod},
    fn_ptr, nat, RecursiveFft,
};

#[inline(always)]
pub fn split_8<T>(slice: &[T]) -> (&[T], &[T], &[T], &[T], &[T], &[T], &[T], &[T]) {
    let (slice0123, slice4567) = split_2(slice);
    let (slice0, slice1, slice2, slice3) = split_4(slice0123);
    let (slice4, slice5, slice6, slice7) = split_4(slice4567);
    (
        slice0, slice1, slice2, slice3, slice4, slice5, slice6, slice7,
    )
}
#[inline(always)]
pub fn split_mut_8<T>(
    slice: &mut [T],
) -> (
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
) {
    let (slice0123, slice4567) = split_mut_2(slice);
    let (slice0, slice1, slice2, slice3) = split_mut_4(slice0123);
    let (slice4, slice5, slice6, slice7) = split_mut_4(slice4567);
    (
        slice0, slice1, slice2, slice3, slice4, slice5, slice6, slice7,
    )
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

    let y = pulp::as_arrays_mut::<8, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7) = split_8(x);
    let (_, w1, w2, w3, w4, w5, w6, w7) = split_8(w_init);

    for ((x0, x1, x2, x3, x4, x5, x6, x7), y, (w1, w2, w3, w4, w5, w6, w7)) in izip!(
        izip!(x0, x1, x2, x3, x4, x5, x6, x7),
        y,
        izip!(w1, w2, w3, w4, w5, w6, w7),
    ) {
        let x0 = *x0;
        let x1 = *x1;
        let x2 = *x2;
        let x3 = *x3;
        let x4 = *x4;
        let x5 = *x5;
        let x6 = *x6;
        let x7 = *x7;

        let a04 = simd.add(x0, x4);
        let s04 = simd.sub(x0, x4);
        let a26 = simd.add(x2, x6);
        let js26 = simd.mul_j(fwd, simd.sub(x2, x6));
        let a15 = simd.add(x1, x5);
        let s15 = simd.sub(x1, x5);
        let a37 = simd.add(x3, x7);
        let js37 = simd.mul_j(fwd, simd.sub(x3, x7));

        let a04_p1_a26 = simd.add(a04, a26);
        let s04_mj_s26 = simd.sub(s04, js26);
        let a04_m1_a26 = simd.sub(a04, a26);
        let s04_pj_s26 = simd.add(s04, js26);
        let a15_p1_a37 = simd.add(a15, a37);
        let w8_s15_mj_s37 = simd.mul_exp_neg_pi_over_8(fwd, simd.sub(s15, js37));
        let j_a15_m1_a37 = simd.mul_j(fwd, simd.sub(a15, a37));
        let v8_s15_pj_s37 = simd.mul_exp_pi_over_8(fwd, simd.add(s15, js37));

        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;
        let w4 = *w4;
        let w5 = *w5;
        let w6 = *w6;
        let w7 = *w7;

        let aa = simd.add(a04_p1_a26, a15_p1_a37);
        let bb = simd.mul(w1, simd.add(s04_mj_s26, w8_s15_mj_s37));
        let cc = simd.mul(w2, simd.sub(a04_m1_a26, j_a15_m1_a37));
        let dd = simd.mul(w3, simd.sub(s04_pj_s26, v8_s15_pj_s37));
        let ee = simd.mul(w4, simd.sub(a04_p1_a26, a15_p1_a37));
        let ff = simd.mul(w5, simd.sub(s04_mj_s26, w8_s15_mj_s37));
        let gg = simd.mul(w6, simd.add(a04_m1_a26, j_a15_m1_a37));
        let hh = simd.mul(w7, simd.add(s04_pj_s26, v8_s15_pj_s37));

        let ab = simd.catlo(aa, bb);
        y[0] = ab;
        let cd = simd.catlo(cc, dd);
        y[1] = cd;
        let ef = simd.catlo(ee, ff);
        y[2] = ef;
        let gh = simd.catlo(gg, hh);
        y[3] = gh;

        let ab = simd.cathi(aa, bb);
        y[4] = ab;
        let cd = simd.cathi(cc, dd);
        y[5] = cd;
        let ef = simd.cathi(ee, ff);
        y[6] = ef;
        let gh = simd.cathi(gg, hh);
        y[7] = gh;
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

    let y = pulp::as_arrays_mut::<8, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7) = split_8(x);
    let (_, w1, w2, w3, w4, w5, w6, w7) = split_8(w_init);

    for ((x0, x1, x2, x3, x4, x5, x6, x7), y, (w1, w2, w3, w4, w5, w6, w7)) in izip!(
        izip!(x0, x1, x2, x3, x4, x5, x6, x7),
        y,
        izip!(w1, w2, w3, w4, w5, w6, w7),
    ) {
        let x0 = *x0;
        let x1 = *x1;
        let x2 = *x2;
        let x3 = *x3;
        let x4 = *x4;
        let x5 = *x5;
        let x6 = *x6;
        let x7 = *x7;

        let a04 = simd.add(x0, x4);
        let s04 = simd.sub(x0, x4);
        let a26 = simd.add(x2, x6);
        let js26 = simd.mul_j(fwd, simd.sub(x2, x6));
        let a15 = simd.add(x1, x5);
        let s15 = simd.sub(x1, x5);
        let a37 = simd.add(x3, x7);
        let js37 = simd.mul_j(fwd, simd.sub(x3, x7));

        let a04_p1_a26 = simd.add(a04, a26);
        let s04_mj_s26 = simd.sub(s04, js26);
        let a04_m1_a26 = simd.sub(a04, a26);
        let s04_pj_s26 = simd.add(s04, js26);
        let a15_p1_a37 = simd.add(a15, a37);
        let w8_s15_mj_s37 = simd.mul_exp_neg_pi_over_8(fwd, simd.sub(s15, js37));
        let j_a15_m1_a37 = simd.mul_j(fwd, simd.sub(a15, a37));
        let v8_s15_pj_s37 = simd.mul_exp_pi_over_8(fwd, simd.add(s15, js37));

        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;
        let w4 = *w4;
        let w5 = *w5;
        let w6 = *w6;
        let w7 = *w7;

        let a = simd.add(a04_p1_a26, a15_p1_a37);
        let b = simd.mul(w1, simd.add(s04_mj_s26, w8_s15_mj_s37));
        let c = simd.mul(w2, simd.sub(a04_m1_a26, j_a15_m1_a37));
        let d = simd.mul(w3, simd.sub(s04_pj_s26, v8_s15_pj_s37));
        let e = simd.mul(w4, simd.sub(a04_p1_a26, a15_p1_a37));
        let f = simd.mul(w5, simd.sub(s04_mj_s26, w8_s15_mj_s37));
        let g = simd.mul(w6, simd.add(a04_m1_a26, j_a15_m1_a37));
        let h = simd.mul(w7, simd.add(s04_pj_s26, v8_s15_pj_s37));

        let (abcd0, abcd1, abcd2, abcd3) = simd.transpose(a, b, c, d);
        let (efgh0, efgh1, efgh2, efgh3) = simd.transpose(e, f, g, h);

        y[0] = abcd0;
        y[1] = efgh0;
        y[2] = abcd1;
        y[3] = efgh1;
        y[4] = abcd2;
        y[5] = efgh2;
        y[6] = abcd3;
        y[7] = efgh3;
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

    let w = pulp::as_arrays::<8, _>(w).0;

    let (x0, x1, x2, x3, x4, x5, x6, x7) = split_8(x);

    for (x0, x1, x2, x3, x4, x5, x6, x7, y, w) in izip!(
        x0.chunks_exact(simd_s),
        x1.chunks_exact(simd_s),
        x2.chunks_exact(simd_s),
        x3.chunks_exact(simd_s),
        x4.chunks_exact(simd_s),
        x5.chunks_exact(simd_s),
        x6.chunks_exact(simd_s),
        x7.chunks_exact(simd_s),
        y.chunks_exact_mut(8 * simd_s),
        w.chunks_exact(s),
    ) {
        let [_, w1, w2, w3, w4, w5, w6, w7] = w[0];

        let w1 = simd.splat(w1);
        let w2 = simd.splat(w2);
        let w3 = simd.splat(w3);
        let w4 = simd.splat(w4);
        let w5 = simd.splat(w5);
        let w6 = simd.splat(w6);
        let w7 = simd.splat(w7);

        let (y0, y1, y2, y3, y4, y5, y6, y7) = split_mut_8(y);

        for ((x0, x1, x2, x3, x4, x5, x6, x7), (y0, y1, y2, y3, y4, y5, y6, y7)) in izip!(
            izip!(x0, x1, x2, x3, x4, x5, x6, x7),
            izip!(y0, y1, y2, y3, y4, y5, y6, y7),
        ) {
            let x0 = *x0;
            let x1 = *x1;
            let x2 = *x2;
            let x3 = *x3;
            let x4 = *x4;
            let x5 = *x5;
            let x6 = *x6;
            let x7 = *x7;

            let a04 = simd.add(x0, x4);
            let s04 = simd.sub(x0, x4);
            let a26 = simd.add(x2, x6);
            let js26 = simd.mul_j(fwd, simd.sub(x2, x6));
            let a15 = simd.add(x1, x5);
            let s15 = simd.sub(x1, x5);
            let a37 = simd.add(x3, x7);
            let js37 = simd.mul_j(fwd, simd.sub(x3, x7));
            let a04_p1_a26 = simd.add(a04, a26);
            let s04_mj_s26 = simd.sub(s04, js26);
            let a04_m1_a26 = simd.sub(a04, a26);
            let s04_pj_s26 = simd.add(s04, js26);
            let a15_p1_a37 = simd.add(a15, a37);
            let w8_s15_mj_s37 = simd.mul_exp_neg_pi_over_8(fwd, simd.sub(s15, js37));
            let j_a15_m1_a37 = simd.mul_j(fwd, simd.sub(a15, a37));
            let v8_s15_pj_s37 = simd.mul_exp_pi_over_8(fwd, simd.add(s15, js37));

            *y0 = simd.add(a04_p1_a26, a15_p1_a37);
            *y1 = simd.mul(w1, simd.add(s04_mj_s26, w8_s15_mj_s37));
            *y2 = simd.mul(w2, simd.sub(a04_m1_a26, j_a15_m1_a37));
            *y3 = simd.mul(w3, simd.sub(s04_pj_s26, v8_s15_pj_s37));
            *y4 = simd.mul(w4, simd.sub(a04_p1_a26, a15_p1_a37));
            *y5 = simd.mul(w5, simd.sub(s04_mj_s26, w8_s15_mj_s37));
            *y6 = simd.mul(w6, simd.add(a04_m1_a26, j_a15_m1_a37));
            *y7 = simd.mul(w7, simd.add(s04_pj_s26, v8_s15_pj_s37));
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
    x4: c64xN,
    x5: c64xN,
    x6: c64xN,
    x7: c64xN,
) -> (c64xN, c64xN, c64xN, c64xN, c64xN, c64xN, c64xN, c64xN) {
    let a04 = simd.add(x0, x4);
    let s04 = simd.sub(x0, x4);
    let a26 = simd.add(x2, x6);
    let js26 = simd.mul_j(fwd, simd.sub(x2, x6));
    let a15 = simd.add(x1, x5);
    let s15 = simd.sub(x1, x5);
    let a37 = simd.add(x3, x7);
    let js37 = simd.mul_j(fwd, simd.sub(x3, x7));

    let a04_p1_a26 = simd.add(a04, a26);
    let s04_mj_s26 = simd.sub(s04, js26);
    let a04_m1_a26 = simd.sub(a04, a26);
    let s04_pj_s26 = simd.add(s04, js26);
    let a15_p1_a37 = simd.add(a15, a37);
    let w8_s15_mj_s37 = simd.mul_exp_neg_pi_over_8(fwd, simd.sub(s15, js37));
    let j_a15_m1_a37 = simd.mul_j(fwd, simd.sub(a15, a37));
    let v8_s15_pj_s37 = simd.mul_exp_pi_over_8(fwd, simd.add(s15, js37));

    (
        simd.add(a04_p1_a26, a15_p1_a37),
        simd.add(s04_mj_s26, w8_s15_mj_s37),
        simd.sub(a04_m1_a26, j_a15_m1_a37),
        simd.sub(s04_pj_s26, v8_s15_pj_s37),
        simd.sub(a04_p1_a26, a15_p1_a37),
        simd.sub(s04_mj_s26, w8_s15_mj_s37),
        simd.add(a04_m1_a26, j_a15_m1_a37),
        simd.add(s04_pj_s26, v8_s15_pj_s37),
    )
}

#[inline(always)]
pub fn stockham_dif8_end<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    write_to_x: bool,
    s: usize,
    x: &mut [c64xN],
    y: &mut [c64xN],
) {
    assert_eq!(s % simd.lane_count(), 0);
    let (x0, x1, x2, x3, x4, x5, x6, x7) = split_mut_8(x);
    let (y0, y1, y2, y3, y4, y5, y6, y7) = split_mut_8(y);

    // we create a fn pointer that will be force-inlined in release builds
    // but not in debug builds. this helps keep compile times low, since dead code
    // elimination handles this well in release builds. and the function pointer indirection
    // prevents inlining in debug builds.
    let last_butterfly: fn(_, _, _, _, _, _, _, _, _, _) -> _ = last_butterfly;

    if write_to_x {
        for (x0, x1, x2, x3, x4, x5, x6, x7) in izip!(x0, x1, x2, x3, x4, x5, x6, x7) {
            (*x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7) =
                last_butterfly(simd, fwd, *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7);
        }
    } else {
        for ((x0, x1, x2, x3, x4, x5, x6, x7), (y0, y1, y2, y3, y4, y5, y6, y7)) in izip!(
            izip!(x0, x1, x2, x3, x4, x5, x6, x7),
            izip!(y0, y1, y2, y3, y4, y5, y6, y7),
        ) {
            (*y0, *y1, *y2, *y3, *y4, *y5, *y6, *y7) =
                last_butterfly(simd, fwd, *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7);
        }
    }
}

struct Dif8<N: nat::Nat>(N);
impl<N: nat::Nat> nat::Nat for Dif8<N> {
    const VALUE: usize = N::VALUE;
}

// size 2
impl RecursiveFft for Dif8<nat::N0> {
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
impl RecursiveFft for Dif8<nat::N1> {
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
        crate::dif4::stockham_dif4_end(simd, fwd, write_to_x, s, x, y);
    }
}

// size 8
impl RecursiveFft for Dif8<nat::N2> {
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
        stockham_dif8_end(simd, fwd, write_to_x, s, x, y);
    }
}

impl<N: nat::Nat> RecursiveFft for Dif8<nat::Plus3<N>>
where
    Dif8<N>: RecursiveFft,
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
        Dif8::<N>::fft_recurse_impl(simd, fwd, !write_to_x, s * 8, y, x, w_init, w);
    }
}

pub(crate) fn fft_impl<c64xN: Pod>(simd: impl FftSimd<c64xN>) -> crate::FftImpl {
    let fwd = [
        fn_ptr::<true, Dif8<nat::N0>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N1>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N2>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N3>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N4>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N5>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N6>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N7>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N8>, _, _>(simd),
        fn_ptr::<true, Dif8<nat::N9>, _, _>(simd),
    ];
    let inv = [
        fn_ptr::<false, Dif8<nat::N0>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N1>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N2>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N3>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N4>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N5>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N6>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N7>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N8>, _, _>(simd),
        fn_ptr::<false, Dif8<nat::N9>, _, _>(simd),
    ];
    crate::FftImpl { fwd, inv }
}

pub fn fft_impl_dispatch(n: usize) -> [fn(&mut [c64], &mut [c64], &[c64], &[c64]); 2] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "nightly")]
        if let Some(simd) = pulp::x86::V4::try_new() {
            if n >= 8 * simd.lane_count() {
                return fft_impl(simd).make_fn_ptr(n);
            }
        }
        if let Some(simd) = pulp::x86::V3::try_new() {
            if n >= 8 * simd.lane_count() {
                return fft_impl(simd).make_fn_ptr(n);
            }
        }
    }
    fft_impl(crate::fft_simd::Scalar).make_fn_ptr(n)
}
