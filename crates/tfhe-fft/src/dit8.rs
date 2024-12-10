use crate::{
    c64,
    dif8::{split_8, split_mut_8},
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

    let y = pulp::as_arrays::<8, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7) = split_mut_8(x);
    let (_, w1, w2, w3, w4, w5, w6, w7) = split_8(w_init);

    for ((x0, x1, x2, x3, x4, x5, x6, x7), y, (w1, w2, w3, w4, w5, w6, w7)) in izip!(
        izip!(x0, x1, x2, x3, x4, x5, x6, x7),
        y,
        izip!(w1, w2, w3, w4, w5, w6, w7),
    ) {
        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;
        let w4 = *w4;
        let w5 = *w5;
        let w6 = *w6;
        let w7 = *w7;

        let ab_0 = y[0];
        let cd_0 = y[1];
        let ef_0 = y[2];
        let gh_0 = y[3];
        let ab_1 = y[4];
        let cd_1 = y[5];
        let ef_1 = y[6];
        let gh_1 = y[7];

        let y0 = simd.catlo(ab_0, ab_1);
        let y1 = simd.mul(w1, simd.cathi(ab_0, ab_1));
        let y2 = simd.mul(w2, simd.catlo(cd_0, cd_1));
        let y3 = simd.mul(w3, simd.cathi(cd_0, cd_1));
        let y4 = simd.mul(w4, simd.catlo(ef_0, ef_1));
        let y5 = simd.mul(w5, simd.cathi(ef_0, ef_1));
        let y6 = simd.mul(w6, simd.catlo(gh_0, gh_1));
        let y7 = simd.mul(w7, simd.cathi(gh_0, gh_1));

        let a04 = simd.add(y0, y4);
        let s04 = simd.sub(y0, y4);
        let a26 = simd.add(y2, y6);
        let js26 = simd.mul_j(fwd, simd.sub(y2, y6));
        let a15 = simd.add(y1, y5);
        let s15 = simd.sub(y1, y5);
        let a37 = simd.add(y3, y7);
        let js37 = simd.mul_j(fwd, simd.sub(y3, y7));

        let a04_p1_a26 = simd.add(a04, a26);
        let a15_p1_a37 = simd.add(a15, a37);
        *x0 = simd.add(a04_p1_a26, a15_p1_a37);
        *x4 = simd.sub(a04_p1_a26, a15_p1_a37);

        let s04_mj_s26 = simd.sub(s04, js26);
        let w8_s15_mj_s37 = simd.mul_exp_neg_pi_over_8(fwd, simd.sub(s15, js37));
        *x1 = simd.add(s04_mj_s26, w8_s15_mj_s37);
        *x5 = simd.sub(s04_mj_s26, w8_s15_mj_s37);

        let a04_m1_a26 = simd.sub(a04, a26);
        let j_a15_m1_a37 = simd.mul_j(fwd, simd.sub(a15, a37));
        *x2 = simd.sub(a04_m1_a26, j_a15_m1_a37);
        *x6 = simd.add(a04_m1_a26, j_a15_m1_a37);

        let s04_pj_s26 = simd.add(s04, js26);
        let v8_s15_pj_s37 = simd.mul_exp_pi_over_8(fwd, simd.add(s15, js37));
        *x3 = simd.sub(s04_pj_s26, v8_s15_pj_s37);
        *x7 = simd.add(s04_pj_s26, v8_s15_pj_s37);
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

    let y = pulp::as_arrays::<8, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7) = split_mut_8(x);
    let (_, w1, w2, w3, w4, w5, w6, w7) = split_8(w_init);

    for ((x0, x1, x2, x3, x4, x5, x6, x7), y, (w1, w2, w3, w4, w5, w6, w7)) in izip!(
        izip!(x0, x1, x2, x3, x4, x5, x6, x7),
        y,
        izip!(w1, w2, w3, w4, w5, w6, w7),
    ) {
        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;
        let w4 = *w4;
        let w5 = *w5;
        let w6 = *w6;
        let w7 = *w7;

        let abcd_0 = y[0];
        let efgh_0 = y[1];
        let abcd_1 = y[2];
        let efgh_1 = y[3];
        let abcd_2 = y[4];
        let efgh_2 = y[5];
        let abcd_3 = y[6];
        let efgh_3 = y[7];

        let (a, b, c, d) = simd.transpose(abcd_0, abcd_1, abcd_2, abcd_3);
        let (e, f, g, h) = simd.transpose(efgh_0, efgh_1, efgh_2, efgh_3);

        let y0 = a;
        let y1 = simd.mul(w1, b);
        let y2 = simd.mul(w2, c);
        let y3 = simd.mul(w3, d);
        let y4 = simd.mul(w4, e);
        let y5 = simd.mul(w5, f);
        let y6 = simd.mul(w6, g);
        let y7 = simd.mul(w7, h);

        let a04 = simd.add(y0, y4);
        let s04 = simd.sub(y0, y4);
        let a26 = simd.add(y2, y6);
        let js26 = simd.mul_j(fwd, simd.sub(y2, y6));
        let a15 = simd.add(y1, y5);
        let s15 = simd.sub(y1, y5);
        let a37 = simd.add(y3, y7);
        let js37 = simd.mul_j(fwd, simd.sub(y3, y7));

        let a04_p1_a26 = simd.add(a04, a26);
        let a15_p1_a37 = simd.add(a15, a37);
        *x0 = simd.add(a04_p1_a26, a15_p1_a37);
        *x4 = simd.sub(a04_p1_a26, a15_p1_a37);

        let s04_mj_s26 = simd.sub(s04, js26);
        let w8_s15_mj_s37 = simd.mul_exp_neg_pi_over_8(fwd, simd.sub(s15, js37));
        *x1 = simd.add(s04_mj_s26, w8_s15_mj_s37);
        *x5 = simd.sub(s04_mj_s26, w8_s15_mj_s37);

        let a04_m1_a26 = simd.sub(a04, a26);
        let j_a15_m1_a37 = simd.mul_j(fwd, simd.sub(a15, a37));
        *x2 = simd.sub(a04_m1_a26, j_a15_m1_a37);
        *x6 = simd.add(a04_m1_a26, j_a15_m1_a37);

        let s04_pj_s26 = simd.add(s04, js26);
        let v8_s15_pj_s37 = simd.mul_exp_pi_over_8(fwd, simd.add(s15, js37));
        *x3 = simd.sub(s04_pj_s26, v8_s15_pj_s37);
        *x7 = simd.add(s04_pj_s26, v8_s15_pj_s37);
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

    let w = pulp::as_arrays::<8, _>(w).0;

    let (x0, x1, x2, x3, x4, x5, x6, x7) = split_mut_8(x);

    for (x0, x1, x2, x3, x4, x5, x6, x7, y, w) in izip!(
        x0.chunks_exact_mut(simd_s),
        x1.chunks_exact_mut(simd_s),
        x2.chunks_exact_mut(simd_s),
        x3.chunks_exact_mut(simd_s),
        x4.chunks_exact_mut(simd_s),
        x5.chunks_exact_mut(simd_s),
        x6.chunks_exact_mut(simd_s),
        x7.chunks_exact_mut(simd_s),
        y.chunks_exact(8 * simd_s),
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

        let (y0, y1, y2, y3, y4, y5, y6, y7) = split_8(y);

        for ((x0, x1, x2, x3, x4, x5, x6, x7), (y0, y1, y2, y3, y4, y5, y6, y7)) in izip!(
            izip!(x0, x1, x2, x3, x4, x5, x6, x7),
            izip!(y0, y1, y2, y3, y4, y5, y6, y7),
        ) {
            let y0 = *y0;
            let y1 = simd.mul(w1, *y1);
            let y2 = simd.mul(w2, *y2);
            let y3 = simd.mul(w3, *y3);
            let y4 = simd.mul(w4, *y4);
            let y5 = simd.mul(w5, *y5);
            let y6 = simd.mul(w6, *y6);
            let y7 = simd.mul(w7, *y7);
            let a04 = simd.add(y0, y4);
            let s04 = simd.sub(y0, y4);
            let a26 = simd.add(y2, y6);
            let js26 = simd.mul_j(fwd, simd.sub(y2, y6));
            let a15 = simd.add(y1, y5);
            let s15 = simd.sub(y1, y5);
            let a37 = simd.add(y3, y7);
            let js37 = simd.mul_j(fwd, simd.sub(y3, y7));

            let a04_p1_a26 = simd.add(a04, a26);
            let a15_p1_a37 = simd.add(a15, a37);
            *x0 = simd.add(a04_p1_a26, a15_p1_a37);
            *x4 = simd.sub(a04_p1_a26, a15_p1_a37);

            let s04_mj_s26 = simd.sub(s04, js26);
            let w8_s15_mj_s37 = simd.mul_exp_neg_pi_over_8(fwd, simd.sub(s15, js37));
            *x1 = simd.add(s04_mj_s26, w8_s15_mj_s37);
            *x5 = simd.sub(s04_mj_s26, w8_s15_mj_s37);

            let a04_m1_a26 = simd.sub(a04, a26);
            let j_a15_m1_a37 = simd.mul_j(fwd, simd.sub(a15, a37));
            *x2 = simd.sub(a04_m1_a26, j_a15_m1_a37);
            *x6 = simd.add(a04_m1_a26, j_a15_m1_a37);

            let s04_pj_s26 = simd.add(s04, js26);
            let v8_s15_pj_s37 = simd.mul_exp_pi_over_8(fwd, simd.add(s15, js37));
            *x3 = simd.sub(s04_pj_s26, v8_s15_pj_s37);
            *x7 = simd.add(s04_pj_s26, v8_s15_pj_s37);
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
pub fn stockham_dit8_end<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    read_from_x: bool,
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

    if read_from_x {
        for (x0, x1, x2, x3, x4, x5, x6, x7) in izip!(x0, x1, x2, x3, x4, x5, x6, x7) {
            (*x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7) =
                last_butterfly(simd, fwd, *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7);
        }
    } else {
        for ((x0, x1, x2, x3, x4, x5, x6, x7), (y0, y1, y2, y3, y4, y5, y6, y7)) in izip!(
            izip!(x0, x1, x2, x3, x4, x5, x6, x7),
            izip!(y0, y1, y2, y3, y4, y5, y6, y7),
        ) {
            (*x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7) =
                last_butterfly(simd, fwd, *y0, *y1, *y2, *y3, *y4, *y5, *y6, *y7);
        }
    }
}

struct Dit8<N: nat::Nat>(N);
impl<N: nat::Nat> nat::Nat for Dit8<N> {
    const VALUE: usize = N::VALUE;
}

// size 2
impl RecursiveFft for Dit8<nat::N0> {
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
impl RecursiveFft for Dit8<nat::N1> {
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
        crate::dit4::stockham_dit4_end(simd, fwd, read_from_x, s, x, y);
    }
}

// size 8
impl RecursiveFft for Dit8<nat::N2> {
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
        stockham_dit8_end(simd, fwd, read_from_x, s, x, y);
    }
}

impl<N: nat::Nat> RecursiveFft for Dit8<nat::Plus3<N>>
where
    Dit8<N>: RecursiveFft,
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
        Dit8::<N>::fft_recurse_impl(simd, fwd, !read_from_x, s * 8, y, x, w_init, w);
        stockham_core(simd, fwd, s, x, y, w_init, w);
    }
}

pub(crate) fn fft_impl<c64xN: Pod>(simd: impl FftSimd<c64xN>) -> crate::FftImpl {
    let fwd = [
        fn_ptr::<true, Dit8<nat::N0>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N1>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N2>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N3>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N4>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N5>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N6>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N7>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N8>, _, _>(simd),
        fn_ptr::<true, Dit8<nat::N9>, _, _>(simd),
    ];
    let inv = [
        fn_ptr::<false, Dit8<nat::N0>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N1>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N2>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N3>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N4>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N5>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N6>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N7>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N8>, _, _>(simd),
        fn_ptr::<false, Dit8<nat::N9>, _, _>(simd),
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
