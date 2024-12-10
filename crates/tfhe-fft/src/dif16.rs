use crate::{
    c64,
    dif2::{split_2, split_mut_2},
    dif8::{split_8, split_mut_8},
    fft_simd::{FftSimd, FftSimdExt, Pod},
    fn_ptr, nat, RecursiveFft,
};

#[inline(always)]
pub fn split_16<T>(
    slice: &[T],
) -> (
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
    &[T],
) {
    let (slice01234567, slice89abcdef) = split_2(slice);
    let (slice0, slice1, slice2, slice3, slice4, slice5, slice6, slice7) = split_8(slice01234567);
    let (slice8, slice9, slicea, sliceb, slicec, sliced, slicee, slicef) = split_8(slice89abcdef);
    (
        slice0, slice1, slice2, slice3, slice4, slice5, slice6, slice7, slice8, slice9, slicea,
        sliceb, slicec, sliced, slicee, slicef,
    )
}
#[inline(always)]
pub fn split_mut_16<T>(
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
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
    &mut [T],
) {
    let (slice01234567, slice89abcdef) = split_mut_2(slice);
    let (slice0, slice1, slice2, slice3, slice4, slice5, slice6, slice7) =
        split_mut_8(slice01234567);
    let (slice8, slice9, slicea, sliceb, slicec, sliced, slicee, slicef) =
        split_mut_8(slice89abcdef);
    (
        slice0, slice1, slice2, slice3, slice4, slice5, slice6, slice7, slice8, slice9, slicea,
        sliceb, slicec, sliced, slicee, slicef,
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

    let y = pulp::as_arrays_mut::<16, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = split_16(x);
    let (_, w1, w2, w3, w4, w5, w6, w7, w8, w9, wa, wb, wc, wd, we, wf) = split_16(w_init);

    for (
        (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
        y,
        (w1, w2, w3, w4, w5, w6, w7, w8, w9, wa, wb, wc, wd, we, wf),
    ) in izip!(
        izip!(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
        y,
        izip!(w1, w2, w3, w4, w5, w6, w7, w8, w9, wa, wb, wc, wd, we, wf),
    ) {
        let x0 = *x0;
        let x1 = *x1;
        let x2 = *x2;
        let x3 = *x3;
        let x4 = *x4;
        let x5 = *x5;
        let x6 = *x6;
        let x7 = *x7;
        let x8 = *x8;
        let x9 = *x9;
        let xa = *xa;
        let xb = *xb;
        let xc = *xc;
        let xd = *xd;
        let xe = *xe;
        let xf = *xf;

        let a08 = simd.add(x0, x8);
        let s08 = simd.sub(x0, x8);
        let a4c = simd.add(x4, xc);
        let s4c = simd.sub(x4, xc);
        let a2a = simd.add(x2, xa);
        let s2a = simd.sub(x2, xa);
        let a6e = simd.add(x6, xe);
        let s6e = simd.sub(x6, xe);
        let a19 = simd.add(x1, x9);
        let s19 = simd.sub(x1, x9);
        let a5d = simd.add(x5, xd);
        let s5d = simd.sub(x5, xd);
        let a3b = simd.add(x3, xb);
        let s3b = simd.sub(x3, xb);
        let a7f = simd.add(x7, xf);
        let s7f = simd.sub(x7, xf);

        let js4c = simd.mul_j(fwd, s4c);
        let js6e = simd.mul_j(fwd, s6e);
        let js5d = simd.mul_j(fwd, s5d);
        let js7f = simd.mul_j(fwd, s7f);

        let a08p1a4c = simd.add(a08, a4c);
        let s08mjs4c = simd.sub(s08, js4c);
        let a08m1a4c = simd.sub(a08, a4c);
        let s08pjs4c = simd.add(s08, js4c);
        let a2ap1a6e = simd.add(a2a, a6e);
        let s2amjs6e = simd.sub(s2a, js6e);
        let a2am1a6e = simd.sub(a2a, a6e);
        let s2apjs6e = simd.add(s2a, js6e);
        let a19p1a5d = simd.add(a19, a5d);
        let s19mjs5d = simd.sub(s19, js5d);
        let a19m1a5d = simd.sub(a19, a5d);
        let s19pjs5d = simd.add(s19, js5d);
        let a3bp1a7f = simd.add(a3b, a7f);
        let s3bmjs7f = simd.sub(s3b, js7f);
        let a3bm1a7f = simd.sub(a3b, a7f);
        let s3bpjs7f = simd.add(s3b, js7f);

        let w8_s2amjs6e = simd.mul_exp_neg_pi_over_8(fwd, s2amjs6e);
        let j_a2am1a6e = simd.mul_j(fwd, a2am1a6e);
        let v8_s2apjs6e = simd.mul_exp_pi_over_8(fwd, s2apjs6e);

        let a08p1a4c_p1_a2ap1a6e = simd.add(a08p1a4c, a2ap1a6e);
        let s08mjs4c_pw_s2amjs6e = simd.add(s08mjs4c, w8_s2amjs6e);
        let a08m1a4c_mj_a2am1a6e = simd.sub(a08m1a4c, j_a2am1a6e);
        let s08pjs4c_mv_s2apjs6e = simd.sub(s08pjs4c, v8_s2apjs6e);
        let a08p1a4c_m1_a2ap1a6e = simd.sub(a08p1a4c, a2ap1a6e);
        let s08mjs4c_mw_s2amjs6e = simd.sub(s08mjs4c, w8_s2amjs6e);
        let a08m1a4c_pj_a2am1a6e = simd.add(a08m1a4c, j_a2am1a6e);
        let s08pjs4c_pv_s2apjs6e = simd.add(s08pjs4c, v8_s2apjs6e);

        let w8_s3bmjs7f = simd.mul_exp_neg_pi_over_8(fwd, s3bmjs7f);
        let j_a3bm1a7f = simd.mul_j(fwd, a3bm1a7f);
        let v8_s3bpjs7f = simd.mul_exp_pi_over_8(fwd, s3bpjs7f);

        let a19p1a5d_p1_a3bp1a7f = simd.add(a19p1a5d, a3bp1a7f);
        let s19mjs5d_pw_s3bmjs7f = simd.add(s19mjs5d, w8_s3bmjs7f);
        let a19m1a5d_mj_a3bm1a7f = simd.sub(a19m1a5d, j_a3bm1a7f);
        let s19pjs5d_mv_s3bpjs7f = simd.sub(s19pjs5d, v8_s3bpjs7f);
        let a19p1a5d_m1_a3bp1a7f = simd.sub(a19p1a5d, a3bp1a7f);
        let s19mjs5d_mw_s3bmjs7f = simd.sub(s19mjs5d, w8_s3bmjs7f);
        let a19m1a5d_pj_a3bm1a7f = simd.add(a19m1a5d, j_a3bm1a7f);
        let s19pjs5d_pv_s3bpjs7f = simd.add(s19pjs5d, v8_s3bpjs7f);

        let h1_s19mjs5d_pw_s3bmjs7f = simd.mul_exp_pi_over_16(fwd, s19mjs5d_pw_s3bmjs7f);
        let w8_a19m1a5d_mj_a3bm1a7f = simd.mul_exp_neg_pi_over_8(fwd, a19m1a5d_mj_a3bm1a7f);
        let h3_s19pjs5d_mv_s3bpjs7f = simd.mul_exp_17pi_over_16(fwd, s19pjs5d_mv_s3bpjs7f);
        let j_a19p1a5d_m1_a3bp1a7f = simd.mul_j(fwd, a19p1a5d_m1_a3bp1a7f);
        let hd_s19mjs5d_mw_s3bmjs7f = simd.mul_exp_neg_17pi_over_16(fwd, s19mjs5d_mw_s3bmjs7f);
        let v8_a19m1a5d_pj_a3bm1a7f = simd.mul_exp_pi_over_8(fwd, a19m1a5d_pj_a3bm1a7f);
        let hf_s19pjs5d_pv_s3bpjs7f = simd.mul_exp_neg_pi_over_16(fwd, s19pjs5d_pv_s3bpjs7f);

        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;
        let w4 = *w4;
        let w5 = *w5;
        let w6 = *w6;
        let w7 = *w7;
        let w8 = *w8;
        let w9 = *w9;
        let wa = *wa;
        let wb = *wb;
        let wc = *wc;
        let wd = *wd;
        let we = *we;
        let wf = *wf;

        let aa = simd.add(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);
        let bb = simd.mul(w1, simd.add(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f));
        let cc = simd.mul(w2, simd.add(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f));
        let dd = simd.mul(w3, simd.add(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f));
        let ee = simd.mul(w4, simd.sub(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f));
        let ff = simd.mul(w5, simd.sub(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f));
        let gg = simd.mul(w6, simd.sub(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f));
        let hh = simd.mul(w7, simd.sub(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f));

        let ii = simd.mul(w8, simd.sub(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f));
        let jj = simd.mul(w9, simd.sub(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f));
        let kk = simd.mul(wa, simd.sub(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f));
        let ll = simd.mul(wb, simd.sub(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f));
        let mm = simd.mul(wc, simd.add(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f));
        let nn = simd.mul(wd, simd.add(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f));
        let oo = simd.mul(we, simd.add(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f));
        let pp = simd.mul(wf, simd.add(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f));

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

        let ab = simd.catlo(aa, bb);
        y[0x0] = ab;
        let cd = simd.catlo(cc, dd);
        y[0x1] = cd;
        let ef = simd.catlo(ee, ff);
        y[0x2] = ef;
        let gh = simd.catlo(gg, hh);
        y[0x3] = gh;
        let ij = simd.catlo(ii, jj);
        y[0x4] = ij;
        let kl = simd.catlo(kk, ll);
        y[0x5] = kl;
        let mn = simd.catlo(mm, nn);
        y[0x6] = mn;
        let op = simd.catlo(oo, pp);
        y[0x7] = op;
        let ab = simd.cathi(aa, bb);
        y[0x8] = ab;
        let cd = simd.cathi(cc, dd);
        y[0x9] = cd;
        let ef = simd.cathi(ee, ff);
        y[0xa] = ef;
        let gh = simd.cathi(gg, hh);
        y[0xb] = gh;
        let ij = simd.cathi(ii, jj);
        y[0xc] = ij;
        let kl = simd.cathi(kk, ll);
        y[0xd] = kl;
        let mn = simd.cathi(mm, nn);
        y[0xe] = mn;
        let op = simd.cathi(oo, pp);
        y[0xf] = op;
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

    let y = pulp::as_arrays_mut::<16, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = split_16(x);
    let (_, w1, w2, w3, w4, w5, w6, w7, w8, w9, wa, wb, wc, wd, we, wf) = split_16(w_init);

    for (
        (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
        y,
        (w1, w2, w3, w4, w5, w6, w7, w8, w9, wa, wb, wc, wd, we, wf),
    ) in izip!(
        izip!(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
        y,
        izip!(w1, w2, w3, w4, w5, w6, w7, w8, w9, wa, wb, wc, wd, we, wf),
    ) {
        let x0 = *x0;
        let x1 = *x1;
        let x2 = *x2;
        let x3 = *x3;
        let x4 = *x4;
        let x5 = *x5;
        let x6 = *x6;
        let x7 = *x7;
        let x8 = *x8;
        let x9 = *x9;
        let xa = *xa;
        let xb = *xb;
        let xc = *xc;
        let xd = *xd;
        let xe = *xe;
        let xf = *xf;

        let a08 = simd.add(x0, x8);
        let s08 = simd.sub(x0, x8);
        let a4c = simd.add(x4, xc);
        let s4c = simd.sub(x4, xc);
        let a2a = simd.add(x2, xa);
        let s2a = simd.sub(x2, xa);
        let a6e = simd.add(x6, xe);
        let s6e = simd.sub(x6, xe);
        let a19 = simd.add(x1, x9);
        let s19 = simd.sub(x1, x9);
        let a5d = simd.add(x5, xd);
        let s5d = simd.sub(x5, xd);
        let a3b = simd.add(x3, xb);
        let s3b = simd.sub(x3, xb);
        let a7f = simd.add(x7, xf);
        let s7f = simd.sub(x7, xf);

        let js4c = simd.mul_j(fwd, s4c);
        let js6e = simd.mul_j(fwd, s6e);
        let js5d = simd.mul_j(fwd, s5d);
        let js7f = simd.mul_j(fwd, s7f);

        let a08p1a4c = simd.add(a08, a4c);
        let s08mjs4c = simd.sub(s08, js4c);
        let a08m1a4c = simd.sub(a08, a4c);
        let s08pjs4c = simd.add(s08, js4c);
        let a2ap1a6e = simd.add(a2a, a6e);
        let s2amjs6e = simd.sub(s2a, js6e);
        let a2am1a6e = simd.sub(a2a, a6e);
        let s2apjs6e = simd.add(s2a, js6e);
        let a19p1a5d = simd.add(a19, a5d);
        let s19mjs5d = simd.sub(s19, js5d);
        let a19m1a5d = simd.sub(a19, a5d);
        let s19pjs5d = simd.add(s19, js5d);
        let a3bp1a7f = simd.add(a3b, a7f);
        let s3bmjs7f = simd.sub(s3b, js7f);
        let a3bm1a7f = simd.sub(a3b, a7f);
        let s3bpjs7f = simd.add(s3b, js7f);

        let w8_s2amjs6e = simd.mul_exp_neg_pi_over_8(fwd, s2amjs6e);
        let j_a2am1a6e = simd.mul_j(fwd, a2am1a6e);
        let v8_s2apjs6e = simd.mul_exp_pi_over_8(fwd, s2apjs6e);

        let a08p1a4c_p1_a2ap1a6e = simd.add(a08p1a4c, a2ap1a6e);
        let s08mjs4c_pw_s2amjs6e = simd.add(s08mjs4c, w8_s2amjs6e);
        let a08m1a4c_mj_a2am1a6e = simd.sub(a08m1a4c, j_a2am1a6e);
        let s08pjs4c_mv_s2apjs6e = simd.sub(s08pjs4c, v8_s2apjs6e);
        let a08p1a4c_m1_a2ap1a6e = simd.sub(a08p1a4c, a2ap1a6e);
        let s08mjs4c_mw_s2amjs6e = simd.sub(s08mjs4c, w8_s2amjs6e);
        let a08m1a4c_pj_a2am1a6e = simd.add(a08m1a4c, j_a2am1a6e);
        let s08pjs4c_pv_s2apjs6e = simd.add(s08pjs4c, v8_s2apjs6e);

        let w8_s3bmjs7f = simd.mul_exp_neg_pi_over_8(fwd, s3bmjs7f);
        let j_a3bm1a7f = simd.mul_j(fwd, a3bm1a7f);
        let v8_s3bpjs7f = simd.mul_exp_pi_over_8(fwd, s3bpjs7f);

        let a19p1a5d_p1_a3bp1a7f = simd.add(a19p1a5d, a3bp1a7f);
        let s19mjs5d_pw_s3bmjs7f = simd.add(s19mjs5d, w8_s3bmjs7f);
        let a19m1a5d_mj_a3bm1a7f = simd.sub(a19m1a5d, j_a3bm1a7f);
        let s19pjs5d_mv_s3bpjs7f = simd.sub(s19pjs5d, v8_s3bpjs7f);
        let a19p1a5d_m1_a3bp1a7f = simd.sub(a19p1a5d, a3bp1a7f);
        let s19mjs5d_mw_s3bmjs7f = simd.sub(s19mjs5d, w8_s3bmjs7f);
        let a19m1a5d_pj_a3bm1a7f = simd.add(a19m1a5d, j_a3bm1a7f);
        let s19pjs5d_pv_s3bpjs7f = simd.add(s19pjs5d, v8_s3bpjs7f);

        let h1_s19mjs5d_pw_s3bmjs7f = simd.mul_exp_pi_over_16(fwd, s19mjs5d_pw_s3bmjs7f);
        let w8_a19m1a5d_mj_a3bm1a7f = simd.mul_exp_neg_pi_over_8(fwd, a19m1a5d_mj_a3bm1a7f);
        let h3_s19pjs5d_mv_s3bpjs7f = simd.mul_exp_17pi_over_16(fwd, s19pjs5d_mv_s3bpjs7f);
        let j_a19p1a5d_m1_a3bp1a7f = simd.mul_j(fwd, a19p1a5d_m1_a3bp1a7f);
        let hd_s19mjs5d_mw_s3bmjs7f = simd.mul_exp_neg_17pi_over_16(fwd, s19mjs5d_mw_s3bmjs7f);
        let v8_a19m1a5d_pj_a3bm1a7f = simd.mul_exp_pi_over_8(fwd, a19m1a5d_pj_a3bm1a7f);
        let hf_s19pjs5d_pv_s3bpjs7f = simd.mul_exp_neg_pi_over_16(fwd, s19pjs5d_pv_s3bpjs7f);

        let w1 = *w1;
        let w2 = *w2;
        let w3 = *w3;
        let w4 = *w4;
        let w5 = *w5;
        let w6 = *w6;
        let w7 = *w7;
        let w8 = *w8;
        let w9 = *w9;
        let wa = *wa;
        let wb = *wb;
        let wc = *wc;
        let wd = *wd;
        let we = *we;
        let wf = *wf;

        let a_ = simd.add(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);
        let b_ = simd.mul(w1, simd.add(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f));
        let c_ = simd.mul(w2, simd.add(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f));
        let d_ = simd.mul(w3, simd.add(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f));
        let e_ = simd.mul(w4, simd.sub(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f));
        let f_ = simd.mul(w5, simd.sub(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f));
        let g_ = simd.mul(w6, simd.sub(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f));
        let h_ = simd.mul(w7, simd.sub(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f));

        let i_ = simd.mul(w8, simd.sub(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f));
        let j_ = simd.mul(w9, simd.sub(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f));
        let k_ = simd.mul(wa, simd.sub(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f));
        let l_ = simd.mul(wb, simd.sub(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f));
        let m_ = simd.mul(wc, simd.add(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f));
        let n_ = simd.mul(wd, simd.add(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f));
        let o_ = simd.mul(we, simd.add(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f));
        let p_ = simd.mul(wf, simd.add(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f));

        let (abcd0, abcd1, abcd2, abcd3) = simd.transpose(a_, b_, c_, d_);
        let (efgh0, efgh1, efgh2, efgh3) = simd.transpose(e_, f_, g_, h_);
        let (ijkl0, ijkl1, ijkl2, ijkl3) = simd.transpose(i_, j_, k_, l_);
        let (mnop0, mnop1, mnop2, mnop3) = simd.transpose(m_, n_, o_, p_);

        y[0x0] = abcd0;
        y[0x1] = efgh0;
        y[0x2] = ijkl0;
        y[0x3] = mnop0;

        y[0x4] = abcd1;
        y[0x5] = efgh1;
        y[0x6] = ijkl1;
        y[0x7] = mnop1;

        y[0x8] = abcd2;
        y[0x9] = efgh2;
        y[0xa] = ijkl2;
        y[0xb] = mnop2;

        y[0xc] = abcd3;
        y[0xd] = efgh3;
        y[0xe] = ijkl3;
        y[0xf] = mnop3;
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

    let w = pulp::as_arrays::<16, _>(w).0;

    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = split_16(x);

    for ((x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf), y, w) in izip!(
        izip!(
            x0.chunks_exact(simd_s),
            x1.chunks_exact(simd_s),
            x2.chunks_exact(simd_s),
            x3.chunks_exact(simd_s),
            x4.chunks_exact(simd_s),
            x5.chunks_exact(simd_s),
            x6.chunks_exact(simd_s),
            x7.chunks_exact(simd_s),
            x8.chunks_exact(simd_s),
            x9.chunks_exact(simd_s),
            xa.chunks_exact(simd_s),
            xb.chunks_exact(simd_s),
            xc.chunks_exact(simd_s),
            xd.chunks_exact(simd_s),
            xe.chunks_exact(simd_s),
            xf.chunks_exact(simd_s),
        ),
        y.chunks_exact_mut(16 * simd_s),
        w.chunks_exact(s),
    ) {
        let [_, w1, w2, w3, w4, w5, w6, w7, w8, w9, wa, wb, wc, wd, we, wf] = w[0];

        let w1 = simd.splat(w1);
        let w2 = simd.splat(w2);
        let w3 = simd.splat(w3);
        let w4 = simd.splat(w4);
        let w5 = simd.splat(w5);
        let w6 = simd.splat(w6);
        let w7 = simd.splat(w7);
        let w8 = simd.splat(w8);
        let w9 = simd.splat(w9);
        let wa = simd.splat(wa);
        let wb = simd.splat(wb);
        let wc = simd.splat(wc);
        let wd = simd.splat(wd);
        let we = simd.splat(we);
        let wf = simd.splat(wf);

        let (y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf) = split_mut_16(y);

        for (
            (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
            (y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf),
        ) in izip!(
            izip!(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
            izip!(y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf),
        ) {
            let x0 = *x0;
            let x1 = *x1;
            let x2 = *x2;
            let x3 = *x3;
            let x4 = *x4;
            let x5 = *x5;
            let x6 = *x6;
            let x7 = *x7;
            let x8 = *x8;
            let x9 = *x9;
            let xa = *xa;
            let xb = *xb;
            let xc = *xc;
            let xd = *xd;
            let xe = *xe;
            let xf = *xf;

            let a08 = simd.add(x0, x8);
            let s08 = simd.sub(x0, x8);
            let a4c = simd.add(x4, xc);
            let s4c = simd.sub(x4, xc);
            let a2a = simd.add(x2, xa);
            let s2a = simd.sub(x2, xa);
            let a6e = simd.add(x6, xe);
            let s6e = simd.sub(x6, xe);
            let a19 = simd.add(x1, x9);
            let s19 = simd.sub(x1, x9);
            let a5d = simd.add(x5, xd);
            let s5d = simd.sub(x5, xd);
            let a3b = simd.add(x3, xb);
            let s3b = simd.sub(x3, xb);
            let a7f = simd.add(x7, xf);
            let s7f = simd.sub(x7, xf);

            let js4c = simd.mul_j(fwd, s4c);
            let js6e = simd.mul_j(fwd, s6e);
            let js5d = simd.mul_j(fwd, s5d);
            let js7f = simd.mul_j(fwd, s7f);

            let a08p1a4c = simd.add(a08, a4c);
            let s08mjs4c = simd.sub(s08, js4c);
            let a08m1a4c = simd.sub(a08, a4c);
            let s08pjs4c = simd.add(s08, js4c);
            let a2ap1a6e = simd.add(a2a, a6e);
            let s2amjs6e = simd.sub(s2a, js6e);
            let a2am1a6e = simd.sub(a2a, a6e);
            let s2apjs6e = simd.add(s2a, js6e);
            let a19p1a5d = simd.add(a19, a5d);
            let s19mjs5d = simd.sub(s19, js5d);
            let a19m1a5d = simd.sub(a19, a5d);
            let s19pjs5d = simd.add(s19, js5d);
            let a3bp1a7f = simd.add(a3b, a7f);
            let s3bmjs7f = simd.sub(s3b, js7f);
            let a3bm1a7f = simd.sub(a3b, a7f);
            let s3bpjs7f = simd.add(s3b, js7f);

            let w8_s2amjs6e = simd.mul_exp_neg_pi_over_8(fwd, s2amjs6e);
            let j_a2am1a6e = simd.mul_j(fwd, a2am1a6e);
            let v8_s2apjs6e = simd.mul_exp_pi_over_8(fwd, s2apjs6e);

            let a08p1a4c_p1_a2ap1a6e = simd.add(a08p1a4c, a2ap1a6e);
            let s08mjs4c_pw_s2amjs6e = simd.add(s08mjs4c, w8_s2amjs6e);
            let a08m1a4c_mj_a2am1a6e = simd.sub(a08m1a4c, j_a2am1a6e);
            let s08pjs4c_mv_s2apjs6e = simd.sub(s08pjs4c, v8_s2apjs6e);
            let a08p1a4c_m1_a2ap1a6e = simd.sub(a08p1a4c, a2ap1a6e);
            let s08mjs4c_mw_s2amjs6e = simd.sub(s08mjs4c, w8_s2amjs6e);
            let a08m1a4c_pj_a2am1a6e = simd.add(a08m1a4c, j_a2am1a6e);
            let s08pjs4c_pv_s2apjs6e = simd.add(s08pjs4c, v8_s2apjs6e);

            let w8_s3bmjs7f = simd.mul_exp_neg_pi_over_8(fwd, s3bmjs7f);
            let j_a3bm1a7f = simd.mul_j(fwd, a3bm1a7f);
            let v8_s3bpjs7f = simd.mul_exp_pi_over_8(fwd, s3bpjs7f);

            let a19p1a5d_p1_a3bp1a7f = simd.add(a19p1a5d, a3bp1a7f);
            let s19mjs5d_pw_s3bmjs7f = simd.add(s19mjs5d, w8_s3bmjs7f);
            let a19m1a5d_mj_a3bm1a7f = simd.sub(a19m1a5d, j_a3bm1a7f);
            let s19pjs5d_mv_s3bpjs7f = simd.sub(s19pjs5d, v8_s3bpjs7f);
            let a19p1a5d_m1_a3bp1a7f = simd.sub(a19p1a5d, a3bp1a7f);
            let s19mjs5d_mw_s3bmjs7f = simd.sub(s19mjs5d, w8_s3bmjs7f);
            let a19m1a5d_pj_a3bm1a7f = simd.add(a19m1a5d, j_a3bm1a7f);
            let s19pjs5d_pv_s3bpjs7f = simd.add(s19pjs5d, v8_s3bpjs7f);

            let h1_s19mjs5d_pw_s3bmjs7f = simd.mul_exp_pi_over_16(fwd, s19mjs5d_pw_s3bmjs7f);
            let w8_a19m1a5d_mj_a3bm1a7f = simd.mul_exp_neg_pi_over_8(fwd, a19m1a5d_mj_a3bm1a7f);
            let h3_s19pjs5d_mv_s3bpjs7f = simd.mul_exp_17pi_over_16(fwd, s19pjs5d_mv_s3bpjs7f);
            let j_a19p1a5d_m1_a3bp1a7f = simd.mul_j(fwd, a19p1a5d_m1_a3bp1a7f);
            let hd_s19mjs5d_mw_s3bmjs7f = simd.mul_exp_neg_17pi_over_16(fwd, s19mjs5d_mw_s3bmjs7f);
            let v8_a19m1a5d_pj_a3bm1a7f = simd.mul_exp_pi_over_8(fwd, a19m1a5d_pj_a3bm1a7f);
            let hf_s19pjs5d_pv_s3bpjs7f = simd.mul_exp_neg_pi_over_16(fwd, s19pjs5d_pv_s3bpjs7f);

            *y0 = simd.add(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);
            *y1 = simd.mul(w1, simd.add(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f));
            *y2 = simd.mul(w2, simd.add(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f));
            *y3 = simd.mul(w3, simd.add(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f));
            *y4 = simd.mul(w4, simd.sub(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f));
            *y5 = simd.mul(w5, simd.sub(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f));
            *y6 = simd.mul(w6, simd.sub(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f));
            *y7 = simd.mul(w7, simd.sub(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f));

            *y8 = simd.mul(w8, simd.sub(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f));
            *y9 = simd.mul(w9, simd.sub(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f));
            *ya = simd.mul(wa, simd.sub(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f));
            *yb = simd.mul(wb, simd.sub(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f));
            *yc = simd.mul(wc, simd.add(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f));
            *yd = simd.mul(wd, simd.add(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f));
            *ye = simd.mul(we, simd.add(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f));
            *yf = simd.mul(wf, simd.add(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f));
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
    x8: c64xN,
    x9: c64xN,
    xa: c64xN,
    xb: c64xN,
    xc: c64xN,
    xd: c64xN,
    xe: c64xN,
    xf: c64xN,
) -> (
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
    c64xN,
) {
    let a08 = simd.add(x0, x8);
    let s08 = simd.sub(x0, x8);
    let a4c = simd.add(x4, xc);
    let s4c = simd.sub(x4, xc);
    let a2a = simd.add(x2, xa);
    let s2a = simd.sub(x2, xa);
    let a6e = simd.add(x6, xe);
    let s6e = simd.sub(x6, xe);
    let a19 = simd.add(x1, x9);
    let s19 = simd.sub(x1, x9);
    let a5d = simd.add(x5, xd);
    let s5d = simd.sub(x5, xd);
    let a3b = simd.add(x3, xb);
    let s3b = simd.sub(x3, xb);
    let a7f = simd.add(x7, xf);
    let s7f = simd.sub(x7, xf);

    let js4c = simd.mul_j(fwd, s4c);
    let js6e = simd.mul_j(fwd, s6e);
    let js5d = simd.mul_j(fwd, s5d);
    let js7f = simd.mul_j(fwd, s7f);

    let a08p1a4c = simd.add(a08, a4c);
    let s08mjs4c = simd.sub(s08, js4c);
    let a08m1a4c = simd.sub(a08, a4c);
    let s08pjs4c = simd.add(s08, js4c);
    let a2ap1a6e = simd.add(a2a, a6e);
    let s2amjs6e = simd.sub(s2a, js6e);
    let a2am1a6e = simd.sub(a2a, a6e);
    let s2apjs6e = simd.add(s2a, js6e);
    let a19p1a5d = simd.add(a19, a5d);
    let s19mjs5d = simd.sub(s19, js5d);
    let a19m1a5d = simd.sub(a19, a5d);
    let s19pjs5d = simd.add(s19, js5d);
    let a3bp1a7f = simd.add(a3b, a7f);
    let s3bmjs7f = simd.sub(s3b, js7f);
    let a3bm1a7f = simd.sub(a3b, a7f);
    let s3bpjs7f = simd.add(s3b, js7f);

    let w8_s2amjs6e = simd.mul_exp_neg_pi_over_8(fwd, s2amjs6e);
    let j_a2am1a6e = simd.mul_j(fwd, a2am1a6e);
    let v8_s2apjs6e = simd.mul_exp_pi_over_8(fwd, s2apjs6e);

    let a08p1a4c_p1_a2ap1a6e = simd.add(a08p1a4c, a2ap1a6e);
    let s08mjs4c_pw_s2amjs6e = simd.add(s08mjs4c, w8_s2amjs6e);
    let a08m1a4c_mj_a2am1a6e = simd.sub(a08m1a4c, j_a2am1a6e);
    let s08pjs4c_mv_s2apjs6e = simd.sub(s08pjs4c, v8_s2apjs6e);
    let a08p1a4c_m1_a2ap1a6e = simd.sub(a08p1a4c, a2ap1a6e);
    let s08mjs4c_mw_s2amjs6e = simd.sub(s08mjs4c, w8_s2amjs6e);
    let a08m1a4c_pj_a2am1a6e = simd.add(a08m1a4c, j_a2am1a6e);
    let s08pjs4c_pv_s2apjs6e = simd.add(s08pjs4c, v8_s2apjs6e);

    let w8_s3bmjs7f = simd.mul_exp_neg_pi_over_8(fwd, s3bmjs7f);
    let j_a3bm1a7f = simd.mul_j(fwd, a3bm1a7f);
    let v8_s3bpjs7f = simd.mul_exp_pi_over_8(fwd, s3bpjs7f);

    let a19p1a5d_p1_a3bp1a7f = simd.add(a19p1a5d, a3bp1a7f);
    let s19mjs5d_pw_s3bmjs7f = simd.add(s19mjs5d, w8_s3bmjs7f);
    let a19m1a5d_mj_a3bm1a7f = simd.sub(a19m1a5d, j_a3bm1a7f);
    let s19pjs5d_mv_s3bpjs7f = simd.sub(s19pjs5d, v8_s3bpjs7f);
    let a19p1a5d_m1_a3bp1a7f = simd.sub(a19p1a5d, a3bp1a7f);
    let s19mjs5d_mw_s3bmjs7f = simd.sub(s19mjs5d, w8_s3bmjs7f);
    let a19m1a5d_pj_a3bm1a7f = simd.add(a19m1a5d, j_a3bm1a7f);
    let s19pjs5d_pv_s3bpjs7f = simd.add(s19pjs5d, v8_s3bpjs7f);

    let h1_s19mjs5d_pw_s3bmjs7f = simd.mul_exp_pi_over_16(fwd, s19mjs5d_pw_s3bmjs7f);
    let w8_a19m1a5d_mj_a3bm1a7f = simd.mul_exp_neg_pi_over_8(fwd, a19m1a5d_mj_a3bm1a7f);
    let h3_s19pjs5d_mv_s3bpjs7f = simd.mul_exp_17pi_over_16(fwd, s19pjs5d_mv_s3bpjs7f);
    let j_a19p1a5d_m1_a3bp1a7f = simd.mul_j(fwd, a19p1a5d_m1_a3bp1a7f);
    let hd_s19mjs5d_mw_s3bmjs7f = simd.mul_exp_neg_17pi_over_16(fwd, s19mjs5d_mw_s3bmjs7f);
    let v8_a19m1a5d_pj_a3bm1a7f = simd.mul_exp_pi_over_8(fwd, a19m1a5d_pj_a3bm1a7f);
    let hf_s19pjs5d_pv_s3bpjs7f = simd.mul_exp_neg_pi_over_16(fwd, s19pjs5d_pv_s3bpjs7f);

    (
        simd.add(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f),
        simd.add(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f),
        simd.add(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f),
        simd.add(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f),
        simd.sub(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f),
        simd.sub(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f),
        simd.sub(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f),
        simd.sub(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f),
        simd.sub(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f),
        simd.sub(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f),
        simd.sub(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f),
        simd.sub(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f),
        simd.add(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f),
        simd.add(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f),
        simd.add(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f),
        simd.add(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f),
    )
}

#[inline(always)]
pub fn stockham_dif16_end<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    write_to_x: bool,
    s: usize,
    x: &mut [c64xN],
    y: &mut [c64xN],
) {
    assert_eq!(s % simd.lane_count(), 0);
    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = split_mut_16(x);
    let (y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf) = split_mut_16(y);

    // we create a fn pointer that will be force-inlined in release builds
    // but not in debug builds. this helps keep compile times low, since dead code
    // elimination handles this well in release builds. and the function pointer indirection
    // prevents inlining in debug builds.
    let last_butterfly: fn(_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) -> _ =
        last_butterfly;

    if write_to_x {
        for (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) in
            izip!(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf)
        {
            (
                *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7, *x8, *x9, *xa, *xb, *xc, *xd, *xe, *xf,
            ) = last_butterfly(
                simd, fwd, *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7, *x8, *x9, *xa, *xb, *xc, *xd,
                *xe, *xf,
            );
        }
    } else {
        for (
            (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
            (y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf),
        ) in izip!(
            izip!(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
            izip!(y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf),
        ) {
            (
                *y0, *y1, *y2, *y3, *y4, *y5, *y6, *y7, *y8, *y9, *ya, *yb, *yc, *yd, *ye, *yf,
            ) = last_butterfly(
                simd, fwd, *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7, *x8, *x9, *xa, *xb, *xc, *xd,
                *xe, *xf,
            );
        }
    }
}

struct Dif16<N: nat::Nat>(N);
impl<N: nat::Nat> nat::Nat for Dif16<N> {
    const VALUE: usize = N::VALUE;
}

// size 2
impl RecursiveFft for Dif16<nat::N0> {
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
impl RecursiveFft for Dif16<nat::N1> {
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
impl RecursiveFft for Dif16<nat::N2> {
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
        crate::dif8::stockham_dif8_end(simd, fwd, write_to_x, s, x, y);
    }
}

// size 16
impl RecursiveFft for Dif16<nat::N3> {
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
        stockham_dif16_end(simd, fwd, write_to_x, s, x, y);
    }
}

impl<N: nat::Nat> RecursiveFft for Dif16<nat::Plus4<N>>
where
    Dif16<N>: RecursiveFft,
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
        Dif16::<N>::fft_recurse_impl(simd, fwd, !write_to_x, s * 16, y, x, w_init, w);
    }
}

pub(crate) fn fft_impl<c64xN: Pod>(simd: impl FftSimd<c64xN>) -> crate::FftImpl {
    let fwd = [
        fn_ptr::<true, Dif16<nat::N0>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N1>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N2>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N3>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N4>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N5>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N6>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N7>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N8>, _, _>(simd),
        fn_ptr::<true, Dif16<nat::N9>, _, _>(simd),
    ];
    let inv = [
        fn_ptr::<false, Dif16<nat::N0>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N1>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N2>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N3>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N4>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N5>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N6>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N7>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N8>, _, _>(simd),
        fn_ptr::<false, Dif16<nat::N9>, _, _>(simd),
    ];
    crate::FftImpl { fwd, inv }
}

pub fn fft_impl_dispatch(n: usize) -> [fn(&mut [c64], &mut [c64], &[c64], &[c64]); 2] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "nightly")]
        if let Some(simd) = pulp::x86::V4::try_new() {
            if n >= 16 * simd.lane_count() {
                return fft_impl(simd).make_fn_ptr(n);
            }
        }
        if let Some(simd) = pulp::x86::V3::try_new() {
            if n >= 16 * simd.lane_count() {
                return fft_impl(simd).make_fn_ptr(n);
            }
        }
    }
    fft_impl(crate::fft_simd::Scalar).make_fn_ptr(n)
}
