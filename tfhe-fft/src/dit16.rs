use crate::{
    c64,
    dif16::{split_16, split_mut_16},
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

    let y = pulp::as_arrays::<16, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = split_mut_16(x);
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

        let ab_0 = y[0x0];
        let cd_0 = y[0x1];
        let ef_0 = y[0x2];
        let gh_0 = y[0x3];
        let ij_0 = y[0x4];
        let kl_0 = y[0x5];
        let mn_0 = y[0x6];
        let op_0 = y[0x7];
        let ab_1 = y[0x8];
        let cd_1 = y[0x9];
        let ef_1 = y[0xa];
        let gh_1 = y[0xb];
        let ij_1 = y[0xc];
        let kl_1 = y[0xd];
        let mn_1 = y[0xe];
        let op_1 = y[0xf];

        let y0 = simd.catlo(ab_0, ab_1);
        let y1 = simd.mul(w1, simd.cathi(ab_0, ab_1));
        let y2 = simd.mul(w2, simd.catlo(cd_0, cd_1));
        let y3 = simd.mul(w3, simd.cathi(cd_0, cd_1));
        let y4 = simd.mul(w4, simd.catlo(ef_0, ef_1));
        let y5 = simd.mul(w5, simd.cathi(ef_0, ef_1));
        let y6 = simd.mul(w6, simd.catlo(gh_0, gh_1));
        let y7 = simd.mul(w7, simd.cathi(gh_0, gh_1));

        let y8 = simd.mul(w8, simd.catlo(ij_0, ij_1));
        let y9 = simd.mul(w9, simd.cathi(ij_0, ij_1));
        let ya = simd.mul(wa, simd.catlo(kl_0, kl_1));
        let yb = simd.mul(wb, simd.cathi(kl_0, kl_1));
        let yc = simd.mul(wc, simd.catlo(mn_0, mn_1));
        let yd = simd.mul(wd, simd.cathi(mn_0, mn_1));
        let ye = simd.mul(we, simd.catlo(op_0, op_1));
        let yf = simd.mul(wf, simd.cathi(op_0, op_1));

        let a08 = simd.add(y0, y8);
        let s08 = simd.sub(y0, y8);
        let a4c = simd.add(y4, yc);
        let s4c = simd.sub(y4, yc);
        let a2a = simd.add(y2, ya);
        let s2a = simd.sub(y2, ya);
        let a6e = simd.add(y6, ye);
        let s6e = simd.sub(y6, ye);
        let a19 = simd.add(y1, y9);
        let s19 = simd.sub(y1, y9);
        let a5d = simd.add(y5, yd);
        let s5d = simd.sub(y5, yd);
        let a3b = simd.add(y3, yb);
        let s3b = simd.sub(y3, yb);
        let a7f = simd.add(y7, yf);
        let s7f = simd.sub(y7, yf);

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

        *x0 = simd.add(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);
        *x8 = simd.sub(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);

        let h1_s19mjs5d_pw_s3bmjs7f = simd.mul_exp_pi_over_16(fwd, s19mjs5d_pw_s3bmjs7f);
        *x1 = simd.add(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f);
        *x9 = simd.sub(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f);

        let w8_a19m1a5d_mj_a3bm1a7f = simd.mul_exp_neg_pi_over_8(fwd, a19m1a5d_mj_a3bm1a7f);
        *x2 = simd.add(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f);
        *xa = simd.sub(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f);

        let h3_s19pjs5d_mv_s3bpjs7f = simd.mul_exp_17pi_over_16(fwd, s19pjs5d_mv_s3bpjs7f);
        *x3 = simd.add(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f);
        *xb = simd.sub(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f);

        let j_a19p1a5d_m1_a3bp1a7f = simd.mul_j(fwd, a19p1a5d_m1_a3bp1a7f);
        *x4 = simd.sub(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f);
        *xc = simd.add(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f);

        let hd_s19mjs5d_mw_s3bmjs7f = simd.mul_exp_neg_17pi_over_16(fwd, s19mjs5d_mw_s3bmjs7f);
        *x5 = simd.sub(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f);
        *xd = simd.add(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f);

        let v8_a19m1a5d_pj_a3bm1a7f = simd.mul_exp_pi_over_8(fwd, a19m1a5d_pj_a3bm1a7f);
        *x6 = simd.sub(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f);
        *xe = simd.add(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f);

        let hf_s19pjs5d_pv_s3bpjs7f = simd.mul_exp_neg_pi_over_16(fwd, s19pjs5d_pv_s3bpjs7f);
        *x7 = simd.sub(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f);
        *xf = simd.add(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f);
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

    let y = pulp::as_arrays::<16, _>(y).0;
    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = split_mut_16(x);
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

        let abcd0 = y[0x0];
        let efgh0 = y[0x1];
        let ijkl0 = y[0x2];
        let mnop0 = y[0x3];

        let abcd1 = y[0x4];
        let efgh1 = y[0x5];
        let ijkl1 = y[0x6];
        let mnop1 = y[0x7];

        let abcd2 = y[0x8];
        let efgh2 = y[0x9];
        let ijkl2 = y[0xa];
        let mnop2 = y[0xb];

        let abcd3 = y[0xc];
        let efgh3 = y[0xd];
        let ijkl3 = y[0xe];
        let mnop3 = y[0xf];

        let (a_, b_, c_, d_) = simd.transpose(abcd0, abcd1, abcd2, abcd3);
        let (e_, f_, g_, h_) = simd.transpose(efgh0, efgh1, efgh2, efgh3);
        let (i_, j_, k_, l_) = simd.transpose(ijkl0, ijkl1, ijkl2, ijkl3);
        let (m_, n_, o_, p_) = simd.transpose(mnop0, mnop1, mnop2, mnop3);

        let y0 = a_;
        let y1 = simd.mul(w1, b_);
        let y2 = simd.mul(w2, c_);
        let y3 = simd.mul(w3, d_);
        let y4 = simd.mul(w4, e_);
        let y5 = simd.mul(w5, f_);
        let y6 = simd.mul(w6, g_);
        let y7 = simd.mul(w7, h_);

        let y8 = simd.mul(w8, i_);
        let y9 = simd.mul(w9, j_);
        let ya = simd.mul(wa, k_);
        let yb = simd.mul(wb, l_);
        let yc = simd.mul(wc, m_);
        let yd = simd.mul(wd, n_);
        let ye = simd.mul(we, o_);
        let yf = simd.mul(wf, p_);

        let a08 = simd.add(y0, y8);
        let s08 = simd.sub(y0, y8);
        let a4c = simd.add(y4, yc);
        let s4c = simd.sub(y4, yc);
        let a2a = simd.add(y2, ya);
        let s2a = simd.sub(y2, ya);
        let a6e = simd.add(y6, ye);
        let s6e = simd.sub(y6, ye);
        let a19 = simd.add(y1, y9);
        let s19 = simd.sub(y1, y9);
        let a5d = simd.add(y5, yd);
        let s5d = simd.sub(y5, yd);
        let a3b = simd.add(y3, yb);
        let s3b = simd.sub(y3, yb);
        let a7f = simd.add(y7, yf);
        let s7f = simd.sub(y7, yf);

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

        *x0 = simd.add(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);
        *x8 = simd.sub(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);

        let h1_s19mjs5d_pw_s3bmjs7f = simd.mul_exp_pi_over_16(fwd, s19mjs5d_pw_s3bmjs7f);
        *x1 = simd.add(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f);
        *x9 = simd.sub(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f);

        let w8_a19m1a5d_mj_a3bm1a7f = simd.mul_exp_neg_pi_over_8(fwd, a19m1a5d_mj_a3bm1a7f);
        *x2 = simd.add(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f);
        *xa = simd.sub(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f);

        let h3_s19pjs5d_mv_s3bpjs7f = simd.mul_exp_17pi_over_16(fwd, s19pjs5d_mv_s3bpjs7f);
        *x3 = simd.add(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f);
        *xb = simd.sub(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f);

        let j_a19p1a5d_m1_a3bp1a7f = simd.mul_j(fwd, a19p1a5d_m1_a3bp1a7f);
        *x4 = simd.sub(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f);
        *xc = simd.add(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f);

        let hd_s19mjs5d_mw_s3bmjs7f = simd.mul_exp_neg_17pi_over_16(fwd, s19mjs5d_mw_s3bmjs7f);
        *x5 = simd.sub(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f);
        *xd = simd.add(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f);

        let v8_a19m1a5d_pj_a3bm1a7f = simd.mul_exp_pi_over_8(fwd, a19m1a5d_pj_a3bm1a7f);
        *x6 = simd.sub(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f);
        *xe = simd.add(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f);

        let hf_s19pjs5d_pv_s3bpjs7f = simd.mul_exp_neg_pi_over_16(fwd, s19pjs5d_pv_s3bpjs7f);
        *x7 = simd.sub(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f);
        *xf = simd.add(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f);
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

    let w = pulp::as_arrays::<16, _>(w).0;

    let (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) = split_mut_16(x);

    for ((x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf), y, w) in izip!(
        izip!(
            x0.chunks_exact_mut(simd_s),
            x1.chunks_exact_mut(simd_s),
            x2.chunks_exact_mut(simd_s),
            x3.chunks_exact_mut(simd_s),
            x4.chunks_exact_mut(simd_s),
            x5.chunks_exact_mut(simd_s),
            x6.chunks_exact_mut(simd_s),
            x7.chunks_exact_mut(simd_s),
            x8.chunks_exact_mut(simd_s),
            x9.chunks_exact_mut(simd_s),
            xa.chunks_exact_mut(simd_s),
            xb.chunks_exact_mut(simd_s),
            xc.chunks_exact_mut(simd_s),
            xd.chunks_exact_mut(simd_s),
            xe.chunks_exact_mut(simd_s),
            xf.chunks_exact_mut(simd_s),
        ),
        y.chunks_exact(16 * simd_s),
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

        let (y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf) = split_16(y);

        for (
            (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
            (y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf),
        ) in izip!(
            izip!(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf),
            izip!(y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf),
        ) {
            let y0 = *y0;
            let y1 = simd.mul(w1, *y1);
            let y2 = simd.mul(w2, *y2);
            let y3 = simd.mul(w3, *y3);
            let y4 = simd.mul(w4, *y4);
            let y5 = simd.mul(w5, *y5);
            let y6 = simd.mul(w6, *y6);
            let y7 = simd.mul(w7, *y7);
            let y8 = simd.mul(w8, *y8);
            let y9 = simd.mul(w9, *y9);
            let ya = simd.mul(wa, *ya);
            let yb = simd.mul(wb, *yb);
            let yc = simd.mul(wc, *yc);
            let yd = simd.mul(wd, *yd);
            let ye = simd.mul(we, *ye);
            let yf = simd.mul(wf, *yf);

            let a08 = simd.add(y0, y8);
            let s08 = simd.sub(y0, y8);
            let a4c = simd.add(y4, yc);
            let s4c = simd.sub(y4, yc);
            let a2a = simd.add(y2, ya);
            let s2a = simd.sub(y2, ya);
            let a6e = simd.add(y6, ye);
            let s6e = simd.sub(y6, ye);
            let a19 = simd.add(y1, y9);
            let s19 = simd.sub(y1, y9);
            let a5d = simd.add(y5, yd);
            let s5d = simd.sub(y5, yd);
            let a3b = simd.add(y3, yb);
            let s3b = simd.sub(y3, yb);
            let a7f = simd.add(y7, yf);
            let s7f = simd.sub(y7, yf);

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

            *x0 = simd.add(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);
            *x8 = simd.sub(a08p1a4c_p1_a2ap1a6e, a19p1a5d_p1_a3bp1a7f);

            let h1_s19mjs5d_pw_s3bmjs7f = simd.mul_exp_pi_over_16(fwd, s19mjs5d_pw_s3bmjs7f);
            *x1 = simd.add(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f);
            *x9 = simd.sub(s08mjs4c_pw_s2amjs6e, h1_s19mjs5d_pw_s3bmjs7f);

            let w8_a19m1a5d_mj_a3bm1a7f = simd.mul_exp_neg_pi_over_8(fwd, a19m1a5d_mj_a3bm1a7f);
            *x2 = simd.add(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f);
            *xa = simd.sub(a08m1a4c_mj_a2am1a6e, w8_a19m1a5d_mj_a3bm1a7f);

            let h3_s19pjs5d_mv_s3bpjs7f = simd.mul_exp_17pi_over_16(fwd, s19pjs5d_mv_s3bpjs7f);
            *x3 = simd.add(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f);
            *xb = simd.sub(s08pjs4c_mv_s2apjs6e, h3_s19pjs5d_mv_s3bpjs7f);

            let j_a19p1a5d_m1_a3bp1a7f = simd.mul_j(fwd, a19p1a5d_m1_a3bp1a7f);
            *x4 = simd.sub(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f);
            *xc = simd.add(a08p1a4c_m1_a2ap1a6e, j_a19p1a5d_m1_a3bp1a7f);

            let hd_s19mjs5d_mw_s3bmjs7f = simd.mul_exp_neg_17pi_over_16(fwd, s19mjs5d_mw_s3bmjs7f);
            *x5 = simd.sub(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f);
            *xd = simd.add(s08mjs4c_mw_s2amjs6e, hd_s19mjs5d_mw_s3bmjs7f);

            let v8_a19m1a5d_pj_a3bm1a7f = simd.mul_exp_pi_over_8(fwd, a19m1a5d_pj_a3bm1a7f);
            *x6 = simd.sub(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f);
            *xe = simd.add(a08m1a4c_pj_a2am1a6e, v8_a19m1a5d_pj_a3bm1a7f);

            let hf_s19pjs5d_pv_s3bpjs7f = simd.mul_exp_neg_pi_over_16(fwd, s19pjs5d_pv_s3bpjs7f);
            *x7 = simd.sub(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f);
            *xf = simd.add(s08pjs4c_pv_s2apjs6e, hf_s19pjs5d_pv_s3bpjs7f);
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
pub fn stockham_dit16_end<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    fwd: bool,
    read_from_x: bool,
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

    if read_from_x {
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
                *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7, *x8, *x9, *xa, *xb, *xc, *xd, *xe, *xf,
            ) = last_butterfly(
                simd, fwd, *y0, *y1, *y2, *y3, *y4, *y5, *y6, *y7, *y8, *y9, *ya, *yb, *yc, *yd,
                *ye, *yf,
            );
        }
    }
}

struct Dit16<N: nat::Nat>(N);
impl<N: nat::Nat> nat::Nat for Dit16<N> {
    const VALUE: usize = N::VALUE;
}

// size 2
impl RecursiveFft for Dit16<nat::N0> {
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
impl RecursiveFft for Dit16<nat::N1> {
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
impl RecursiveFft for Dit16<nat::N2> {
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
        crate::dit8::stockham_dit8_end(simd, fwd, read_from_x, s, x, y);
    }
}

// size 16
impl RecursiveFft for Dit16<nat::N3> {
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
        stockham_dit16_end(simd, fwd, read_from_x, s, x, y);
    }
}

impl<N: nat::Nat> RecursiveFft for Dit16<nat::Plus4<N>>
where
    Dit16<N>: RecursiveFft,
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
        Dit16::<N>::fft_recurse_impl(simd, fwd, !read_from_x, s * 16, y, x, w_init, w);
        stockham_core(simd, fwd, s, x, y, w_init, w);
    }
}

pub(crate) fn fft_impl<c64xN: Pod>(simd: impl FftSimd<c64xN>) -> crate::FftImpl {
    let fwd = [
        fn_ptr::<true, Dit16<nat::N0>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N1>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N2>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N3>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N4>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N5>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N6>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N7>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N8>, _, _>(simd),
        fn_ptr::<true, Dit16<nat::N9>, _, _>(simd),
    ];
    let inv = [
        fn_ptr::<false, Dit16<nat::N0>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N1>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N2>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N3>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N4>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N5>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N6>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N7>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N8>, _, _>(simd),
        fn_ptr::<false, Dit16<nat::N9>, _, _>(simd),
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
