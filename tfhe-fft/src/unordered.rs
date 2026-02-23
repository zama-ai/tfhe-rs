//! Unordered FFT module.
//!
//! This module computes the forward or inverse FFT in a similar fashion to the ordered module,
//! with two crucial differences.
//! Given an FFT plan, the forward transform takes its inputs in standard order, and outputs the
//! forward FFT terms in an unspecified order. And the backward transform takes its inputs in the
//! aforementioned order, and outputs the inverse FFT in the standard order.

use crate::{
    c64,
    dif2::{split_2, split_mut_2},
    dif4::split_mut_4,
    dif8::split_mut_8,
    fft_simd::{init_wt, sincospi64, FftSimd, FftSimdExt, Pod},
    ordered::FftAlgo,
};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
#[cfg(feature = "std")]
use core::time::Duration;
#[cfg(feature = "std")]
use dyn_stack::PodBuffer;
use dyn_stack::{PodStack, StackReq};

#[inline(always)]
fn fwd_butterfly_x2<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    z0: c64xN,
    z1: c64xN,
    w1: c64xN,
) -> (c64xN, c64xN) {
    (simd.add(z0, z1), simd.mul(w1, simd.sub(z0, z1)))
}

#[inline(always)]
fn inv_butterfly_x2<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    z0: c64xN,
    z1: c64xN,
    w1: c64xN,
) -> (c64xN, c64xN) {
    let z1 = simd.mul(w1, z1);
    (simd.add(z0, z1), simd.sub(z0, z1))
}

#[inline(always)]
fn fwd_butterfly_x4<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    z0: c64xN,
    z1: c64xN,
    z2: c64xN,
    z3: c64xN,
    w1: c64xN,
    w2: c64xN,
    w3: c64xN,
) -> (c64xN, c64xN, c64xN, c64xN) {
    let z0p2 = simd.add(z0, z2);
    let z0m2 = simd.sub(z0, z2);
    let z1p3 = simd.add(z1, z3);
    let jz1m3 = simd.mul_j(true, simd.sub(z1, z3));

    (
        simd.add(z0p2, z1p3),
        simd.mul(w1, simd.sub(z0m2, jz1m3)),
        simd.mul(w2, simd.sub(z0p2, z1p3)),
        simd.mul(w3, simd.add(z0m2, jz1m3)),
    )
}

#[inline(always)]
fn inv_butterfly_x4<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    z0: c64xN,
    z1: c64xN,
    z2: c64xN,
    z3: c64xN,
    w1: c64xN,
    w2: c64xN,
    w3: c64xN,
) -> (c64xN, c64xN, c64xN, c64xN) {
    let z1 = simd.mul(w1, z1);
    let z2 = simd.mul(w2, z2);
    let z3 = simd.mul(w3, z3);

    let z0p2 = simd.add(z0, z2);
    let z0m2 = simd.sub(z0, z2);
    let z1p3 = simd.add(z1, z3);
    let jz1m3 = simd.mul_j(false, simd.sub(z1, z3));

    (
        simd.add(z0p2, z1p3),
        simd.sub(z0m2, jz1m3),
        simd.sub(z0p2, z1p3),
        simd.add(z0m2, jz1m3),
    )
}

#[inline(always)]
fn fwd_butterfly_x8<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    z0: c64xN,
    z1: c64xN,
    z2: c64xN,
    z3: c64xN,
    z4: c64xN,
    z5: c64xN,
    z6: c64xN,
    z7: c64xN,
    w1: c64xN,
    w2: c64xN,
    w3: c64xN,
    w4: c64xN,
    w5: c64xN,
    w6: c64xN,
    w7: c64xN,
) -> (c64xN, c64xN, c64xN, c64xN, c64xN, c64xN, c64xN, c64xN) {
    let z0p4 = simd.add(z0, z4);
    let z0m4 = simd.sub(z0, z4);
    let z2p6 = simd.add(z2, z6);
    let jz2m6 = simd.mul_j(true, simd.sub(z2, z6));

    let z1p5 = simd.add(z1, z5);
    let z1m5 = simd.sub(z1, z5);
    let z3p7 = simd.add(z3, z7);
    let jz3m7 = simd.mul_j(true, simd.sub(z3, z7));

    // z0 + z2 + z4 + z6
    let t0 = simd.add(z0p4, z2p6);
    // z1 + z3 + z5 + z7
    let t1 = simd.add(z1p5, z3p7);
    // z0 + w4z2 + z4 + w4z6
    let t2 = simd.sub(z0p4, z2p6);
    // w2z1 + w6z3 + w2z5 + w6z7
    let t3 = simd.mul_j(true, simd.sub(z1p5, z3p7));
    // z0 + w2z2 + z4 + w6z6
    let t4 = simd.sub(z0m4, jz2m6);
    // w1z1 + w3z3 + w5z5 + w7z7
    let t5 = simd.mul_exp_neg_pi_over_8(true, simd.sub(z1m5, jz3m7));
    // z0 + w2z2 + w4z4 + w6z6
    let t6 = simd.add(z0m4, jz2m6);
    // w7z1 + w1z3 + w3z5 + w5z7
    let t7 = simd.mul_exp_pi_over_8(true, simd.add(z1m5, jz3m7));

    (
        simd.add(t0, t1),
        simd.mul(w1, simd.add(t4, t5)),
        simd.mul(w2, simd.sub(t2, t3)),
        simd.mul(w3, simd.sub(t6, t7)),
        simd.mul(w4, simd.sub(t0, t1)),
        simd.mul(w5, simd.sub(t4, t5)),
        simd.mul(w6, simd.add(t2, t3)),
        simd.mul(w7, simd.add(t6, t7)),
    )
}

#[inline(always)]
fn inv_butterfly_x8<c64xN: Pod>(
    simd: impl FftSimd<c64xN>,
    z0: c64xN,
    z1: c64xN,
    z2: c64xN,
    z3: c64xN,
    z4: c64xN,
    z5: c64xN,
    z6: c64xN,
    z7: c64xN,
    w1: c64xN,
    w2: c64xN,
    w3: c64xN,
    w4: c64xN,
    w5: c64xN,
    w6: c64xN,
    w7: c64xN,
) -> (c64xN, c64xN, c64xN, c64xN, c64xN, c64xN, c64xN, c64xN) {
    let z1 = simd.mul(w1, z1);
    let z2 = simd.mul(w2, z2);
    let z3 = simd.mul(w3, z3);
    let z4 = simd.mul(w4, z4);
    let z5 = simd.mul(w5, z5);
    let z6 = simd.mul(w6, z6);
    let z7 = simd.mul(w7, z7);

    let z0p4 = simd.add(z0, z4);
    let z0m4 = simd.sub(z0, z4);
    let z2p6 = simd.add(z2, z6);
    let jz2m6 = simd.mul_j(false, simd.sub(z2, z6));

    let z1p5 = simd.add(z1, z5);
    let z1m5 = simd.sub(z1, z5);
    let z3p7 = simd.add(z3, z7);
    let jz3m7 = simd.mul_j(false, simd.sub(z3, z7));

    // z0 + z2 + z4 + z6
    let t0 = simd.add(z0p4, z2p6);
    // z1 + z3 + z5 + z7
    let t1 = simd.add(z1p5, z3p7);
    // z0 + w4z2 + z4 + w4z6
    let t2 = simd.sub(z0p4, z2p6);
    // w2z1 + w6z3 + w2z5 + w6z7
    let t3 = simd.mul_j(false, simd.sub(z1p5, z3p7));
    // z0 + w2z2 + z4 + w6z6
    let t4 = simd.sub(z0m4, jz2m6);
    // w1z1 + w3z3 + w5z5 + w7z7
    let t5 = simd.mul_exp_neg_pi_over_8(false, simd.sub(z1m5, jz3m7));
    // z0 + w2z2 + w4z4 + w6z6
    let t6 = simd.add(z0m4, jz2m6);
    // w7z1 + w1z3 + w3z5 + w5z7
    let t7 = simd.mul_exp_pi_over_8(false, simd.add(z1m5, jz3m7));

    (
        simd.add(t0, t1),
        simd.add(t4, t5),
        simd.sub(t2, t3),
        simd.sub(t6, t7),
        simd.sub(t0, t1),
        simd.sub(t4, t5),
        simd.add(t2, t3),
        simd.add(t6, t7),
    )
}

#[inline(always)]
fn fwd_process_x2<c64xN: Pod>(simd: impl FftSimd<c64xN>, z: &mut [c64], w: &[c64]) {
    let z: &mut [c64xN] = bytemuck::cast_slice_mut(z);
    let w: &[[c64xN; 1]] = bytemuck::cast_slice(w);
    let (z0, z1) = split_mut_2(z);

    for (z0, z1, &[w1]) in izip!(z0, z1, w) {
        (*z0, *z1) = fwd_butterfly_x2(simd, *z0, *z1, w1);
    }
}

#[inline(always)]
fn inv_process_x2<c64xN: Pod>(simd: impl FftSimd<c64xN>, z: &mut [c64], w: &[c64]) {
    let z: &mut [c64xN] = bytemuck::cast_slice_mut(z);
    let w: &[[c64xN; 1]] = bytemuck::cast_slice(w);
    let (z0, z1) = split_mut_2(z);

    for (z0, z1, &[w1]) in izip!(z0, z1, w) {
        (*z0, *z1) = inv_butterfly_x2(simd, *z0, *z1, w1);
    }
}

#[inline(always)]
fn fwd_process_x4<c64xN: Pod>(simd: impl FftSimd<c64xN>, z: &mut [c64], w: &[c64]) {
    let z: &mut [c64xN] = bytemuck::cast_slice_mut(z);
    let w: &[[c64xN; 3]] = bytemuck::cast_slice(w);
    let (z0, z1, z2, z3) = split_mut_4(z);

    for (z0, z1, z2, z3, &[w1, w2, w3]) in izip!(z0, z1, z2, z3, w) {
        (*z0, *z2, *z1, *z3) = fwd_butterfly_x4(simd, *z0, *z1, *z2, *z3, w1, w2, w3);
    }
}

#[inline(always)]
fn inv_process_x4<c64xN: Pod>(simd: impl FftSimd<c64xN>, z: &mut [c64], w: &[c64]) {
    let z: &mut [c64xN] = bytemuck::cast_slice_mut(z);
    let w: &[[c64xN; 3]] = bytemuck::cast_slice(w);
    let (z0, z1, z2, z3) = split_mut_4(z);

    for (z0, z1, z2, z3, &[w1, w2, w3]) in izip!(z0, z1, z2, z3, w) {
        (*z0, *z1, *z2, *z3) = inv_butterfly_x4(simd, *z0, *z2, *z1, *z3, w1, w2, w3);
    }
}

#[inline(always)]
fn fwd_process_x8<c64xN: Pod>(simd: impl FftSimd<c64xN>, z: &mut [c64], w: &[c64]) {
    let z: &mut [c64xN] = bytemuck::cast_slice_mut(z);
    let w: &[[c64xN; 7]] = bytemuck::cast_slice(w);
    let (z0, z1, z2, z3, z4, z5, z6, z7) = split_mut_8(z);

    for (z0, z1, z2, z3, z4, z5, z6, z7, &[w1, w2, w3, w4, w5, w6, w7]) in
        izip!(z0, z1, z2, z3, z4, z5, z6, z7, w)
    {
        (*z0, *z4, *z2, *z6, *z1, *z5, *z3, *z7) = fwd_butterfly_x8(
            simd, *z0, *z1, *z2, *z3, *z4, *z5, *z6, *z7, w1, w2, w3, w4, w5, w6, w7,
        );
    }
}

#[inline(always)]
fn inv_process_x8<c64xN: Pod>(simd: impl FftSimd<c64xN>, z: &mut [c64], w: &[c64]) {
    let z: &mut [c64xN] = bytemuck::cast_slice_mut(z);
    let w: &[[c64xN; 7]] = bytemuck::cast_slice(w);
    let (z0, z1, z2, z3, z4, z5, z6, z7) = split_mut_8(z);

    for (z0, z1, z2, z3, z4, z5, z6, z7, &[w1, w2, w3, w4, w5, w6, w7]) in
        izip!(z0, z1, z2, z3, z4, z5, z6, z7, w)
    {
        (*z0, *z1, *z2, *z3, *z4, *z5, *z6, *z7) = inv_butterfly_x8(
            simd, *z0, *z4, *z2, *z6, *z1, *z5, *z3, *z7, w1, w2, w3, w4, w5, w6, w7,
        );
    }
}

macro_rules! dispatcher {
    ($name: ident, $impl: ident) => {
        fn $name() -> fn(&mut [c64], &[c64]) {
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            {
                #[cfg(feature = "avx512")]
                if pulp::x86::V4::try_new().is_some() {
                    return |z, w| {
                        let simd = pulp::x86::V4::try_new().unwrap();
                        simd.vectorize(
                            #[inline(always)]
                            || $impl(simd, z, w),
                        );
                    };
                }

                if pulp::x86::V3::try_new().is_some() {
                    return |z, w| {
                        let simd = pulp::x86::V3::try_new().unwrap();
                        simd.vectorize(
                            #[inline(always)]
                            || $impl(simd, z, w),
                        );
                    };
                }
            }

            |z, w| $impl(crate::fft_simd::Scalar, z, w)
        }
    };
}

dispatcher!(get_fwd_process_x2, fwd_process_x2);
dispatcher!(get_fwd_process_x4, fwd_process_x4);
dispatcher!(get_fwd_process_x8, fwd_process_x8);

dispatcher!(get_inv_process_x2, inv_process_x2);
dispatcher!(get_inv_process_x4, inv_process_x4);
dispatcher!(get_inv_process_x8, inv_process_x8);

fn get_complex_per_reg() -> usize {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        #[cfg(feature = "avx512")]
        if let Some(simd) = pulp::x86::V4::try_new() {
            return simd.lane_count();
        }
        if let Some(simd) = pulp::x86::V3::try_new() {
            return simd.lane_count();
        }
    }
    crate::fft_simd::Scalar.lane_count()
}

fn init_twiddles(
    n: usize,
    complex_per_reg: usize,
    base_n: usize,
    base_r: usize,
    w: &mut [c64],
    w_inv: &mut [c64],
) {
    let theta = 2.0 / n as f64;
    if n <= base_n {
        init_wt(base_r, n, w, w_inv);
    } else {
        let r = if n == 2 * base_n {
            2
        } else if n == 4 * base_n {
            4
        } else {
            8
        };

        let m = n / r;
        let (w, w_next) = w.split_at_mut((r - 1) * m);
        let (w_inv_next, w_inv) = w_inv.split_at_mut(w_inv.len() - (r - 1) * m);

        let mut p = 0;
        while p < m {
            for i in 0..complex_per_reg {
                for k in 1..r {
                    let (sk, ck) = sincospi64(theta * (k * (p + i)) as f64);
                    let idx = (r - 1) * p + (k - 1) * complex_per_reg + i;
                    w[idx] = c64 { re: ck, im: -sk };
                    w_inv[idx] = c64 { re: ck, im: sk };
                }
            }

            p += complex_per_reg;
        }

        init_twiddles(n / r, complex_per_reg, base_n, base_r, w_next, w_inv_next);
    }
}

#[inline(never)]
fn fwd_depth(
    z: &mut [c64],
    w: &[c64],
    base_fn: fn(&mut [c64], &mut [c64], &[c64], &[c64]),
    base_n: usize,
    base_scratch: &mut [c64],
    fwd_process_x2: fn(&mut [c64], &[c64]),
    fwd_process_x4: fn(&mut [c64], &[c64]),
    fwd_process_x8: fn(&mut [c64], &[c64]),
) {
    let n = z.len();
    if n == base_n {
        let (w_init, w) = split_2(w);
        base_fn(z, base_scratch, w_init, w);
    } else {
        let r = if n == 2 * base_n {
            2
        } else if n == 4 * base_n {
            4
        } else {
            8
        };

        let m = n / r;
        let (w_head, w_tail) = w.split_at((r - 1) * m);

        if n == 2 * base_n {
            fwd_process_x2(z, w_head);
        } else if n == 4 * base_n {
            fwd_process_x4(z, w_head);
        } else {
            fwd_process_x8(z, w_head);
        }

        for z in z.chunks_exact_mut(m) {
            fwd_depth(
                z,
                w_tail,
                base_fn,
                base_n,
                base_scratch,
                fwd_process_x2,
                fwd_process_x4,
                fwd_process_x8,
            );
        }
    }
}

#[inline(never)]
fn inv_depth(
    z: &mut [c64],
    w: &[c64],
    base_fn: fn(&mut [c64], &mut [c64], &[c64], &[c64]),
    base_n: usize,
    base_scratch: &mut [c64],
    inv_process_x2: fn(&mut [c64], &[c64]),
    inv_process_x4: fn(&mut [c64], &[c64]),
    inv_process_x8: fn(&mut [c64], &[c64]),
) {
    let n = z.len();

    if n == base_n {
        let (w_init, w) = split_2(w);
        base_fn(z, base_scratch, w_init, w);
    } else {
        let r = if n == 2 * base_n {
            2
        } else if n == 4 * base_n {
            4
        } else {
            8
        };

        let m = n / r;
        let (w_head, w_tail) = w.split_at(w.len() - (r - 1) * m);
        for z in z.chunks_exact_mut(m) {
            inv_depth(
                z,
                w_head,
                base_fn,
                base_n,
                base_scratch,
                inv_process_x2,
                inv_process_x4,
                inv_process_x8,
            );
        }

        if r == 2 {
            inv_process_x2(z, w_tail);
        } else if r == 4 {
            inv_process_x4(z, w_tail);
        } else {
            inv_process_x8(z, w_tail);
        }
    }
}

/// Unordered FFT plan.
///
/// This type holds a forward and inverse FFT plan and twiddling factors for a specific size.
/// The size must be a power of two.
#[derive(Clone)]
pub struct Plan {
    monomial_twiddles: ABox<[c64]>,
    indices: ABox<[usize]>,
    twiddles: ABox<[c64]>,
    twiddles_inv: ABox<[c64]>,
    fwd_process_x2: fn(&mut [c64], &[c64]),
    fwd_process_x4: fn(&mut [c64], &[c64]),
    fwd_process_x8: fn(&mut [c64], &[c64]),
    inv_process_x2: fn(&mut [c64], &[c64]),
    inv_process_x4: fn(&mut [c64], &[c64]),
    inv_process_x8: fn(&mut [c64], &[c64]),
    base_n: usize,
    base_fn_fwd: fn(&mut [c64], &mut [c64], &[c64], &[c64]),
    base_fn_inv: fn(&mut [c64], &mut [c64], &[c64], &[c64]),
    base_algo: FftAlgo,
    n: usize,
}

impl core::fmt::Debug for Plan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plan")
            .field("base_algo", &self.base_algo)
            .field("base_size", &self.base_n)
            .field("fft_size", &self.fft_size())
            .finish()
    }
}

/// Method for selecting the unordered FFT plan.
#[derive(Clone, Copy, Debug)]
pub enum Method {
    /// Select the FFT plan by manually providing the underlying algorithm.
    /// The unordered FFT works by using an internal ordered FFT plan, whose size and algorithm can
    /// be specified by the user.
    UserProvided { base_algo: FftAlgo, base_n: usize },
    /// Select the FFT plan by measuring the running time of all the possible plans and selecting
    /// the fastest one. The provided duration specifies how long the benchmark of each plan should
    /// last.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    Measure(Duration),
}

#[cfg(feature = "std")]
fn measure_fastest_scratch(n: usize) -> StackReq {
    if n <= 512 {
        crate::ordered::measure_fastest_scratch(n)
    } else {
        let base_n = 4096;
        crate::ordered::measure_fastest_scratch(base_n)
            .and(StackReq::new_aligned::<c64>(n + base_n, CACHELINE_ALIGN)) // twiddles
            .and(StackReq::new_aligned::<c64>(n, CACHELINE_ALIGN)) // buf
            .and(StackReq::new_aligned::<c64>(base_n, CACHELINE_ALIGN)) // scratch
    }
}

#[cfg(feature = "std")]
fn measure_fastest(
    mut min_bench_duration_per_algo: Duration,
    n: usize,
    stack: &mut PodStack,
) -> (FftAlgo, usize, Duration) {
    const MIN_DURATION: Duration = Duration::from_millis(1);
    min_bench_duration_per_algo = min_bench_duration_per_algo.max(MIN_DURATION);

    if n <= 256 {
        let (algo, duration) =
            crate::ordered::measure_fastest(min_bench_duration_per_algo, n, stack);
        (algo, n, duration)
    } else {
        // bench

        let bases = [512, 1024];
        let mut algos: [Option<FftAlgo>; 4] = [None; 4];
        let mut avg_durations: [Option<Duration>; 4] = [None; 4];
        let fwd_process_x2 = get_fwd_process_x2();
        let fwd_process_x4 = get_fwd_process_x4();
        let fwd_process_x8 = get_fwd_process_x8();

        let mut n_algos = 0;
        for (i, base_n) in bases.into_iter().enumerate() {
            if n < base_n {
                break;
            }

            n_algos += 1;

            // we'll measure the corresponding plan
            let (base_algo, duration) =
                crate::ordered::measure_fastest(min_bench_duration_per_algo, base_n, stack);

            algos[i] = Some(base_algo);

            if n == base_n {
                avg_durations[i] = Some(duration);
                continue;
            }

            // get the forward base algo
            let base_fn = crate::ordered::get_fn_ptr(base_algo, base_n)[0];

            let f = |_| c64 { re: 0.0, im: 0.0 };
            let align = CACHELINE_ALIGN;
            let (w, stack) = stack.make_aligned_with::<c64>(n + base_n, align, f);
            let (scratch, stack) = stack.make_aligned_with::<c64>(base_n, align, f);
            let (z, _) = stack.make_aligned_with::<c64>(n, align, f);

            let n_runs = min_bench_duration_per_algo.as_secs_f64()
                / (duration.as_secs_f64() * (n / base_n) as f64);

            let n_runs = n_runs.ceil() as u32;

            // For wasm we have a dedicated implementation going through js-sys
            use crate::time::Instant;
            let now = Instant::now();
            for _ in 0..n_runs {
                fwd_depth(
                    z,
                    w,
                    base_fn,
                    base_n,
                    scratch,
                    fwd_process_x2,
                    fwd_process_x4,
                    fwd_process_x8,
                );
            }
            let duration = now.elapsed();
            avg_durations[i] = Some(duration / n_runs);
        }

        let best_time = avg_durations[..n_algos].iter().min().unwrap().unwrap();
        let best_index = avg_durations[..n_algos]
            .iter()
            .position(|elem| elem.unwrap() == best_time)
            .unwrap();

        (algos[best_index].unwrap(), bases[best_index], best_time)
    }
}

impl Plan {
    /// Returns a new FFT plan for the given vector size, selected by the provided method.
    ///
    /// # Panics
    ///
    /// - Panics if `n` is not a power of two.
    /// - If the method is user-provided, panics if `n` is not equal to the base ordered FFT size,
    /// and the base FFT size is less than `32`.
    ///
    /// # Example
    #[cfg_attr(feature = "std", doc = " ```")]
    #[cfg_attr(not(feature = "std"), doc = " ```ignore")]
    /// use tfhe_fft::unordered::{Method, Plan};
    /// use core::time::Duration;
    ///
    /// let plan = Plan::new(4, Method::Measure(Duration::from_millis(10)));
    /// ```
    pub fn new(n: usize, method: Method) -> Self {
        assert!(n.is_power_of_two());

        let (base_algo, base_n) = match method {
            Method::UserProvided { base_algo, base_n } => {
                assert!(base_n.is_power_of_two());
                assert!(base_n <= n);
                if base_n != n {
                    assert!(base_n >= 32);
                }
                assert!(base_n.trailing_zeros() <= 10);
                (base_algo, base_n)
            }

            #[cfg(feature = "std")]
            Method::Measure(duration) => {
                let mut buf = PodBuffer::try_new(measure_fastest_scratch(n)).unwrap();
                let (algo, base_n, _) = measure_fastest(duration, n, PodStack::new(&mut buf));
                (algo, base_n)
            }
        };

        let [base_fn_fwd, base_fn_inv] = crate::ordered::get_fn_ptr(base_algo, base_n);

        let nan = c64 {
            re: f64::NAN,
            im: f64::NAN,
        };
        let mut twiddles = avec![nan; n + base_n].into_boxed_slice();
        let mut twiddles_inv = avec![nan; n + base_n].into_boxed_slice();

        use crate::ordered::FftAlgo::*;
        let base_r = match base_algo {
            Dif2 | Dit2 => 2,
            Dif4 | Dit4 => 4,
            Dif8 | Dit8 => 8,
            Dif16 | Dit16 => 16,
        };

        init_twiddles(
            n,
            get_complex_per_reg(),
            base_n,
            base_r,
            &mut twiddles,
            &mut twiddles_inv,
        );

        let nan = c64 {
            re: f64::NAN,
            im: f64::NAN,
        };
        let mut monomial_twiddles = avec![nan; n].into_boxed_slice();

        let theta = -2.0 / n as f64;
        for (i, twid) in monomial_twiddles.iter_mut().enumerate() {
            let (s, c) = sincospi64(theta * i as f64);
            *twid = c64 { re: c, im: s };
        }
        let mut indices = avec![0usize; n].into_boxed_slice();

        let nbits = n.trailing_zeros();
        let base_nbits = base_n.trailing_zeros();

        for (i, idx) in indices.iter_mut().enumerate() {
            *idx = bit_rev_twice_inv(nbits, base_nbits, i);
        }

        Self {
            twiddles,
            twiddles_inv,
            fwd_process_x2: get_fwd_process_x2(),
            fwd_process_x4: get_fwd_process_x4(),
            fwd_process_x8: get_fwd_process_x8(),
            inv_process_x2: get_inv_process_x2(),
            inv_process_x4: get_inv_process_x4(),
            inv_process_x8: get_inv_process_x8(),
            base_n,
            base_fn_fwd,
            base_fn_inv,
            n,
            base_algo,
            monomial_twiddles,
            indices,
        }
    }

    /// Returns the vector size of the FFT.
    ///
    /// # Example
    #[cfg_attr(feature = "std", doc = " ```")]
    #[cfg_attr(not(feature = "std"), doc = " ```ignore")]
    /// use tfhe_fft::unordered::{Method, Plan};
    /// use core::time::Duration;
    ///
    /// let plan = Plan::new(4, Method::Measure(Duration::from_millis(10)));
    /// assert_eq!(plan.fft_size(), 4);
    /// ```
    pub fn fft_size(&self) -> usize {
        self.n
    }

    /// Returns the algorithm and size of the internal ordered FFT plan.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe_fft::{
    ///     ordered::FftAlgo,
    ///     unordered::{Method, Plan},
    /// };
    ///
    /// let plan = Plan::new(
    ///     4,
    ///     Method::UserProvided {
    ///         base_algo: FftAlgo::Dif2,
    ///         base_n: 4,
    ///     },
    /// );
    /// assert_eq!(plan.algo(), (FftAlgo::Dif2, 4));
    /// ```
    pub fn algo(&self) -> (FftAlgo, usize) {
        (self.base_algo, self.base_n)
    }

    /// Returns the size and alignment of the scratch memory needed to perform an FFT.
    ///
    /// # Example
    #[cfg_attr(feature = "std", doc = " ```")]
    #[cfg_attr(not(feature = "std"), doc = " ```ignore")]
    /// use tfhe_fft::unordered::{Method, Plan};
    /// use core::time::Duration;
    ///
    /// let plan = Plan::new(4, Method::Measure(Duration::from_millis(10)));
    /// let scratch = plan.fft_scratch();
    /// ```
    pub fn fft_scratch(&self) -> StackReq {
        StackReq::new_aligned::<c64>(self.algo().1, CACHELINE_ALIGN)
    }

    /// Performs a forward FFT in place, using the provided stack as scratch space.
    ///
    /// # Note
    ///
    /// The values in `buf` must be in standard order prior to calling this function.
    /// When this function returns, the values in `buf` will contain the terms of the forward
    /// transform in permuted order.
    ///
    /// # Example
    #[cfg_attr(feature = "std", doc = " ```")]
    #[cfg_attr(not(feature = "std"), doc = " ```ignore")]
    /// use tfhe_fft::c64;
    /// use tfhe_fft::unordered::{Method, Plan};
    /// use dyn_stack::{PodStack, PodBuffer};
    /// use core::time::Duration;
    ///
    /// let plan = Plan::new(4, Method::Measure(Duration::from_millis(10)));
    ///
    /// let mut memory = PodBuffer::try_new(plan.fft_scratch()).unwrap();
    /// let stack = PodStack::new(&mut memory);
    ///
    /// let mut buf = [c64::default(); 4];
    /// plan.fwd(&mut buf, stack);
    /// ```
    pub fn fwd(&self, buf: &mut [c64], stack: &mut PodStack) {
        assert_eq!(self.fft_size(), buf.len());
        let (scratch, _) = stack.make_aligned_raw::<c64>(self.algo().1, CACHELINE_ALIGN);
        fwd_depth(
            buf,
            &self.twiddles,
            self.base_fn_fwd,
            self.base_n,
            scratch,
            self.fwd_process_x2,
            self.fwd_process_x4,
            self.fwd_process_x8,
        );
    }

    /// Performs a forward FFT on the implicit polynomial `X^degree`, storing the result in `buf`.
    /// The coefficients are permuted so that they're compatible with other FFTs produced by the
    /// same plan.
    pub fn fwd_monomial(&self, degree: usize, buf: &mut [c64]) {
        struct Impl<'a> {
            this: &'a Plan,
            degree: usize,
            buf: &'a mut [c64],
        }

        impl pulp::WithSimd for Impl<'_> {
            type Output = ();

            #[inline(always)]
            fn with_simd<S: pulp::Simd>(self, simd: S) -> Self::Output {
                let Self { this, degree, buf } = self;
                let _ = simd;
                assert_eq!(this.fft_size(), buf.len());
                assert!(degree < this.fft_size());

                let twiddles = &*this.monomial_twiddles;
                let indices = &*this.indices;

                let n = this.fft_size();
                let base_n = this.base_n;
                let n_mask = n - 1;

                assert!(n.is_power_of_two());
                assert_eq!(twiddles.len(), n);

                match n / base_n {
                    1 => {
                        // n == base_n
                        for (i, z) in buf.iter_mut().enumerate() {
                            *z = twiddles[(i * degree) & n_mask];
                        }
                    }
                    2 => {
                        // n == 2 * base_n
                        let (z0, z1) = buf.split_at_mut(n / 2);
                        for (i, (z0, z1)) in izip!(z0, z1).enumerate() {
                            *z0 = twiddles[((2 * i) * degree) & n_mask];
                            *z1 = twiddles[((2 * i + 1) * degree) & n_mask];
                        }
                    }
                    _ => {
                        for (z, &idx) in buf.iter_mut().zip(indices.iter()) {
                            *z = twiddles[(idx * degree) & n_mask];
                        }
                    }
                }
            }
        }

        pulp::Arch::new().dispatch(Impl {
            this: self,
            degree,
            buf,
        })
    }

    /// Performs an inverse FFT in place, using the provided stack as scratch space.
    ///
    /// # Note
    ///
    /// The values in `buf` must be in permuted order prior to calling this function.
    /// When this function returns, the values in `buf` will contain the terms of the forward
    /// transform in standard order.
    ///
    /// # Example
    #[cfg_attr(feature = "std", doc = " ```")]
    #[cfg_attr(not(feature = "std"), doc = " ```ignore")]
    /// use tfhe_fft::c64;
    /// use tfhe_fft::unordered::{Method, Plan};
    /// use dyn_stack::{PodStack, PodBuffer};
    /// use core::time::Duration;
    ///
    /// let plan = Plan::new(4, Method::Measure(Duration::from_millis(10)));
    ///
    /// let mut memory = PodBuffer::try_new(plan.fft_scratch()).unwrap();
    /// let stack = PodStack::new(&mut memory);
    ///
    /// let mut buf = [c64::default(); 4];
    /// plan.fwd(&mut buf, stack);
    /// plan.inv(&mut buf, stack);
    /// ```
    pub fn inv(&self, buf: &mut [c64], stack: &mut PodStack) {
        assert_eq!(self.fft_size(), buf.len());
        let (scratch, _) = stack.make_aligned_raw::<c64>(self.algo().1, CACHELINE_ALIGN);
        inv_depth(
            buf,
            &self.twiddles_inv,
            self.base_fn_inv,
            self.base_n,
            scratch,
            self.inv_process_x2,
            self.inv_process_x4,
            self.inv_process_x8,
        );
    }

    /// Serialize a buffer containing data in the Fourier domain that is stored in the
    /// plan-specific permuted order, and store the result with the serializer in the standard
    /// order.
    ///
    /// # Panics
    ///
    /// - Panics if the length of `buf` is not equal to the FFT size.
    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    pub fn serialize_fourier_buffer<S: serde::Serializer>(
        &self,
        serializer: S,
        buf: &[c64],
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let n = self.n;
        let base_n = self.base_n;
        assert_eq!(n, buf.len());

        let mut seq = serializer.serialize_seq(Some(n))?;

        let nbits = n.trailing_zeros();
        let base_nbits = base_n.trailing_zeros();

        for i in 0..n {
            seq.serialize_element(&buf[bit_rev_twice(nbits, base_nbits, i)])?;
        }

        seq.end()
    }

    /// Deserialize data in the Fourier domain that is produced by the deserializer in the standard
    /// order into a buffer so that it will contain the data in the plan-specific permuted order
    ///
    /// # Panics
    ///
    /// - Panics if the length of `buf` is not equal to the FFT size.
    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    pub fn deserialize_fourier_buffer<'de, D: serde::Deserializer<'de>>(
        &self,
        deserializer: D,
        buf: &mut [c64],
    ) -> Result<(), D::Error> {
        use serde::de::{SeqAccess, Visitor};

        let n = self.n;
        let base_n = self.base_n;
        assert_eq!(n, buf.len());

        struct SeqVisitor<'a> {
            buf: &'a mut [c64],
            base_n: usize,
        }

        impl<'de> Visitor<'de> for SeqVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(
                    formatter,
                    "a sequence of {} 64-bit complex numbers",
                    self.buf.len()
                )
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let n = self.buf.len();
                let nbits = n.trailing_zeros();
                let base_nbits = self.base_n.trailing_zeros();

                let mut i = 0;

                while let Some(value) = seq.next_element::<c64>()? {
                    if i < n {
                        self.buf[bit_rev_twice(nbits, base_nbits, i)] = value;
                    }

                    i += 1;
                }

                if i != n {
                    Err(serde::de::Error::invalid_length(i, &self))
                } else {
                    Ok(())
                }
            }
        }

        deserializer.deserialize_seq(SeqVisitor { buf, base_n })
    }
}

#[inline]
fn bit_rev(nbits: u32, i: usize) -> usize {
    i.reverse_bits() >> (usize::BITS - nbits)
}

#[cfg(any(test, feature = "serde"))]
#[inline]
fn bit_rev_twice(nbits: u32, base_nbits: u32, i: usize) -> usize {
    let i_rev = bit_rev(nbits, i);
    let bottom_mask = (1 << base_nbits) - 1;
    let bottom_bits = bit_rev(base_nbits, i_rev);
    (i_rev & !bottom_mask) | bottom_bits
}

#[inline]
fn bit_rev_twice_inv(nbits: u32, base_nbits: u32, i: usize) -> usize {
    let bottom_mask = (1 << base_nbits) - 1;
    let bottom_bits = bit_rev(base_nbits, i);
    let i_rev = (i & !bottom_mask) | bottom_bits;
    bit_rev(nbits, i_rev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use dyn_stack::PodBuffer;
    use num_complex::ComplexFloat;
    use rand::{random, random_range};

    extern crate alloc;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn test_fwd() {
        for n in [128, 256, 512, 1024] {
            let mut z = vec![c64::default(); n];

            for z in &mut z {
                z.re = random();
                z.im = random();
            }

            let mut z_target = z.clone();
            let mut planner = rustfft::FftPlanner::new();
            let fwd = planner.plan_fft_forward(n);
            fwd.process(&mut z_target);

            let plan = Plan::new(
                n,
                Method::UserProvided {
                    base_algo: FftAlgo::Dif4,
                    base_n: 32,
                },
            );
            let base_n = plan.algo().1;
            let mut mem = PodBuffer::try_new(plan.fft_scratch()).unwrap();
            let stack = PodStack::new(&mut mem);
            plan.fwd(&mut z, stack);

            for (i, z_target) in z_target.iter().enumerate() {
                let idx = bit_rev_twice(n.trailing_zeros(), base_n.trailing_zeros(), i);
                assert!((z[idx] - z_target).abs() < 1e-12);
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn test_fwd_monomial() {
        for n in [256, 512, 1024] {
            for base_n in [32, n, n / 2, n / 4, n / 8] {
                for _ in 0..10 {
                    let mut z = vec![c64::default(); n];
                    let degree = random_range(0..n);
                    z[degree] = c64 { re: 1.0, im: 0.0 };

                    let plan = Plan::new(
                        n,
                        Method::UserProvided {
                            base_algo: FftAlgo::Dif4,
                            base_n,
                        },
                    );
                    let mut mem = PodBuffer::try_new(plan.fft_scratch()).unwrap();
                    let stack = PodStack::new(&mut mem);

                    let mut z_target = z.clone();
                    plan.fwd(&mut z_target, stack);

                    plan.fwd_monomial(degree, &mut z);

                    for (z, z_target) in z.iter().zip(z_target.iter()) {
                        assert!((z - z_target).abs() < 1e-12);
                    }
                }
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn test_roundtrip() {
        for n in [32, 64, 256, 512, 1024] {
            let mut z = vec![c64::default(); n];

            for z in &mut z {
                z.re = random();
                z.im = random();
            }

            let orig = z.clone();

            let plan = Plan::new(
                n,
                Method::UserProvided {
                    base_algo: FftAlgo::Dif4,
                    base_n: 32,
                },
            );
            let mut mem = PodBuffer::try_new(plan.fft_scratch()).unwrap();
            let stack = PodStack::new(&mut mem);
            plan.fwd(&mut z, stack);
            plan.inv(&mut z, stack);

            for z in &mut z {
                *z /= n as f64;
            }

            for (z_actual, z_expected) in z.iter().zip(&orig) {
                assert!((z_actual - z_expected).abs() < 1e-12);
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn test_equivalency() {
        use num_complex::Complex;
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let n = 2048;
        let mut z = vec![c64::default(); n];

        for z in &mut z {
            z.re = rng.gen_range(0.0..1.0);
            z.im = rng.gen_range(0.0..1.0);
        }

        let plan = Plan::new(
            n,
            Method::UserProvided {
                base_algo: FftAlgo::Dif4,
                base_n: 32,
            },
        );
        let mut mem = PodBuffer::try_new(plan.fft_scratch()).unwrap();
        let stack = PodStack::new(&mut mem);
        plan.fwd(&mut z, stack);

        let target: [Complex<f64>; 2048] = [
            Complex {
                re: 1028.0259662650005,
                im: 1018.8306666971462,
            },
            Complex {
                re: -1.6117693610211064,
                im: -15.013711192807873,
            },
            Complex {
                re: 1.3112674293911724,
                im: 1.2251429785920784,
            },
            Complex {
                re: -20.28528463346552,
                im: 7.110672678227614,
            },
            Complex {
                re: 9.486891728598781,
                im: 2.911901435501745,
            },
            Complex {
                re: 12.25008872714404,
                im: 5.963396048157125,
            },
            Complex {
                re: -2.5962764345333165,
                im: -12.831877293461819,
            },
            Complex {
                re: 2.782043447688152,
                im: -2.2254088385521733,
            },
            Complex {
                re: 15.025822460761447,
                im: -6.901562095005431,
            },
            Complex {
                re: -7.7320015638941175,
                im: -16.668149825543075,
            },
            Complex {
                re: -5.952552151230277,
                im: -4.236714632923816,
            },
            Complex {
                re: -10.32976710102734,
                im: 9.37939095519813,
            },
            Complex {
                re: -10.749671593352927,
                im: 26.65904438791769,
            },
            Complex {
                re: -5.495747841263954,
                im: -16.484718062584925,
            },
            Complex {
                re: 8.045029058598553,
                im: 3.8950963050069536,
            },
            Complex {
                re: -9.212441503840381,
                im: -1.7096057638193103,
            },
            Complex {
                re: 19.613036175931143,
                im: 8.632734765942075,
            },
            Complex {
                re: 0.8871336107056365,
                im: -12.430422527338864,
            },
            Complex {
                re: -18.33721373243693,
                im: 9.667933777622913,
            },
            Complex {
                re: -9.129128861942249,
                im: 6.792851918959798,
            },
            Complex {
                re: -17.691345686451033,
                im: 20.462809228552956,
            },
            Complex {
                re: 0.8196471635013776,
                im: 13.903538212651679,
            },
            Complex {
                re: -14.612927131721474,
                im: 26.28646522826971,
            },
            Complex {
                re: -1.9266345213265765,
                im: -18.5116444369889,
            },
            Complex {
                re: -23.22135429999605,
                im: -3.695931488535109,
            },
            Complex {
                re: 14.035565672187667,
                im: 2.060372212125138,
            },
            Complex {
                re: -6.652169508447743,
                im: 7.876956812328883,
            },
            Complex {
                re: -10.637574685713666,
                im: 10.856497724586053,
            },
            Complex {
                re: -5.4394388959817395,
                im: 11.425732577484197,
            },
            Complex {
                re: 2.8126657769443963,
                im: 2.897746766280224,
            },
            Complex {
                re: -30.84383177107336,
                im: -16.693174572395996,
            },
            Complex {
                re: 1.26359411816019,
                im: -5.2266421995563555,
            },
            Complex {
                re: 30.788282562891066,
                im: -4.42682448758667,
            },
            Complex {
                re: -10.881145178981333,
                im: -4.886861935606913,
            },
            Complex {
                re: 11.909004404395587,
                im: -8.972956450555657,
            },
            Complex {
                re: 7.457364703957756,
                im: 6.050797558455422,
            },
            Complex {
                re: 2.6166154221759808,
                im: -3.764953521219243,
            },
            Complex {
                re: -8.241160876585377,
                im: 11.317153896914625,
            },
            Complex {
                re: 2.539579436009626,
                im: 9.66852195630992,
            },
            Complex {
                re: 11.988516710433085,
                im: 9.288431313060022,
            },
            Complex {
                re: -5.235275716786529,
                im: -0.060624486914479414,
            },
            Complex {
                re: 4.834178886045402,
                im: 7.989895672073488,
            },
            Complex {
                re: 22.47620086739977,
                im: 0.3093510534923656,
            },
            Complex {
                re: 5.535096119344459,
                im: 12.365184657835606,
            },
            Complex {
                re: -12.102199148517418,
                im: -29.00935811610653,
            },
            Complex {
                re: -2.4358159100396235,
                im: -9.003944212814954,
            },
            Complex {
                re: 25.920524886714876,
                im: 17.729715744732047,
            },
            Complex {
                re: 9.909927367822194,
                im: -10.123939499496494,
            },
            Complex {
                re: 13.59538132312677,
                im: 13.426396519419585,
            },
            Complex {
                re: -29.99375200993027,
                im: 13.59043160119673,
            },
            Complex {
                re: 12.91948274129384,
                im: 11.187993117012375,
            },
            Complex {
                re: -16.52473440881338,
                im: 5.737525274042028,
            },
            Complex {
                re: -2.088229278873378,
                im: -18.192539096325365,
            },
            Complex {
                re: 17.373519163452514,
                im: 4.100544520805514,
            },
            Complex {
                re: 3.1067670187257073,
                im: -10.320319488898004,
            },
            Complex {
                re: 15.023282840430767,
                im: -1.3107168940158433,
            },
            Complex {
                re: 2.12032305068377,
                im: 2.7153895462920072,
            },
            Complex {
                re: -14.499997469600016,
                im: 6.9620892254787465,
            },
            Complex {
                re: 6.313774244993018,
                im: 14.095880872892534,
            },
            Complex {
                re: -0.7351930216807379,
                im: -7.121045869688501,
            },
            Complex {
                re: -4.709227004773897,
                im: -20.718198404219155,
            },
            Complex {
                re: -7.790227219313385,
                im: 14.19504310843211,
            },
            Complex {
                re: 19.961995300660842,
                im: -25.492654225774103,
            },
            Complex {
                re: -12.886075251513232,
                im: 13.576214170135668,
            },
            Complex {
                re: -12.70206371312696,
                im: 24.39257797384933,
            },
            Complex {
                re: 25.4640391469203,
                im: -14.232324132421372,
            },
            Complex {
                re: -4.49845947621799,
                im: 11.952299090504125,
            },
            Complex {
                re: 4.120845475491185,
                im: -8.458601221813485,
            },
            Complex {
                re: -16.845625883172914,
                im: -10.115639893749465,
            },
            Complex {
                re: 2.0146482585195313,
                im: 2.9022477054857854,
            },
            Complex {
                re: -2.0434027910696297,
                im: -16.95230202898982,
            },
            Complex {
                re: -12.727204500271226,
                im: -1.5112216094891089,
            },
            Complex {
                re: 4.460715577516242,
                im: 7.298053055963965,
            },
            Complex {
                re: -15.201004425621546,
                im: -3.643352597958192,
            },
            Complex {
                re: -17.178938829448526,
                im: -7.269222810804612,
            },
            Complex {
                re: 3.6995889143984115,
                im: 11.32353159052323,
            },
            Complex {
                re: 9.856606656588676,
                im: -0.15708229250553885,
            },
            Complex {
                re: 1.002011947771364,
                im: -23.026577810296068,
            },
            Complex {
                re: 19.316616688515552,
                im: -26.987237511377522,
            },
            Complex {
                re: -12.87339624457927,
                im: 15.263034715141025,
            },
            Complex {
                re: 17.206045321300998,
                im: -5.753212499841329,
            },
            Complex {
                re: 16.75998043798385,
                im: 10.02889526325729,
            },
            Complex {
                re: 24.86147190691085,
                im: 14.845425680213081,
            },
            Complex {
                re: 21.770804109643883,
                im: 5.472761990483826,
            },
            Complex {
                re: 6.173861818983644,
                im: 2.779263857593321,
            },
            Complex {
                re: -3.306292845835979,
                im: 1.2514510183654073,
            },
            Complex {
                re: -10.589776586213551,
                im: 10.835415489493093,
            },
            Complex {
                re: 21.354773869607456,
                im: 25.677462496219444,
            },
            Complex {
                re: 19.009171740520543,
                im: 7.327229335843681,
            },
            Complex {
                re: 9.540606241741107,
                im: -7.641250440487708,
            },
            Complex {
                re: 23.857348431649974,
                im: -2.6133071272040365,
            },
            Complex {
                re: 5.378906999079025,
                im: 4.612209829044062,
            },
            Complex {
                re: -12.425164741725483,
                im: 19.79323386897317,
            },
            Complex {
                re: 5.344349257495103,
                im: -10.75488071248251,
            },
            Complex {
                re: -21.378831513449022,
                im: -6.7124414913580726,
            },
            Complex {
                re: -10.723422531336306,
                im: 1.599743887554859,
            },
            Complex {
                re: 19.94580091986104,
                im: 13.752274049039102,
            },
            Complex {
                re: 1.9766889123082088,
                im: -13.203864577133283,
            },
            Complex {
                re: -3.870810047648199,
                im: -18.929842412819653,
            },
            Complex {
                re: -11.46489452314677,
                im: 3.1978078586164953,
            },
            Complex {
                re: 25.41501249455765,
                im: 5.89359024870779,
            },
            Complex {
                re: 19.541363810041915,
                im: -0.33577677224777935,
            },
            Complex {
                re: 10.02778029220173,
                im: -35.85876300996001,
            },
            Complex {
                re: 9.772825909300176,
                im: 4.894850565902111,
            },
            Complex {
                re: -22.92962789502502,
                im: -4.698482122931518,
            },
            Complex {
                re: -5.760276468264342,
                im: 1.5193740271503797,
            },
            Complex {
                re: -14.172295323882778,
                im: 0.7035668707669265,
            },
            Complex {
                re: -16.931595611586815,
                im: -0.22314620849418887,
            },
            Complex {
                re: 15.107856668297106,
                im: -6.871811984082004,
            },
            Complex {
                re: 10.411914616224461,
                im: -0.983439047957614,
            },
            Complex {
                re: 11.642769650643567,
                im: 7.634013193704006,
            },
            Complex {
                re: 23.74299706849616,
                im: -14.947527880743275,
            },
            Complex {
                re: -9.631494310991457,
                im: -0.4034703132980937,
            },
            Complex {
                re: 38.84690684971271,
                im: -7.819020662094461,
            },
            Complex {
                re: 5.480236629930408,
                im: 20.439521278247817,
            },
            Complex {
                re: -6.194972765742682,
                im: -11.879099549949284,
            },
            Complex {
                re: -15.44018327569065,
                im: -18.645077292737405,
            },
            Complex {
                re: -17.0107273832313,
                im: 3.5400876795121787,
            },
            Complex {
                re: 16.48465271915904,
                im: -12.952312210723413,
            },
            Complex {
                re: 14.668687998777747,
                im: 5.788777788405749,
            },
            Complex {
                re: -4.738328900633055,
                im: -24.12471447899992,
            },
            Complex {
                re: 7.9533618468179,
                im: 6.646345495132278,
            },
            Complex {
                re: 12.82191985043,
                im: -13.87832186104814,
            },
            Complex {
                re: 28.97611656990535,
                im: -18.719246951384473,
            },
            Complex {
                re: -7.0879258155532945,
                im: -0.7155883041959576,
            },
            Complex {
                re: -16.321381653625966,
                im: 6.044742784125379,
            },
            Complex {
                re: -4.596160725511149,
                im: 0.14589972137458762,
            },
            Complex {
                re: -18.06457295366512,
                im: 27.007491079308288,
            },
            Complex {
                re: 20.634964311519106,
                im: 17.00202447958753,
            },
            Complex {
                re: 5.225277241606747,
                im: 2.423084994662922,
            },
            Complex {
                re: -0.1933989830891445,
                im: -6.451546431462679,
            },
            Complex {
                re: -2.2859227763753163,
                im: 15.419675393141016,
            },
            Complex {
                re: 2.5047060233798346,
                im: -5.608157004608893,
            },
            Complex {
                re: 19.925767902765056,
                im: 24.304173508269848,
            },
            Complex {
                re: -3.876320999628123,
                im: 18.364492538423693,
            },
            Complex {
                re: -38.69717789689757,
                im: -11.514610046238788,
            },
            Complex {
                re: -11.28378950414232,
                im: 1.7963755029815651,
            },
            Complex {
                re: 19.098020322932356,
                im: 13.069725495131152,
            },
            Complex {
                re: 16.05193649072467,
                im: -19.777951315776292,
            },
            Complex {
                re: 2.98914356244319,
                im: 19.968601941027522,
            },
            Complex {
                re: -0.7412565632291299,
                im: -11.001096412387769,
            },
            Complex {
                re: 11.2673615646571,
                im: -7.77060018748361,
            },
            Complex {
                re: -24.467646487505505,
                im: -4.15547168693216,
            },
            Complex {
                re: 2.7533683500515,
                im: 3.8549089212854124,
            },
            Complex {
                re: 10.52124618617088,
                im: 3.495770734790426,
            },
            Complex {
                re: 5.332664773675603,
                im: -4.706461063969051,
            },
            Complex {
                re: 22.670870017379485,
                im: -24.438628190075065,
            },
            Complex {
                re: 11.456461814641866,
                im: 6.661606897393465,
            },
            Complex {
                re: 17.170446787152134,
                im: 6.8416307108608105,
            },
            Complex {
                re: -17.690393533541442,
                im: 7.201025953583903,
            },
            Complex {
                re: -13.476138882188746,
                im: 5.744820930127671,
            },
            Complex {
                re: -0.9380347199726202,
                im: -4.0547585742805925,
            },
            Complex {
                re: 12.610705976806198,
                im: -12.316127836749505,
            },
            Complex {
                re: 5.369389284463962,
                im: 29.435802305040397,
            },
            Complex {
                re: 0.4423204979596127,
                im: -1.1670561194519316,
            },
            Complex {
                re: -10.24692823183144,
                im: -33.891676276395906,
            },
            Complex {
                re: 11.196890710431063,
                im: -9.881600457765012,
            },
            Complex {
                re: -14.615127173515138,
                im: -10.50635363525803,
            },
            Complex {
                re: -8.899354725016671,
                im: 9.117790310544017,
            },
            Complex {
                re: 8.874888716808623,
                im: 10.957548192856832,
            },
            Complex {
                re: 16.19558877138588,
                im: 1.833578218960076,
            },
            Complex {
                re: -18.135010828987618,
                im: -13.518213015468703,
            },
            Complex {
                re: -18.907073795839235,
                im: -3.4672498159881044,
            },
            Complex {
                re: -10.429245580900592,
                im: 11.43165463273113,
            },
            Complex {
                re: -2.959367702958237,
                im: 29.83330172841742,
            },
            Complex {
                re: 6.656024776125527,
                im: -14.517624586261366,
            },
            Complex {
                re: -6.113768162304773,
                im: 8.605066056031395,
            },
            Complex {
                re: 11.491699567451217,
                im: -0.8675856180933366,
            },
            Complex {
                re: 11.107044188390658,
                im: -11.148729472170343,
            },
            Complex {
                re: -2.480038165090889,
                im: -13.96096667827495,
            },
            Complex {
                re: -6.133175716656055,
                im: 7.285624374527638,
            },
            Complex {
                re: 2.8161502658425133,
                im: 8.54463896598238,
            },
            Complex {
                re: -22.333129778307278,
                im: -6.138306382828617,
            },
            Complex {
                re: -14.091587480057466,
                im: 3.35257307275866,
            },
            Complex {
                re: 6.502552489401501,
                im: 5.139508248996664,
            },
            Complex {
                re: -20.616717548434636,
                im: 9.647606887692353,
            },
            Complex {
                re: 20.397319096483564,
                im: -3.2651063863010616,
            },
            Complex {
                re: 16.06494152863663,
                im: 0.8327611067130958,
            },
            Complex {
                re: -9.788620431086375,
                im: 1.266790137316554,
            },
            Complex {
                re: -0.4512121282574535,
                im: 15.070648963781712,
            },
            Complex {
                re: -10.836830612627377,
                im: -0.9031037127332944,
            },
            Complex {
                re: 3.0843274737055477,
                im: -21.271391610833295,
            },
            Complex {
                re: -10.252311484313498,
                im: 0.2552896280508712,
            },
            Complex {
                re: -11.089055369488932,
                im: 9.291676225210107,
            },
            Complex {
                re: 6.904128558250919,
                im: -18.551765065644695,
            },
            Complex {
                re: -10.35376500370079,
                im: 3.1076515876348774,
            },
            Complex {
                re: -21.53897166610131,
                im: -7.002158613136196,
            },
            Complex {
                re: -8.808235010541223,
                im: 2.72807054421241,
            },
            Complex {
                re: -22.397737519797065,
                im: 2.404393168334403,
            },
            Complex {
                re: 22.048213502114866,
                im: 14.369224020865154,
            },
            Complex {
                re: -5.2172926484039435,
                im: -5.936396737619827,
            },
            Complex {
                re: 2.6209350681696595,
                im: -9.702223353631124,
            },
            Complex {
                re: -30.120890813643555,
                im: 22.646616500437176,
            },
            Complex {
                re: 9.912526477969623,
                im: 14.231259307000471,
            },
            Complex {
                re: 14.958866995272867,
                im: 16.153570845426813,
            },
            Complex {
                re: -6.290442446646532,
                im: 16.241406107667228,
            },
            Complex {
                re: -4.509161534980114,
                im: 20.339711865683718,
            },
            Complex {
                re: -20.29062121382213,
                im: -3.1510963194146138,
            },
            Complex {
                re: 2.5880542541477976,
                im: -5.5031160537354005,
            },
            Complex {
                re: -0.4614802642036162,
                im: 4.034906018595789,
            },
            Complex {
                re: 10.005534411295322,
                im: -12.175662303050059,
            },
            Complex {
                re: 3.09757376532731,
                im: -21.476272605040897,
            },
            Complex {
                re: 9.357605769017665,
                im: 34.79439922904942,
            },
            Complex {
                re: -12.281421340409803,
                im: 0.7098777991460139,
            },
            Complex {
                re: -16.638938245295932,
                im: 10.141216211909143,
            },
            Complex {
                re: 15.314649224968631,
                im: -1.5438556603467062,
            },
            Complex {
                re: -21.75173842809958,
                im: 17.057561506943387,
            },
            Complex {
                re: 5.024679794368951,
                im: 22.852689051359008,
            },
            Complex {
                re: 4.694228815656034,
                im: -18.62939106970076,
            },
            Complex {
                re: 1.344592363293474,
                im: -2.734812908361836,
            },
            Complex {
                re: 9.773243511407248,
                im: 3.6510945352484345,
            },
            Complex {
                re: 16.114668949587326,
                im: 9.102746197458327,
            },
            Complex {
                re: -26.680126156444516,
                im: -6.393746232168626,
            },
            Complex {
                re: -2.745839039372761,
                im: 11.902629570720514,
            },
            Complex {
                re: 32.937127873927295,
                im: 6.076865159827808,
            },
            Complex {
                re: 10.297155933797253,
                im: 0.9684239177581708,
            },
            Complex {
                re: -6.230425300247173,
                im: -5.582421032945627,
            },
            Complex {
                re: 6.743270478536752,
                im: -7.374887500817593,
            },
            Complex {
                re: 1.1796640683643336,
                im: 12.165142361285053,
            },
            Complex {
                re: -5.165445037280208,
                im: 18.763969685843016,
            },
            Complex {
                re: 7.651015396487168,
                im: -20.223348393872826,
            },
            Complex {
                re: 12.628445104490153,
                im: 2.02828317513875,
            },
            Complex {
                re: -17.80609922034911,
                im: -7.668233095353999,
            },
            Complex {
                re: -15.007641588363668,
                im: -9.70687199757384,
            },
            Complex {
                re: 4.950863807243907,
                im: -6.454790273473089,
            },
            Complex {
                re: -5.704768754301221,
                im: -20.638908478964417,
            },
            Complex {
                re: 2.0949921604679975,
                im: -5.969193394621694,
            },
            Complex {
                re: -14.015836215299426,
                im: -6.008029354183316,
            },
            Complex {
                re: 11.764815998604206,
                im: -7.9639077105934994,
            },
            Complex {
                re: 0.7987633936023337,
                im: 6.60478700813403,
            },
            Complex {
                re: 7.372246783433016,
                im: 8.753106246685634,
            },
            Complex {
                re: 2.8237943213215786,
                im: 2.478693805042268,
            },
            Complex {
                re: 9.83715804021296,
                im: 6.211757067671594,
            },
            Complex {
                re: 8.323519576441065,
                im: 19.748947189947508,
            },
            Complex {
                re: -7.29300701733631,
                im: 13.332503360894544,
            },
            Complex {
                re: -11.454902205563783,
                im: 15.534425150530947,
            },
            Complex {
                re: 14.761037874272274,
                im: 12.482815327575214,
            },
            Complex {
                re: -3.9052030989193582,
                im: -8.745483333422666,
            },
            Complex {
                re: -10.29658543928155,
                im: -17.85390477602305,
            },
            Complex {
                re: -3.454253132821332,
                im: -4.242877559090589,
            },
            Complex {
                re: -6.801078893425469,
                im: 29.256364180576526,
            },
            Complex {
                re: -12.892149544792623,
                im: -6.273592485813063,
            },
            Complex {
                re: 20.927189146277293,
                im: 0.5643124615863386,
            },
            Complex {
                re: -5.554468897753606,
                im: -4.659590634296643,
            },
            Complex {
                re: 0.4773254908450424,
                im: -15.559807472454843,
            },
            Complex {
                re: 1.3980372069727396,
                im: 5.750438547112767,
            },
            Complex {
                re: 0.23066291674739325,
                im: -3.0132785466514433,
            },
            Complex {
                re: -19.3799594759589,
                im: -6.260450700431114,
            },
            Complex {
                re: -6.958710493680245,
                im: -6.688689148992693,
            },
            Complex {
                re: 18.714513003395673,
                im: -12.139964055868633,
            },
            Complex {
                re: 14.932676464690271,
                im: -2.8093523584452686,
            },
            Complex {
                re: 11.20013499194657,
                im: 9.50123202580238,
            },
            Complex {
                re: -13.816063162566936,
                im: 1.498822177641208,
            },
            Complex {
                re: 7.563080840552125,
                im: 28.625398382799023,
            },
            Complex {
                re: -9.28289135745532,
                im: 3.0991621800194853,
            },
            Complex {
                re: -1.180887166345881,
                im: 0.7247014303386714,
            },
            Complex {
                re: -14.535438260202586,
                im: 20.066507098199047,
            },
            Complex {
                re: 2.324418939447421,
                im: 8.779981890745457,
            },
            Complex {
                re: 11.058519865155263,
                im: 24.88021839980392,
            },
            Complex {
                re: 2.3325813624488525,
                im: 11.954950423671335,
            },
            Complex {
                re: 3.4576035174351833,
                im: -12.507157770615486,
            },
            Complex {
                re: -3.9894121115304335,
                im: 13.864022402635332,
            },
            Complex {
                re: -6.902035012590352,
                im: 11.78720852988728,
            },
            Complex {
                re: 0.9987229131308424,
                im: 3.00142381974446,
            },
            Complex {
                re: 13.86900577624618,
                im: 0.9370807398649976,
            },
            Complex {
                re: -20.737262138693843,
                im: 11.017176793695622,
            },
            Complex {
                re: -10.145380208044468,
                im: -10.489063712899554,
            },
            Complex {
                re: 14.983780940343895,
                im: 33.21030103345157,
            },
            Complex {
                re: -12.168526296965837,
                im: -5.9132515754374815,
            },
            Complex {
                re: -23.536931134167684,
                im: -0.5384059362843396,
            },
            Complex {
                re: -6.744678899812265,
                im: -19.98216673123754,
            },
            Complex {
                re: 19.028684386772316,
                im: -15.932711522469017,
            },
            Complex {
                re: 2.755468299263806,
                im: 11.351583779471477,
            },
            Complex {
                re: -13.338948011071624,
                im: 28.404018847750397,
            },
            Complex {
                re: 0.7823031348196228,
                im: -15.594387674398757,
            },
            Complex {
                re: -20.961805618830038,
                im: 15.601578963787507,
            },
            Complex {
                re: 18.10402291539686,
                im: 3.9563757086108033,
            },
            Complex {
                re: -11.49166858022786,
                im: 5.483631483223635,
            },
            Complex {
                re: 2.2026010664388984,
                im: -0.5227129237213992,
            },
            Complex {
                re: -5.520566986458462,
                im: 12.100931681165843,
            },
            Complex {
                re: 14.439664721952479,
                im: -16.31757007954623,
            },
            Complex {
                re: 16.242893540064316,
                im: -17.884366952484918,
            },
            Complex {
                re: 18.977269990131557,
                im: 17.693114622762803,
            },
            Complex {
                re: -7.8645813304810614,
                im: -1.4494772403540335,
            },
            Complex {
                re: 1.4879596773412915,
                im: -0.5341117653260015,
            },
            Complex {
                re: 0.17792881057955512,
                im: -2.892799655310421,
            },
            Complex {
                re: -21.361207055172812,
                im: 2.480083991984145,
            },
            Complex {
                re: -6.0495557652475105,
                im: -17.37892895506268,
            },
            Complex {
                re: 16.48266794221194,
                im: 26.073891524657675,
            },
            Complex {
                re: -2.6381274583925585,
                im: 9.741020554255797,
            },
            Complex {
                re: -1.6227088059276502,
                im: 20.551426420155448,
            },
            Complex {
                re: -8.904014616929338,
                im: -11.459371308574124,
            },
            Complex {
                re: 0.08205547143563141,
                im: 20.081003696467338,
            },
            Complex {
                re: -0.9692577709049344,
                im: 0.46227861486215005,
            },
            Complex {
                re: -9.502562699326788,
                im: -10.206659958510762,
            },
            Complex {
                re: -12.830658115539924,
                im: -14.071642658906828,
            },
            Complex {
                re: 11.971937883634082,
                im: 11.955764894307235,
            },
            Complex {
                re: 7.060288176310949,
                im: 4.719417145703684,
            },
            Complex {
                re: 1.1866048321225025,
                im: -10.205809208787048,
            },
            Complex {
                re: 8.306897412146556,
                im: 3.209027899760823,
            },
            Complex {
                re: 15.316784783243335,
                im: -13.947053430079272,
            },
            Complex {
                re: 3.5243908601416747,
                im: -2.9549895394107266,
            },
            Complex {
                re: 7.228034256385309,
                im: 15.459194337247341,
            },
            Complex {
                re: 5.22380976262591,
                im: 2.2275338240085087,
            },
            Complex {
                re: -6.758063594330443,
                im: 19.99160744305187,
            },
            Complex {
                re: 9.055412556778949,
                im: 0.10535584444193002,
            },
            Complex {
                re: -0.5212199148345373,
                im: -1.1532476387551363,
            },
            Complex {
                re: -6.699760020299823,
                im: -20.06704927841285,
            },
            Complex {
                re: 1.5528828042634482,
                im: -16.149281661810893,
            },
            Complex {
                re: 10.735818307554947,
                im: -15.581284702993699,
            },
            Complex {
                re: 3.536463611266538,
                im: -9.406904243310137,
            },
            Complex {
                re: 15.335892608274102,
                im: 21.8805011998269,
            },
            Complex {
                re: 3.944110757690334,
                im: -25.94398669047233,
            },
            Complex {
                re: -2.771747024243134,
                im: 20.409979227841948,
            },
            Complex {
                re: -12.078324850596498,
                im: -4.565776955178567,
            },
            Complex {
                re: -15.567746339791517,
                im: 11.920347993565644,
            },
            Complex {
                re: -28.942814971945552,
                im: 20.105718190425833,
            },
            Complex {
                re: 7.398683291266836,
                im: -3.965654180594908,
            },
            Complex {
                re: 14.261125812277674,
                im: -3.811487796094804,
            },
            Complex {
                re: -7.307915799147931,
                im: -3.4168682424746377,
            },
            Complex {
                re: 13.37870232405555,
                im: 4.822433182349451,
            },
            Complex {
                re: 1.5028816275729557,
                im: 22.58628303567199,
            },
            Complex {
                re: 0.1467317655076723,
                im: 23.48775087363032,
            },
            Complex {
                re: -5.558656769331895,
                im: 2.180396728461207,
            },
            Complex {
                re: 6.2444039530251665,
                im: -1.0063973640488664,
            },
            Complex {
                re: 17.33473330862097,
                im: -16.344679491123678,
            },
            Complex {
                re: -15.705851865952555,
                im: 23.303240396554536,
            },
            Complex {
                re: 14.804138868916171,
                im: -13.860465602767729,
            },
            Complex {
                re: 6.711568020982279,
                im: 9.213315542417792,
            },
            Complex {
                re: -6.418382347623902,
                im: 10.801664695347121,
            },
            Complex {
                re: 13.810050162330523,
                im: 27.504493573447775,
            },
            Complex {
                re: -8.721044283612805,
                im: -7.4148470834499935,
            },
            Complex {
                re: -9.15029430271592,
                im: -8.516060855762515,
            },
            Complex {
                re: 2.0867044361135036,
                im: -18.751351578912796,
            },
            Complex {
                re: 0.20923399264974307,
                im: -23.446798586420986,
            },
            Complex {
                re: 14.48900852100177,
                im: 1.923271877039749,
            },
            Complex {
                re: 2.1916279752667833,
                im: 19.819111364942707,
            },
            Complex {
                re: 17.706425710454525,
                im: 7.299408451723826,
            },
            Complex {
                re: 27.917544061503833,
                im: 0.11882846442544981,
            },
            Complex {
                re: -13.137812499919749,
                im: 2.3215838573980774,
            },
            Complex {
                re: 33.76326789846986,
                im: -12.362336221902638,
            },
            Complex {
                re: 19.859439054345437,
                im: -7.111101380205134,
            },
            Complex {
                re: 17.273538621556085,
                im: 0.09258115329589778,
            },
            Complex {
                re: 11.495643067698774,
                im: 5.71124511293366,
            },
            Complex {
                re: -1.744494972459508,
                im: 4.0098929648844255,
            },
            Complex {
                re: -26.10838593587146,
                im: -10.683295483814579,
            },
            Complex {
                re: 0.9104167354817667,
                im: 1.0593561350905905,
            },
            Complex {
                re: 12.541302912478649,
                im: -23.23077547657512,
            },
            Complex {
                re: 36.66479360803275,
                im: 9.04325950206973,
            },
            Complex {
                re: 13.372138096990676,
                im: -4.025968425098549,
            },
            Complex {
                re: -12.46266080807398,
                im: 10.251616419357202,
            },
            Complex {
                re: -2.3235798598766184,
                im: 24.758059214349327,
            },
            Complex {
                re: -8.944529560249066,
                im: 7.675461987198305,
            },
            Complex {
                re: 16.186043137692913,
                im: 4.264344679338463,
            },
            Complex {
                re: -3.5661002112401317,
                im: -18.380578696584227,
            },
            Complex {
                re: 11.639938694239113,
                im: -12.537579557666735,
            },
            Complex {
                re: 10.096558064482776,
                im: -7.571413466369111,
            },
            Complex {
                re: -10.953542122393284,
                im: 2.0682673232536217,
            },
            Complex {
                re: 7.151115065893588,
                im: 5.628202765879623,
            },
            Complex {
                re: 23.137628160524134,
                im: -12.87296022083679,
            },
            Complex {
                re: -2.144292755972402,
                im: -13.087386362235657,
            },
            Complex {
                re: 17.35563123117715,
                im: 17.10264650655507,
            },
            Complex {
                re: 10.759062075568739,
                im: -21.991116256631308,
            },
            Complex {
                re: -6.3427844995375455,
                im: -2.7796229809665856,
            },
            Complex {
                re: 18.32418480776461,
                im: -3.4594998752187633,
            },
            Complex {
                re: -14.993701327268674,
                im: 8.593848887950143,
            },
            Complex {
                re: -1.209480045255809,
                im: 15.912797088677213,
            },
            Complex {
                re: 8.007773722902012,
                im: 8.328660046320394,
            },
            Complex {
                re: 3.635574626080345,
                im: 12.01395912712238,
            },
            Complex {
                re: -3.9763500923648163,
                im: -7.351874223790097,
            },
            Complex {
                re: 9.348051847622775,
                im: -1.7765126779945497,
            },
            Complex {
                re: 8.220535587384067,
                im: -8.152820491587537,
            },
            Complex {
                re: -19.342749187628492,
                im: -4.451858196974698,
            },
            Complex {
                re: 15.108292435793285,
                im: -31.93018546717763,
            },
            Complex {
                re: -18.281986616627588,
                im: -34.53243499403097,
            },
            Complex {
                re: -11.687896173233344,
                im: -0.2816800196564717,
            },
            Complex {
                re: -2.0049039506507667,
                im: 18.203969833915636,
            },
            Complex {
                re: 15.58876638139823,
                im: -18.674309905114054,
            },
            Complex {
                re: -11.131684421279143,
                im: 4.662392085212824,
            },
            Complex {
                re: -21.244642595085303,
                im: 8.186561009317305,
            },
            Complex {
                re: 17.79207156026142,
                im: 11.115122183680096,
            },
            Complex {
                re: -5.581605352148693,
                im: 12.931708150567191,
            },
            Complex {
                re: 23.422100821982283,
                im: -4.09576924226451,
            },
            Complex {
                re: 5.14249115485588,
                im: 17.1296806868889,
            },
            Complex {
                re: 10.301487498377277,
                im: 26.34082307377158,
            },
            Complex {
                re: 9.276913759088401,
                im: -8.586416864422413,
            },
            Complex {
                re: -12.829714142422432,
                im: 3.8430493654785276,
            },
            Complex {
                re: 2.479235901836338,
                im: 0.015092691513818757,
            },
            Complex {
                re: -0.45278241584203904,
                im: -2.1840502066765426,
            },
            Complex {
                re: 9.287187432871125,
                im: -10.222163641928184,
            },
            Complex {
                re: -6.6046661761858925,
                im: 1.1538521791020315,
            },
            Complex {
                re: 28.571759406096373,
                im: -1.1854066205190819,
            },
            Complex {
                re: -23.54186629194379,
                im: -2.171612088313559,
            },
            Complex {
                re: -23.658394951901823,
                im: 14.48063824756328,
            },
            Complex {
                re: 12.2184736122543,
                im: -10.531508905911693,
            },
            Complex {
                re: 24.932479923014167,
                im: -13.97341561416677,
            },
            Complex {
                re: 0.09744138417804826,
                im: 15.052543260547965,
            },
            Complex {
                re: 4.739156671152596,
                im: 10.613013592944448,
            },
            Complex {
                re: 0.93921240356529,
                im: -12.550392781166604,
            },
            Complex {
                re: 0.9783225554901662,
                im: -19.682570957304634,
            },
            Complex {
                re: -15.320365204076388,
                im: -5.249895251029107,
            },
            Complex {
                re: -12.288435410480528,
                im: 14.930344624501485,
            },
            Complex {
                re: 1.564945771845454,
                im: -4.642581407325782,
            },
            Complex {
                re: 3.286035332455361,
                im: 0.9620812108268835,
            },
            Complex {
                re: 21.01137727645643,
                im: -11.03705116939122,
            },
            Complex {
                re: -22.507955074305954,
                im: -0.31085274058539003,
            },
            Complex {
                re: 14.846109226254553,
                im: -15.375913024066172,
            },
            Complex {
                re: -5.20655121565105,
                im: 1.6180259427525883,
            },
            Complex {
                re: 2.2514663124711287,
                im: 7.730658210536141,
            },
            Complex {
                re: -0.889340088234615,
                im: 2.1333212709729494,
            },
            Complex {
                re: -4.2931731383071146,
                im: 23.874463236126452,
            },
            Complex {
                re: 10.486891674328565,
                im: 15.160469268974444,
            },
            Complex {
                re: -1.72262439899239,
                im: -6.0516229528100265,
            },
            Complex {
                re: 5.035129007803812,
                im: -1.87984916029927,
            },
            Complex {
                re: -3.2388301858472612,
                im: 0.350689149221588,
            },
            Complex {
                re: -9.828412242577492,
                im: -21.302786132600303,
            },
            Complex {
                re: -18.45884912317817,
                im: 9.213740932843459,
            },
            Complex {
                re: -9.764277248364746,
                im: -1.1129730696565332,
            },
            Complex {
                re: 0.2385543935502335,
                im: 0.9956274053015145,
            },
            Complex {
                re: -30.99881144221836,
                im: 3.9592403189555743,
            },
            Complex {
                re: 16.374236237226334,
                im: 18.234665458480734,
            },
            Complex {
                re: 26.95047110381829,
                im: 7.477889838048215,
            },
            Complex {
                re: -11.579158339694912,
                im: -13.899683783325397,
            },
            Complex {
                re: -24.52974282481005,
                im: 4.752970154631453,
            },
            Complex {
                re: 3.62399029499804,
                im: 8.579354111019262,
            },
            Complex {
                re: -17.009223748729447,
                im: 2.5991826558544,
            },
            Complex {
                re: 0.45703486319698783,
                im: 5.839827908139467,
            },
            Complex {
                re: 21.96016906593818,
                im: -8.562944491493823,
            },
            Complex {
                re: 3.1279975430064715,
                im: -11.890170396938231,
            },
            Complex {
                re: 9.06265471120285,
                im: 25.188767015377994,
            },
            Complex {
                re: 1.2481376155726913,
                im: -5.727503236161135,
            },
            Complex {
                re: -5.80643080017345,
                im: 4.765257159799247,
            },
            Complex {
                re: -8.54514782172761,
                im: -6.694265582591102,
            },
            Complex {
                re: -6.7304756395905345,
                im: 3.0700157243055557,
            },
            Complex {
                re: -0.6250266233106596,
                im: 0.2878287002775485,
            },
            Complex {
                re: 7.564171275767544,
                im: 16.501757153298847,
            },
            Complex {
                re: -25.46754294197423,
                im: -15.325729534124335,
            },
            Complex {
                re: 24.52358050630964,
                im: -1.8399026904579436,
            },
            Complex {
                re: -12.785037328755225,
                im: 3.7187309807469333,
            },
            Complex {
                re: 1.533739925653606,
                im: 6.542482856645107,
            },
            Complex {
                re: 3.569728802371198,
                im: 10.709594471101768,
            },
            Complex {
                re: 18.675040752064426,
                im: 16.366197714311788,
            },
            Complex {
                re: -1.569262799440664,
                im: -26.061704335939183,
            },
            Complex {
                re: 0.838492009542863,
                im: -0.7724505137130704,
            },
            Complex {
                re: -11.643369587451822,
                im: -18.635570632797567,
            },
            Complex {
                re: 9.167738142319752,
                im: 3.0495310339069697,
            },
            Complex {
                re: -19.570962602026444,
                im: -7.3201060665416255,
            },
            Complex {
                re: -2.019724355464452,
                im: 2.3255722185532024,
            },
            Complex {
                re: -5.24648925559689,
                im: 25.30673373308118,
            },
            Complex {
                re: -14.480921139636285,
                im: -0.5885946402633557,
            },
            Complex {
                re: 3.787149262662025,
                im: 11.094943846990017,
            },
            Complex {
                re: 36.00345927671544,
                im: -22.701647849725532,
            },
            Complex {
                re: -0.3265103932563713,
                im: 19.32674627102231,
            },
            Complex {
                re: 7.224658447152217,
                im: -17.02874505020464,
            },
            Complex {
                re: -13.554614775182833,
                im: -35.820335133406914,
            },
            Complex {
                re: 8.602832241808656,
                im: 6.254752706544378,
            },
            Complex {
                re: 1.6380081248073495,
                im: 18.645561240028698,
            },
            Complex {
                re: -23.87032576831573,
                im: -16.299522862120895,
            },
            Complex {
                re: 11.570522471213117,
                im: -12.03029765960833,
            },
            Complex {
                re: -12.347805060045932,
                im: -9.334292535215566,
            },
            Complex {
                re: 6.6129533876516895,
                im: -21.4859042498319,
            },
            Complex {
                re: 14.790056324109663,
                im: -1.2367759245072971,
            },
            Complex {
                re: -13.101909087788247,
                im: -21.674257004775125,
            },
            Complex {
                re: -8.261638891409046,
                im: -5.895890830974685,
            },
            Complex {
                re: 0.6326528482646157,
                im: -0.17996415937667187,
            },
            Complex {
                re: -14.37933104527806,
                im: 4.152135275428236,
            },
            Complex {
                re: 5.942758182846271,
                im: 3.9606005198168948,
            },
            Complex {
                re: -18.002919633093683,
                im: -0.5469732120249269,
            },
            Complex {
                re: 9.222029741721943,
                im: 21.04500256690426,
            },
            Complex {
                re: 13.208817249848051,
                im: 25.72226812750418,
            },
            Complex {
                re: -9.952929334934064,
                im: -4.42266466581323,
            },
            Complex {
                re: 19.90283918026901,
                im: 0.013995323785304326,
            },
            Complex {
                re: 7.407518851194528,
                im: 5.123535823155135,
            },
            Complex {
                re: -2.4516700711433135,
                im: 3.183704216689785,
            },
            Complex {
                re: 12.09109676185664,
                im: 6.621653270076545,
            },
            Complex {
                re: 10.41773190378413,
                im: -11.124521703962719,
            },
            Complex {
                re: 17.35254437208373,
                im: 9.275406344086882,
            },
            Complex {
                re: -8.01768958077906,
                im: 7.907619361035268,
            },
            Complex {
                re: 13.520099238726978,
                im: 12.07865619353596,
            },
            Complex {
                re: -4.039168796695833,
                im: -15.054764198528268,
            },
            Complex {
                re: 17.59887158876547,
                im: -12.233371075833128,
            },
            Complex {
                re: -0.8035780018780541,
                im: -2.1879777893826766,
            },
            Complex {
                re: 10.178385448207278,
                im: 16.31576948839421,
            },
            Complex {
                re: 23.29895547895184,
                im: -10.111472510362624,
            },
            Complex {
                re: -1.2493965592164213,
                im: -14.105933201667671,
            },
            Complex {
                re: -5.339389587044726,
                im: 21.667493383764583,
            },
            Complex {
                re: -9.792315793004128,
                im: 30.461539236438394,
            },
            Complex {
                re: -4.051877910193845,
                im: 4.846016962675711,
            },
            Complex {
                re: -26.62094089769998,
                im: -1.9920757484537401,
            },
            Complex {
                re: -20.4565160052507,
                im: 8.038524516498482,
            },
            Complex {
                re: 20.155008335896078,
                im: 15.89222842850166,
            },
            Complex {
                re: -9.093782003922598,
                im: -12.071186190135009,
            },
            Complex {
                re: -9.012513711930803,
                im: 21.308423448776836,
            },
            Complex {
                re: -5.728850708305036,
                im: -11.920083248144788,
            },
            Complex {
                re: 0.8819479298901438,
                im: -7.161702067951728,
            },
            Complex {
                re: 1.6700420010532349,
                im: -2.6003302661530876,
            },
            Complex {
                re: 12.414251802198963,
                im: 5.1825599603861985,
            },
            Complex {
                re: -15.323676489408065,
                im: -14.183983367961913,
            },
            Complex {
                re: 16.17931847343062,
                im: 1.3773647118965053,
            },
            Complex {
                re: 5.739334653268656,
                im: -9.295340427692558,
            },
            Complex {
                re: 1.7595215662121422,
                im: -0.062434241923361,
            },
            Complex {
                re: 17.156920169912397,
                im: 14.06639237098653,
            },
            Complex {
                re: 12.846729982055088,
                im: -0.8614801963981016,
            },
            Complex {
                re: 11.323056757801531,
                im: 8.032803553061555,
            },
            Complex {
                re: 11.608938207402353,
                im: 7.38182579110228,
            },
            Complex {
                re: 7.4949488093300705,
                im: 9.310337032908526,
            },
            Complex {
                re: -20.875530533628343,
                im: 13.009431038590833,
            },
            Complex {
                re: 7.258942355977196,
                im: 7.498661558561772,
            },
            Complex {
                re: 22.78031766679476,
                im: -24.139433396289775,
            },
            Complex {
                re: -7.840927146312576,
                im: -1.8384623836207723,
            },
            Complex {
                re: 9.539488343699805,
                im: 17.985129987868348,
            },
            Complex {
                re: -4.829002114607199,
                im: -4.154905564363294,
            },
            Complex {
                re: -0.6132329906573579,
                im: 11.015864924724715,
            },
            Complex {
                re: 11.953433218628984,
                im: 19.807986789971082,
            },
            Complex {
                re: 7.596374989049833,
                im: -8.728185371057059,
            },
            Complex {
                re: 17.006292859732937,
                im: 6.061949337514421,
            },
            Complex {
                re: 15.848844864459785,
                im: 3.8474155893496382,
            },
            Complex {
                re: 16.95185805697109,
                im: -6.086236361050718,
            },
            Complex {
                re: 2.905722655893861,
                im: -6.892445426229574,
            },
            Complex {
                re: 17.796076512729808,
                im: -4.6103873474952195,
            },
            Complex {
                re: 7.5781984285379975,
                im: 6.808782282254889,
            },
            Complex {
                re: -19.82034690171866,
                im: -5.844319451999288,
            },
            Complex {
                re: 7.928715686974101,
                im: -8.77069490663079,
            },
            Complex {
                re: -4.021511858300244,
                im: -10.818256132479563,
            },
            Complex {
                re: 3.9816887204042852,
                im: 8.363299527931252,
            },
            Complex {
                re: 22.596823041393687,
                im: -11.2073051458925,
            },
            Complex {
                re: 10.923270315321414,
                im: -20.160908804152,
            },
            Complex {
                re: -10.888188252521802,
                im: 3.2850920669322594,
            },
            Complex {
                re: -14.947207915033442,
                im: -30.666505229255485,
            },
            Complex {
                re: 21.102845868254324,
                im: 2.3175884324984803,
            },
            Complex {
                re: -2.933963356496125,
                im: -13.57308399451193,
            },
            Complex {
                re: -7.14169211848375,
                im: -9.596336796121513,
            },
            Complex {
                re: 6.857425784332723,
                im: 0.5087278403910955,
            },
            Complex {
                re: -15.332204118455374,
                im: 11.645237532414688,
            },
            Complex {
                re: 19.642295422250577,
                im: 11.881757478681365,
            },
            Complex {
                re: -11.867661469634722,
                im: 2.972642945278531,
            },
            Complex {
                re: -5.894172926171458,
                im: 4.228356502753517,
            },
            Complex {
                re: -16.525768791071815,
                im: -15.362910261084869,
            },
            Complex {
                re: 3.00338946255431,
                im: -12.32677638116985,
            },
            Complex {
                re: -4.089457034557412,
                im: 6.9701078285030835,
            },
            Complex {
                re: -3.6397445515223654,
                im: -11.289710408847077,
            },
            Complex {
                re: 16.9490182195718,
                im: 10.520553026633424,
            },
            Complex {
                re: -11.972818953490048,
                im: -7.546930330428587,
            },
            Complex {
                re: 14.103118632159022,
                im: 22.813881296932706,
            },
            Complex {
                re: 1.419337343927472,
                im: 2.8532414359337994,
            },
            Complex {
                re: -3.745912044472835,
                im: 8.23418046383562,
            },
            Complex {
                re: 0.7576141414975934,
                im: 0.46159776549204246,
            },
            Complex {
                re: 8.560210834997154,
                im: 7.762746011732926,
            },
            Complex {
                re: 5.561934805177291,
                im: -11.778331146748487,
            },
            Complex {
                re: 3.6914691250000757,
                im: 17.32878298973776,
            },
            Complex {
                re: -11.908498895994786,
                im: -12.772959685492228,
            },
            Complex {
                re: 0.33429522751582663,
                im: -5.916837217392783,
            },
            Complex {
                re: -14.083173987600812,
                im: -9.229858610953713,
            },
            Complex {
                re: -35.81809790383742,
                im: -7.247401843414047,
            },
            Complex {
                re: -3.179163543694573,
                im: -12.673451732757076,
            },
            Complex {
                re: 15.287888093934558,
                im: 9.403954220621884,
            },
            Complex {
                re: -5.409894259425638,
                im: -8.320676155385472,
            },
            Complex {
                re: -4.1729934023316835,
                im: -1.551367438081924,
            },
            Complex {
                re: -13.614611545941951,
                im: 11.677690329288858,
            },
            Complex {
                re: -16.60123564079211,
                im: -7.437508661009771,
            },
            Complex {
                re: -11.094979764846544,
                im: 0.7233275685920879,
            },
            Complex {
                re: 13.735644699413761,
                im: 2.277319820165805,
            },
            Complex {
                re: 8.477201316604098,
                im: -9.158895501829743,
            },
            Complex {
                re: -8.818315166064043,
                im: 10.114913597890418,
            },
            Complex {
                re: 9.211392800434169,
                im: -13.123823213087773,
            },
            Complex {
                re: 12.837141274126733,
                im: 5.58472688022622,
            },
            Complex {
                re: 1.9448078191168792,
                im: -8.497269496599511,
            },
            Complex {
                re: -12.520424186372153,
                im: -3.555398860552507,
            },
            Complex {
                re: 12.101500125759603,
                im: 15.655411947329249,
            },
            Complex {
                re: 8.057374233664211,
                im: 5.325546497716675,
            },
            Complex {
                re: 17.742464118514654,
                im: 11.181572700268543,
            },
            Complex {
                re: 1.042500166261835,
                im: -2.7927071937110903,
            },
            Complex {
                re: 3.917410524452299,
                im: 14.124352686538769,
            },
            Complex {
                re: 11.48567453661705,
                im: 1.307017857399551,
            },
            Complex {
                re: 2.199721450292288,
                im: -35.343078404863626,
            },
            Complex {
                re: -12.18019881448965,
                im: 18.841639918237533,
            },
            Complex {
                re: -15.029231240335779,
                im: -0.18741617432278357,
            },
            Complex {
                re: 7.91056781703674,
                im: 10.50747330791755,
            },
            Complex {
                re: 8.553657336293998,
                im: 6.916043398125792,
            },
            Complex {
                re: -14.977436835980592,
                im: -4.2520198855989975,
            },
            Complex {
                re: 7.294461356943452,
                im: -4.995112461808724,
            },
            Complex {
                re: 0.8905825100294673,
                im: 6.964051265779461,
            },
            Complex {
                re: -8.260339089999988,
                im: -19.757896363768044,
            },
            Complex {
                re: 18.4025421382188,
                im: -1.3243441417072734,
            },
            Complex {
                re: -13.922348741740645,
                im: 9.515035619762752,
            },
            Complex {
                re: -23.000644226322635,
                im: 29.76235959240597,
            },
            Complex {
                re: 22.89072024246816,
                im: -7.911324468331986,
            },
            Complex {
                re: -36.372214914564616,
                im: -1.9342417519548718,
            },
            Complex {
                re: 3.1066703854379316,
                im: -20.047764076009752,
            },
            Complex {
                re: -11.533844713883816,
                im: 2.6997417357259863,
            },
            Complex {
                re: 24.072273560955367,
                im: -11.326860558065514,
            },
            Complex {
                re: -14.797612547572715,
                im: 6.0055783847261575,
            },
            Complex {
                re: -20.865479153335432,
                im: 14.203053480056692,
            },
            Complex {
                re: 12.567077253572496,
                im: 0.15086884726077532,
            },
            Complex {
                re: 10.517215705505205,
                im: 27.019591282991698,
            },
            Complex {
                re: -16.24787797616591,
                im: -0.8954907212287146,
            },
            Complex {
                re: -16.130855130465964,
                im: 15.310508909107519,
            },
            Complex {
                re: -4.241793512032968,
                im: 6.756925616187872,
            },
            Complex {
                re: -2.654088302042653,
                im: -13.560323192174225,
            },
            Complex {
                re: -8.295919299533336,
                im: 14.356303897350752,
            },
            Complex {
                re: 26.62725793569047,
                im: -11.07220445983889,
            },
            Complex {
                re: 25.93443599596089,
                im: 11.605255488779477,
            },
            Complex {
                re: -14.715433373485855,
                im: -3.2407089008652976,
            },
            Complex {
                re: -20.156476034208623,
                im: -26.315873827002076,
            },
            Complex {
                re: -8.567845410995329,
                im: 0.8842117127701918,
            },
            Complex {
                re: 3.418817838625171,
                im: -11.0735781131217,
            },
            Complex {
                re: -3.9803819375937195,
                im: -4.20503817869988,
            },
            Complex {
                re: 8.829091493196305,
                im: 9.850007073377045,
            },
            Complex {
                re: 9.30028212795435,
                im: 16.247225172007106,
            },
            Complex {
                re: 3.145363301533669,
                im: 6.885036701747389,
            },
            Complex {
                re: 4.476717772890202,
                im: -18.749083005942254,
            },
            Complex {
                re: 18.924073692185623,
                im: -12.688994419883889,
            },
            Complex {
                re: -4.3578956547199095,
                im: 6.646860929608399,
            },
            Complex {
                re: 21.433616741752683,
                im: 14.664386188909688,
            },
            Complex {
                re: 18.386968512789604,
                im: 7.990937733249016,
            },
            Complex {
                re: -16.854574072763214,
                im: -5.597022216281496,
            },
            Complex {
                re: -1.082792938910849,
                im: -0.507252834006239,
            },
            Complex {
                re: 6.42210998338753,
                im: 14.041172265222881,
            },
            Complex {
                re: -2.0102504213951295,
                im: -9.916700396908539,
            },
            Complex {
                re: -11.403953749196647,
                im: 15.233674866180031,
            },
            Complex {
                re: -2.026414691146724,
                im: 20.730364000616134,
            },
            Complex {
                re: 6.403120201563759,
                im: -16.71796096109781,
            },
            Complex {
                re: -15.330142808464194,
                im: -9.908302696590997,
            },
            Complex {
                re: 4.175055397113709,
                im: 25.630576454538875,
            },
            Complex {
                re: -16.87206161584738,
                im: -0.2879112228343317,
            },
            Complex {
                re: -8.92691117587019,
                im: 2.4912815909769086,
            },
            Complex {
                re: -11.33762784790602,
                im: -12.163218988413234,
            },
            Complex {
                re: -7.280989745215731,
                im: 6.297667123780089,
            },
            Complex {
                re: -10.954018909366477,
                im: 4.8775303271552595,
            },
            Complex {
                re: 26.297490436951794,
                im: 12.123165249663739,
            },
            Complex {
                re: 42.05151867540354,
                im: -24.249261819757184,
            },
            Complex {
                re: -0.9807544146123472,
                im: -6.600570061650941,
            },
            Complex {
                re: 18.59065004060976,
                im: 8.140966194668943,
            },
            Complex {
                re: -2.299087292246986,
                im: 8.152566008623682,
            },
            Complex {
                re: 4.962004253573276,
                im: -0.321192252054046,
            },
            Complex {
                re: -15.678233133171128,
                im: -12.61619489521458,
            },
            Complex {
                re: -12.456047869818043,
                im: -4.53086430594861,
            },
            Complex {
                re: -6.240774073762967,
                im: -14.733241931143883,
            },
            Complex {
                re: -15.703443906392325,
                im: 26.91460832015491,
            },
            Complex {
                re: -17.22602140604675,
                im: -9.135525191308679,
            },
            Complex {
                re: 23.58713237648665,
                im: -15.161388167587472,
            },
            Complex {
                re: 18.427591863037755,
                im: 14.114807991861522,
            },
            Complex {
                re: -2.1129445309072734,
                im: -3.0754638470100772,
            },
            Complex {
                re: 2.6892066470071434,
                im: 7.006136031174257,
            },
            Complex {
                re: 5.609435422593936,
                im: -17.295596399214052,
            },
            Complex {
                re: 27.64407367783039,
                im: 6.069293026161215,
            },
            Complex {
                re: 2.8031474235241554,
                im: 10.319981743791185,
            },
            Complex {
                re: -7.60373181082705,
                im: 27.419091620669686,
            },
            Complex {
                re: -10.260540105465331,
                im: -14.169850084079734,
            },
            Complex {
                re: 12.293943262551142,
                im: 9.294279148147245,
            },
            Complex {
                re: 14.928979765808208,
                im: 2.3696734866860343,
            },
            Complex {
                re: 6.438216577717645,
                im: 5.573709934873667,
            },
            Complex {
                re: 16.560316800439534,
                im: 14.13743675989354,
            },
            Complex {
                re: -8.000631850337644,
                im: 5.009263144375194,
            },
            Complex {
                re: -8.31769167476375,
                im: 24.613668530313234,
            },
            Complex {
                re: 16.069234000531814,
                im: 22.449050574673343,
            },
            Complex {
                re: -6.951916687039786,
                im: 6.039575096529692,
            },
            Complex {
                re: 14.913899980622832,
                im: -1.4703649172893387,
            },
            Complex {
                re: 5.755769468242623,
                im: 8.797096421180843,
            },
            Complex {
                re: 7.827342796051067,
                im: -13.05693103844332,
            },
            Complex {
                re: -15.921266386387867,
                im: -12.88382928440214,
            },
            Complex {
                re: 9.010654660263718,
                im: 6.492992467440838,
            },
            Complex {
                re: -29.90717940675159,
                im: 9.367336533839858,
            },
            Complex {
                re: 2.0875882732250948,
                im: -1.6263359084168592,
            },
            Complex {
                re: -7.592577009854719,
                im: -5.915380586077681,
            },
            Complex {
                re: -4.541179139920156,
                im: -5.981800982658909,
            },
            Complex {
                re: -4.386369676261697,
                im: -19.452604887463124,
            },
            Complex {
                re: -11.33167870976195,
                im: 21.181077824703962,
            },
            Complex {
                re: 3.2037298711829623,
                im: 7.6212884412390345,
            },
            Complex {
                re: -4.592636779613006,
                im: -8.077623381084361,
            },
            Complex {
                re: 10.603110549444935,
                im: 12.762691781276759,
            },
            Complex {
                re: -6.533116056239498,
                im: -10.485967855732987,
            },
            Complex {
                re: 4.377155865047593,
                im: 23.455078347683905,
            },
            Complex {
                re: -15.915592755842708,
                im: 5.608790602985215,
            },
            Complex {
                re: 3.6393718918579125,
                im: 13.58174703550222,
            },
            Complex {
                re: -2.995724703408409,
                im: -18.357614779558805,
            },
            Complex {
                re: -39.23755073667651,
                im: -13.138857556903066,
            },
            Complex {
                re: 7.26719578608663,
                im: -3.8110477195223726,
            },
            Complex {
                re: 26.479892499941958,
                im: 4.33388775293214,
            },
            Complex {
                re: 3.018689487672842,
                im: 11.600672768248556,
            },
            Complex {
                re: -0.7667005235898348,
                im: 17.072759393674154,
            },
            Complex {
                re: -11.484077932980401,
                im: -4.407517216413414,
            },
            Complex {
                re: -17.055148123052636,
                im: -8.261014991744105,
            },
            Complex {
                re: 23.049423647653946,
                im: 19.040447777183104,
            },
            Complex {
                re: -12.209578119944785,
                im: -9.505835117642146,
            },
            Complex {
                re: 4.480672223281408,
                im: 11.387274202816112,
            },
            Complex {
                re: 19.31291799982691,
                im: 5.161433914765398,
            },
            Complex {
                re: -21.102992441924254,
                im: -9.614956514445508,
            },
            Complex {
                re: -15.628447885695623,
                im: 3.1755218180196003,
            },
            Complex {
                re: 3.715185982346979,
                im: 25.612415682051775,
            },
            Complex {
                re: 0.5285263532308679,
                im: 21.123777965530756,
            },
            Complex {
                re: 12.209726311114306,
                im: 14.277632030696001,
            },
            Complex {
                re: 10.210162618831559,
                im: 13.72727614728857,
            },
            Complex {
                re: -6.549254372853877,
                im: 1.4391492660120813,
            },
            Complex {
                re: -6.368727700653185,
                im: -10.218177137501893,
            },
            Complex {
                re: 9.960556461671388,
                im: 13.04704641721253,
            },
            Complex {
                re: -18.30367902435369,
                im: -4.92067002895139,
            },
            Complex {
                re: -5.741718387613791,
                im: -19.575865047943104,
            },
            Complex {
                re: 7.711814965409347,
                im: 3.1054668724163665,
            },
            Complex {
                re: 1.4200753964995414,
                im: 12.386074858968364,
            },
            Complex {
                re: -26.455396959491345,
                im: -11.872050529307824,
            },
            Complex {
                re: 10.684318933841451,
                im: 0.01596900962821035,
            },
            Complex {
                re: 9.809368467015116,
                im: 13.61634828398048,
            },
            Complex {
                re: -2.174044572270148,
                im: 19.69421823807732,
            },
            Complex {
                re: 4.055926861813366,
                im: -1.5112195500316759,
            },
            Complex {
                re: -16.069169321571017,
                im: 5.963444577049006,
            },
            Complex {
                re: 1.9415907292868297,
                im: 13.316559260975428,
            },
            Complex {
                re: -11.121415102656094,
                im: -8.274310751341392,
            },
            Complex {
                re: 8.117010176328293,
                im: -13.10015913768985,
            },
            Complex {
                re: -16.860991336765686,
                im: 0.8628627618680036,
            },
            Complex {
                re: 11.572833682306797,
                im: -17.277153882679364,
            },
            Complex {
                re: -1.2785760006356908,
                im: 5.970002884768071,
            },
            Complex {
                re: 12.703507623114232,
                im: 0.6351663467350761,
            },
            Complex {
                re: 11.042802275422272,
                im: -3.3971241916022814,
            },
            Complex {
                re: -6.36000283633641,
                im: 3.722634236277652,
            },
            Complex {
                re: -5.467348955440871,
                im: 2.7323609762716545,
            },
            Complex {
                re: -3.165865556452656,
                im: -6.55051812710666,
            },
            Complex {
                re: -25.06238314538698,
                im: -6.0852365642136625,
            },
            Complex {
                re: -30.245332537718802,
                im: -13.948779896109226,
            },
            Complex {
                re: 11.157461537726812,
                im: -5.992026920649378,
            },
            Complex {
                re: -3.8578007257714644,
                im: -1.2725501365946208,
            },
            Complex {
                re: 3.826236712722059,
                im: 8.169271311972125,
            },
            Complex {
                re: 30.374712845187517,
                im: 4.692232489440425,
            },
            Complex {
                re: 3.854477525551415,
                im: -2.544958960459998,
            },
            Complex {
                re: 2.742873047532915,
                im: -5.90125833426189,
            },
            Complex {
                re: -4.749088401379869,
                im: 6.978424225425753,
            },
            Complex {
                re: -1.8911742575641393,
                im: 1.2725033140408115,
            },
            Complex {
                re: 10.255429841972777,
                im: 0.8048476109415699,
            },
            Complex {
                re: -8.28427919368095,
                im: -13.356610115834755,
            },
            Complex {
                re: -2.72698126258146,
                im: -8.408564250911393,
            },
            Complex {
                re: -6.287280743145965,
                im: 1.0212088073104075,
            },
            Complex {
                re: 3.3825599340248793,
                im: 6.215833982166582,
            },
            Complex {
                re: -10.64448963122655,
                im: -4.406030067575616,
            },
            Complex {
                re: -5.994853684263722,
                im: 28.235107733150034,
            },
            Complex {
                re: 11.761898702005205,
                im: 12.102879685348416,
            },
            Complex {
                re: -1.0689741530496946,
                im: 6.25793612887723,
            },
            Complex {
                re: -7.682836845111964,
                im: -19.37759979764929,
            },
            Complex {
                re: -21.511882138462013,
                im: 14.61810822642105,
            },
            Complex {
                re: 12.550186065221157,
                im: -21.552701630593972,
            },
            Complex {
                re: 3.8560489046282687,
                im: 35.533429181611375,
            },
            Complex {
                re: 20.62798863910714,
                im: 1.3602835755393112,
            },
            Complex {
                re: 2.7022395532117245,
                im: 5.081215320430115,
            },
            Complex {
                re: 4.711614201227228,
                im: -7.588658338167244,
            },
            Complex {
                re: -15.95304610942188,
                im: -10.38296689535735,
            },
            Complex {
                re: 3.2038504439593893,
                im: -8.60277010835144,
            },
            Complex {
                re: 7.058259638920978,
                im: -4.804788432764228,
            },
            Complex {
                re: -1.5749473671299645,
                im: -9.920446741683248,
            },
            Complex {
                re: -9.226948124705018,
                im: 8.71967934679002,
            },
            Complex {
                re: 12.109778334137618,
                im: 6.209330309094593,
            },
            Complex {
                re: 6.14920541628799,
                im: 1.3184532025314413,
            },
            Complex {
                re: -4.830505849024606,
                im: -1.8163522426587138,
            },
            Complex {
                re: -38.81085958561469,
                im: 0.6887780941914894,
            },
            Complex {
                re: -15.346423595097743,
                im: 2.583863297839196,
            },
            Complex {
                re: -2.6546245457525526,
                im: 12.126690458879771,
            },
            Complex {
                re: -8.786600389096941,
                im: 5.601893852441095,
            },
            Complex {
                re: -2.597452409439314,
                im: -14.267887834028443,
            },
            Complex {
                re: -4.313692369005295,
                im: 11.082654835844105,
            },
            Complex {
                re: 1.201707014306613,
                im: -19.617531686163808,
            },
            Complex {
                re: 3.011038284481966,
                im: -6.700208871898555,
            },
            Complex {
                re: 4.0537375409724845,
                im: -26.81927740707893,
            },
            Complex {
                re: 17.761615817565445,
                im: 4.934303753511828,
            },
            Complex {
                re: -19.69165281128152,
                im: -2.332929663980895,
            },
            Complex {
                re: 13.126037286864289,
                im: 3.657049015132735,
            },
            Complex {
                re: -2.12884095231788,
                im: -3.0016413934070565,
            },
            Complex {
                re: -27.834492707716556,
                im: -5.516630193477832,
            },
            Complex {
                re: 8.458269237440566,
                im: -3.341367949856302,
            },
            Complex {
                re: 16.22922437834491,
                im: -8.548044334420009,
            },
            Complex {
                re: 17.335808252855756,
                im: 25.859040846749792,
            },
            Complex {
                re: 7.644920368732074,
                im: 16.66917258339536,
            },
            Complex {
                re: 2.1223779085400722,
                im: -2.4658770090452755,
            },
            Complex {
                re: -3.80853355515948,
                im: -13.906944826224175,
            },
            Complex {
                re: -4.986630771171738,
                im: 16.46318037695779,
            },
            Complex {
                re: 7.381614532665513,
                im: 13.001496914432721,
            },
            Complex {
                re: 9.612147095085364,
                im: 4.531711335346824,
            },
            Complex {
                re: 8.145512029279173,
                im: -4.937451993120042,
            },
            Complex {
                re: 12.645768562388744,
                im: 7.042732562575678,
            },
            Complex {
                re: 4.26025398630798,
                im: -3.653944917675622,
            },
            Complex {
                re: -5.658246245746236,
                im: 21.74901290447518,
            },
            Complex {
                re: 30.965986145870552,
                im: -7.9911203090434455,
            },
            Complex {
                re: 4.103253695010379,
                im: 1.196335278931454,
            },
            Complex {
                re: 13.540131655978787,
                im: 16.91557114804047,
            },
            Complex {
                re: 3.5015380750430616,
                im: 6.146906778343098,
            },
            Complex {
                re: -1.1187879340852298,
                im: -12.778093927229616,
            },
            Complex {
                re: -2.9861248017797064,
                im: -8.886737258373083,
            },
            Complex {
                re: -13.156134408379973,
                im: 9.140987495111546,
            },
            Complex {
                re: 2.260149813010156,
                im: -6.009768060059912,
            },
            Complex {
                re: -19.78431988758574,
                im: -0.4694728955676819,
            },
            Complex {
                re: 5.737262572824283,
                im: 8.48021069173669,
            },
            Complex {
                re: 19.19208583450884,
                im: -28.204173015851033,
            },
            Complex {
                re: 11.872650269147348,
                im: 23.10987669770487,
            },
            Complex {
                re: 5.705005769676062,
                im: -7.837272471135287,
            },
            Complex {
                re: -10.77887801928246,
                im: 4.6365281936774725,
            },
            Complex {
                re: -2.8345454201693077,
                im: 20.635554885825897,
            },
            Complex {
                re: -5.707940696998806,
                im: -9.625418098590819,
            },
            Complex {
                re: -6.9707303564570555,
                im: -14.201300182306287,
            },
            Complex {
                re: -13.684227910975062,
                im: 5.0421722646548455,
            },
            Complex {
                re: 4.3901080221944495,
                im: -16.21645196613673,
            },
            Complex {
                re: -12.263562705227844,
                im: -12.034193601827198,
            },
            Complex {
                re: -9.551074335304286,
                im: 23.711647766754194,
            },
            Complex {
                re: -8.489600737453816,
                im: -2.5806790802215023,
            },
            Complex {
                re: 13.164645635718685,
                im: 9.836666240124085,
            },
            Complex {
                re: 17.471332045082526,
                im: 12.438064043307795,
            },
            Complex {
                re: -5.510678720159192,
                im: -6.189378542607947,
            },
            Complex {
                re: 17.640990920219124,
                im: 10.723871204069859,
            },
            Complex {
                re: -24.63242400305045,
                im: 19.506474233885957,
            },
            Complex {
                re: -8.228486482671354,
                im: 16.421079871272873,
            },
            Complex {
                re: 0.7805996556358863,
                im: 11.238074059094135,
            },
            Complex {
                re: -4.1948874986833165,
                im: 3.4090884176334013,
            },
            Complex {
                re: 0.8326035690871221,
                im: 3.3603099066931335,
            },
            Complex {
                re: -10.198487634663358,
                im: -10.65748277681271,
            },
            Complex {
                re: -13.606550369289208,
                im: 18.615788809982927,
            },
            Complex {
                re: -11.053643475486972,
                im: -2.6994105067768714,
            },
            Complex {
                re: 10.752145421974562,
                im: 16.325575960132117,
            },
            Complex {
                re: -13.848759246886658,
                im: 1.7960312503317741,
            },
            Complex {
                re: -20.0466870062832,
                im: 24.540491386174025,
            },
            Complex {
                re: 18.717319608145093,
                im: -1.9995160502807252,
            },
            Complex {
                re: 11.045627001925844,
                im: -6.122798878938731,
            },
            Complex {
                re: -6.397687826958159,
                im: -6.469895723603274,
            },
            Complex {
                re: 5.126769926896805,
                im: 9.160332018861535,
            },
            Complex {
                re: 8.776295349366311,
                im: 0.05223269349528348,
            },
            Complex {
                re: -20.51067356916887,
                im: 13.927471135330785,
            },
            Complex {
                re: -18.605654615777336,
                im: 25.01030294809027,
            },
            Complex {
                re: -0.20325865017149586,
                im: -2.0994330891917166,
            },
            Complex {
                re: -1.3461630569168113,
                im: 0.7892436123345741,
            },
            Complex {
                re: -1.302531334359899,
                im: 6.680651405284232,
            },
            Complex {
                re: 15.443686816835282,
                im: -16.446767792224804,
            },
            Complex {
                re: -3.173906564719852,
                im: 7.804197310160529,
            },
            Complex {
                re: -14.52314906201335,
                im: -22.35865261180171,
            },
            Complex {
                re: 6.6416145893372,
                im: 17.504370980859786,
            },
            Complex {
                re: 4.068487753457497,
                im: -18.297929082845982,
            },
            Complex {
                re: 20.848024059146134,
                im: -24.98959454583469,
            },
            Complex {
                re: -6.1433351862734495,
                im: -10.318410765948219,
            },
            Complex {
                re: -14.978653369696001,
                im: -6.955104233308481,
            },
            Complex {
                re: 0.865342693790204,
                im: 6.573736040651352,
            },
            Complex {
                re: 9.217201019612869,
                im: -3.8844769523014886,
            },
            Complex {
                re: -0.766249679887923,
                im: 1.6488301863669923,
            },
            Complex {
                re: 1.0685859538001234,
                im: -24.99162381552571,
            },
            Complex {
                re: -2.757316366838827,
                im: -14.15121704596666,
            },
            Complex {
                re: -15.257691258355141,
                im: 12.37303360804286,
            },
            Complex {
                re: 14.507676675795336,
                im: -8.948865571311488,
            },
            Complex {
                re: 12.198265603435264,
                im: 6.722497575651578,
            },
            Complex {
                re: -13.218325018169551,
                im: 6.538509973308958,
            },
            Complex {
                re: -15.978772719767209,
                im: 3.7454399030652556,
            },
            Complex {
                re: 3.5050524519147874,
                im: 11.038299049232213,
            },
            Complex {
                re: 20.41424701358951,
                im: -8.161417636912713,
            },
            Complex {
                re: 1.2478265159241992,
                im: 5.267003053678193,
            },
            Complex {
                re: 16.99016600112104,
                im: 11.995731717148477,
            },
            Complex {
                re: 17.030026960362804,
                im: -11.690850709100493,
            },
            Complex {
                re: 21.427941036877062,
                im: 11.22616551402438,
            },
            Complex {
                re: 4.899248073630557,
                im: -9.295363152449259,
            },
            Complex {
                re: -2.425357630196171,
                im: 8.504534944890816,
            },
            Complex {
                re: -0.5501120969280597,
                im: 12.94592078230703,
            },
            Complex {
                re: 6.672376445741033,
                im: -11.975217399979176,
            },
            Complex {
                re: 10.093256480908213,
                im: 2.0044680512255306,
            },
            Complex {
                re: 1.9099955696231534,
                im: -5.288800977604185,
            },
            Complex {
                re: -28.89528675937086,
                im: -1.4705993543988076,
            },
            Complex {
                re: 10.283368247136547,
                im: -8.965573910432646,
            },
            Complex {
                re: -2.654580695043413,
                im: 12.219851400262627,
            },
            Complex {
                re: 8.666894162652552,
                im: 12.74585234907248,
            },
            Complex {
                re: 10.987998193367613,
                im: -13.849087320571963,
            },
            Complex {
                re: 19.89893022764705,
                im: -0.7077227962216974,
            },
            Complex {
                re: 23.70997074850015,
                im: -0.03793354031304119,
            },
            Complex {
                re: 2.233761901952521,
                im: 0.2630978735070837,
            },
            Complex {
                re: 9.30781926441566,
                im: -6.952592314573268,
            },
            Complex {
                re: 1.5805449565792564,
                im: 8.894969134726072,
            },
            Complex {
                re: -21.601262489318643,
                im: 0.7965624700190403,
            },
            Complex {
                re: -11.137093016561757,
                im: 0.09974786146183678,
            },
            Complex {
                re: -16.890210416177595,
                im: 7.791150338769183,
            },
            Complex {
                re: -22.632603887986967,
                im: -4.113981038536977,
            },
            Complex {
                re: -7.461226644424132,
                im: -14.183739751421083,
            },
            Complex {
                re: -2.1506951111484565,
                im: 6.943001794579617,
            },
            Complex {
                re: -21.445111314637206,
                im: 2.0275542087971345,
            },
            Complex {
                re: -0.7548634418211386,
                im: 2.657897731253551,
            },
            Complex {
                re: -1.3641778512516733,
                im: 2.022119090399185,
            },
            Complex {
                re: 18.853632498463533,
                im: -9.772505187164587,
            },
            Complex {
                re: 6.4455937146906646,
                im: 9.413108397436023,
            },
            Complex {
                re: 4.337210745213864,
                im: 9.41239480351584,
            },
            Complex {
                re: -20.38334233779129,
                im: -0.7136675109534991,
            },
            Complex {
                re: -10.128176448916157,
                im: -6.510218851042784,
            },
            Complex {
                re: 1.2734348021642112,
                im: -24.56318130774961,
            },
            Complex {
                re: -16.252156966983723,
                im: -1.114818896499067,
            },
            Complex {
                re: -3.688785322645707,
                im: 3.55471906207627,
            },
            Complex {
                re: -21.087329322850188,
                im: -7.803058959918249,
            },
            Complex {
                re: -9.915794266146754,
                im: 16.60079680218079,
            },
            Complex {
                re: 9.635603592548925,
                im: -38.22226891796744,
            },
            Complex {
                re: 4.357674888961437,
                im: 6.135521203346115,
            },
            Complex {
                re: 18.943240946675033,
                im: 37.04385385061936,
            },
            Complex {
                re: -20.16878388839174,
                im: 18.8807790228959,
            },
            Complex {
                re: 0.29831093715601886,
                im: 7.261235907752636,
            },
            Complex {
                re: 5.887290626952598,
                im: 3.913775792433553,
            },
            Complex {
                re: 4.90850303800763,
                im: -1.5807037807163713,
            },
            Complex {
                re: 5.963075498827047,
                im: 6.140154157703807,
            },
            Complex {
                re: 6.012269379226285,
                im: 5.55183337510466,
            },
            Complex {
                re: 8.19990603938331,
                im: 24.128040396455987,
            },
            Complex {
                re: -19.935819877625786,
                im: -7.80894157480068,
            },
            Complex {
                re: -1.285744257444663,
                im: -4.209886601786094,
            },
            Complex {
                re: 2.7844275744774722,
                im: 24.857731485121537,
            },
            Complex {
                re: 3.9630730386705135,
                im: -21.80290579795563,
            },
            Complex {
                re: -2.085967427204219,
                im: -15.438458950071304,
            },
            Complex {
                re: 16.702592667396903,
                im: -0.7581617793671374,
            },
            Complex {
                re: 2.653191893685653,
                im: -3.17224883043358,
            },
            Complex {
                re: 4.925497759886728,
                im: -23.687260759414592,
            },
            Complex {
                re: 12.569142284151308,
                im: 4.9871690700248035,
            },
            Complex {
                re: 23.08865936577273,
                im: -10.334614586515611,
            },
            Complex {
                re: 12.122034547826036,
                im: 1.8967203644697128,
            },
            Complex {
                re: 1.7155218503145768,
                im: -7.69628879008227,
            },
            Complex {
                re: 26.45525173685907,
                im: -1.037770012403855,
            },
            Complex {
                re: -28.063656007877444,
                im: 9.688202264777933,
            },
            Complex {
                re: -6.263280942452175,
                im: -4.625626824662526,
            },
            Complex {
                re: -33.72107967090071,
                im: 15.169108971987473,
            },
            Complex {
                re: 1.863690325729796,
                im: -20.58666810627081,
            },
            Complex {
                re: 0.08867882477908928,
                im: 25.243480908725232,
            },
            Complex {
                re: 4.9454585045453126,
                im: -21.898563733746823,
            },
            Complex {
                re: 7.531503542232132,
                im: -0.4902914930487743,
            },
            Complex {
                re: 12.11351191869345,
                im: -8.53094416295561,
            },
            Complex {
                re: -27.699186734149986,
                im: -8.928313799708443,
            },
            Complex {
                re: 6.277146801982811,
                im: -8.450720350933587,
            },
            Complex {
                re: -2.1354336657828763,
                im: 4.3767805942924785,
            },
            Complex {
                re: 13.861741151393637,
                im: -1.024297830897845,
            },
            Complex {
                re: -13.10331736259246,
                im: 2.737218714464033,
            },
            Complex {
                re: -2.806877108582376,
                im: 2.7041222236150806,
            },
            Complex {
                re: 3.3036095629397373,
                im: 5.202548055643125,
            },
            Complex {
                re: -7.629252591829536,
                im: 4.14660012425563,
            },
            Complex {
                re: -13.224956790869715,
                im: 0.9934734530354614,
            },
            Complex {
                re: 2.5982929169465905,
                im: -3.9222547072220246,
            },
            Complex {
                re: -10.22057106591322,
                im: -18.181325171163383,
            },
            Complex {
                re: 2.1466606371304477,
                im: 9.504385888076929,
            },
            Complex {
                re: 10.379795640336512,
                im: 5.479861452829001,
            },
            Complex {
                re: -0.040422523642726915,
                im: -17.657096286764528,
            },
            Complex {
                re: 6.1394809760322895,
                im: -18.12845613068456,
            },
            Complex {
                re: -5.613279132012324,
                im: -7.179406593293189,
            },
            Complex {
                re: 8.338772028298557,
                im: 8.824795673929334,
            },
            Complex {
                re: -23.886670310672272,
                im: 28.42299798021065,
            },
            Complex {
                re: -14.274259968592098,
                im: -0.42302038587160684,
            },
            Complex {
                re: 4.8556103648423194,
                im: 16.51337528280246,
            },
            Complex {
                re: -19.635308418841085,
                im: -14.364692706980259,
            },
            Complex {
                re: 20.552886348326428,
                im: -34.364546998911365,
            },
            Complex {
                re: 17.300392898602237,
                im: 10.50595384234611,
            },
            Complex {
                re: 7.657301067419826,
                im: 6.456228145912306,
            },
            Complex {
                re: -7.030445868022754,
                im: 25.679217173112633,
            },
            Complex {
                re: -1.380332411671732,
                im: -9.071969950212555,
            },
            Complex {
                re: -17.277852242815193,
                im: -0.4913788457719388,
            },
            Complex {
                re: 8.074428475555653,
                im: -23.964953369333656,
            },
            Complex {
                re: 0.5555561956672372,
                im: -16.54008040150928,
            },
            Complex {
                re: 19.1409263517605,
                im: 22.526442050567674,
            },
            Complex {
                re: 13.509475753439574,
                im: -1.8474317966143587,
            },
            Complex {
                re: -4.83910219158668,
                im: -6.068220665111351,
            },
            Complex {
                re: 12.948913688960161,
                im: 19.424353991831037,
            },
            Complex {
                re: 19.750054402945977,
                im: -10.234818694324016,
            },
            Complex {
                re: 13.353511079115943,
                im: 3.497520456231807,
            },
            Complex {
                re: -18.873714463103994,
                im: -12.256381143431803,
            },
            Complex {
                re: 16.055438926873705,
                im: -0.8820144018353364,
            },
            Complex {
                re: 14.704895104985251,
                im: -6.567748202755816,
            },
            Complex {
                re: 11.625988807490398,
                im: -11.910746453550644,
            },
            Complex {
                re: -10.295304447609919,
                im: 0.7117833776706899,
            },
            Complex {
                re: -25.07238637132678,
                im: -8.671909472222943,
            },
            Complex {
                re: -2.0645335400627087,
                im: 0.4802595393731304,
            },
            Complex {
                re: -6.014819409329901,
                im: 9.95770028219696,
            },
            Complex {
                re: 1.0720343679377367,
                im: 20.110617878408213,
            },
            Complex {
                re: 8.5864727118142,
                im: 6.04343341249621,
            },
            Complex {
                re: 29.239583675166223,
                im: 13.019122186021121,
            },
            Complex {
                re: 6.355078337868386,
                im: 16.112458548992755,
            },
            Complex {
                re: 5.758300920144382,
                im: -4.544934789806314,
            },
            Complex {
                re: -7.992790760125365,
                im: 21.373516239861452,
            },
            Complex {
                re: 6.788067999569731,
                im: 4.4552734151794775,
            },
            Complex {
                re: -16.64144826897763,
                im: -3.1616553647056187,
            },
            Complex {
                re: 13.685780272757452,
                im: 5.084254724240919,
            },
            Complex {
                re: -11.90470909055906,
                im: 8.238912930322947,
            },
            Complex {
                re: -13.76733757602555,
                im: 0.6243288446742241,
            },
            Complex {
                re: 31.692184987454652,
                im: -7.669081223517979,
            },
            Complex {
                re: 9.056463331409178,
                im: 16.489220517074425,
            },
            Complex {
                re: 0.8114729975310464,
                im: 15.385408719952716,
            },
            Complex {
                re: -13.457228234383454,
                im: 0.7688731204765826,
            },
            Complex {
                re: 13.548365612375015,
                im: 2.4990230071232378,
            },
            Complex {
                re: 27.930368740093538,
                im: -22.720192389451718,
            },
            Complex {
                re: -10.041590589569513,
                im: -27.836592666687736,
            },
            Complex {
                re: 16.02424420930638,
                im: 7.743195135273027,
            },
            Complex {
                re: 20.507846968522387,
                im: -7.716171277736806,
            },
            Complex {
                re: -8.630339171632091,
                im: 6.326655471135256,
            },
            Complex {
                re: -5.667371729033773,
                im: -0.45280089159090764,
            },
            Complex {
                re: -8.149774885012409,
                im: -14.17127603893541,
            },
            Complex {
                re: 8.255162335328407,
                im: 4.1271782916110595,
            },
            Complex {
                re: -5.793780449413255,
                im: 11.432136770076815,
            },
            Complex {
                re: -12.669091096448405,
                im: 2.9672250975891115,
            },
            Complex {
                re: 2.813377945515576,
                im: -0.28141660587904305,
            },
            Complex {
                re: 19.020435379195924,
                im: 20.583685839401593,
            },
            Complex {
                re: -5.817420340547317,
                im: -3.9295260357849218,
            },
            Complex {
                re: -6.575602524769308,
                im: 8.07306732428419,
            },
            Complex {
                re: -18.204732137554327,
                im: 19.172551031026366,
            },
            Complex {
                re: -25.907333575858516,
                im: 8.733025464859743,
            },
            Complex {
                re: 15.919117271075795,
                im: 3.7076013191092905,
            },
            Complex {
                re: 7.413192969250581,
                im: 4.524626488002864,
            },
            Complex {
                re: 19.01764208420903,
                im: -13.148443157873494,
            },
            Complex {
                re: 26.62212886530355,
                im: -0.23131358374527755,
            },
            Complex {
                re: 20.533486865990334,
                im: -12.395509330331848,
            },
            Complex {
                re: -1.9861434947034797,
                im: -28.523563297227426,
            },
            Complex {
                re: 11.948603321994556,
                im: -10.292622499343349,
            },
            Complex {
                re: 5.977895602129645,
                im: 3.784450035559372,
            },
            Complex {
                re: -11.182969558175254,
                im: -4.157843249923827,
            },
            Complex {
                re: 9.511964102444386,
                im: 10.982820894121378,
            },
            Complex {
                re: 7.993443758640279,
                im: 15.004507485605073,
            },
            Complex {
                re: -16.689464060402663,
                im: 9.104399008327393,
            },
            Complex {
                re: -4.856092994739772,
                im: -19.241480584055957,
            },
            Complex {
                re: 9.906016472254601,
                im: 12.522335751580453,
            },
            Complex {
                re: -8.270817762117948,
                im: -5.521370293863713,
            },
            Complex {
                re: -14.174295043887895,
                im: 3.743307720659229,
            },
            Complex {
                re: -12.500840596862416,
                im: 14.610524916669641,
            },
            Complex {
                re: 5.463729100435873,
                im: -5.088084582580779,
            },
            Complex {
                re: -16.72700730846004,
                im: -7.875766566620062,
            },
            Complex {
                re: -4.780667016098363,
                im: 4.812363869451216,
            },
            Complex {
                re: -15.95056426162195,
                im: -18.61261749528998,
            },
            Complex {
                re: 7.004284339078248,
                im: 5.444089268412133,
            },
            Complex {
                re: 4.728244287040498,
                im: 0.21476727918997085,
            },
            Complex {
                re: -6.457640746555039,
                im: -24.069982664702522,
            },
            Complex {
                re: -12.697824121365839,
                im: 31.182871414821683,
            },
            Complex {
                re: 7.704879635916081,
                im: 26.996494384444272,
            },
            Complex {
                re: 11.510077272362107,
                im: -3.2519459341272867,
            },
            Complex {
                re: 6.044969818942092,
                im: -11.508230213825433,
            },
            Complex {
                re: 16.77925234500462,
                im: 1.094915489271557,
            },
            Complex {
                re: -23.18387628276119,
                im: -5.898889801314535,
            },
            Complex {
                re: 14.212761522610789,
                im: 4.531305384217196,
            },
            Complex {
                re: 17.36674460828989,
                im: -5.056530504519205,
            },
            Complex {
                re: -0.22058326619869462,
                im: -20.85688450115707,
            },
            Complex {
                re: -5.748347752503165,
                im: -6.004638654649867,
            },
            Complex {
                re: 3.028941506360471,
                im: -19.525732616600493,
            },
            Complex {
                re: -4.291028794067875,
                im: -5.016452729533919,
            },
            Complex {
                re: -9.197965971237775,
                im: -4.540963930912733,
            },
            Complex {
                re: 10.40145336926523,
                im: -8.227199679139858,
            },
            Complex {
                re: 7.885208381696089,
                im: -1.001738881758517,
            },
            Complex {
                re: -6.747495317199423,
                im: 1.742777295051337,
            },
            Complex {
                re: -10.401036820219325,
                im: 2.913782929792254,
            },
            Complex {
                re: 0.31824964763834984,
                im: 4.188060547863891,
            },
            Complex {
                re: 1.9889481190615217,
                im: 2.4924448616649366,
            },
            Complex {
                re: 1.9297606267377936,
                im: -21.53830556482338,
            },
            Complex {
                re: -8.52257006400053,
                im: 10.105327798475244,
            },
            Complex {
                re: 6.901684171972502,
                im: 6.799709191975279,
            },
            Complex {
                re: 2.803214257096143,
                im: 8.587101532694035,
            },
            Complex {
                re: -16.28558680507465,
                im: 9.537385663574106,
            },
            Complex {
                re: -7.153690276095013,
                im: -18.41574097765385,
            },
            Complex {
                re: -22.74814917956514,
                im: -9.554582125155875,
            },
            Complex {
                re: -2.6839229724961275,
                im: -0.7319896178839471,
            },
            Complex {
                re: -18.82180719098583,
                im: 12.333615737301413,
            },
            Complex {
                re: 0.9850585925927122,
                im: -10.963400476282125,
            },
            Complex {
                re: -12.620779217176732,
                im: -22.736309889370006,
            },
            Complex {
                re: 7.88880403803434,
                im: 1.7571446121950804,
            },
            Complex {
                re: 9.082187783381823,
                im: -7.669448749698359,
            },
            Complex {
                re: 9.847560035559074,
                im: 2.4532497814463516,
            },
            Complex {
                re: 9.499436266806768,
                im: 3.022414732555866,
            },
            Complex {
                re: 5.713955037396536,
                im: -0.4351189234666186,
            },
            Complex {
                re: 3.674562738229558,
                im: 15.263306362293545,
            },
            Complex {
                re: 9.694515181554863,
                im: -5.299766761801526,
            },
            Complex {
                re: -5.260258037797985,
                im: -0.8237307947421817,
            },
            Complex {
                re: 0.34613272294211206,
                im: 7.304989853937762,
            },
            Complex {
                re: 3.7519382485475674,
                im: 10.094541666047618,
            },
            Complex {
                re: 8.423690497502989,
                im: -3.8840338824357055,
            },
            Complex {
                re: 2.7095383837705747,
                im: -2.8908912502857658,
            },
            Complex {
                re: 2.3736846790060335,
                im: -0.5669863559232322,
            },
            Complex {
                re: 18.498298857927992,
                im: 3.2075289924376964,
            },
            Complex {
                re: -3.005530071350078,
                im: -12.30122727210356,
            },
            Complex {
                re: 4.109323513886008,
                im: 7.23244533374687,
            },
            Complex {
                re: -17.61884138386103,
                im: -7.834000063654185,
            },
            Complex {
                re: -6.089018807997786,
                im: 26.339632155062443,
            },
            Complex {
                re: -7.0859745330670245,
                im: -6.768933837145216,
            },
            Complex {
                re: -11.317011106951139,
                im: 3.1396836714356877,
            },
            Complex {
                re: 27.6498916981475,
                im: -32.89426702947082,
            },
            Complex {
                re: 17.058822364862465,
                im: 7.999623493518664,
            },
            Complex {
                re: 15.368280668226655,
                im: 7.441348476195676,
            },
            Complex {
                re: 12.245143637309642,
                im: -1.0454585932888119,
            },
            Complex {
                re: 8.877265602373324,
                im: -0.3851750189367851,
            },
            Complex {
                re: 17.52609855173253,
                im: -3.3181189483080153,
            },
            Complex {
                re: -4.315303953261579,
                im: 4.347473880310279,
            },
            Complex {
                re: 1.8582196866714216,
                im: 17.795888213117856,
            },
            Complex {
                re: 4.253961855151641,
                im: -9.281334343956376,
            },
            Complex {
                re: 2.4731507649675475,
                im: 8.599080349141902,
            },
            Complex {
                re: 20.77231589127016,
                im: 10.40333372042403,
            },
            Complex {
                re: -7.107332702856286,
                im: -9.232269173634077,
            },
            Complex {
                re: 12.284347672696201,
                im: -20.007777016406738,
            },
            Complex {
                re: 17.787486794718507,
                im: 13.025912228865312,
            },
            Complex {
                re: 11.745984741518274,
                im: -1.477437308777517,
            },
            Complex {
                re: 6.400041540590201,
                im: 2.387380079962638,
            },
            Complex {
                re: 3.7147444942376655,
                im: -12.345636448699489,
            },
            Complex {
                re: -3.1239064869352635,
                im: 10.675430411909753,
            },
            Complex {
                re: 17.946267210706395,
                im: -4.815019253883419,
            },
            Complex {
                re: -4.16034788605916,
                im: -21.418297945243246,
            },
            Complex {
                re: -5.080844079416224,
                im: 2.785237650426783,
            },
            Complex {
                re: 5.766942309697372,
                im: 35.34672522603995,
            },
            Complex {
                re: -17.339289278766064,
                im: -11.125020358075012,
            },
            Complex {
                re: -2.3875372072669516,
                im: 0.023625864058749002,
            },
            Complex {
                re: -0.4686844992063577,
                im: 11.163310476672013,
            },
            Complex {
                re: -7.0070916166154005,
                im: -0.49121524407012096,
            },
            Complex {
                re: -6.985340813431913,
                im: 11.386007410442915,
            },
            Complex {
                re: -11.919640393892456,
                im: 15.33564379901729,
            },
            Complex {
                re: -12.912901895031606,
                im: -12.50245755926507,
            },
            Complex {
                re: 7.8970981822411215,
                im: -16.611985132691625,
            },
            Complex {
                re: 18.666469703243525,
                im: -4.456473407578569,
            },
            Complex {
                re: -8.609804363785052,
                im: -10.730148064420547,
            },
            Complex {
                re: -0.6007718010330674,
                im: -4.484190438083157,
            },
            Complex {
                re: -4.619896781503612,
                im: 14.245123176781117,
            },
            Complex {
                re: 14.658926498021135,
                im: -0.9052427199104809,
            },
            Complex {
                re: 16.938971515641928,
                im: 11.048825124717084,
            },
            Complex {
                re: 3.0229957918732095,
                im: 19.652150720479597,
            },
            Complex {
                re: -7.31084622082583,
                im: 20.866059373608714,
            },
            Complex {
                re: 8.03326784619792,
                im: -24.266372800325268,
            },
            Complex {
                re: 5.031203504702198,
                im: 8.982743666494935,
            },
            Complex {
                re: 16.125261346189124,
                im: -9.418735675388405,
            },
            Complex {
                re: -1.2733942084891128,
                im: 18.075944107917948,
            },
            Complex {
                re: 6.468747942972154,
                im: 4.616006544836633,
            },
            Complex {
                re: 10.65276519872385,
                im: 18.631003374953735,
            },
            Complex {
                re: 7.9424943204531715,
                im: -16.29601773717587,
            },
            Complex {
                re: -29.38196961155061,
                im: -19.477291831465134,
            },
            Complex {
                re: -8.856705670467903,
                im: 2.8623412898891245,
            },
            Complex {
                re: 16.398989279719256,
                im: -6.87851102229234,
            },
            Complex {
                re: -21.610566014107782,
                im: 24.866845080515485,
            },
            Complex {
                re: -6.3307136702926465,
                im: -4.284301897348901,
            },
            Complex {
                re: -7.076345422453177,
                im: -25.17309618475514,
            },
            Complex {
                re: -8.31260939216217,
                im: -9.24281557988013,
            },
            Complex {
                re: -11.45110217381113,
                im: -4.798309383711727,
            },
            Complex {
                re: -10.396126589991969,
                im: 9.23483926918439,
            },
            Complex {
                re: -10.926818763657511,
                im: -0.4122676641952481,
            },
            Complex {
                re: 10.708250628437728,
                im: -14.241951111227612,
            },
            Complex {
                re: 4.234752198864121,
                im: -11.593293549342338,
            },
            Complex {
                re: -10.215988944921131,
                im: 11.724914851726595,
            },
            Complex {
                re: -4.264491022095115,
                im: -16.091478675551443,
            },
            Complex {
                re: -15.09111238233286,
                im: -2.7153055636207126,
            },
            Complex {
                re: 8.401962159263594,
                im: 4.277146067035055,
            },
            Complex {
                re: 15.95338090913826,
                im: -3.247453401184262,
            },
            Complex {
                re: -2.1165430873224667,
                im: 5.683391653144622,
            },
            Complex {
                re: 17.511062420611328,
                im: -10.220976035589786,
            },
            Complex {
                re: -0.030926260501177083,
                im: 4.94141308744213,
            },
            Complex {
                re: -22.3012792095272,
                im: -23.358716491404927,
            },
            Complex {
                re: 0.7893858162648115,
                im: -11.498507317179364,
            },
            Complex {
                re: -1.2511335236764332,
                im: -0.8241039145082354,
            },
            Complex {
                re: 0.006003993795387075,
                im: 11.911130306703896,
            },
            Complex {
                re: -4.112342698794271,
                im: 2.4151684830645763,
            },
            Complex {
                re: 20.86412671518926,
                im: 0.6190325040099323,
            },
            Complex {
                re: -14.449279354983343,
                im: 21.178881577637977,
            },
            Complex {
                re: -2.25629516483676,
                im: 2.2730612901699594,
            },
            Complex {
                re: 5.951062389532792,
                im: -13.783607467924611,
            },
            Complex {
                re: 4.940691505822118,
                im: 17.426527156988286,
            },
            Complex {
                re: -11.28249550572123,
                im: -14.895723979283595,
            },
            Complex {
                re: -3.7049059663515918,
                im: -4.049546741133053,
            },
            Complex {
                re: -9.994972124206576,
                im: -15.266987660786857,
            },
            Complex {
                re: -16.35904675455085,
                im: 6.438576332025133,
            },
            Complex {
                re: 9.160628178789619,
                im: -2.7636964332234215,
            },
            Complex {
                re: -29.34375385092801,
                im: 0.9509884640374857,
            },
            Complex {
                re: 10.601291017720488,
                im: 1.7452471557704996,
            },
            Complex {
                re: 12.19949860914809,
                im: -4.682105203113405,
            },
            Complex {
                re: -19.48165700469612,
                im: -10.0078808589477,
            },
            Complex {
                re: 2.20903564185086,
                im: -1.5780724881005135,
            },
            Complex {
                re: 18.778094176491077,
                im: 5.280292809227996,
            },
            Complex {
                re: -6.635309389048036,
                im: 11.47997470742768,
            },
            Complex {
                re: 11.76866385314553,
                im: 0.25994172034871,
            },
            Complex {
                re: -9.415073275114754,
                im: -6.7872778121116175,
            },
            Complex {
                re: -18.823644977597667,
                im: -9.738522818073264,
            },
            Complex {
                re: 2.390754851323047,
                im: -4.939204547808517,
            },
            Complex {
                re: -17.908649332249013,
                im: -5.285735467980636,
            },
            Complex {
                re: -4.4901313452241745,
                im: 3.506868598354072,
            },
            Complex {
                re: -6.15026915933057,
                im: -10.135617115212721,
            },
            Complex {
                re: -28.93955057713877,
                im: 13.795822343670693,
            },
            Complex {
                re: -3.2751089978426333,
                im: 20.4091932159973,
            },
            Complex {
                re: -3.480366146553842,
                im: -24.438850798270224,
            },
            Complex {
                re: -10.929149484095037,
                im: 11.106172689267359,
            },
            Complex {
                re: -11.179141545729676,
                im: -3.3683525900619675,
            },
            Complex {
                re: 13.856455534281611,
                im: -28.34837538803404,
            },
            Complex {
                re: 2.6225852035759356,
                im: 6.932727510723776,
            },
            Complex {
                re: 12.165561515783198,
                im: -16.078508195433503,
            },
            Complex {
                re: 12.245294253674382,
                im: -7.158446287398121,
            },
            Complex {
                re: -17.814933397608243,
                im: -2.2552589768514366,
            },
            Complex {
                re: -14.122511317229307,
                im: -4.2006386915824665,
            },
            Complex {
                re: -8.860800396603324,
                im: -4.317200643478168,
            },
            Complex {
                re: -3.6352288745392443,
                im: -9.64229007423607,
            },
            Complex {
                re: -0.40317812774472905,
                im: 2.789524338121744,
            },
            Complex {
                re: 19.9472342158657,
                im: -6.300707804611787,
            },
            Complex {
                re: -12.399363447207868,
                im: -7.582098130744138,
            },
            Complex {
                re: -14.75022568543383,
                im: -26.195152238910097,
            },
            Complex {
                re: -3.6002887155384484,
                im: -4.676112127044274,
            },
            Complex {
                re: -11.33416688250685,
                im: 3.702564803788688,
            },
            Complex {
                re: -0.4508893423929674,
                im: 2.2450542033943712,
            },
            Complex {
                re: -6.665375411472505,
                im: 3.914959036074085,
            },
            Complex {
                re: 5.443514999854095,
                im: 14.08462811393849,
            },
            Complex {
                re: -3.3143167330819328,
                im: 13.209905914390188,
            },
            Complex {
                re: 15.332990970448007,
                im: -13.243458967578318,
            },
            Complex {
                re: 16.494289003879715,
                im: -24.74930204929008,
            },
            Complex {
                re: -6.630260952302833,
                im: -23.85843219413842,
            },
            Complex {
                re: 17.72076460179183,
                im: 4.060676181315637,
            },
            Complex {
                re: 5.72624214611591,
                im: -1.8304438356119732,
            },
            Complex {
                re: 9.685597367994664,
                im: -10.525855378034933,
            },
            Complex {
                re: -11.483167956989831,
                im: -0.2816403115558477,
            },
            Complex {
                re: 4.524221212972851,
                im: -1.9004279193657716,
            },
            Complex {
                re: -18.310095985707466,
                im: 9.775849835198432,
            },
            Complex {
                re: -4.379428152706627,
                im: 2.065542737014151,
            },
            Complex {
                re: 29.173177548299268,
                im: -0.43779767807905023,
            },
            Complex {
                re: -2.5984940248284047,
                im: 1.1085521590266438,
            },
            Complex {
                re: -6.346391186522915,
                im: 11.205212008750218,
            },
            Complex {
                re: -5.521307683583492,
                im: 2.667645169150215,
            },
            Complex {
                re: -30.235278357650614,
                im: -1.834301543799847,
            },
            Complex {
                re: 9.854008893496303,
                im: 6.200169376233236,
            },
            Complex {
                re: -7.124887062342451,
                im: 8.34201226874872,
            },
            Complex {
                re: 2.3377368558843603,
                im: 13.994680702517918,
            },
            Complex {
                re: -15.957625700779513,
                im: -7.342277297514187,
            },
            Complex {
                re: -2.0200057835319285,
                im: 8.329000709645372,
            },
            Complex {
                re: -6.091592692601475,
                im: -7.646957149050456,
            },
            Complex {
                re: 10.001593482758082,
                im: -4.459578320511661,
            },
            Complex {
                re: 15.747546079886632,
                im: 2.2932397378305622,
            },
            Complex {
                re: 6.286687860903498,
                im: 9.020375522355286,
            },
            Complex {
                re: -2.0108969947029784,
                im: -18.22620381870767,
            },
            Complex {
                re: 0.862905347447644,
                im: -7.006598633743745,
            },
            Complex {
                re: -1.4591096918398243,
                im: 2.383153936325451,
            },
            Complex {
                re: -9.615881468661481,
                im: 38.339331662113125,
            },
            Complex {
                re: -4.264093553430381,
                im: 6.235998669271195,
            },
            Complex {
                re: -4.163606328861517,
                im: -10.724957724335198,
            },
            Complex {
                re: 0.2866220458929263,
                im: -9.106924688007833,
            },
            Complex {
                re: 1.8907497599806256,
                im: -9.989776400322782,
            },
            Complex {
                re: 10.002639641103023,
                im: -9.215319594515277,
            },
            Complex {
                re: -17.11563551574956,
                im: -14.321257732473406,
            },
            Complex {
                re: -5.291885800079906,
                im: -0.2565159384472442,
            },
            Complex {
                re: 0.05390065636715935,
                im: -5.25015048537726,
            },
            Complex {
                re: -5.093968324262189,
                im: 21.00047164621477,
            },
            Complex {
                re: 1.8924815161932589,
                im: -6.495695556597933,
            },
            Complex {
                re: -11.889406762665548,
                im: 2.8358970233278664,
            },
            Complex {
                re: 6.755884012163659,
                im: 2.5775328020928905,
            },
            Complex {
                re: 0.8830342755345022,
                im: 8.430524784796898,
            },
            Complex {
                re: 2.4968026597845974,
                im: 10.092727498545063,
            },
            Complex {
                re: 4.134508625182141,
                im: -24.19984694342367,
            },
            Complex {
                re: -18.650344013044737,
                im: -18.40941934456824,
            },
            Complex {
                re: -8.051282312303798,
                im: 18.21434589965462,
            },
            Complex {
                re: -0.45191920416581155,
                im: 9.104356986347344,
            },
            Complex {
                re: 4.493094431287341,
                im: 22.59885688706809,
            },
            Complex {
                re: 4.560267522170824,
                im: -4.95374459406239,
            },
            Complex {
                re: -3.3641169338464296,
                im: 16.532830326519896,
            },
            Complex {
                re: 19.321429794013397,
                im: -5.004262195036349,
            },
            Complex {
                re: -10.04719407482197,
                im: 12.351843840899212,
            },
            Complex {
                re: -6.1702272307986155,
                im: -1.0114288043557789,
            },
            Complex {
                re: 29.637156576681743,
                im: -3.539480733603284,
            },
            Complex {
                re: -10.408829384235188,
                im: 11.540584426369051,
            },
            Complex {
                re: 3.399791173494858,
                im: -2.5881572587929322,
            },
            Complex {
                re: -6.086392547093525,
                im: 1.3894028174023323,
            },
            Complex {
                re: 24.07546256055904,
                im: 14.703006514352555,
            },
            Complex {
                re: 14.26263758477461,
                im: -0.5747597228544743,
            },
            Complex {
                re: 10.646873569929342,
                im: 7.324894592837662,
            },
            Complex {
                re: -2.3024130614468508,
                im: -5.661095776694957,
            },
            Complex {
                re: -18.831295255550828,
                im: -25.46483141126365,
            },
            Complex {
                re: 14.220423457216146,
                im: -5.2924304648686435,
            },
            Complex {
                re: 10.532011938028765,
                im: 15.365949609672068,
            },
            Complex {
                re: -3.6412972530043364,
                im: 4.2882175131094415,
            },
            Complex {
                re: -18.19683705332141,
                im: -1.8697007754053088,
            },
            Complex {
                re: -7.12762468616333,
                im: 9.868801155454413,
            },
            Complex {
                re: -0.7090756323656215,
                im: 5.734189538295341,
            },
            Complex {
                re: -6.3061762577049585,
                im: 19.230325824810947,
            },
            Complex {
                re: 9.15314598700527,
                im: -10.506785197446568,
            },
            Complex {
                re: -9.637066789208394,
                im: -18.63333397745755,
            },
            Complex {
                re: -11.249737889891856,
                im: -15.252059393032571,
            },
            Complex {
                re: -8.480806755686665,
                im: 11.502466758122962,
            },
            Complex {
                re: -10.730593018284104,
                im: -24.42048953104958,
            },
            Complex {
                re: 15.229719865374841,
                im: 18.54678188393069,
            },
            Complex {
                re: -13.667228961067421,
                im: 6.064222242699724,
            },
            Complex {
                re: 12.038133917292438,
                im: -8.038187299524647,
            },
            Complex {
                re: 13.555835316553365,
                im: 5.30625822143206,
            },
            Complex {
                re: 10.067933976962605,
                im: 22.014744733233638,
            },
            Complex {
                re: 1.7943975933705323,
                im: -4.478088451260621,
            },
            Complex {
                re: -7.3943145199180025,
                im: -15.621559116251568,
            },
            Complex {
                re: 23.641087615439908,
                im: 37.02303924493386,
            },
            Complex {
                re: -6.698754341287253,
                im: 6.527205379182851,
            },
            Complex {
                re: 4.093983988941094,
                im: -1.0049398700512575,
            },
            Complex {
                re: -9.642924206031205,
                im: 21.014860035143656,
            },
            Complex {
                re: -6.092600051583098,
                im: -7.138872979789937,
            },
            Complex {
                re: -21.53537915359774,
                im: 15.747187342107967,
            },
            Complex {
                re: 24.360609498548193,
                im: 4.010823696982267,
            },
            Complex {
                re: -20.118316186998964,
                im: 2.9734394993838507,
            },
            Complex {
                re: -4.12814289240822,
                im: -2.555626668005605,
            },
            Complex {
                re: 2.3539175561186436,
                im: 2.5637545725472366,
            },
            Complex {
                re: 8.079945239255137,
                im: -5.5245353362149565,
            },
            Complex {
                re: -2.3493405640883056,
                im: -3.6510812655650198,
            },
            Complex {
                re: 27.696520118411634,
                im: 13.463093996336667,
            },
            Complex {
                re: 6.984613471652674,
                im: 35.17077286930748,
            },
            Complex {
                re: -11.008127490839303,
                im: -22.685435329620308,
            },
            Complex {
                re: -5.862816053488834,
                im: 26.186822968253807,
            },
            Complex {
                re: -0.40395393666928747,
                im: 15.191429872573032,
            },
            Complex {
                re: -16.5553618005105,
                im: -32.76794084785999,
            },
            Complex {
                re: -4.416269102130208,
                im: -0.4178948589506563,
            },
            Complex {
                re: -6.721067008449467,
                im: 8.23414686336547,
            },
            Complex {
                re: 5.700643954282141,
                im: -19.77726450555056,
            },
            Complex {
                re: -8.853044642808364,
                im: 14.762158627491385,
            },
            Complex {
                re: 4.262813053079238,
                im: -1.228229517506597,
            },
            Complex {
                re: 4.9897147543933755,
                im: 24.574036945944364,
            },
            Complex {
                re: -2.683654861777958,
                im: 13.830587547974735,
            },
            Complex {
                re: 3.30829666017771,
                im: -0.7889739359871477,
            },
            Complex {
                re: 21.827519997022815,
                im: 33.978018133897216,
            },
            Complex {
                re: -10.123135577788313,
                im: 4.136347213838592,
            },
            Complex {
                re: -5.307077746023433,
                im: 22.272540601554127,
            },
            Complex {
                re: -13.904201577665894,
                im: 20.07811112734162,
            },
            Complex {
                re: 0.2653457644292221,
                im: 1.7780312877159532,
            },
            Complex {
                re: 3.859311225130728,
                im: -22.97862708360943,
            },
            Complex {
                re: 5.803374200598698,
                im: 18.863376698995236,
            },
            Complex {
                re: -6.122701473669709,
                im: 6.263954489277401,
            },
            Complex {
                re: 2.5844814191615626,
                im: 20.531981588629,
            },
            Complex {
                re: -11.803305944440663,
                im: 2.7150438602454026,
            },
            Complex {
                re: 3.030286734820462,
                im: -10.81683487676447,
            },
            Complex {
                re: -0.3859633951080115,
                im: 0.08066366641761835,
            },
            Complex {
                re: 10.958547568422999,
                im: -2.094670315663642,
            },
            Complex {
                re: -0.023814876733285306,
                im: -0.6215944848294548,
            },
            Complex {
                re: -5.36851085740903,
                im: -28.485524216586107,
            },
            Complex {
                re: -18.471127855414824,
                im: -22.680947004222137,
            },
            Complex {
                re: -4.054060098829879,
                im: 7.7633954836448,
            },
            Complex {
                re: 0.9888070679524201,
                im: -22.586735840296967,
            },
            Complex {
                re: 4.872137232384343,
                im: 7.361297278039238,
            },
            Complex {
                re: -0.5827820162112536,
                im: -9.00181929206203,
            },
            Complex {
                re: 2.5265740087284065,
                im: -1.172903072712209,
            },
            Complex {
                re: -10.676542459985429,
                im: 4.856206564032922,
            },
            Complex {
                re: -5.813032041581691,
                im: 8.564504844180867,
            },
            Complex {
                re: 12.766072438057046,
                im: -6.20111656531064,
            },
            Complex {
                re: -19.997851155072713,
                im: 9.637477174211767,
            },
            Complex {
                re: -28.865422143612392,
                im: 18.30497711528949,
            },
            Complex {
                re: 14.253495911900778,
                im: -11.213029215069698,
            },
            Complex {
                re: -4.701938518413279,
                im: 15.00293153472111,
            },
            Complex {
                re: -11.585752094205603,
                im: -6.91310191727001,
            },
            Complex {
                re: 4.181248155106237,
                im: 7.482576127928644,
            },
            Complex {
                re: 2.532754269325025,
                im: -18.63962280938757,
            },
            Complex {
                re: 32.74907172947182,
                im: 15.057563976780994,
            },
            Complex {
                re: -14.454904225493763,
                im: 5.60051728192248,
            },
            Complex {
                re: 4.211690012262294,
                im: -4.611905097494152,
            },
            Complex {
                re: 36.44194062820918,
                im: 9.12986120358238,
            },
            Complex {
                re: 2.2198832207372705,
                im: -6.722418173820192,
            },
            Complex {
                re: -11.15884221820299,
                im: -21.68665282338131,
            },
            Complex {
                re: 1.3438050367030208,
                im: 2.0006471022567194,
            },
            Complex {
                re: 1.0316939463699382,
                im: -26.68677282470535,
            },
            Complex {
                re: 15.244415841027413,
                im: 4.833327940701537,
            },
            Complex {
                re: -0.13251643884861697,
                im: 39.54865235672784,
            },
            Complex {
                re: 32.38326953860222,
                im: -17.82825760155793,
            },
            Complex {
                re: 5.3948234024699175,
                im: -13.72257753353932,
            },
            Complex {
                re: 16.081539618004832,
                im: -23.06690088659948,
            },
            Complex {
                re: -24.677772290055884,
                im: -23.25772908725949,
            },
            Complex {
                re: 25.32266440084222,
                im: 2.10464011970806,
            },
            Complex {
                re: 8.678157597370209,
                im: 29.130299908084023,
            },
            Complex {
                re: 5.254301469882794,
                im: 17.09983242271655,
            },
            Complex {
                re: 21.433576052554116,
                im: -9.51580787963645,
            },
            Complex {
                re: 9.170274806209235,
                im: -5.247853417809527,
            },
            Complex {
                re: 14.832751570104735,
                im: -22.129701367999488,
            },
            Complex {
                re: -9.138093128438147,
                im: 0.3004366504358922,
            },
            Complex {
                re: 11.937805830809408,
                im: -1.8740208238286726,
            },
            Complex {
                re: 17.06653745387504,
                im: 23.813129367122635,
            },
            Complex {
                re: -3.310310802657838,
                im: -3.8927459102369024,
            },
            Complex {
                re: -9.849026771357602,
                im: 0.16346392583089964,
            },
            Complex {
                re: -1.9115236282774006,
                im: -5.986548463955227,
            },
            Complex {
                re: -9.83293052434437,
                im: -18.40712654700187,
            },
            Complex {
                re: -2.565203259673842,
                im: 1.3166638106305335,
            },
            Complex {
                re: 7.329984244961188,
                im: 21.18144104555535,
            },
            Complex {
                re: 0.5322982756330088,
                im: -12.878098273001982,
            },
            Complex {
                re: 16.92659245223865,
                im: 15.454594054305831,
            },
            Complex {
                re: 5.619384601167851,
                im: 4.586982392760097,
            },
            Complex {
                re: -12.991062746569824,
                im: -10.327164781919192,
            },
            Complex {
                re: -13.087100471197797,
                im: -6.004705575821339,
            },
            Complex {
                re: 0.2936897811090997,
                im: 1.1164258529899813,
            },
            Complex {
                re: 9.347291348872638,
                im: -1.7990276922067423,
            },
            Complex {
                re: -8.7674358200819,
                im: -11.450588532820056,
            },
            Complex {
                re: -21.55748095938172,
                im: 3.1048893580558747,
            },
            Complex {
                re: 29.45815259929552,
                im: -0.33326988090358967,
            },
            Complex {
                re: -9.335597966495865,
                im: -0.42560930315608303,
            },
            Complex {
                re: 10.07756980650306,
                im: -15.09918540298154,
            },
            Complex {
                re: -23.793163206934523,
                im: -16.623807817267245,
            },
            Complex {
                re: -2.955325834834804,
                im: 3.477708625932954,
            },
            Complex {
                re: -25.66285516207745,
                im: 14.70466376867078,
            },
            Complex {
                re: -17.1790818753678,
                im: -1.2557142402897519,
            },
            Complex {
                re: 2.01497103906358,
                im: -9.11911820413873,
            },
            Complex {
                re: -4.483728636087804,
                im: 19.89809738808738,
            },
            Complex {
                re: 6.2694355491755624,
                im: 10.14370255952367,
            },
            Complex {
                re: -22.314156955541193,
                im: -20.332642645390358,
            },
            Complex {
                re: 3.7204594687825505,
                im: 25.744748765550497,
            },
            Complex {
                re: 22.606266595559312,
                im: -1.074865427399808,
            },
            Complex {
                re: -5.826461570718632,
                im: 2.9801705153139313,
            },
            Complex {
                re: 18.631133902863873,
                im: -21.1652359664781,
            },
            Complex {
                re: -4.452742460819701,
                im: -28.361117807381046,
            },
            Complex {
                re: 15.145452010417866,
                im: 2.131935229875893,
            },
            Complex {
                re: -6.369976305907954,
                im: 18.833322088074663,
            },
            Complex {
                re: -9.782989343103676,
                im: -27.740350786143154,
            },
            Complex {
                re: 8.788568109640975,
                im: -18.149503977459478,
            },
            Complex {
                re: 13.791338081097098,
                im: 14.152748328113887,
            },
            Complex {
                re: 20.803837419928367,
                im: -10.234554496493239,
            },
            Complex {
                re: 10.140158141949128,
                im: -12.569396516850187,
            },
            Complex {
                re: -2.642086895638294,
                im: -5.9062269137527075,
            },
            Complex {
                re: -1.145026640498831,
                im: 1.6310353351347153,
            },
            Complex {
                re: -4.2789978163617945,
                im: -1.2941754262700211,
            },
            Complex {
                re: -1.5433014546799266,
                im: -1.3799970597185398,
            },
            Complex {
                re: -1.5265813464591282,
                im: -19.2598847775402,
            },
            Complex {
                re: -13.630711276810953,
                im: -11.606595075337083,
            },
            Complex {
                re: 7.075233823929619,
                im: -0.1986070522898764,
            },
            Complex {
                re: -5.631026230445633,
                im: 2.8103782828601807,
            },
            Complex {
                re: -4.190652882374069,
                im: -9.026353166959302,
            },
            Complex {
                re: 7.26410762472239,
                im: -4.1111233501265545,
            },
            Complex {
                re: 3.7857875593588393,
                im: 1.2218328630930655,
            },
            Complex {
                re: -6.950617423742591,
                im: 0.18386867903676074,
            },
            Complex {
                re: -2.806924281767941,
                im: -2.749574758006813,
            },
            Complex {
                re: 1.9048248054572872,
                im: -7.894113873339095,
            },
            Complex {
                re: 10.28484405624057,
                im: 11.089378580773584,
            },
            Complex {
                re: -1.9841319909677395,
                im: -5.082205843064897,
            },
            Complex {
                re: 5.112242435768352,
                im: 5.767416268788445,
            },
            Complex {
                re: 5.4453836708882015,
                im: -5.003111933174893,
            },
            Complex {
                re: -2.8948611911745816,
                im: -23.27277161470719,
            },
            Complex {
                re: -9.36949823790812,
                im: -9.90527358415774,
            },
            Complex {
                re: 40.977405504915936,
                im: 1.5369220197484115,
            },
            Complex {
                re: -2.4050330251270076,
                im: 11.456375124717663,
            },
            Complex {
                re: 0.7840233403898256,
                im: -2.019640252705555,
            },
            Complex {
                re: -12.039545780705234,
                im: 12.374190288668174,
            },
            Complex {
                re: 15.685346800378726,
                im: -7.943898485349346,
            },
            Complex {
                re: 5.068916455326681,
                im: 3.305664630916768,
            },
            Complex {
                re: -12.035430156214124,
                im: -12.462578586791121,
            },
            Complex {
                re: 10.872028000674023,
                im: 3.609082256762213,
            },
            Complex {
                re: -7.434371755671336,
                im: -4.605693450449347,
            },
            Complex {
                re: -17.259053381319507,
                im: 3.4156951118443444,
            },
            Complex {
                re: -12.518375695112473,
                im: 20.76840842846059,
            },
            Complex {
                re: -7.499875469569252,
                im: 4.241432641142718,
            },
            Complex {
                re: 19.49938631575975,
                im: -12.370578728305967,
            },
            Complex {
                re: -28.30096421705197,
                im: 11.447267247766817,
            },
            Complex {
                re: -4.145830634446797,
                im: 0.6020129627407727,
            },
            Complex {
                re: -4.077793902135664,
                im: -23.668819504783322,
            },
            Complex {
                re: -2.8699708935783006,
                im: -5.941539607161145,
            },
            Complex {
                re: 22.97038009091443,
                im: -13.317466470094887,
            },
            Complex {
                re: -21.700409494708744,
                im: -4.276081531151522,
            },
            Complex {
                re: -15.73511295904233,
                im: -4.839248578708322,
            },
            Complex {
                re: 11.174794165812811,
                im: -5.02632042712437,
            },
            Complex {
                re: 17.930268775771935,
                im: -15.41627727832335,
            },
            Complex {
                re: -9.115393378862883,
                im: -1.748199745844719,
            },
            Complex {
                re: -9.526049177325175,
                im: -5.880473666604645,
            },
            Complex {
                re: -0.5454460085564792,
                im: 5.421170228769679,
            },
            Complex {
                re: 31.612733868237907,
                im: 10.597984966470468,
            },
            Complex {
                re: -4.115611150280513,
                im: -12.376933434327286,
            },
            Complex {
                re: 21.6977161516156,
                im: -15.297420113265403,
            },
            Complex {
                re: -3.1422028609957415,
                im: 1.1717373035299605,
            },
            Complex {
                re: 1.9505185342589346,
                im: -12.017345007623085,
            },
            Complex {
                re: 1.3770142817981155,
                im: -11.83569940317366,
            },
            Complex {
                re: 7.517368770592359,
                im: 3.0991961840361437,
            },
            Complex {
                re: -3.7168932793378087,
                im: 18.66602326725325,
            },
            Complex {
                re: 12.60412532784608,
                im: 13.069997113203295,
            },
            Complex {
                re: -6.565281644336703,
                im: -2.0519705257334477,
            },
            Complex {
                re: 1.6806810206084446,
                im: -31.360528652953484,
            },
            Complex {
                re: 25.554572908170798,
                im: -5.386439408681861,
            },
            Complex {
                re: -5.511270690898389,
                im: 7.198921572701657,
            },
            Complex {
                re: -22.852558519658192,
                im: -14.199054274681647,
            },
            Complex {
                re: -2.471576951494411,
                im: 20.983968125300233,
            },
            Complex {
                re: -6.619505574087517,
                im: -2.7811962565655466,
            },
            Complex {
                re: -5.159254577189047,
                im: -6.020500264809318,
            },
            Complex {
                re: 0.8053706479263374,
                im: -4.360747328469012,
            },
            Complex {
                re: -7.597590672610702,
                im: -3.0246871976603673,
            },
            Complex {
                re: 2.1482255792866702,
                im: 13.19408570196779,
            },
            Complex {
                re: -12.074300397899075,
                im: 10.159406365043047,
            },
            Complex {
                re: 14.368309810336687,
                im: 5.6974436376814666,
            },
            Complex {
                re: -12.17296661127092,
                im: 27.699942506768167,
            },
            Complex {
                re: -22.375915622116676,
                im: 5.595687113973403,
            },
            Complex {
                re: 4.293995247162689,
                im: -1.2640761793929887,
            },
            Complex {
                re: -3.9298573858489956,
                im: 6.488741309397988,
            },
            Complex {
                re: 8.633544343905895,
                im: 12.508537843586149,
            },
            Complex {
                re: -1.5807540481880604,
                im: 15.368931214877623,
            },
            Complex {
                re: 10.64961734598725,
                im: 16.167469307130176,
            },
            Complex {
                re: 6.099627252338821,
                im: 7.142136802926487,
            },
            Complex {
                re: 8.149305380788414,
                im: 15.634187352919923,
            },
            Complex {
                re: -10.434649376836466,
                im: -0.6933687155073369,
            },
            Complex {
                re: 3.417109663323253,
                im: -13.602735122519455,
            },
            Complex {
                re: 1.0760683206415829,
                im: -27.470988953013183,
            },
            Complex {
                re: 2.6115829405457003,
                im: -1.9099612386263167,
            },
            Complex {
                re: -17.97900525143622,
                im: -0.9052208155217123,
            },
            Complex {
                re: 5.173457983640089,
                im: 22.595097638647708,
            },
            Complex {
                re: 18.42195319600197,
                im: 0.40089160251192935,
            },
            Complex {
                re: 10.143079431237622,
                im: 3.6973690078255146,
            },
            Complex {
                re: 12.503690123355977,
                im: 1.4663730876949628,
            },
            Complex {
                re: 5.86239970092462,
                im: -19.811896515764793,
            },
            Complex {
                re: 8.035047475667222,
                im: 14.762470907603944,
            },
            Complex {
                re: 3.892671760628078,
                im: 4.237445227989204,
            },
            Complex {
                re: -13.014866092112817,
                im: -8.916117933353192,
            },
            Complex {
                re: -8.46164614239492,
                im: -10.756557314073653,
            },
            Complex {
                re: 2.5550352095220523,
                im: 43.34966160954228,
            },
            Complex {
                re: -8.941205772648656,
                im: -0.42706765753681974,
            },
            Complex {
                re: 8.197619422797091,
                im: -8.282859203621687,
            },
            Complex {
                re: -15.918035470289473,
                im: 12.747474653452528,
            },
            Complex {
                re: 21.292596560389327,
                im: 0.5998741521349564,
            },
            Complex {
                re: 4.404997164617046,
                im: 20.00081457612402,
            },
            Complex {
                re: -9.125769110325601,
                im: -14.867590192666931,
            },
            Complex {
                re: 24.450083760095985,
                im: -4.190528953973889,
            },
            Complex {
                re: 24.161911993674273,
                im: 4.132734086773654,
            },
            Complex {
                re: -5.411497876219621,
                im: -5.769566809816823,
            },
            Complex {
                re: 27.79496108489705,
                im: -2.069462516212746,
            },
            Complex {
                re: -23.82671667339708,
                im: -2.9990555788934428,
            },
            Complex {
                re: -11.920079151733166,
                im: -18.445485239162362,
            },
            Complex {
                re: 11.392943089828563,
                im: 11.828650852173267,
            },
            Complex {
                re: 1.2889101291477258,
                im: -2.990291495837166,
            },
            Complex {
                re: 21.74743727641311,
                im: -28.310020424132546,
            },
            Complex {
                re: -17.960902491329144,
                im: -18.0431062612551,
            },
            Complex {
                re: -9.476007324212722,
                im: -19.96560237334372,
            },
            Complex {
                re: -4.401274137289729,
                im: -3.851069702832584,
            },
            Complex {
                re: 12.56414471937658,
                im: -9.875003528805912,
            },
            Complex {
                re: 6.534039681771295,
                im: -2.892434414406248,
            },
            Complex {
                re: -0.04506841685463048,
                im: -2.6120455405039973,
            },
            Complex {
                re: -6.325116934790534,
                im: -9.955476167441791,
            },
            Complex {
                re: 14.01336246749955,
                im: -15.80691990286801,
            },
            Complex {
                re: 24.421659836878966,
                im: 3.9105168299004753,
            },
            Complex {
                re: -19.17685351082366,
                im: 7.8290521441686955,
            },
            Complex {
                re: -1.5715776579515932,
                im: -8.516219662836011,
            },
            Complex {
                re: -2.7678350845278157,
                im: -18.260974508152376,
            },
            Complex {
                re: -19.672510846573164,
                im: 18.042911518310493,
            },
            Complex {
                re: 0.7597985025759204,
                im: -7.3071407753190005,
            },
            Complex {
                re: 13.86325732889225,
                im: 16.291283787747226,
            },
            Complex {
                re: -3.460180251549126,
                im: -2.021695360221633,
            },
            Complex {
                re: 5.154886863805563,
                im: 9.390732216420421,
            },
            Complex {
                re: 14.323761594922958,
                im: 11.280175357030723,
            },
            Complex {
                re: 16.562505608913973,
                im: 13.45003169212834,
            },
            Complex {
                re: -21.71503072681655,
                im: 4.055868967552855,
            },
            Complex {
                re: -25.185915100156983,
                im: -16.16228589381319,
            },
            Complex {
                re: -24.68431805923367,
                im: -1.9018586098109047,
            },
            Complex {
                re: -13.972175125421028,
                im: -7.67576866815792,
            },
            Complex {
                re: -2.2560173460933997,
                im: 0.2984886448102557,
            },
            Complex {
                re: 5.149398949653667,
                im: -19.05305567894343,
            },
            Complex {
                re: -19.78038714950273,
                im: 30.466719775791844,
            },
            Complex {
                re: -9.508838854092964,
                im: -7.831638431504114,
            },
            Complex {
                re: 13.79170907928065,
                im: -0.03436604905208718,
            },
            Complex {
                re: 4.5839709506518105,
                im: 8.453976794635356,
            },
            Complex {
                re: -3.3796693755735063,
                im: 1.668803386583246,
            },
            Complex {
                re: 9.762441301388858,
                im: 8.546519150641789,
            },
            Complex {
                re: -13.749612504281867,
                im: -4.38368818986492,
            },
            Complex {
                re: 6.108730652832888,
                im: 8.20357371161023,
            },
            Complex {
                re: 0.09033781304262867,
                im: -24.954105821764866,
            },
            Complex {
                re: -6.704549700609635,
                im: -5.7498663969176915,
            },
            Complex {
                re: 3.5669604473825203,
                im: -5.033988435088559,
            },
            Complex {
                re: -2.4686639380015354,
                im: -3.301836706777941,
            },
            Complex {
                re: 1.813421838432756,
                im: -28.606052173148665,
            },
            Complex {
                re: 16.92403629000961,
                im: -12.542815245588441,
            },
            Complex {
                re: 5.342950497610023,
                im: -34.99300448657549,
            },
            Complex {
                re: 32.16545029254558,
                im: 8.66835151445916,
            },
            Complex {
                re: 21.378002454413647,
                im: 3.528089799223478,
            },
            Complex {
                re: -12.072641678374065,
                im: -12.735052620354718,
            },
            Complex {
                re: 44.60593402335257,
                im: 15.784653779607648,
            },
            Complex {
                re: 2.1588013073184738,
                im: -24.209470279914324,
            },
            Complex {
                re: -27.76203590515962,
                im: -0.8058729403005298,
            },
            Complex {
                re: 18.242415904170066,
                im: 16.72734262954434,
            },
            Complex {
                re: 4.97927440491753,
                im: -16.7552797525941,
            },
            Complex {
                re: -19.914188543297932,
                im: -10.490681658767022,
            },
            Complex {
                re: -20.970799132169418,
                im: -17.79478612361888,
            },
            Complex {
                re: 4.486259964912683,
                im: -15.64928068695593,
            },
            Complex {
                re: 6.3363164847979405,
                im: 3.650139456719308,
            },
            Complex {
                re: -18.09290093983951,
                im: 24.674889857691454,
            },
            Complex {
                re: -9.771014219156715,
                im: 14.38481998757101,
            },
            Complex {
                re: 8.058387856004328,
                im: -3.8825260274896047,
            },
            Complex {
                re: -23.816371409816036,
                im: 0.6326722479571067,
            },
            Complex {
                re: -8.988646934235662,
                im: 8.251931624632547,
            },
            Complex {
                re: 3.3276044752750673,
                im: 1.578800371193037,
            },
            Complex {
                re: -7.59831408527478,
                im: 9.824275987162718,
            },
            Complex {
                re: 7.701954991332694,
                im: 5.574813420701819,
            },
            Complex {
                re: -13.096072762573833,
                im: -10.584406297697049,
            },
            Complex {
                re: -5.981237988912614,
                im: -0.7179184369947649,
            },
            Complex {
                re: 29.12188306626394,
                im: -0.11339961154260081,
            },
            Complex {
                re: -14.17813488515293,
                im: -9.896470910762574,
            },
            Complex {
                re: 3.651380388735177,
                im: -3.6231280753219206,
            },
            Complex {
                re: -20.178661433531673,
                im: 8.01737134403267,
            },
            Complex {
                re: -15.064937063022182,
                im: 13.0421050255239,
            },
            Complex {
                re: 22.625490107894286,
                im: 8.631679725995816,
            },
            Complex {
                re: -10.551924804262066,
                im: 6.630068457475332,
            },
            Complex {
                re: 6.618272164062223,
                im: -1.267615524096672,
            },
            Complex {
                re: -10.961986207638942,
                im: -13.628747589180467,
            },
            Complex {
                re: -3.704853043648937,
                im: -18.49849998091574,
            },
            Complex {
                re: -36.66996712435405,
                im: -20.064616794229384,
            },
            Complex {
                re: -5.040096653761515,
                im: 3.302796273836224,
            },
            Complex {
                re: 5.949514251165351,
                im: 6.31556205079038,
            },
            Complex {
                re: 6.259257072428331,
                im: 25.049631792859632,
            },
            Complex {
                re: -2.1478240354262557,
                im: -13.89160300527538,
            },
            Complex {
                re: -6.685417337892513,
                im: 32.43530631573292,
            },
            Complex {
                re: -4.8431546410234905,
                im: 20.01056947706563,
            },
            Complex {
                re: 6.1550189409627105,
                im: -5.540159919884599,
            },
            Complex {
                re: -8.561440810240946,
                im: -28.670947208338156,
            },
            Complex {
                re: -0.1599078053023515,
                im: 3.1427477662284584,
            },
            Complex {
                re: -20.387630031851632,
                im: -27.19639844333117,
            },
            Complex {
                re: -15.748984127611331,
                im: -6.595292511204785,
            },
            Complex {
                re: 13.922954298261622,
                im: -11.7685982799245,
            },
            Complex {
                re: 14.3718479140724,
                im: -8.961556502767952,
            },
            Complex {
                re: 18.768500376470623,
                im: -21.926783142233123,
            },
            Complex {
                re: 10.308401022077192,
                im: -2.5718611739154245,
            },
            Complex {
                re: -5.468302878711819,
                im: -5.973343799304773,
            },
            Complex {
                re: 10.612830821329203,
                im: 0.6786134447767536,
            },
            Complex {
                re: 6.497302644160499,
                im: 6.78258639363428,
            },
            Complex {
                re: -13.79961506739579,
                im: 11.192976127787624,
            },
            Complex {
                re: 15.218658496757945,
                im: -17.948542609819228,
            },
            Complex {
                re: 28.14281570297498,
                im: 2.529767061449946,
            },
            Complex {
                re: 9.070944766747917,
                im: -2.268590798151294,
            },
            Complex {
                re: 1.6989952351822577,
                im: -9.13938097900829,
            },
            Complex {
                re: 0.6136480239769262,
                im: 0.7626163386562848,
            },
            Complex {
                re: -5.91386912996015,
                im: 8.433723012938596,
            },
            Complex {
                re: 34.87080043276313,
                im: 14.200097074434353,
            },
            Complex {
                re: -9.584577347214948,
                im: 12.321976878866163,
            },
            Complex {
                re: -6.117794882332338,
                im: -2.092751601283502,
            },
            Complex {
                re: 20.954350678148632,
                im: 8.150582401646542,
            },
            Complex {
                re: -31.6570928782108,
                im: -13.594031506117812,
            },
            Complex {
                re: -2.3735757071415824,
                im: -14.23718881448296,
            },
            Complex {
                re: -20.410443296982372,
                im: 15.609557167030067,
            },
            Complex {
                re: -32.69630397292776,
                im: -13.290432066202772,
            },
            Complex {
                re: -11.333546417960257,
                im: -14.08858429872268,
            },
            Complex {
                re: 31.25997322981408,
                im: -25.97434145090049,
            },
            Complex {
                re: 12.914318168935894,
                im: -0.08510432645777577,
            },
            Complex {
                re: -7.24060484885468,
                im: 13.853874200797058,
            },
            Complex {
                re: -13.938003799969113,
                im: 20.23819566615476,
            },
            Complex {
                re: -15.817460619971603,
                im: -12.174708432209403,
            },
            Complex {
                re: -0.08917108916746086,
                im: -14.552275572303726,
            },
            Complex {
                re: -15.953993369581447,
                im: 7.525976155951566,
            },
            Complex {
                re: -24.45480403858061,
                im: -3.7643007587787904,
            },
            Complex {
                re: 11.783860304513315,
                im: 16.86480190410658,
            },
            Complex {
                re: 10.123816034759955,
                im: -10.400582740931885,
            },
            Complex {
                re: 6.857464433121257,
                im: 34.26659162638774,
            },
            Complex {
                re: -27.245104215975257,
                im: -12.473896310484585,
            },
            Complex {
                re: 3.6936539154803394,
                im: 6.73147650304003,
            },
            Complex {
                re: 2.4396547259682175,
                im: -14.779653189252755,
            },
            Complex {
                re: 3.875181621260447,
                im: 13.342409722264879,
            },
            Complex {
                re: -11.338079344459477,
                im: 1.8641393709797576,
            },
            Complex {
                re: -2.5721078209531867,
                im: 6.933160363693035,
            },
            Complex {
                re: 4.318197301098163,
                im: -2.7745217568884826,
            },
            Complex {
                re: 8.156920540856985,
                im: -12.03307762044313,
            },
            Complex {
                re: -1.8067593524925254,
                im: 6.432903775337436,
            },
            Complex {
                re: 6.0450725032282655,
                im: -7.178243358917859,
            },
            Complex {
                re: -16.85768380816865,
                im: -1.4367980606548412,
            },
            Complex {
                re: 11.858044192318662,
                im: -12.199155314045411,
            },
            Complex {
                re: -25.818554878784038,
                im: -1.501440396850077,
            },
            Complex {
                re: 8.665860120322122,
                im: 6.983037391605539,
            },
            Complex {
                re: -10.685624068669775,
                im: -4.5607844065002805,
            },
            Complex {
                re: -12.756608136721983,
                im: -16.691071666944374,
            },
            Complex {
                re: -20.168998599529406,
                im: 4.316169324168188,
            },
            Complex {
                re: 8.491280206624612,
                im: -0.08914251035122644,
            },
            Complex {
                re: 10.285954756265745,
                im: 8.567168626619559,
            },
            Complex {
                re: 2.088652359730742,
                im: -20.00284913911074,
            },
            Complex {
                re: 11.03643917832094,
                im: -0.6761292951512521,
            },
            Complex {
                re: 8.234666892640858,
                im: 0.20693920921305864,
            },
            Complex {
                re: 7.236901440342585,
                im: -26.08672433230018,
            },
            Complex {
                re: -9.415746828909166,
                im: 2.3860102129705005,
            },
            Complex {
                re: -22.519429043405587,
                im: 10.87534645755105,
            },
            Complex {
                re: -14.047146936076647,
                im: 3.5845508614455563,
            },
            Complex {
                re: -10.765337504369578,
                im: -3.2952401776654194,
            },
            Complex {
                re: 2.580617467952071,
                im: -26.173982434010064,
            },
            Complex {
                re: 1.352252447942778,
                im: 17.614786974670977,
            },
            Complex {
                re: -5.364800334058605,
                im: -8.594547096480294,
            },
            Complex {
                re: 9.556680472998009,
                im: -13.132788201676803,
            },
            Complex {
                re: 3.079134959000806,
                im: -11.84718471648354,
            },
            Complex {
                re: 17.204639479326165,
                im: 20.82430505901594,
            },
            Complex {
                re: 10.665158303441402,
                im: -16.354040736243935,
            },
            Complex {
                re: 20.104382779448414,
                im: -19.12727157878553,
            },
            Complex {
                re: 6.59730868619312,
                im: -8.206884235801109,
            },
            Complex {
                re: 16.817074806490993,
                im: 3.8859641378972913,
            },
            Complex {
                re: 6.333534267343904,
                im: 18.267281032436767,
            },
            Complex {
                re: 15.912816404219571,
                im: 6.757132319703812,
            },
            Complex {
                re: -34.46989546715765,
                im: 3.2605832902075806,
            },
            Complex {
                re: -10.699879998875637,
                im: 13.87515586871546,
            },
            Complex {
                re: 8.174910214213048,
                im: -6.6333398979234754,
            },
            Complex {
                re: -10.017787198175343,
                im: -1.038585281876312,
            },
            Complex {
                re: -11.005950721046212,
                im: 20.48459605510572,
            },
            Complex {
                re: -2.7610267752857647,
                im: 12.692628939918755,
            },
            Complex {
                re: 9.624482391739697,
                im: 5.2309056589697605,
            },
            Complex {
                re: -13.473427100363805,
                im: 0.14070791194926446,
            },
            Complex {
                re: -1.9003740963434006,
                im: -12.80488962049461,
            },
            Complex {
                re: 3.76510896565188,
                im: -23.098775615412315,
            },
            Complex {
                re: -1.8534055988123548,
                im: -17.84710060219776,
            },
            Complex {
                re: 24.246715935556963,
                im: -22.526193417941958,
            },
            Complex {
                re: 19.302212018393544,
                im: -5.171202532787905,
            },
            Complex {
                re: 0.8832550851739578,
                im: 18.520316755377877,
            },
            Complex {
                re: -9.216475972485448,
                im: -9.685712617741082,
            },
            Complex {
                re: -8.970432844135159,
                im: 15.63016103380543,
            },
            Complex {
                re: -29.765869313274457,
                im: -4.45875409993473,
            },
            Complex {
                re: -13.069613983231179,
                im: 12.547674593551012,
            },
            Complex {
                re: -16.387095383344366,
                im: -29.424885631252927,
            },
            Complex {
                re: 24.12216060035886,
                im: -21.129137345685667,
            },
            Complex {
                re: -12.59307920634992,
                im: -12.66653021003397,
            },
            Complex {
                re: -13.422376836695513,
                im: 2.7704821356865894,
            },
            Complex {
                re: -16.94214076762204,
                im: 10.41407721530965,
            },
            Complex {
                re: -11.98303326971262,
                im: -7.1083126094792455,
            },
            Complex {
                re: -4.264974264704817,
                im: -12.097025578083628,
            },
            Complex {
                re: -6.019891524067809,
                im: 9.089476569248419,
            },
            Complex {
                re: 6.530200822981083,
                im: -14.465947211986197,
            },
            Complex {
                re: 0.4696293743706019,
                im: -5.904357549116605,
            },
            Complex {
                re: -1.6296619938468426,
                im: 18.09459947276371,
            },
            Complex {
                re: 32.62418638856332,
                im: 26.799719152727413,
            },
            Complex {
                re: -16.23892649943583,
                im: 20.374421547984717,
            },
            Complex {
                re: 5.255608364336785,
                im: -11.17898589033269,
            },
            Complex {
                re: 4.045549074437985,
                im: -29.184667619198983,
            },
            Complex {
                re: -4.303860152779596,
                im: -2.1353933166292816,
            },
            Complex {
                re: 12.75401114653914,
                im: 39.77558556877867,
            },
            Complex {
                re: 11.88927292758147,
                im: 6.030890233197537,
            },
            Complex {
                re: 7.753474330678147,
                im: -11.441124380416127,
            },
            Complex {
                re: -9.712695075353578,
                im: -7.795524248055251,
            },
            Complex {
                re: 6.682859147406952,
                im: -3.748519420498191,
            },
            Complex {
                re: -3.948100379774706,
                im: -18.262314878057357,
            },
            Complex {
                re: 3.5646057770794077,
                im: 0.8445791340914388,
            },
            Complex {
                re: -32.67342781128047,
                im: -4.189590793510979,
            },
            Complex {
                re: -20.037103380457133,
                im: 7.006495465644139,
            },
            Complex {
                re: -6.273850156137668,
                im: -7.033139773291185,
            },
            Complex {
                re: -0.5364612361310197,
                im: 17.193012361542024,
            },
            Complex {
                re: 33.539479336735624,
                im: -2.688906799522515,
            },
            Complex {
                re: 7.020818353886631,
                im: 8.410833631176974,
            },
            Complex {
                re: -16.438325264562017,
                im: 13.195574498387721,
            },
            Complex {
                re: 9.562532187458888,
                im: -0.3833078484288617,
            },
            Complex {
                re: -3.0556802730114567,
                im: 4.898127170061912,
            },
            Complex {
                re: 10.757424651167595,
                im: 3.0151115873027337,
            },
            Complex {
                re: 3.760276258974277,
                im: 12.358744278102035,
            },
            Complex {
                re: -8.558404281501966,
                im: 0.40995171101075645,
            },
            Complex {
                re: -7.97867277684624,
                im: 2.256071050237697,
            },
            Complex {
                re: -4.853522974654981,
                im: 17.321151696718534,
            },
            Complex {
                re: 19.964180239620866,
                im: -34.0436830458125,
            },
            Complex {
                re: 5.208177377932033,
                im: 18.426048410198923,
            },
            Complex {
                re: -7.470380871163232,
                im: -6.304803624870738,
            },
            Complex {
                re: -6.213820082726382,
                im: -7.142076699722933,
            },
            Complex {
                re: -4.570376737779419,
                im: 11.264846255814303,
            },
            Complex {
                re: -19.427815633893744,
                im: -1.0660475154348434,
            },
            Complex {
                re: -6.318121544620231,
                im: -8.089753028876956,
            },
            Complex {
                re: -12.218167528690046,
                im: -12.807339298181603,
            },
            Complex {
                re: -0.020250190641862176,
                im: 20.861933693043838,
            },
            Complex {
                re: 10.552895822770806,
                im: -33.12410316053875,
            },
            Complex {
                re: -17.268697610656304,
                im: -1.9075715137041938,
            },
            Complex {
                re: 5.813028743845772,
                im: 13.028665573980355,
            },
            Complex {
                re: 0.8609114622862175,
                im: -34.742683496592676,
            },
            Complex {
                re: 11.521349817037727,
                im: 21.278265862671404,
            },
            Complex {
                re: -3.194595529224424,
                im: 24.005162754572755,
            },
            Complex {
                re: 3.29198816271046,
                im: -2.9180564940722364,
            },
            Complex {
                re: 20.694289627976822,
                im: 2.892306893066383,
            },
            Complex {
                re: -3.3116243684128595,
                im: 2.121340306105017,
            },
            Complex {
                re: -10.339634688554309,
                im: -6.094247030336335,
            },
            Complex {
                re: 9.453015283775729,
                im: 1.5927113997062552,
            },
            Complex {
                re: 5.226719781656833,
                im: -18.54989214598973,
            },
            Complex {
                re: 13.40637610425334,
                im: -3.3592842175527684,
            },
            Complex {
                re: 0.8397875960796144,
                im: 20.600712147795782,
            },
            Complex {
                re: -6.607587443806032,
                im: 0.40231500518111396,
            },
            Complex {
                re: -3.0469368263370757,
                im: -6.992825726009068,
            },
            Complex {
                re: 8.931555204898254,
                im: -0.24339965839042677,
            },
            Complex {
                re: 1.8265930942548527,
                im: -0.36446357493462234,
            },
            Complex {
                re: 8.956326036418973,
                im: -21.821358767704055,
            },
            Complex {
                re: -2.30085957607973,
                im: 0.09942470668130454,
            },
            Complex {
                re: 8.93428021617235,
                im: 0.4677745989235298,
            },
            Complex {
                re: 23.835704431369145,
                im: -39.524778262859456,
            },
            Complex {
                re: 4.789679051973552,
                im: 7.249481818565202,
            },
            Complex {
                re: -4.901947697443352,
                im: -4.437926582974358,
            },
            Complex {
                re: -16.143691334064535,
                im: 7.359320100540037,
            },
            Complex {
                re: -18.44416457430058,
                im: -9.085030492957555,
            },
            Complex {
                re: -7.489731294797418,
                im: -13.588485321580343,
            },
            Complex {
                re: -2.3401594665792795,
                im: 14.073415381086896,
            },
            Complex {
                re: 7.313691919780059,
                im: 29.001578308013105,
            },
            Complex {
                re: -8.154073046730757,
                im: -18.029148701167394,
            },
            Complex {
                re: 0.10728621040188457,
                im: -8.09097540003227,
            },
            Complex {
                re: 4.127336951848779,
                im: 2.649805935883597,
            },
            Complex {
                re: -10.112654036730337,
                im: 32.45001251443141,
            },
            Complex {
                re: 20.730807196773316,
                im: 4.929622876660426,
            },
            Complex {
                re: 19.112699597047847,
                im: -12.13724121332104,
            },
            Complex {
                re: 24.16351926422062,
                im: -1.5174674075280397,
            },
            Complex {
                re: 21.40341233972251,
                im: -21.76113165910897,
            },
            Complex {
                re: -11.437116262611365,
                im: 18.821181487584962,
            },
            Complex {
                re: 11.416925853184656,
                im: -11.731081395750977,
            },
            Complex {
                re: 4.092312425744262,
                im: -15.27095965200755,
            },
            Complex {
                re: 18.320929018136823,
                im: -0.7020252665844038,
            },
            Complex {
                re: 22.43169484793321,
                im: 17.75816467002693,
            },
            Complex {
                re: 14.932635929640622,
                im: 7.668368734237499,
            },
            Complex {
                re: 3.4387485339675616,
                im: -2.7197214881961598,
            },
            Complex {
                re: 18.683032436228807,
                im: 1.9520651113651546,
            },
            Complex {
                re: -13.554013429740072,
                im: 5.530472728594148,
            },
            Complex {
                re: 1.2927338613309463,
                im: -0.871577179547304,
            },
            Complex {
                re: 1.0265595855879277,
                im: -13.436496716515018,
            },
            Complex {
                re: -7.218212232061874,
                im: -35.93457874109659,
            },
            Complex {
                re: 10.915654678249894,
                im: 1.7877574580305855,
            },
            Complex {
                re: -16.096448385635302,
                im: 4.151987980139023,
            },
            Complex {
                re: 9.88830027146236,
                im: 20.8755779587038,
            },
            Complex {
                re: 20.515360983508362,
                im: 8.582851993541103,
            },
            Complex {
                re: 10.447358870666434,
                im: -10.525598314368505,
            },
            Complex {
                re: -1.6360678615533786,
                im: 7.250358321619364,
            },
            Complex {
                re: 7.883173735122365,
                im: 5.759915503780947,
            },
            Complex {
                re: 9.906493555531476,
                im: 8.167073590185241,
            },
            Complex {
                re: -24.393948162236526,
                im: 11.265927522144594,
            },
            Complex {
                re: 22.279039731785808,
                im: 11.19572884393088,
            },
            Complex {
                re: -2.468417129368195,
                im: -8.032512798632592,
            },
            Complex {
                re: -8.387478527839724,
                im: -1.7211595267785098,
            },
            Complex {
                re: -7.50787922240011,
                im: 1.5883952662110516,
            },
            Complex {
                re: 12.779181146648016,
                im: -24.42401486522038,
            },
            Complex {
                re: -5.32947391462315,
                im: -22.679529413902966,
            },
            Complex {
                re: 6.865883373324738,
                im: 6.697998421752681,
            },
            Complex {
                re: -16.452070341519395,
                im: 1.7793550755453449,
            },
            Complex {
                re: 7.378889282051623,
                im: -4.822330681431286,
            },
            Complex {
                re: -3.181524581611681,
                im: 20.113107321130194,
            },
            Complex {
                re: 21.588035236751008,
                im: 18.903730029734472,
            },
            Complex {
                re: -4.712048652397783,
                im: 1.091343977364577,
            },
            Complex {
                re: 21.40840081352153,
                im: 17.62196608534864,
            },
            Complex {
                re: -7.271761008105426,
                im: -6.800475469369344,
            },
            Complex {
                re: 6.884941557031489,
                im: -1.9630136161524638,
            },
            Complex {
                re: -19.365514383917592,
                im: -26.09771709100059,
            },
            Complex {
                re: 0.03124250409133289,
                im: -21.111216364865378,
            },
            Complex {
                re: 3.5197109516024803,
                im: 4.211735197822403,
            },
            Complex {
                re: 6.694557850031641,
                im: 16.580327917977986,
            },
            Complex {
                re: -10.625674303912131,
                im: -15.098535123866625,
            },
            Complex {
                re: 7.632503535197641,
                im: -13.496552671137913,
            },
            Complex {
                re: 6.666570604893374,
                im: -22.632893585097666,
            },
            Complex {
                re: 29.145972983851596,
                im: -0.8536495350355571,
            },
            Complex {
                re: 0.9067224217164398,
                im: -27.699802136818,
            },
            Complex {
                re: -7.576905654415817,
                im: -1.1455385765250885,
            },
            Complex {
                re: 15.052385197274083,
                im: 18.229692487971043,
            },
            Complex {
                re: 6.069332330883644,
                im: -4.2928863996131374,
            },
            Complex {
                re: -6.355401052480392,
                im: -24.76740313934717,
            },
            Complex {
                re: 7.831633490089889,
                im: 16.966375049774904,
            },
            Complex {
                re: -5.913610066884166,
                im: -10.281223606587622,
            },
            Complex {
                re: -20.173608761620233,
                im: -9.757240636163429,
            },
            Complex {
                re: 4.895181714281126,
                im: 9.526537645058433,
            },
            Complex {
                re: 10.803124004645198,
                im: -8.350028627906413,
            },
            Complex {
                re: -27.18547055676217,
                im: 14.082242470336512,
            },
            Complex {
                re: 5.6237579114346685,
                im: -5.791789191848009,
            },
            Complex {
                re: 7.273473206398575,
                im: -2.8127717625208994,
            },
            Complex {
                re: -8.39303416352648,
                im: -24.268316163560513,
            },
            Complex {
                re: -1.5429127747670837,
                im: -1.2280791030286409,
            },
            Complex {
                re: 5.9728644096379915,
                im: -0.933548218192918,
            },
            Complex {
                re: 1.3970800698663988,
                im: -27.976725082838605,
            },
            Complex {
                re: -2.4403283796622004,
                im: 3.1778344134879974,
            },
            Complex {
                re: -3.352367586639299,
                im: -9.913664407371627,
            },
            Complex {
                re: 2.082423140203958,
                im: -4.925201296192659,
            },
            Complex {
                re: -12.975036605200348,
                im: -2.0758739423518704,
            },
            Complex {
                re: 12.307239650139405,
                im: 9.521031534454856,
            },
            Complex {
                re: -9.681326186042455,
                im: -4.63540786736651,
            },
            Complex {
                re: -3.953727767630223,
                im: -26.316503773503513,
            },
            Complex {
                re: -4.000729686969219,
                im: -3.3865021532012625,
            },
            Complex {
                re: -3.5846549415151028,
                im: -25.931030982872826,
            },
            Complex {
                re: -4.583378822880908,
                im: 34.47368839374613,
            },
            Complex {
                re: -14.466274756748824,
                im: -13.597172093084078,
            },
            Complex {
                re: -1.2538988317214708,
                im: 14.137013500127729,
            },
            Complex {
                re: -16.35024984201194,
                im: -6.991647870738452,
            },
            Complex {
                re: -6.0548730446071595,
                im: 12.637500610781641,
            },
            Complex {
                re: -11.030106297458207,
                im: 20.9486641001171,
            },
            Complex {
                re: -12.186092689262018,
                im: -17.90258162743261,
            },
            Complex {
                re: 8.042718901622504,
                im: 13.462715086518344,
            },
            Complex {
                re: 19.29119190608053,
                im: -0.6280691467420034,
            },
            Complex {
                re: 13.410805124842312,
                im: 7.81483905609603,
            },
            Complex {
                re: -12.398582012797174,
                im: 5.637676180206061,
            },
            Complex {
                re: 13.63080022648324,
                im: -11.529333732777864,
            },
            Complex {
                re: -3.1135121204425555,
                im: 5.275693881502347,
            },
            Complex {
                re: 5.541815771295165,
                im: -2.589107627203119,
            },
            Complex {
                re: -19.16256900996271,
                im: -10.632106629807346,
            },
            Complex {
                re: -19.272775453133477,
                im: 18.46635844624998,
            },
            Complex {
                re: 0.8350597228718639,
                im: -12.053024201527187,
            },
            Complex {
                re: 12.16971556870166,
                im: 10.202116247487377,
            },
            Complex {
                re: -4.135928628469216,
                im: 14.90505270952766,
            },
            Complex {
                re: 29.84713314660266,
                im: -10.07501142259072,
            },
            Complex {
                re: -4.653724947235952,
                im: -2.7290478450233326,
            },
            Complex {
                re: -12.88757561739201,
                im: 13.546366081888436,
            },
            Complex {
                re: -8.393421829489057,
                im: 11.758860937500588,
            },
            Complex {
                re: -13.604932384502023,
                im: -0.1783753372945318,
            },
            Complex {
                re: -9.916144322769801,
                im: -15.001550402816077,
            },
            Complex {
                re: -16.1677560071056,
                im: 15.813093042905333,
            },
            Complex {
                re: -0.1537638426176029,
                im: -4.452188963049495,
            },
            Complex {
                re: 10.332039817251923,
                im: 9.594508294375494,
            },
            Complex {
                re: 11.850671702588672,
                im: -9.400176084724182,
            },
            Complex {
                re: -14.263876443510647,
                im: 4.742826119092702,
            },
            Complex {
                re: -1.4875205763015629,
                im: 11.245249608603785,
            },
            Complex {
                re: 2.306702541112209,
                im: -6.531798665694801,
            },
            Complex {
                re: -6.970594125789383,
                im: 17.30283942462678,
            },
            Complex {
                re: 4.443477016308156,
                im: 7.85318998559781,
            },
            Complex {
                re: 1.983824884988087,
                im: -1.5733628594331366,
            },
            Complex {
                re: 11.799985204352502,
                im: 29.794704040364294,
            },
            Complex {
                re: 11.054898195854348,
                im: 23.355153230708225,
            },
            Complex {
                re: 6.249049053528303,
                im: -10.334724654169467,
            },
            Complex {
                re: 0.04650986364704757,
                im: 8.799498275791867,
            },
            Complex {
                re: -2.250133147845606,
                im: -15.867604454180857,
            },
            Complex {
                re: -6.887261134810052,
                im: 1.7111833034703938,
            },
            Complex {
                re: -8.84978733991143,
                im: 3.4845142276558585,
            },
            Complex {
                re: -10.465403850737271,
                im: 13.748393744379658,
            },
            Complex {
                re: 13.680123911139628,
                im: 1.2014882257826525,
            },
            Complex {
                re: -10.693286296036788,
                im: 16.304900109046535,
            },
            Complex {
                re: 8.47018291913661,
                im: 18.986586495678868,
            },
            Complex {
                re: -1.036234396228234,
                im: -3.8005707084694897,
            },
            Complex {
                re: 4.8062820419980765,
                im: 12.94382728933951,
            },
            Complex {
                re: 5.9234803821178925,
                im: -28.138192747112985,
            },
            Complex {
                re: 1.1529885348577746,
                im: -11.495558020222578,
            },
            Complex {
                re: 4.960206436761174,
                im: 3.5403352146724183,
            },
            Complex {
                re: 10.893774495566218,
                im: 12.570003128580044,
            },
            Complex {
                re: 9.550722142711798,
                im: 9.160757007116201,
            },
            Complex {
                re: -14.100147022138044,
                im: 17.844397052587787,
            },
            Complex {
                re: -20.312128642253317,
                im: -0.7927575892086889,
            },
            Complex {
                re: 11.188067480060223,
                im: 18.29684548559172,
            },
            Complex {
                re: -0.3799977028000989,
                im: 20.467277042912386,
            },
            Complex {
                re: -13.112844266093933,
                im: -2.1929492140645745,
            },
            Complex {
                re: -10.431590518414508,
                im: -4.747891566569974,
            },
            Complex {
                re: -27.587296916919097,
                im: 30.747679677229605,
            },
            Complex {
                re: 5.823207085873912,
                im: -43.093629296375795,
            },
            Complex {
                re: -2.5759756007902403,
                im: -10.00965930461534,
            },
            Complex {
                re: 2.797012061142158,
                im: -14.030641254332501,
            },
            Complex {
                re: -4.561267077397079,
                im: -4.899762870927911,
            },
            Complex {
                re: 1.1934202675456702,
                im: -6.935570639037028,
            },
            Complex {
                re: -22.94899271662821,
                im: -1.793524869805407,
            },
            Complex {
                re: 2.4905939030292314,
                im: 12.279279967448119,
            },
            Complex {
                re: 14.859187684578062,
                im: 13.343557301855196,
            },
            Complex {
                re: 9.007631332873103,
                im: -19.120789537544944,
            },
            Complex {
                re: -9.879331820151323,
                im: -5.202248895455606,
            },
            Complex {
                re: 1.2499461007641592,
                im: -9.955118443389003,
            },
            Complex {
                re: -27.610256180311534,
                im: -29.080694928332665,
            },
            Complex {
                re: 7.893725913626362,
                im: -8.573267047548804,
            },
            Complex {
                re: 10.62496448730797,
                im: 15.934186812276616,
            },
            Complex {
                re: -10.782103674407631,
                im: 21.24125925246104,
            },
            Complex {
                re: -19.39137002328502,
                im: 14.962916991036288,
            },
            Complex {
                re: 11.30349217647764,
                im: 20.512873463618703,
            },
            Complex {
                re: -20.94035143358808,
                im: 8.841301938919859,
            },
            Complex {
                re: -13.538762086547173,
                im: 1.481545651071472,
            },
            Complex {
                re: 9.951267440923097,
                im: -3.9254349738582075,
            },
            Complex {
                re: -6.146020680530084,
                im: -1.3226961010392895,
            },
            Complex {
                re: -17.032483030849704,
                im: 2.4834777364519773,
            },
            Complex {
                re: 0.3687381806246286,
                im: 3.0557936987205725,
            },
            Complex {
                re: 7.322736576260196,
                im: -1.6038683935482796,
            },
            Complex {
                re: -2.4504356436416552,
                im: 8.944766816385574,
            },
            Complex {
                re: -15.771232393747207,
                im: 15.685931257212044,
            },
            Complex {
                re: 15.734003517171056,
                im: -15.067092667200217,
            },
            Complex {
                re: 5.773145349633559,
                im: -6.073146585986499,
            },
            Complex {
                re: 19.49532275496003,
                im: -17.223393290938308,
            },
            Complex {
                re: 6.243222781225395,
                im: 17.159859616136284,
            },
            Complex {
                re: 10.358620424075227,
                im: 21.78322654143226,
            },
            Complex {
                re: 8.464225148207312,
                im: -36.12090409615447,
            },
            Complex {
                re: -11.689926282260966,
                im: -5.624640426578853,
            },
            Complex {
                re: -25.146649197359064,
                im: -15.076644872281367,
            },
            Complex {
                re: 12.87475784420009,
                im: 9.666392868790268,
            },
            Complex {
                re: 10.056349087226078,
                im: -10.847677615803933,
            },
            Complex {
                re: 1.0255032858590707,
                im: 18.67815354014246,
            },
            Complex {
                re: 11.04606455852754,
                im: -5.941996551055421,
            },
            Complex {
                re: 19.993810309061647,
                im: -5.0150184321296685,
            },
            Complex {
                re: 14.12975790494121,
                im: -10.715819404192704,
            },
            Complex {
                re: -8.482916178176747,
                im: 19.0388719582385,
            },
            Complex {
                re: 0.9531572119748031,
                im: -5.854165842078675,
            },
            Complex {
                re: 9.35119060662994,
                im: 2.6360003146573847,
            },
            Complex {
                re: 6.659666726559724,
                im: -5.398854782403736,
            },
            Complex {
                re: 7.24215778531781,
                im: 4.659170761076703,
            },
            Complex {
                re: 15.420377615964707,
                im: -16.246945101440165,
            },
            Complex {
                re: 14.019516500296163,
                im: 7.918188891389749,
            },
            Complex {
                re: 2.7524917674984994,
                im: 1.5106638675198254,
            },
            Complex {
                re: -7.864847196859198,
                im: 0.7463409842651485,
            },
            Complex {
                re: -12.864138930864552,
                im: 6.527812738241186,
            },
            Complex {
                re: 7.614500611237879,
                im: -3.544164616310395,
            },
            Complex {
                re: -1.7574806243226133,
                im: 32.1347618329694,
            },
            Complex {
                re: -3.1516760649817464,
                im: -3.903686371304752,
            },
            Complex {
                re: -8.990818127927088,
                im: -21.64707886009647,
            },
            Complex {
                re: 3.165457366788538,
                im: -6.629990124713149,
            },
            Complex {
                re: 17.151038935822356,
                im: 0.16554862377543733,
            },
            Complex {
                re: 3.421783266516517,
                im: 1.450746887194355,
            },
            Complex {
                re: -0.806535241790657,
                im: -16.04828893352648,
            },
            Complex {
                re: 10.221335152066509,
                im: 0.8713025508588852,
            },
            Complex {
                re: -12.072748808982393,
                im: -4.452054167144542,
            },
            Complex {
                re: -4.129206663370214,
                im: -1.9996251869081503,
            },
            Complex {
                re: 8.067143491083288,
                im: 9.991568088994544,
            },
            Complex {
                re: 0.6156923692637917,
                im: 8.36233649059898,
            },
            Complex {
                re: -18.14292954721735,
                im: -6.427197019455781,
            },
            Complex {
                re: 13.416472108107875,
                im: 10.576892352363,
            },
            Complex {
                re: -15.186390745232934,
                im: -6.526605274431221,
            },
            Complex {
                re: 3.0831738255964867,
                im: -0.009753318544627243,
            },
            Complex {
                re: -17.547767969519366,
                im: -16.507769913080683,
            },
            Complex {
                re: -5.802628533899133,
                im: -1.6259896965300884,
            },
            Complex {
                re: -7.3662785468693555,
                im: 8.654940447294752,
            },
            Complex {
                re: 13.207039900296806,
                im: 17.19326875444186,
            },
            Complex {
                re: 10.024177306091625,
                im: -2.120161622380467,
            },
            Complex {
                re: 9.083729121535526,
                im: -9.854194344065103,
            },
            Complex {
                re: 9.592093464448636,
                im: -10.20819701513267,
            },
            Complex {
                re: -21.00368866785323,
                im: 0.48169547033184834,
            },
            Complex {
                re: 3.9356726633225394,
                im: 7.203710027003137,
            },
            Complex {
                re: 2.838567025399292,
                im: -0.08913442364922697,
            },
            Complex {
                re: -9.317401326003493,
                im: 2.1053269601086027,
            },
            Complex {
                re: -5.284411746439661,
                im: -10.23762324138835,
            },
            Complex {
                re: 11.266247393326449,
                im: 8.452813937073484,
            },
            Complex {
                re: 18.076915743085372,
                im: -25.65354365209486,
            },
            Complex {
                re: -18.98354435563568,
                im: -18.13560321006387,
            },
            Complex {
                re: 3.9635782283911025,
                im: 11.408439632795268,
            },
            Complex {
                re: 2.620308322740067,
                im: 1.959298504822606,
            },
            Complex {
                re: 8.571596458957936,
                im: 9.6521900463296,
            },
            Complex {
                re: -16.840121469626723,
                im: -1.0727088800809526,
            },
            Complex {
                re: 19.920405822601616,
                im: -8.053498791344435,
            },
            Complex {
                re: 7.322350031155238,
                im: 3.554339270382064,
            },
            Complex {
                re: -12.317489650735094,
                im: 12.871269234122167,
            },
            Complex {
                re: 1.3632118849816823,
                im: 19.098853727653996,
            },
            Complex {
                re: -15.748168456795069,
                im: 24.44943013903609,
            },
            Complex {
                re: -5.297250697069679,
                im: -14.10210244916562,
            },
            Complex {
                re: -0.3545329247520357,
                im: 10.704798391477315,
            },
            Complex {
                re: 20.20281612632003,
                im: 22.386990527005274,
            },
            Complex {
                re: 15.045982891267654,
                im: 19.65871324331252,
            },
            Complex {
                re: -43.77817084948016,
                im: -19.54716940117796,
            },
            Complex {
                re: 3.679828173848965,
                im: -6.394855101472423,
            },
            Complex {
                re: -4.135041668481105,
                im: 8.458969117645156,
            },
            Complex {
                re: -6.5082392663977595,
                im: 32.71277534826032,
            },
            Complex {
                re: -13.214903111043403,
                im: -6.017350221546563,
            },
            Complex {
                re: -25.86894813523783,
                im: 17.962152718672264,
            },
            Complex {
                re: -9.024424764734368,
                im: 18.881692299107037,
            },
            Complex {
                re: -3.183228249050037,
                im: -18.381101362431654,
            },
            Complex {
                re: 5.110985914802613,
                im: 16.479456074918915,
            },
            Complex {
                re: -24.15437255371251,
                im: 3.9619539846309086,
            },
            Complex {
                re: 5.692778215200827,
                im: 7.18490127857089,
            },
            Complex {
                re: -6.49300268236337,
                im: 12.64578327223557,
            },
            Complex {
                re: -3.8973239004438893,
                im: 8.075602369856615,
            },
            Complex {
                re: -27.629630327163685,
                im: 0.034142480144491394,
            },
            Complex {
                re: -6.45554783861701,
                im: 29.965325810175642,
            },
            Complex {
                re: 9.272182503097378,
                im: 24.331648458363816,
            },
            Complex {
                re: -27.303324311113716,
                im: -9.80032200100784,
            },
            Complex {
                re: -21.609716107753904,
                im: 5.916296017408097,
            },
            Complex {
                re: 13.975998424641078,
                im: 18.091142816335726,
            },
            Complex {
                re: -9.060440991480899,
                im: 13.234022111974184,
            },
            Complex {
                re: -8.684150681103233,
                im: -7.769960834658668,
            },
            Complex {
                re: -6.401609639154691,
                im: 13.711059954662861,
            },
            Complex {
                re: 14.299799472064159,
                im: 29.25861199933605,
            },
            Complex {
                re: 6.052921658479621,
                im: 6.3776226102634155,
            },
            Complex {
                re: 6.043063504433965,
                im: -23.375723169737253,
            },
            Complex {
                re: 12.272125151662634,
                im: 12.985328546950473,
            },
            Complex {
                re: 3.015001717194856,
                im: 12.173062064155227,
            },
            Complex {
                re: -15.086823216632707,
                im: 16.357803958445956,
            },
            Complex {
                re: -10.938695140568846,
                im: 2.1926436011504298,
            },
            Complex {
                re: -6.187399666113853,
                im: -5.930666827114669,
            },
            Complex {
                re: -13.729935571414352,
                im: 9.704846377748915,
            },
            Complex {
                re: -5.921419126697401,
                im: 1.5464923039838478,
            },
            Complex {
                re: -19.80459669557133,
                im: 1.5953542358558526,
            },
            Complex {
                re: -3.756573466469277,
                im: 9.855043325012058,
            },
            Complex {
                re: 11.849049483350184,
                im: 1.5962123632002747,
            },
            Complex {
                re: 14.57020762610259,
                im: -23.874838420316337,
            },
            Complex {
                re: -3.3173283929421453,
                im: -7.903529461648982,
            },
            Complex {
                re: -1.9515492844021,
                im: -8.361494069226321,
            },
            Complex {
                re: 19.58638248268339,
                im: -13.07259782832524,
            },
            Complex {
                re: -8.969744921214973,
                im: 12.95569527560939,
            },
            Complex {
                re: 2.6404335480265693,
                im: 4.378231645813241,
            },
            Complex {
                re: 1.5423010150244245,
                im: 5.100478630232149,
            },
            Complex {
                re: -7.242079283872142,
                im: -22.535224561038127,
            },
            Complex {
                re: -11.637888092165854,
                im: -18.722914993865793,
            },
            Complex {
                re: 15.830585090949636,
                im: 0.9681462965510241,
            },
            Complex {
                re: 10.946053128915858,
                im: -1.3843370784855416,
            },
            Complex {
                re: 12.942254942561021,
                im: -7.750253610471707,
            },
            Complex {
                re: 7.857445209947002,
                im: -0.36309476167924726,
            },
            Complex {
                re: 9.551211044958842,
                im: -4.762412895022921,
            },
            Complex {
                re: 8.887078449629572,
                im: 0.49614226350355306,
            },
            Complex {
                re: 5.085392442507693,
                im: 16.95560486074702,
            },
            Complex {
                re: 3.7226440493272364,
                im: 0.005809249173158282,
            },
            Complex {
                re: 21.54255167915923,
                im: 11.912338265692508,
            },
            Complex {
                re: 0.9422934664923845,
                im: 2.0401519267528148,
            },
            Complex {
                re: 16.16668703308904,
                im: 11.66754979063105,
            },
            Complex {
                re: -11.322480873695074,
                im: -1.3390401032076675,
            },
            Complex {
                re: 4.12329171198059,
                im: -10.549346259168296,
            },
            Complex {
                re: -26.47010562089414,
                im: -1.0749366294511482,
            },
            Complex {
                re: -5.1347006744067,
                im: -24.278090761426363,
            },
            Complex {
                re: -3.412977072562116,
                im: -5.068294546807142,
            },
            Complex {
                re: 6.400426352941281,
                im: 2.872254733372519,
            },
            Complex {
                re: -4.75539027264518,
                im: -2.792784606713925,
            },
            Complex {
                re: 18.17263035403434,
                im: 7.264845317890765,
            },
            Complex {
                re: 3.5396466120172327,
                im: 14.532351692099752,
            },
            Complex {
                re: 19.700750027454767,
                im: 4.756829235235843,
            },
            Complex {
                re: -8.244259480097133,
                im: 11.175327008721602,
            },
            Complex {
                re: 7.845539381428518,
                im: 9.027580495461425,
            },
            Complex {
                re: -29.027794967698455,
                im: 4.417636526951849,
            },
            Complex {
                re: 3.2447931348162324,
                im: -13.473354404380615,
            },
            Complex {
                re: -5.82552214007912,
                im: -10.380392331210176,
            },
            Complex {
                re: -5.452969122358773,
                im: 16.493199402744274,
            },
            Complex {
                re: 14.074530551816753,
                im: 0.08218901387785182,
            },
            Complex {
                re: -12.04178549661909,
                im: 1.2350191387282061,
            },
            Complex {
                re: -2.3992329602951443,
                im: 13.54377331639,
            },
            Complex {
                re: -1.944098057276975,
                im: 0.3571354175794852,
            },
            Complex {
                re: -14.209154703180536,
                im: -9.629410470405713,
            },
            Complex {
                re: -8.058238401951499,
                im: 15.07687625826167,
            },
            Complex {
                re: -1.563003487810021,
                im: -9.059099296321579,
            },
            Complex {
                re: -13.87950575140036,
                im: -0.7606750137420191,
            },
            Complex {
                re: -5.118367702077299,
                im: 3.7400069426366747,
            },
        ];
        assert_eq!(target.as_slice(), z.as_slice());
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests_serde {
    use super::*;
    use alloc::{vec, vec::Vec};
    use dyn_stack::PodBuffer;
    use num_complex::ComplexFloat;
    use rand::random;

    extern crate alloc;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn test_serde() {
        for n in [64, 128, 256, 512, 1024] {
            let mut z = vec![c64::default(); n];

            for z in &mut z {
                z.re = random();
                z.im = random();
            }

            let orig = z.clone();

            let plan1 = Plan::new(
                n,
                Method::UserProvided {
                    base_algo: FftAlgo::Dif4,
                    base_n: 32,
                },
            );
            let plan2 = Plan::new(
                n,
                Method::UserProvided {
                    base_algo: FftAlgo::Dif4,
                    base_n: 64,
                },
            );

            let mut mem = PodBuffer::try_new(plan1.fft_scratch().or(plan2.fft_scratch())).unwrap();
            let stack = PodStack::new(&mut mem);

            plan1.fwd(&mut z, stack);

            let mut buf = Vec::<u8>::new();
            let mut serializer = bincode::Serializer::new(&mut buf, bincode::options());
            plan1.serialize_fourier_buffer(&mut serializer, &z).unwrap();

            let mut deserializer = bincode::de::Deserializer::from_slice(&buf, bincode::options());
            plan2
                .deserialize_fourier_buffer(&mut deserializer, &mut z)
                .unwrap();

            plan2.inv(&mut z, stack);

            for z in &mut z {
                *z /= n as f64;
            }

            for (z_actual, z_expected) in z.iter().zip(&orig) {
                assert!((z_actual - z_expected).abs() < 1e-12);
            }
        }
    }
}
