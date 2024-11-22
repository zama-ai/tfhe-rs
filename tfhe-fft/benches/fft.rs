use core::ptr::NonNull;
use criterion::{criterion_group, criterion_main, Criterion};
use dyn_stack::{PodStack, StackReq};
use serde::Serialize;
use std::{fs, path::PathBuf};
use tfhe_fft::c64;

struct FftwAlloc {
    bytes: NonNull<core::ffi::c_void>,
}

impl Drop for FftwAlloc {
    fn drop(&mut self) {
        unsafe {
            fftw_sys::fftw_free(self.bytes.as_ptr());
        }
    }
}

impl FftwAlloc {
    pub fn new(size_bytes: usize) -> FftwAlloc {
        unsafe {
            let bytes = fftw_sys::fftw_malloc(size_bytes);
            if bytes.is_null() {
                use std::alloc::{handle_alloc_error, Layout};
                handle_alloc_error(Layout::from_size_align_unchecked(size_bytes, 1));
            }
            FftwAlloc {
                bytes: NonNull::new_unchecked(bytes),
            }
        }
    }
}

pub struct PlanInterleavedC64 {
    plan: fftw_sys::fftw_plan,
    n: usize,
}

impl Drop for PlanInterleavedC64 {
    fn drop(&mut self) {
        unsafe {
            fftw_sys::fftw_destroy_plan(self.plan);
        }
    }
}

pub enum Sign {
    Forward,
    Backward,
}

impl PlanInterleavedC64 {
    pub fn new(n: usize, sign: Sign) -> Self {
        let size_bytes = n.checked_mul(core::mem::size_of::<c64>()).unwrap();
        let src = FftwAlloc::new(size_bytes);
        let dst = FftwAlloc::new(size_bytes);
        unsafe {
            let p = fftw_sys::fftw_plan_dft_1d(
                n.try_into().unwrap(),
                src.bytes.as_ptr() as _,
                dst.bytes.as_ptr() as _,
                match sign {
                    Sign::Forward => fftw_sys::FFTW_FORWARD as _,
                    Sign::Backward => fftw_sys::FFTW_BACKWARD as _,
                },
                fftw_sys::FFTW_MEASURE,
            );
            PlanInterleavedC64 { plan: p, n }
        }
    }

    pub fn print(&self) {
        unsafe {
            fftw_sys::fftw_print_plan(self.plan);
        }
    }

    pub fn execute(&self, src: &mut [c64], dst: &mut [c64]) {
        assert_eq!(src.len(), self.n);
        assert_eq!(dst.len(), self.n);
        let src = src.as_mut_ptr();
        let dst = dst.as_mut_ptr();
        unsafe {
            use fftw_sys::{fftw_alignment_of, fftw_execute_dft};
            assert_eq!(fftw_alignment_of(src as _), 0);
            assert_eq!(fftw_alignment_of(dst as _), 0);
            fftw_execute_dft(self.plan, src as _, dst as _);
        }
    }
}

#[derive(Serialize)]
struct BenchmarkParametersRecord {
    display_name: String,
    polynomial_size: usize,
}

/// Writes benchmarks parameters to disk in JSON format.
fn write_to_json(bench_id: &str, display_name: impl Into<String>, polynomial_size: usize) {
    let record = BenchmarkParametersRecord {
        display_name: display_name.into(),
        polynomial_size,
    };

    let mut params_directory = ["benchmarks_parameters", bench_id]
        .iter()
        .collect::<PathBuf>();
    fs::create_dir_all(&params_directory).unwrap();
    params_directory.push("parameters.json");

    fs::write(params_directory, serde_json::to_string(&record).unwrap()).unwrap();
}

pub fn bench_ffts(c: &mut Criterion) {
    for n in [
        1 << 8,
        1 << 9,
        1 << 10,
        1 << 11,
        1 << 12,
        1 << 13,
        1 << 14,
        1 << 15,
        1 << 16,
    ] {
        let mut mem = dyn_stack::GlobalPodBuffer::new(StackReq::all_of([
            StackReq::new_aligned::<c64>(2 * n, 256), // scratch
            StackReq::new_aligned::<c64>(n, 256),     // src
            StackReq::new_aligned::<c64>(n, 256),     // dst
        ]));
        let stack = PodStack::new(&mut mem);
        let z = c64::new(0.0, 0.0);

        use rustfft::FftPlannerAvx;
        let mut scratch = [];

        let bench_duration = std::time::Duration::from_millis(10);
        let unordered =
            tfhe_fft::unordered::Plan::new(n, tfhe_fft::unordered::Method::Measure(bench_duration));

        let (dst, stack) = stack.make_aligned_with::<c64>(n, 64, |_| z);
        let (src, stack) = stack.make_aligned_with::<c64>(n, 64, |_| z);

        let bench_id = format!("rustfft-fwd-{n}");
        c.bench_function(&bench_id, |b| {
            let mut planner = FftPlannerAvx::<f64>::new().unwrap();
            let fwd_rustfft = planner.plan_fft_forward(n);
            b.iter(|| fwd_rustfft.process_outofplace_with_scratch(src, dst, &mut scratch))
        });
        write_to_json(&bench_id, "rustfft-fwd", n);

        let bench_id = format!("fftw-fwd-{n}");
        c.bench_function(&bench_id, |b| {
            let fwd_fftw = PlanInterleavedC64::new(n, Sign::Forward);
            b.iter(|| {
                fwd_fftw.execute(src, dst);
            })
        });
        write_to_json(&bench_id, "fftw-fwd", n);

        if n <= 1024 {
            let ordered =
                tfhe_fft::ordered::Plan::new(n, tfhe_fft::ordered::Method::Measure(bench_duration));

            let bench_id = format!("tfhe-ordered-fwd-{n}");
            c.bench_function(&bench_id, |b| b.iter(|| ordered.fwd(dst, stack)));
            write_to_json(&bench_id, "tfhe-ordered-fwd", n);
        }

        let bench_id = format!("tfhe-unordered-fwd-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| unordered.fwd(dst, stack));
        });
        write_to_json(&bench_id, "tfhe-unordered-fwd", n);

        let bench_id = format!("tfhe-unordered-inv-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| unordered.inv(dst, stack));
        });
        write_to_json(&bench_id, "tfhe-unordered-inv", n);

        // memcpy
        let bench_id = format!("memcpy-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
            })
        });
        write_to_json(&bench_id, "memcpy", n);

        let bench_id = format!("tfhe-unordered-fwd-monomial-{n}");
        c.bench_function(&bench_id, |b| {
            let mut degree = 0;
            b.iter(|| {
                degree += 1;
                if degree == n {
                    degree = 0;
                }
                unordered.fwd_monomial(degree, dst);
            })
        });
        write_to_json(&bench_id, "tfhe-unordered-fwd-monomial", n);
    }
}

#[cfg(feature = "fft128")]
pub fn bench_fft128(c: &mut Criterion) {
    for n in [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384] {
        use tfhe_fft::fft128::*;
        let twid_re0 = vec![0.0; n];
        let twid_re1 = vec![0.0; n];
        let twid_im0 = vec![0.0; n];
        let twid_im1 = vec![0.0; n];

        let mut data_re0 = vec![0.0; n];
        let mut data_re1 = vec![0.0; n];
        let mut data_im0 = vec![0.0; n];
        let mut data_im1 = vec![0.0; n];

        let bench_id = format!("tfhe-fft128-fwd-{n}");
        c.bench_function(&bench_id, |bench| {
            bench.iter(|| {
                negacyclic_fwd_fft_scalar(
                    &mut data_re0,
                    &mut data_re1,
                    &mut data_im0,
                    &mut data_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );
            });
        });
        write_to_json(&bench_id, "fft128-fwd", n);

        let bench_id = format!("tfhe-fft128-inv-{n}");
        c.bench_function(&bench_id, |bench| {
            bench.iter(|| {
                negacyclic_inv_fft_scalar(
                    &mut data_re0,
                    &mut data_re1,
                    &mut data_im0,
                    &mut data_im1,
                    &twid_re0,
                    &twid_re1,
                    &twid_im0,
                    &twid_im1,
                );
            });
        });
        write_to_json(&bench_id, "fft128-inv", n);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(simd) = pulp::x86::V3::try_new() {
            let bench_id = format!("tfhe-fft128-avx-fwd-{n}");
            c.bench_function(&bench_id, |bench| {
                bench.iter(|| {
                    negacyclic_fwd_fft_avxfma(
                        simd,
                        &mut data_re0,
                        &mut data_re1,
                        &mut data_im0,
                        &mut data_im1,
                        &twid_re0,
                        &twid_re1,
                        &twid_im0,
                        &twid_im1,
                    );
                });
            });
            write_to_json(&bench_id, "fft128-fwd-avx", n);

            let bench_id = format!("tfhe-fft128-avx-inv-{n}");
            c.bench_function(&bench_id, |bench| {
                bench.iter(|| {
                    negacyclic_inv_fft_avxfma(
                        simd,
                        &mut data_re0,
                        &mut data_re1,
                        &mut data_im0,
                        &mut data_im1,
                        &twid_re0,
                        &twid_re1,
                        &twid_im0,
                        &twid_im1,
                    );
                });
            });
            write_to_json(&bench_id, "fft128-inv-avx", n);
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[cfg(feature = "nightly")]
        if let Some(simd) = pulp::x86::V4::try_new() {
            let bench_id = format!("tfhe-fft128-avx512-fwd-{n}");
            c.bench_function(&bench_id, |bench| {
                bench.iter(|| {
                    negacyclic_fwd_fft_avx512(
                        simd,
                        &mut data_re0,
                        &mut data_re1,
                        &mut data_im0,
                        &mut data_im1,
                        &twid_re0,
                        &twid_re1,
                        &twid_im0,
                        &twid_im1,
                    );
                });
            });
            write_to_json(&bench_id, "fft128-fwd-avx512", n);

            let bench_id = format!("tfhe-fft128-avx512-inv-{n}");
            c.bench_function(&bench_id, |bench| {
                bench.iter(|| {
                    negacyclic_inv_fft_avx512(
                        simd,
                        &mut data_re0,
                        &mut data_re1,
                        &mut data_im0,
                        &mut data_im1,
                        &twid_re0,
                        &twid_re1,
                        &twid_im0,
                        &twid_im1,
                    );
                });
            });
            write_to_json(&bench_id, "fft128-inv-avx512", n);
        }
    }
}

criterion_group!(fft, bench_ffts);
#[cfg(feature = "fft128")]
criterion_group!(fft128, bench_fft128);

#[cfg(not(feature = "fft128"))]
criterion_main!(fft);
#[cfg(feature = "fft128")]
criterion_main!(fft, fft128);
