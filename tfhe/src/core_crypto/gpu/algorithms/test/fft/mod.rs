pub mod fft_data;
use crate::core_crypto::commons::test_tools::{modular_distance, new_random_generator};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{
    forward_fft16x4x16_async, fourier_transform_backward_as_torus_f128_async,
    fourier_transform_forward_as_torus_f128_async, CudaStreams,
};
use crate::core_crypto::prelude::*;
use aligned_vec::avec;
use fft_data::golden_v1::*;
use std::fmt::Write;
use tfhe_cuda_backend::bindings::cuda_fft16x4x16_is_supported_async;
use tfhe_cuda_backend::cuda_bind::cuda_synchronize_device;

// ============================================================================
// Throughput-oriented FFT16x4x16 forward-transform bit-wise regression test.
//
// Mirrors the FFT128 golden test above: a fixed, deterministic input is run
// through the forward FFT16x4x16 core once to produce golden output, and every
// subsequent run must reproduce that output *bit for bit*. This guards against
// silent numerical drift when the FFT16x4x16 kernels are refactored.
//
// The golden data lives in `fft_data::fft16x4x16_golden_v1` and is (re)generated
// by the `generate_fft16x4x16_golden` maintenance helper below — a plain (non
// `#[test]`) function; run it on an H100 (sm_90) to refresh the file, then
// commit the result.
//
// FFT16x4x16 is specialized for N = 2048 and needs the sm_90 named-barrier /
// mbarrier primitives, so this only runs on compute capability 9.x (H100+).
// ============================================================================

/// Polynomial size the FFT16x4x16 core is specialized for.
const FFT16_POLYNOMIAL_SIZE: usize = 2048;

/// The FFT16x4x16 core relies on the sm_90 named-barrier / mbarrier primitives,
/// so it only runs on Hopper (compute capability 9.x) and newer. Tests that
/// drive it must skip on anything older.
fn fft16x4x16_is_supported() -> bool {
    // Safe: a pure runtime device-capability query with no aliasing concerns.
    unsafe { cuda_fft16x4x16_is_supported_async(0) }
}

/// Deterministic input for the FFT16x4x16 forward transform.
///
/// Builds a fixed real polynomial of size `FFT16_POLYNOMIAL_SIZE` and packs it
/// into `FFT16_POLYNOMIAL_SIZE / 2` complex coefficients — the encoding the
/// forward FFT consumes: `complex[i] = (poly[i], poly[i + N/2])`. The result is
/// returned interleaved as `[re, im, re, im, ...]` f64 (length N), which is the
/// layout `forward_fft16x4x16_async` expects on the device.
fn fft16x4x16_reference_input() -> Vec<f64> {
    let n = FFT16_POLYNOMIAL_SIZE;
    let half = n / 2;

    // Deterministic real polynomial, values in [-1, 1). Same generator as the
    // FFT128 regression input in spirit: a cheap bijective hash of the index.
    let poly_coeff = |k: usize| -> f64 {
        let bits = (k as u64)
            .wrapping_mul(0x517c_c1b7_2722_0a95)
            .rotate_left(17)
            ^ 0xdead_beef_cafe_babe;
        (bits as i64) as f64 / (i64::MAX as f64)
    };

    let mut input = vec![0.0f64; n];
    for i in 0..half {
        input[2 * i] = poly_coeff(i); // real part
        input[2 * i + 1] = poly_coeff(i + half); // imaginary part
    }
    input
}

/// Runs the forward FFT16x4x16 on [`fft16x4x16_reference_input`] and returns the
/// output spectrum as raw f64 bit patterns (interleaved re, im), ready for a
/// bit-exact comparison against golden data.
fn run_fft16x4x16_forward() -> Vec<u64> {
    let input = fft16x4x16_reference_input();
    let n = input.len();

    let stream = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let mut output = vec![0.0f64; n];

    unsafe {
        let d_input = CudaVec::<f64>::from_cpu_async(&input, &stream, 0);
        let mut d_output = CudaVec::<f64>::new(n, &stream, 0);

        forward_fft16x4x16_async(
            &stream,
            &d_input,
            &mut d_output,
            FFT16_POLYNOMIAL_SIZE as u32,
            1,
        );

        d_output.copy_to_cpu_async(&mut output, &stream, 0);
        cuda_synchronize_device(0);
    }

    output.iter().map(|x| x.to_bits()).collect()
}

fn test_roundtrip<Scalar: UnsignedTorus>() {
    let mut generator = new_random_generator();
    for size_log in 6..=12 {
        let size = 1_usize << size_log;
        let fourier_size = PolynomialSize(size).to_fourier_polynomial_size().0;

        let mut poly = avec![Scalar::ZERO; size].into_boxed_slice();
        let mut roundtrip = avec![Scalar::ZERO; size].into_boxed_slice();
        let mut fourier_re0 = avec![0.0f64; fourier_size].into_boxed_slice();
        let mut fourier_re1 = avec![0.0f64; fourier_size].into_boxed_slice();
        let mut fourier_im0 = avec![0.0f64; fourier_size].into_boxed_slice();
        let mut fourier_im1 = avec![0.0f64; fourier_size].into_boxed_slice();
        for x in poly.as_mut().iter_mut() {
            *x = generator.random_uniform();
        }

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

        unsafe {
            fourier_transform_forward_as_torus_f128_async(
                &stream,
                &mut fourier_re0,
                &mut fourier_re1,
                &mut fourier_im0,
                &mut fourier_im1,
                &poly,
                poly.len() as u32,
                1,
            );

            fourier_transform_backward_as_torus_f128_async(
                &stream,
                &mut roundtrip,
                &fourier_re0,
                &fourier_re1,
                &fourier_im0,
                &fourier_im1,
                size as u32,
                1,
            );
            cuda_synchronize_device(0);
        }

        for (expected, actual) in izip_eq!(poly.as_ref().iter(), roundtrip.as_ref().iter()) {
            if Scalar::BITS <= 64 {
                assert_eq!(*expected, *actual);
            } else {
                let abs_diff = modular_distance(*expected, *actual);
                let threshold = Scalar::ONE << (128 - 100);
                assert!(
                    abs_diff < threshold,
                    "abs_diff: {abs_diff}, threshold: {threshold}",
                );
            }
        }
    }
}

fn test_regression_128() {
    let size: usize = POLYNOMIAL_SIZE;
    let fourier_size = PolynomialSize(size).to_fourier_polynomial_size().0;

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let mut poly = avec![u128::ZERO; size].into_boxed_slice();
    let mut fourier_re0 = avec![0.0f64; fourier_size].into_boxed_slice();
    let mut fourier_re1 = avec![0.0f64; fourier_size].into_boxed_slice();
    let mut fourier_im0 = avec![0.0f64; fourier_size].into_boxed_slice();
    let mut fourier_im1 = avec![0.0f64; fourier_size].into_boxed_slice();

    for (i, x) in poly.as_mut().iter_mut().enumerate() {
        let val = (i as u128).wrapping_mul(0x517cc1b727220a95u128) ^ 0xdeadbeefcafebabeu128;
        *x = val;
    }

    unsafe {
        fourier_transform_forward_as_torus_f128_async(
            &stream,
            &mut fourier_re0,
            &mut fourier_re1,
            &mut fourier_im0,
            &mut fourier_im1,
            &poly,
            poly.len() as u32,
            1,
        );
    }

    let bundles = izip_eq!(
        fourier_re0.iter(),
        EXPECTED_RE0.iter(),
        fourier_re1.iter(),
        EXPECTED_RE1.iter(),
        fourier_im0.iter(),
        EXPECTED_IM0.iter(),
        fourier_im1.iter(),
        EXPECTED_IM1.iter()
    );

    for (i, (re0, e_re0, re1, e_re1, im0, e_im0, im1, e_im1)) in bundles.enumerate() {
        assert_eq!(
            re0.to_bits(),
            *e_re0,
            "Bitwise mismatch in RE0 at index {i}"
        );
        assert_eq!(
            re1.to_bits(),
            *e_re1,
            "Bitwise mismatch in RE1 at index {i}"
        );
        assert_eq!(
            im0.to_bits(),
            *e_im0,
            "Bitwise mismatch in IM0 at index {i}"
        );
        assert_eq!(
            im1.to_bits(),
            *e_im1,
            "Bitwise mismatch in IM1 at index {i}"
        );
    }
}

#[test]
fn test_roundtrip_u128() {
    test_roundtrip::<u128>();
}

#[test]
fn test_regression_u128() {
    test_regression_128();
}

/// Bit-wise regression test for the forward FFT16x4x16 transform: the fixed
/// deterministic input must always reproduce the committed golden spectrum,
/// bit for bit. Regenerate the golden data with `generate_fft16x4x16_golden`.
#[test]
fn test_regression_fft16x4x16() {
    use fft_data::fft16x4x16_golden_v1::{EXPECTED_IM, EXPECTED_RE, POLYNOMIAL_SIZE};

    if !fft16x4x16_is_supported() {
        println!(
            "skipping test_regression_fft16x4x16: FFT16x4x16 requires compute \
             capability 9.x (Hopper) or newer"
        );
        return;
    }

    assert_eq!(POLYNOMIAL_SIZE, FFT16_POLYNOMIAL_SIZE);

    let bits = run_fft16x4x16_forward();
    let half = FFT16_POLYNOMIAL_SIZE / 2;

    for i in 0..half {
        assert_eq!(
            bits[2 * i],
            EXPECTED_RE[i],
            "Bitwise mismatch in real part at frequency {i}"
        );
        assert_eq!(
            bits[2 * i + 1],
            EXPECTED_IM[i],
            "Bitwise mismatch in imaginary part at frequency {i}"
        );
    }
}

/// (Re)generates the FFT16x4x16 golden file. This is *not* a test — it is a
/// manual maintenance helper. To refresh the golden data, temporarily annotate
/// it with `#[test]` `#[ignore]`, run it on an H100 (sm_90) with
/// `cargo test ... -- --ignored --exact`, then commit the regenerated file and
/// remove the annotations again.
#[allow(dead_code)]
fn generate_fft16x4x16_golden() {
    if !fft16x4x16_is_supported() {
        println!(
            "skipping generate_fft16x4x16_golden: FFT16x4x16 requires compute \
             capability 9.x (Hopper) or newer"
        );
        return;
    }

    let bits = run_fft16x4x16_forward();
    let half = FFT16_POLYNOMIAL_SIZE / 2;

    let mut re = String::new();
    let mut im = String::new();
    for i in 0..half {
        let _ = writeln!(re, "    {:#018x},", bits[2 * i]);
        let _ = writeln!(im, "    {:#018x},", bits[2 * i + 1]);
    }

    let contents = format!(
        "// @generated by the `generate_fft16x4x16_golden` helper in\n\
         // core_crypto::gpu::algorithms::test::fft. Do not edit by hand.\n\
         pub const POLYNOMIAL_SIZE: usize = {FFT16_POLYNOMIAL_SIZE};\n\
         pub const EXPECTED_RE: [u64; POLYNOMIAL_SIZE / 2] = [\n{re}];\n\n\
         pub const EXPECTED_IM: [u64; POLYNOMIAL_SIZE / 2] = [\n{im}];\n"
    );

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/core_crypto/gpu/algorithms/test/fft/fft_data/fft16x4x16_golden_v1.rs"
    );
    std::fs::write(path, contents).expect("failed to write FFT16x4x16 golden file");
    println!("wrote FFT16x4x16 golden data to {path}");
}
