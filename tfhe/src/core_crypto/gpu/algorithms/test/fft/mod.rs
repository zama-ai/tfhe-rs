pub mod fft_data;
use crate::core_crypto::commons::test_tools::{modular_distance, new_random_generator};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{
    backward_fft16x16x4_async, forward_fft16x16x4_async,
    fourier_transform_backward_as_torus_f128_async, fourier_transform_forward_as_torus_f128_async,
    CudaStreams,
};
use crate::core_crypto::prelude::*;
use aligned_vec::avec;
use fft_data::golden_v1::*;
use std::fmt::Write;
use tfhe_cuda_backend::bindings::cuda_pbs_golden_is_supported_async;
use tfhe_cuda_backend::cuda_bind::cuda_synchronize_device;

// ============================================================================
// Paired FFT16x16x4 transform tests (the forward and inverse FFTs of the
// specialized 2_2_params PBS, see fft16x16x4.cuh).
//
// A bit-wise regression test mirrors the FFT128 golden test above: a fixed,
// deterministic input is run through the forward transform once to produce
// golden output, and every subsequent run must reproduce it *bit for bit*. A
// roundtrip test checks the inverse transform against the forward one.
//
// The golden data lives in `fft_data::fft16x16x4_golden_v1` and is (re)generated
// by the `generate_fft16x16x4_golden` maintenance helper below — a plain (non
// `#[test]`) function; run it on an H100 (sm_90) to refresh the file, then
// commit the result.
//
// The transform is specialized for N = 2048 and processes two polynomials per
// block. It runs on compute capability 8.x and newer, where it reproduces the
// H100 golden data bit for bit (checked on A100, L40 and an RTX 4060 Laptop).
// ============================================================================

/// Polynomial size the FFT16x16x4 transform is specialized for.
const FFT16_POLYNOMIAL_SIZE: usize = 2048;
/// Polynomials per transform launch (two per block, must be even).
const FFT16_NUM_POLYNOMIALS: usize = 2;

/// True on compute capability 8.x and newer, where the FFT16x16x4 transform
/// runs and matches the committed golden data bit for bit.
fn fft16x16x4_is_supported() -> bool {
    // Safe: a pure runtime device-capability query with no aliasing concerns.
    unsafe { cuda_pbs_golden_is_supported_async(0) }
}

/// Deterministic input for the FFT16x16x4 forward transform: two fixed real
/// polynomials of size `FFT16_POLYNOMIAL_SIZE`, each packed into N/2 complex
/// coefficients the way the forward FFT consumes them,
/// `complex[i] = (poly[i], poly[i + N/2])`, and returned interleaved as
/// `[re, im, re, im, ...]` f64 (length 2 * N), the layout
/// `forward_fft16x16x4_async` expects on the device.
fn fft16x16x4_reference_input() -> Vec<f64> {
    let n = FFT16_POLYNOMIAL_SIZE;
    let half = n / 2;

    // Deterministic real polynomial, values in [-1, 1): a cheap bijective hash
    // of the global coefficient index.
    let poly_coeff = |k: usize| -> f64 {
        let bits = (k as u64)
            .wrapping_mul(0x517c_c1b7_2722_0a95)
            .rotate_left(17)
            ^ 0xdead_beef_cafe_babe;
        (bits as i64) as f64 / (i64::MAX as f64)
    };

    let mut input = vec![0.0f64; FFT16_NUM_POLYNOMIALS * n];
    for p in 0..FFT16_NUM_POLYNOMIALS {
        for i in 0..half {
            input[p * n + 2 * i] = poly_coeff(p * n + i); // real part
            input[p * n + 2 * i + 1] = poly_coeff(p * n + i + half); // imaginary part
        }
    }
    input
}

/// Runs the forward FFT16x16x4 on [`fft16x16x4_reference_input`] and returns the
/// output spectra as raw f64 bit patterns (interleaved re, im), ready for a
/// bit-exact comparison against golden data.
fn run_fft16x16x4_forward() -> Vec<u64> {
    let input = fft16x16x4_reference_input();
    let n = input.len();

    let stream = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let mut output = vec![0.0f64; n];

    unsafe {
        let d_input = CudaVec::<f64>::from_cpu_async(&input, &stream, 0);
        let mut d_output = CudaVec::<f64>::new(n, &stream, 0);

        forward_fft16x16x4_async(
            &stream,
            &d_input,
            &mut d_output,
            FFT16_POLYNOMIAL_SIZE as u32,
            FFT16_NUM_POLYNOMIALS as u32,
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

/// Bit-wise regression test for the forward FFT16x16x4 transform: the fixed
/// deterministic input must always reproduce the committed golden spectra,
/// bit for bit. Regenerate the golden data with `generate_fft16x16x4_golden`.
#[test]
fn test_regression_fft16x16x4() {
    use fft_data::fft16x16x4_golden_v1::{
        EXPECTED_IM, EXPECTED_RE, NUM_POLYNOMIALS, POLYNOMIAL_SIZE,
    };

    if !fft16x16x4_is_supported() {
        println!(
            "skipping test_regression_fft16x16x4: FFT16x16x4 requires compute \
             capability 8.x (Ampere) or newer"
        );
        return;
    }

    assert_eq!(POLYNOMIAL_SIZE, FFT16_POLYNOMIAL_SIZE);
    assert_eq!(NUM_POLYNOMIALS, FFT16_NUM_POLYNOMIALS);

    let bits = run_fft16x16x4_forward();
    let half = FFT16_POLYNOMIAL_SIZE / 2;
    for i in 0..FFT16_NUM_POLYNOMIALS * half {
        assert_eq!(
            bits[2 * i],
            EXPECTED_RE[i],
            "Bitwise mismatch in real part at polynomial {} frequency {}",
            i / half,
            i % half
        );
        assert_eq!(
            bits[2 * i + 1],
            EXPECTED_IM[i],
            "Bitwise mismatch in imaginary part at polynomial {} frequency {}",
            i / half,
            i % half
        );
    }
}

/// Forward then inverse must give N/2 times the input (the test transforms
/// carry no 1/N), up to rounding.
#[test]
fn test_roundtrip_fft16x16x4() {
    if !fft16x16x4_is_supported() {
        println!(
            "skipping test_roundtrip_fft16x16x4: FFT16x16x4 requires compute \
             capability 8.x (Ampere) or newer"
        );
        return;
    }

    let n = FFT16_POLYNOMIAL_SIZE;
    let num_polynomials = 8;
    let len = num_polynomials * n;
    let mut generator = new_random_generator();
    // Uniform in [-1, 1): the magnitude the C++ fixtures use as well.
    let input: Vec<f64> = (0..len)
        .map(|_| {
            let r: u64 = generator.random_uniform();
            (r >> 11) as f64 / (1u64 << 52) as f64 * 2.0 - 1.0
        })
        .collect();

    let stream = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let mut roundtrip = vec![0.0f64; len];
    unsafe {
        let d_input = CudaVec::<f64>::from_cpu_async(&input, &stream, 0);
        let mut d_spectrum = CudaVec::<f64>::new(len, &stream, 0);
        let mut d_output = CudaVec::<f64>::new(len, &stream, 0);
        forward_fft16x16x4_async(
            &stream,
            &d_input,
            &mut d_spectrum,
            n as u32,
            num_polynomials as u32,
        );
        backward_fft16x16x4_async(
            &stream,
            &d_spectrum,
            &mut d_output,
            n as u32,
            num_polynomials as u32,
        );
        d_output.copy_to_cpu_async(&mut roundtrip, &stream, 0);
        cuda_synchronize_device(0);
    }

    let scale = (n / 2) as f64;
    let tolerance = 1e-9;
    for (i, (expected, actual)) in izip_eq!(input.iter(), roundtrip.iter()).enumerate() {
        let actual = actual / scale;
        assert!(
            (expected - actual).abs() <= tolerance,
            "roundtrip mismatch at index {i}: expected {expected}, got {actual}"
        );
    }
}

/// (Re)generates the FFT16x16x4 golden file. This is *not* a test — it is a
/// manual maintenance helper. To refresh the golden data, temporarily annotate
/// it with `#[test]` `#[ignore]`, run it on an H100 (sm_90) with
/// `cargo test ... -- --ignored --exact`, then commit the regenerated file and
/// remove the annotations again.
#[allow(dead_code)]
fn generate_fft16x16x4_golden() {
    if !fft16x16x4_is_supported() {
        println!(
            "skipping generate_fft16x16x4_golden: FFT16x16x4 requires compute \
             capability 8.x (Ampere) or newer"
        );
        return;
    }

    let bits = run_fft16x16x4_forward();
    let count = FFT16_NUM_POLYNOMIALS * FFT16_POLYNOMIAL_SIZE / 2;

    let mut re = String::new();
    let mut im = String::new();
    for i in 0..count {
        let _ = writeln!(re, "    {:#018x},", bits[2 * i]);
        let _ = writeln!(im, "    {:#018x},", bits[2 * i + 1]);
    }

    let contents = format!(
        "// @generated by the `generate_fft16x16x4_golden` helper in\n\
         // core_crypto::gpu::algorithms::test::fft. Do not edit by hand.\n\
         pub const POLYNOMIAL_SIZE: usize = {FFT16_POLYNOMIAL_SIZE};\n\
         pub const NUM_POLYNOMIALS: usize = {FFT16_NUM_POLYNOMIALS};\n\
         pub const EXPECTED_RE: [u64; NUM_POLYNOMIALS * POLYNOMIAL_SIZE / 2] = [\n{re}];\n\n\
         pub const EXPECTED_IM: [u64; NUM_POLYNOMIALS * POLYNOMIAL_SIZE / 2] = [\n{im}];\n"
    );

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/core_crypto/gpu/algorithms/test/fft/fft_data/fft16x16x4_golden_v1.rs"
    );
    std::fs::write(path, contents).expect("failed to write FFT16x16x4 golden file");
    println!("wrote FFT16x16x4 golden data to {path}");
}
