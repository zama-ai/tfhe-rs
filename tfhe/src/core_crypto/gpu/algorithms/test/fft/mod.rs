pub mod fft_data;
use crate::core_crypto::commons::test_tools::{modular_distance, new_random_generator};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{
    fourier_transform_backward_as_torus_f128_async, fourier_transform_forward_as_torus_f128_async,
    CudaStreams,
};
use crate::core_crypto::prelude::*;
use aligned_vec::avec;
use fft_data::golden_v1::*;
use tfhe_cuda_backend::cuda_bind::cuda_synchronize_device;

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
