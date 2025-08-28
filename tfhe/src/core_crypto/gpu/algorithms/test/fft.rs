use crate::core_crypto::commons::test_tools::{modular_distance, new_random_generator};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{
    fourier_transform_backward_as_torus_f128_async, fourier_transform_forward_as_torus_f128_async,
    CudaStreams,
};
use crate::core_crypto::prelude::*;
use aligned_vec::avec;
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

#[test]
fn test_roundtrip_u128() {
    test_roundtrip::<u128>();
}
