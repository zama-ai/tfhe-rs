use dyn_stack::{GlobalPodBuffer, ReborrowMut};

use super::*;
use crate::core_crypto::commons::test_tools::{modular_distance, new_random_generator};
use aligned_vec::avec;

fn test_roundtrip<Scalar: UnsignedTorus>() {
    let mut generator = new_random_generator();
    for size_log in 6..=14 {
        let size = 1_usize << size_log;
        let fourier_size = PolynomialSize(size).to_fourier_polynomial_size().0;

        let fft = Fft128::new(PolynomialSize(size));
        let fft = fft.as_view();

        let mut poly = avec![Scalar::ZERO; size].into_boxed_slice();
        let mut roundtrip = avec![Scalar::ZERO; size].into_boxed_slice();
        let mut fourier_re0 = avec![0.0f64; fourier_size].into_boxed_slice();
        let mut fourier_re1 = avec![0.0f64; fourier_size].into_boxed_slice();
        let mut fourier_im0 = avec![0.0f64; fourier_size].into_boxed_slice();
        let mut fourier_im1 = avec![0.0f64; fourier_size].into_boxed_slice();

        for x in poly.as_mut().iter_mut() {
            *x = generator.random_uniform();
        }

        let mut mem = GlobalPodBuffer::new(fft.backward_scratch().unwrap());
        let mut stack = PodStack::new(&mut mem);

        fft.forward_as_torus(
            &mut fourier_re0,
            &mut fourier_re1,
            &mut fourier_im0,
            &mut fourier_im1,
            &poly,
        );
        fft.backward_as_torus(
            &mut roundtrip,
            &fourier_re0,
            &fourier_re1,
            &fourier_im0,
            &fourier_im1,
            stack.rb_mut(),
        );

        for (expected, actual) in izip!(poly.as_ref().iter(), roundtrip.as_ref().iter()) {
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

fn test_product<Scalar: UnsignedTorus>() {
    fn convolution_naive<Scalar: UnsignedTorus>(
        out: &mut [Scalar],
        lhs: &[Scalar],
        rhs: &[Scalar],
    ) {
        assert_eq!(out.len(), lhs.len());
        assert_eq!(out.len(), rhs.len());
        let n = out.len();
        let mut full_prod = vec![Scalar::ZERO; 2 * n];
        for i in 0..n {
            for j in 0..n {
                full_prod[i + j] = full_prod[i + j].wrapping_add(lhs[i].wrapping_mul(rhs[j]));
            }
        }
        for i in 0..n {
            out[i] = full_prod[i].wrapping_sub(full_prod[i + n]);
        }
    }

    let mut generator = new_random_generator();
    for size_log in 6..=14 {
        for _ in 0..10 {
            let size = 1_usize << size_log;
            let fourier_size = PolynomialSize(size).to_fourier_polynomial_size().0;

            let fft = Fft128::new(PolynomialSize(size));
            let fft = fft.as_view();

            let mut poly0 = avec![Scalar::ZERO; size].into_boxed_slice();
            let mut poly1 = avec![Scalar::ZERO; size].into_boxed_slice();

            let mut convolution_from_fft = avec![Scalar::ZERO; size].into_boxed_slice();
            let mut convolution_from_naive = avec![Scalar::ZERO; size].into_boxed_slice();

            let mut fourier0_re0 = avec![0.0f64; fourier_size].into_boxed_slice();
            let mut fourier0_re1 = avec![0.0f64; fourier_size].into_boxed_slice();
            let mut fourier0_im0 = avec![0.0f64; fourier_size].into_boxed_slice();
            let mut fourier0_im1 = avec![0.0f64; fourier_size].into_boxed_slice();

            let mut fourier1_re0 = avec![0.0f64; fourier_size].into_boxed_slice();
            let mut fourier1_re1 = avec![0.0f64; fourier_size].into_boxed_slice();
            let mut fourier1_im0 = avec![0.0f64; fourier_size].into_boxed_slice();
            let mut fourier1_im1 = avec![0.0f64; fourier_size].into_boxed_slice();

            let integer_magnitude = 16;
            for (x, y) in izip!(poly0.as_mut().iter_mut(), poly1.as_mut().iter_mut()) {
                *x = generator.random_uniform();
                *y = generator.random_uniform();

                *y >>= Scalar::BITS - integer_magnitude;
            }

            let mut mem = GlobalPodBuffer::new(fft.backward_scratch().unwrap());
            let mut stack = PodStack::new(&mut mem);

            fft.forward_as_torus(
                &mut fourier0_re0,
                &mut fourier0_re1,
                &mut fourier0_im0,
                &mut fourier0_im1,
                &poly0,
            );
            fft.forward_as_integer(
                &mut fourier1_re0,
                &mut fourier1_re1,
                &mut fourier1_im0,
                &mut fourier1_im1,
                &poly1,
            );

            for (f0_re0, f0_re1, f0_im0, f0_im1, f1_re0, f1_re1, f1_im0, f1_im1) in izip!(
                &mut *fourier0_re0,
                &mut *fourier0_re1,
                &mut *fourier0_im0,
                &mut *fourier0_im1,
                &*fourier1_re0,
                &*fourier1_re1,
                &*fourier1_im0,
                &*fourier1_im1,
            ) {
                let f0_re = f128(*f0_re0, *f0_re1);
                let f0_im = f128(*f0_im0, *f0_im1);
                let f1_re = f128(*f1_re0, *f1_re1);
                let f1_im = f128(*f1_im0, *f1_im1);

                f128(*f0_re0, *f0_re1) = f0_re * f1_re - f0_im * f1_im;
                f128(*f0_im0, *f0_im1) = f0_im * f1_re + f0_re * f1_im;
            }

            fft.backward_as_torus(
                &mut convolution_from_fft,
                &fourier0_re0,
                &fourier0_re1,
                &fourier0_im0,
                &fourier0_im1,
                stack.rb_mut(),
            );
            convolution_naive(
                convolution_from_naive.as_mut(),
                poly0.as_ref(),
                poly1.as_ref(),
            );

            for (expected, actual) in izip!(
                convolution_from_naive.as_ref().iter(),
                convolution_from_fft.as_ref().iter()
            ) {
                let threshold = Scalar::ONE
                    << (Scalar::BITS.saturating_sub(100 - integer_magnitude - size_log));
                let abs_diff = modular_distance(*expected, *actual);
                assert!(
                    abs_diff <= threshold,
                    "abs_diff: {abs_diff}, threshold: {threshold}",
                );
            }
        }
    }
}

#[test]
fn test_roundtrip_u32() {
    test_roundtrip::<u32>();
}
#[test]
fn test_roundtrip_u64() {
    test_roundtrip::<u64>();
}
#[test]
fn test_roundtrip_u128() {
    test_roundtrip::<u128>();
}

#[test]
fn test_product_u32() {
    test_product::<u32>();
}

#[test]
fn test_product_u64() {
    test_product::<u64>();
}

#[test]
fn test_product_u128() {
    test_product::<u128>();
}
