use dyn_stack::{GlobalMemBuffer, ReborrowMut};

use super::super::polynomial::FourierPolynomial;
use super::*;
use crate::core_crypto::commons::test_tools::new_random_generator;
use crate::core_crypto::entities::Polynomial;
use aligned_vec::avec;

fn abs_diff<Scalar: UnsignedTorus>(a: Scalar, b: Scalar) -> Scalar {
    if a > b {
        a - b
    } else {
        b - a
    }
}

fn test_roundtrip<Scalar: UnsignedTorus>() {
    let mut generator = new_random_generator();
    for i in 2..=14 {
        let size = 1_usize << i;

        let fft = Fft::new(PolynomialSize(size));
        let fft = fft.as_view();

        let mut poly = Polynomial::from_container(avec![Scalar::ZERO; size].into_boxed_slice());
        let mut roundtrip =
            Polynomial::from_container(avec![Scalar::ZERO; size].into_boxed_slice());
        let mut fourier = FourierPolynomial {
            data: avec![c64::default(); size / 2].into_boxed_slice(),
        };

        for x in poly.as_mut().iter_mut() {
            *x = generator.random_uniform();
        }

        let mut mem = GlobalMemBuffer::new(
            fft.forward_scratch()
                .unwrap()
                .and(fft.backward_scratch().unwrap()),
        );
        let mut stack = DynStack::new(&mut mem);

        fft.forward_as_torus(
            unsafe { fourier.as_mut_view().into_uninit() },
            poly.as_view(),
            stack.rb_mut(),
        );
        fft.backward_as_torus(
            unsafe { roundtrip.as_mut_view().into_uninit() },
            fourier.as_view(),
            stack.rb_mut(),
        );

        for (expected, actual) in izip!(poly.as_ref().iter(), roundtrip.as_ref().iter()) {
            if Scalar::BITS == 32 {
                assert!(abs_diff(*expected, *actual) == Scalar::ZERO);
            } else {
                assert!(abs_diff(*expected, *actual) < (Scalar::ONE << (64 - 50)));
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
    for i in 5..=14 {
        for _ in 0..100 {
            let size = 1_usize << i;

            let fft = Fft::new(PolynomialSize(size));
            let fft = fft.as_view();

            let mut poly0 =
                Polynomial::from_container(avec![Scalar::ZERO; size].into_boxed_slice());
            let mut poly1 =
                Polynomial::from_container(avec![Scalar::ZERO; size].into_boxed_slice());

            let mut convolution_from_fft =
                Polynomial::from_container(avec![Scalar::ZERO; size].into_boxed_slice());
            let mut convolution_from_naive =
                Polynomial::from_container(avec![Scalar::ZERO; size].into_boxed_slice());

            let mut fourier0 = FourierPolynomial {
                data: avec![c64::default(); size / 2].into_boxed_slice(),
            };
            let mut fourier1 = FourierPolynomial {
                data: avec![c64::default(); size / 2 ].into_boxed_slice(),
            };

            for (x, y) in izip!(poly0.as_mut().iter_mut(), poly1.as_mut().iter_mut()) {
                *x = generator.random_uniform();
                *y = generator.random_uniform();
                if Scalar::BITS == 64 {
                    *x >>= 32;
                    *y >>= 32;
                } else {
                    *x >>= 16;
                    *y >>= 16;
                }
            }

            let mut mem = GlobalMemBuffer::new(
                fft.forward_scratch()
                    .unwrap()
                    .and(fft.backward_scratch().unwrap()),
            );
            let mut stack = DynStack::new(&mut mem);

            // SAFETY: forward_as_torus doesn't write any uninitialized values into its output
            fft.forward_as_torus(
                unsafe { fourier0.as_mut_view().into_uninit() },
                poly0.as_view(),
                stack.rb_mut(),
            );
            // SAFETY: forward_as_integer doesn't write any uninitialized values into its output
            fft.forward_as_integer(
                unsafe { fourier1.as_mut_view().into_uninit() },
                poly1.as_view(),
                stack.rb_mut(),
            );

            for (f0, f1) in izip!(&mut *fourier0.data, &*fourier1.data) {
                *f0 *= *f1;
            }

            // SAFETY: backward_as_torus doesn't write any uninitialized values into its output
            fft.backward_as_torus(
                unsafe { convolution_from_fft.as_mut_view().into_uninit() },
                fourier0.as_view(),
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
                assert!(abs_diff(*expected, *actual) < (Scalar::ONE << (Scalar::BITS - 5)));
            }
        }
    }
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
fn test_roundtrip_u32() {
    test_roundtrip::<u32>();
}
#[test]
fn test_roundtrip_u64() {
    test_roundtrip::<u64>();
}

#[test]
fn f64_to_i64_bit_twiddles() {
    for x in [
        0.0,
        -0.0,
        37.1242161_f64,
        -37.1242161_f64,
        0.1,
        -0.1,
        1.0,
        -1.0,
        0.9,
        -0.9,
        2.0,
        -2.0,
        1e-310,
        -1e-310,
        2.0_f64.powi(62),
        -(2.0_f64.powi(62)),
        1.1 * 2.0_f64.powi(62),
        1.1 * -(2.0_f64.powi(62)),
        -(2.0_f64.powi(63)),
    ] {
        // this test checks the correctness of converting from f64 to i64 by manipulating the bits
        // of the ieee754 representation of the floating point values.
        //
        // if the value is not representable as an i64, the result is unspecified.
        //
        // https://en.wikipedia.org/wiki/Double-precision_floating-point_format
        let bits = x.to_bits();
        let implicit_mantissa = bits & 0xFFFFFFFFFFFFF;
        let explicit_mantissa = implicit_mantissa | 0x10000000000000;
        let biased_exp = ((bits >> 52) & 0x7FF) as i64;
        let sign = bits >> 63;

        let explicit_mantissa_lshift = explicit_mantissa << 11;

        // equivalent to:
        //
        // let exp = biased_exp - 1023;
        // let explicit_mantissa_shift = explicit_mantissa_lshift >> (63 - exp.max(0));
        let right_shift_amount = (1086 - biased_exp) as u64;

        let explicit_mantissa_shift = if right_shift_amount < 64 {
            explicit_mantissa_lshift >> right_shift_amount
        } else {
            0
        };

        let value = if sign == 0 {
            explicit_mantissa_shift as i64
        } else {
            (explicit_mantissa_shift as i64).wrapping_neg()
        };

        let value = if biased_exp == 0 { 0 } else { value };
        assert_eq!(value, x as i64);
    }
}
