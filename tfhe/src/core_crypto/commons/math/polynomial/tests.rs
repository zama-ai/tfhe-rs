use rand::Rng;

use crate::core_crypto::prelude::{MonomialDegree, PolynomialSize};

use crate::core_crypto::commons::math::polynomial::Polynomial;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::test_tools::*;

fn test_multiply_divide_unit_monomial<T: UnsignedTorus>() {
    //! tests if multiply_by_monomial and divide_by_monomial cancel each other
    let mut rng = rand::thread_rng();
    let mut generator = new_random_generator();

    // settings
    let polynomial_size = (rng.gen::<usize>() % 2048) + 1;

    // generates a random Torus polynomial
    let mut poly = Polynomial::from_container(
        generator
            .random_uniform_tensor::<T>(polynomial_size)
            .into_container(),
    );

    // copy this polynomial
    let ground_truth = poly.clone();

    // generates a random r
    let mut r: usize = rng.gen();
    r %= polynomial_size;

    // multiply by X^r and then divides by X^r
    poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(r));
    poly.update_with_wrapping_unit_monomial_div(MonomialDegree(r));

    // test
    assert_eq!(&poly, &ground_truth);

    // generates a random r_big
    let mut r_big: usize = rng.gen();
    r_big = r_big % polynomial_size + 2048;

    // multiply by X^r_big and then divides by X^r_big
    poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(r_big));
    poly.update_with_wrapping_unit_monomial_div(MonomialDegree(r_big));

    // test
    assert_eq!(&poly, &ground_truth);

    // divides by X^r_big and then multiply by X^r_big
    poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(r_big));
    poly.update_with_wrapping_unit_monomial_div(MonomialDegree(r_big));

    // test
    assert_eq!(&poly, &ground_truth);
}

/// test if we have the same result when using schoolbook or karatsuba
/// for random polynomial multiplication
fn test_multiply_karatsuba<T: UnsignedTorus>() {
    // 50 times the test
    for _i in 0..50 {
        // random source
        let mut rng = rand::thread_rng();

        // random settings settings
        let polynomial_log = (rng.gen::<usize>() % 7) + 6;
        let polynomial_size = PolynomialSize(1 << polynomial_log);
        let mut generator = new_random_generator();

        // generates two random Torus polynomials
        let poly_1 = Polynomial::from_container(
            generator
                .random_uniform_tensor::<T>(polynomial_size.0)
                .into_container(),
        );
        let poly_2 = Polynomial::from_container(
            generator
                .random_uniform_tensor::<T>(polynomial_size.0)
                .into_container(),
        );

        // copy this polynomial
        let mut sb_mul = Polynomial::allocate(T::ZERO, polynomial_size);
        let mut ka_mul = Polynomial::allocate(T::ZERO, polynomial_size);

        // compute the schoolbook
        sb_mul.fill_with_wrapping_mul(&poly_1, &poly_2);

        // compute the karatsuba
        ka_mul.fill_with_karatsuba_mul(&poly_1, &poly_2);

        // test
        assert_eq!(&sb_mul, &ka_mul);
    }
}

#[test]
pub fn test_multiply_divide_unit_monomial_u32() {
    test_multiply_divide_unit_monomial::<u32>()
}

#[test]
pub fn test_multiply_divide_unit_monomial_u64() {
    test_multiply_divide_unit_monomial::<u64>()
}

#[test]
pub fn test_multiply_karatsuba_u32() {
    test_multiply_karatsuba::<u32>()
}

#[test]
pub fn test_multiply_karatsuba_u64() {
    test_multiply_karatsuba::<u64>()
}
