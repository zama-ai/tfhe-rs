//! Module providing algorithms to perform computations on polynomials modulo $X^{N} + 1$.

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::MonomialDegree;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Adds a polynomial to the output polynomial.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::entities::*;
/// let mut first = Polynomial::from_container(vec![1u8, 2, 3, 4, 5, 6]);
/// let second = Polynomial::from_container(vec![255u8, 255, 255, 1, 2, 3]);
/// polynomial_wrapping_add_assign(&mut first, &second);
/// assert_eq!(first.as_ref(), &[0u8, 1, 2, 5, 7, 9]);
/// ```
pub fn polynomial_wrapping_add_assign<Scalar, OutputCont, InputCont>(
    lhs: &mut Polynomial<OutputCont>,
    rhs: &Polynomial<InputCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert_eq!(lhs.polynomial_size(), rhs.polynomial_size());
    slice_wrapping_add_assign(lhs.as_mut(), rhs.as_ref())
}

/// Adds the sum of the element-wise product between two lists of polynomials to the output
/// polynomial.
///
/// I.e., if the output polynomial is $C(X)$, for a collection of polynomials $(P\_i(X)))\_i$
/// and another collection of polynomials $(B\_i(X))\_i$ we perform the operation:
/// $$
/// C(X) := C(X) + \sum\_i P\_i(X) \times B\_i(X) mod (X^{N} + 1)
/// $$
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let poly_list = PolynomialList::from_container(vec![100_u8, 20, 3, 4, 5, 6], PolynomialSize(3));
/// let bin_poly_list = PolynomialList::from_container(vec![0, 1, 1, 1, 0, 0], PolynomialSize(3));
/// let mut output = Polynomial::new(250, PolynomialSize(3));
/// polynomial_wrapping_add_multisum_assign(&mut output, &poly_list, &bin_poly_list);
/// assert_eq!(output.as_ref(), &[231, 96, 120]);
/// ```
pub fn polynomial_wrapping_add_multisum_assign<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    poly_list_1: &PolynomialList<InputCont1>,
    poly_list_2: &PolynomialList<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        polynomial_wrapping_add_mul_assign(output, &poly_1, &poly_2);
    }
}

/// Adds the result of the product between two polynomials, reduced modulo $(X^{N}+1)$, to the
/// output polynomial.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::entities::*;
/// let poly_1 = Polynomial::from_container(vec![1_u8, 2, 3]);
/// let poly_2 = Polynomial::from_container(vec![0, 1, 1]);
/// let mut res = Polynomial::from_container(vec![1, 0, 253]);
/// polynomial_wrapping_add_mul_assign(&mut res, &poly_1, &poly_2);
/// assert_eq!(res.as_ref(), &[252, 254, 0]);
/// ```
pub fn polynomial_wrapping_add_mul_assign<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    assert!(
        output.polynomial_size() == lhs.polynomial_size(),
        "Output polynomial size {:?} is not the same as input lhs polynomial {:?}.",
        output.polynomial_size(),
        lhs.polynomial_size(),
    );
    assert!(
        output.polynomial_size() == rhs.polynomial_size(),
        "Output polynomial size {:?} is not the same as input rhs polynomial {:?}.",
        output.polynomial_size(),
        rhs.polynomial_size(),
    );
    let degree = output.degree();
    let polynomial_size = output.polynomial_size();

    for (lhs_degree, &lhs_coeff) in lhs.iter().enumerate() {
        for (rhs_degree, &rhs_coeff) in rhs.iter().enumerate() {
            let target_degree = lhs_degree + rhs_degree;
            if target_degree <= degree {
                let output_coefficient = &mut output.as_mut()[target_degree];

                *output_coefficient =
                    (*output_coefficient).wrapping_add(lhs_coeff.wrapping_mul(rhs_coeff));
            } else {
                let target_degree = target_degree % polynomial_size.0;
                let output_coefficient = &mut output.as_mut()[target_degree];

                *output_coefficient =
                    (*output_coefficient).wrapping_sub(lhs_coeff.wrapping_mul(rhs_coeff));
            }
        }
    }
}

/// Divides (mod $(X^{N}+1)$), the output polynomial with a monic monomial of a given degree i.e.
/// $X^{degree}$.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Examples
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let mut poly = Polynomial::from_container(vec![1u8, 2, 3]);
/// polynomial_wrapping_monic_monomial_div_assign(&mut poly, MonomialDegree(2));
/// assert_eq!(poly.as_ref(), &[3, 255, 254]);
/// ```
pub fn polynomial_wrapping_monic_monomial_div_assign<Scalar, OutputCont>(
    output: &mut Polynomial<OutputCont>,
    monomial_degree: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let full_cycles_count = monomial_degree.0 / output.as_ref().container_len();
    if full_cycles_count % 2 != 0 {
        output
            .as_mut()
            .iter_mut()
            .for_each(|a| *a = a.wrapping_neg());
    }
    let remaining_degree = monomial_degree.0 % output.as_ref().container_len();
    output.as_mut().rotate_left(remaining_degree);
    output
        .as_mut()
        .iter_mut()
        .rev()
        .take(remaining_degree)
        .for_each(|a| *a = a.wrapping_neg());
}

/// Multiplies (mod $(X^{N}+1)$), the output polynomial with a monic monomial of a given degree i.e.
/// $X^{degree}$.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Examples
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let mut poly = Polynomial::from_container(vec![1u8, 2, 3]);
/// polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(2));
/// assert_eq!(poly.as_ref(), &[254, 253, 1]);
/// ```
pub fn polynomial_wrapping_monic_monomial_mul_assign<Scalar, OutputCont>(
    output: &mut Polynomial<OutputCont>,
    monomial_degree: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let full_cycles_count = monomial_degree.0 / output.as_ref().container_len();
    if full_cycles_count % 2 != 0 {
        output
            .as_mut()
            .iter_mut()
            .for_each(|a| *a = a.wrapping_neg());
    }
    let remaining_degree = monomial_degree.0 % output.as_ref().container_len();
    output.as_mut().rotate_right(remaining_degree);
    output
        .as_mut()
        .iter_mut()
        .take(remaining_degree)
        .for_each(|a| *a = a.wrapping_neg());
}

/// Subtracts the sum of the element-wise product between two lists of polynomials, to the output
/// polynomial.
///
/// I.e., if the output polynomial is $C(X)$, for two lists of polynomials $(P\_i(X)))\_i$ and
/// $(B\_i(X))\_i$ we perform the operation:
/// $$
/// C(X) := C(X) + \sum\_i P\_i(X) \times B\_i(X) mod (X^{N} + 1)
/// $$
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let poly_list =
///     PolynomialList::from_container(vec![100 as u8, 20, 3, 4, 5, 6], PolynomialSize(3));
/// let bin_poly_list = PolynomialList::from_container(vec![0, 1, 1, 1, 0, 0], PolynomialSize(3));
/// let mut output = Polynomial::new(250 as u8, PolynomialSize(3));
/// polynomial_wrapping_sub_multisum_assign(&mut output, &poly_list, &bin_poly_list);
/// assert_eq!(output.as_ref(), &[13, 148, 124]);
/// ```
pub fn polynomial_wrapping_sub_multisum_assign<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    poly_list_1: &PolynomialList<InputCont1>,
    poly_list_2: &PolynomialList<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        polynomial_wrapping_sub_mul_assign(output, &poly_1, &poly_2);
    }
}

/// Subtracts the result of the product between two polynomials, reduced modulo $(X^{N}+1)$, to the
/// output polynomial.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::entities::*;
/// let poly_1 = Polynomial::from_container(vec![1_u8, 2, 3]);
/// let poly_2 = Polynomial::from_container(vec![0, 1, 1]);
/// let mut res = Polynomial::from_container(vec![255, 255, 1]);
/// polynomial_wrapping_sub_mul_assign(&mut res, &poly_1, &poly_2);
/// assert_eq!(res.as_ref(), &[4, 1, 254]);
/// ```
pub fn polynomial_wrapping_sub_mul_assign<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    assert!(
        output.polynomial_size() == lhs.polynomial_size(),
        "Output polynomial size {:?} is not the same as input lhs polynomial {:?}.",
        output.polynomial_size(),
        lhs.polynomial_size(),
    );
    assert!(
        output.polynomial_size() == rhs.polynomial_size(),
        "Output polynomial size {:?} is not the same as input rhs polynomial {:?}.",
        output.polynomial_size(),
        rhs.polynomial_size(),
    );
    let degree = output.degree();
    let polynomial_size = output.polynomial_size();

    for (lhs_degree, &lhs_coeff) in lhs.iter().enumerate() {
        for (rhs_degree, &rhs_coeff) in rhs.iter().enumerate() {
            let target_degree = lhs_degree + rhs_degree;
            if target_degree <= degree {
                let output_coefficient = &mut output.as_mut()[target_degree];

                *output_coefficient =
                    (*output_coefficient).wrapping_sub(lhs_coeff.wrapping_mul(rhs_coeff));
            } else {
                let target_degree = target_degree % polynomial_size.0;
                let output_coefficient = &mut output.as_mut()[target_degree];

                *output_coefficient =
                    (*output_coefficient).wrapping_add(lhs_coeff.wrapping_mul(rhs_coeff));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::core_crypto::algorithms::polynomial_algorithms::*;
    use crate::core_crypto::commons::parameters::*;
    use crate::core_crypto::commons::test_tools::*;

    fn test_multiply_divide_unit_monomial<T: UnsignedTorus>() {
        //! tests if multiply_by_monomial and divide_by_monomial cancel each other
        let mut rng = rand::thread_rng();
        let mut generator = new_random_generator();

        // settings
        let polynomial_size = random_polynomial_size(2048);

        // generates a random Torus polynomial
        let mut poly = Polynomial::new(T::ZERO, polynomial_size);
        generator.fill_slice_with_random_uniform(poly.as_mut());

        let polynomial_size = polynomial_size.0;

        // copy this polynomial
        let ground_truth = poly.clone();

        // generates a random r
        let mut r: usize = rng.gen();
        r %= polynomial_size;

        // multiply by X^r and then divides by X^r
        polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(r));
        polynomial_wrapping_monic_monomial_div_assign(&mut poly, MonomialDegree(r));

        // test
        assert_eq!(&poly, &ground_truth);

        // generates a random r_big
        let mut r_big: usize = rng.gen();
        r_big = r_big % polynomial_size + 2048;

        // multiply by X^r_big and then divides by X^r_big
        polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(r_big));
        polynomial_wrapping_monic_monomial_div_assign(&mut poly, MonomialDegree(r_big));

        // test
        assert_eq!(&poly, &ground_truth);

        // divides by X^r_big and then multiply by X^r_big
        polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(r_big));
        polynomial_wrapping_monic_monomial_div_assign(&mut poly, MonomialDegree(r_big));

        // test
        assert_eq!(&poly, &ground_truth);
    }

    #[test]
    pub fn test_multiply_divide_unit_monomial_u32() {
        test_multiply_divide_unit_monomial::<u32>()
    }

    #[test]
    pub fn test_multiply_divide_unit_monomial_u64() {
        test_multiply_divide_unit_monomial::<u64>()
    }
}
