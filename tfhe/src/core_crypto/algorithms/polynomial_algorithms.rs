//! Module providing algorithms to perform computations on polynomials modulo $X^{N} + 1$.

use itertools::Itertools;

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::parameters::MonomialDegree;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Add a polynomial to the output polynomial.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `lhs` and `rhs` do not have the same polynomial size.
///
/// # Example
///
/// ```rust
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
    slice_wrapping_add_assign(lhs.as_mut(), rhs.as_ref());
}

pub fn polynomial_wrapping_add_assign_custom_mod<Scalar, OutputCont, InputCont>(
    lhs: &mut Polynomial<OutputCont>,
    rhs: &Polynomial<InputCont>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert_eq!(lhs.polynomial_size(), rhs.polynomial_size());
    slice_wrapping_add_assign_custom_mod(lhs.as_mut(), rhs.as_ref(), custom_modulus)
}

/// Subtract a polynomial to the output polynomial.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `lhs` and `rhs` do not have the same polynomial size.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::entities::*;
/// let mut first = Polynomial::from_container(vec![1u8, 2, 3, 4, 5, 6]);
/// let second = Polynomial::from_container(vec![255u8, 255, 255, 1, 2, 3]);
/// polynomial_wrapping_sub_assign(&mut first, &second);
/// assert_eq!(first.as_ref(), &[2, 3, 4, 3, 3, 3]);
/// ```
pub fn polynomial_wrapping_sub_assign<Scalar, OutputCont, InputCont>(
    lhs: &mut Polynomial<OutputCont>,
    rhs: &Polynomial<InputCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert_eq!(lhs.polynomial_size(), rhs.polynomial_size());
    slice_wrapping_sub_assign(lhs.as_mut(), rhs.as_ref());
}

pub fn polynomial_wrapping_sub_assign_custom_mod<Scalar, OutputCont, InputCont>(
    lhs: &mut Polynomial<OutputCont>,
    rhs: &Polynomial<InputCont>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert_eq!(lhs.polynomial_size(), rhs.polynomial_size());
    slice_wrapping_sub_assign_custom_mod(lhs.as_mut(), rhs.as_ref(), custom_modulus)
}

/// Add the sum of the element-wise product between two lists of polynomials to the output
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
/// # Panics
///
/// This function will panic in any of these situations:
/// - the lists are not of the same size
/// - the polynomial sizes are not the same
///
/// # Example
///
/// ```rust
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
    assert_eq!(
        poly_list_1.polynomial_count(),
        poly_list_2.polynomial_count()
    );
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        polynomial_wrapping_add_mul_assign(output, &poly_1, &poly_2);
    }
}

pub fn polynomial_wrapping_add_multisum_assign_custom_mod<
    Scalar,
    OutputCont,
    InputCont1,
    InputCont2,
>(
    output: &mut Polynomial<OutputCont>,
    poly_list_1: &PolynomialList<InputCont1>,
    poly_list_2: &PolynomialList<InputCont2>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    assert_eq!(
        poly_list_1.polynomial_count(),
        poly_list_2.polynomial_count()
    );
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        polynomial_wrapping_add_mul_assign_custom_mod(output, &poly_1, &poly_2, custom_modulus);
    }
}

/// Fill the output polynomial, with the result of the product of two polynomials, reduced modulo
/// $(X^{N} + 1)$ with the schoolbook algorithm.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `output`, `lhs` and `rhs` do not have the same polynomial size.
fn polynomial_wrapping_add_mul_schoolbook_assign<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    assert_eq!(lhs.polynomial_size(), rhs.polynomial_size());
    fn implementation<Scalar: UnsignedInteger>(
        mut output: Polynomial<&mut [Scalar]>,
        lhs: Polynomial<&[Scalar]>,
        rhs: Polynomial<&[Scalar]>,
    ) {
        let polynomial_size = output.polynomial_size();
        let degree = output.degree();

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
    implementation(output.as_mut_view(), lhs.as_view(), rhs.as_view());
}

fn polynomial_wrapping_add_mul_schoolbook_assign_custom_mod<
    Scalar,
    OutputCont,
    InputCont1,
    InputCont2,
>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    fn implementation<Scalar: UnsignedInteger>(
        mut output: Polynomial<&mut [Scalar]>,
        lhs: Polynomial<&[Scalar]>,
        rhs: Polynomial<&[Scalar]>,
        custom_modulus: Scalar,
    ) {
        let polynomial_size = output.polynomial_size();
        let degree = output.degree();
        for (lhs_degree, &lhs_coeff) in lhs.iter().enumerate() {
            for (rhs_degree, &rhs_coeff) in rhs.iter().enumerate() {
                let target_degree = lhs_degree + rhs_degree;
                if target_degree <= degree {
                    let output_coefficient = &mut output.as_mut()[target_degree];

                    *output_coefficient = (*output_coefficient).wrapping_add_custom_mod(
                        lhs_coeff.wrapping_mul_custom_mod(rhs_coeff, custom_modulus),
                        custom_modulus,
                    );
                } else {
                    let target_degree = target_degree % polynomial_size.0;
                    let output_coefficient = &mut output.as_mut()[target_degree];

                    *output_coefficient = (*output_coefficient).wrapping_sub_custom_mod(
                        lhs_coeff.wrapping_mul_custom_mod(rhs_coeff, custom_modulus),
                        custom_modulus,
                    );
                }
            }
        }
    }
    implementation(
        output.as_mut_view(),
        lhs.as_view(),
        rhs.as_view(),
        custom_modulus,
    );
}

/// Add the result of the product between two polynomials, reduced modulo $(X^{N}+1)$, to the
/// output polynomial.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `output`, `lhs` and `rhs` do not have the same polynomial size.
///
/// # Example
///
/// ```rust
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

    let polynomial_size = output.polynomial_size();

    if polynomial_size.0.is_power_of_two() && polynomial_size.0 > KARATUSBA_STOP {
        let mut tmp = Polynomial::new(Scalar::ZERO, polynomial_size);

        polynomial_karatsuba_wrapping_mul(&mut tmp, lhs, rhs);
        polynomial_wrapping_add_assign(output, &tmp);
    } else {
        polynomial_wrapping_add_mul_schoolbook_assign(output, lhs, rhs);
    }
}

pub fn polynomial_wrapping_add_mul_assign_custom_mod<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
    custom_modulus: Scalar,
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

    let polynomial_size = output.polynomial_size();

    if polynomial_size.0.is_power_of_two() && polynomial_size.0 > KARATUSBA_STOP {
        let mut tmp = Polynomial::new(Scalar::ZERO, polynomial_size);

        polynomial_karatsuba_wrapping_mul_custom_mod(&mut tmp, lhs, rhs, custom_modulus);
        polynomial_wrapping_add_assign_custom_mod(output, &tmp, custom_modulus);
    } else {
        polynomial_wrapping_add_mul_schoolbook_assign_custom_mod(output, lhs, rhs, custom_modulus)
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
/// ```rust
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
    if !full_cycles_count.is_multiple_of(2) {
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

pub fn polynomial_wrapping_monic_monomial_div_assign_custom_mod<Scalar, OutputCont>(
    output: &mut Polynomial<OutputCont>,
    monomial_degree: MonomialDegree,
    modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let full_cycles_count = monomial_degree.0 / output.as_ref().container_len();
    if !full_cycles_count.is_multiple_of(2) {
        output
            .as_mut()
            .iter_mut()
            .for_each(|a| *a = (*a).wrapping_neg_custom_mod(modulus));
    }
    let remaining_degree = monomial_degree.0 % output.as_ref().container_len();
    output.as_mut().rotate_left(remaining_degree);
    output
        .as_mut()
        .iter_mut()
        .rev()
        .take(remaining_degree)
        .for_each(|a| *a = (*a).wrapping_neg_custom_mod(modulus));
}

/// Multiply (mod $(X^{N}+1)$), the output polynomial with a monic monomial of a given degree i.e.
/// $X^{degree}$.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Examples
///
/// ```rust
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
    if !full_cycles_count.is_multiple_of(2) {
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

pub fn polynomial_wrapping_monic_monomial_mul_assign_custom_mod<Scalar, OutputCont>(
    output: &mut Polynomial<OutputCont>,
    monomial_degree: MonomialDegree,
    modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let full_cycles_count = monomial_degree.0 / output.as_ref().container_len();
    if !full_cycles_count.is_multiple_of(2) {
        output
            .as_mut()
            .iter_mut()
            .for_each(|a| *a = (*a).wrapping_neg_custom_mod(modulus));
    }
    let remaining_degree = monomial_degree.0 % output.as_ref().container_len();
    output.as_mut().rotate_right(remaining_degree);
    output
        .as_mut()
        .iter_mut()
        .take(remaining_degree)
        .for_each(|a| *a = (*a).wrapping_neg_custom_mod(modulus));
}

/// performs the operation: dst = -src, with wrapping arithmetic
fn copy_with_neg<Scalar: UnsignedInteger>(dst: &mut [Scalar], src: &[Scalar]) {
    for (dst, src) in dst.iter_mut().zip(src) {
        *dst = src.wrapping_neg();
    }
}

/// performs the operation: dst = src
fn copy_without_neg<Scalar: UnsignedInteger>(dst: &mut [Scalar], src: &[Scalar]) {
    dst.copy_from_slice(src);
}

/// Divides (mod $(X^{N}+1)$), the input polynomial with a monic monomial of a given degree i.e.
/// $X^{degree}$.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `output` and `input` do not have the same polynomial size.
///
/// # Examples
///
/// ```rust
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let input = Polynomial::from_container(vec![1u8, 2, 3]);
/// let mut output = Polynomial::from_container(vec![0, 0, 0]);
/// polynomial_wrapping_monic_monomial_div(&mut output, &input, MonomialDegree(2));
/// assert_eq!(output.as_ref(), &[3, 255, 254]);
/// ```
pub fn polynomial_wrapping_monic_monomial_div<Scalar, OutputCont, InputCont>(
    output: &mut Polynomial<OutputCont>,
    input: &Polynomial<InputCont>,
    monomial_degree: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        output.polynomial_size() == input.polynomial_size(),
        "Output polynomial size {:?} is not the same as input polynomial size {:?}.",
        output.polynomial_size(),
        input.polynomial_size(),
    );

    let polynomial_size = output.polynomial_size().0;
    let remaining_degree = monomial_degree.0 % polynomial_size;

    let full_cycles_count = monomial_degree.0 / polynomial_size;
    if full_cycles_count.is_multiple_of(2) {
        copy_without_neg(
            &mut output[..polynomial_size - remaining_degree],
            &input[remaining_degree..],
        );
        copy_with_neg(
            &mut output[polynomial_size - remaining_degree..],
            &input[..remaining_degree],
        );
    } else {
        copy_with_neg(
            &mut output[..polynomial_size - remaining_degree],
            &input[remaining_degree..],
        );
        copy_without_neg(
            &mut output[polynomial_size - remaining_degree..],
            &input[..remaining_degree],
        );
    }
}

/// Multiply (mod $(X^{N}+1)$), the input polynomial with a monic monomial of a given degree i.e.
/// $X^{degree}$.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `output` and `input` do not have the same polynomial size.
///
/// # Examples
///
/// ```rust
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let input = Polynomial::from_container(vec![1u8, 2, 3]);
/// let mut output = Polynomial::from_container(vec![0, 0, 0]);
/// polynomial_wrapping_monic_monomial_mul(&mut output, &input, MonomialDegree(2));
/// assert_eq!(output.as_ref(), &[254, 253, 1]);
/// ```
pub fn polynomial_wrapping_monic_monomial_mul<Scalar, OutputCont, InputCont>(
    output: &mut Polynomial<OutputCont>,
    input: &Polynomial<InputCont>,
    monomial_degree: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        output.polynomial_size() == input.polynomial_size(),
        "Output polynomial size {:?} is not the same as input polynomial size {:?}.",
        output.polynomial_size(),
        input.polynomial_size(),
    );

    let polynomial_size = output.polynomial_size().0;
    let remaining_degree = monomial_degree.0 % polynomial_size;

    let full_cycles_count = monomial_degree.0 / polynomial_size;
    if full_cycles_count.is_multiple_of(2) {
        copy_with_neg(
            &mut output[..remaining_degree],
            &input[polynomial_size - remaining_degree..],
        );
        copy_without_neg(
            &mut output[remaining_degree..],
            &input[..polynomial_size - remaining_degree],
        );
    } else {
        copy_without_neg(
            &mut output[..remaining_degree],
            &input[polynomial_size - remaining_degree..],
        );
        copy_with_neg(
            &mut output[remaining_degree..],
            &input[..polynomial_size - remaining_degree],
        );
    }
}

/// Multiply (mod $(X^{N}+1)$), the input polynomial with a monic monomial of a given degree i.e.
/// $X^{degree}$, then subtract the input from the result and assign to the output.
///
/// output = input * X^degree - input
///
/// # Panics
///
/// This function will panic if `output` and `input` do not have the same polynomial size.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
pub(crate) fn polynomial_wrapping_monic_monomial_mul_and_subtract<Scalar, OutputCont, InputCont>(
    output: &mut Polynomial<OutputCont>,
    input: &Polynomial<InputCont>,
    monomial_degree: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    /// performs the operation: dst = -src - src_orig, with wrapping arithmetic
    fn copy_with_neg_and_subtract<Scalar: UnsignedInteger>(
        dst: &mut [Scalar],
        src: &[Scalar],
        src_orig: &[Scalar],
    ) {
        for ((dst, src), src_orig) in dst.iter_mut().zip(src).zip(src_orig) {
            *dst = src.wrapping_neg().wrapping_sub(*src_orig);
        }
    }

    /// performs the operation: dst = src - src_orig, with wrapping arithmetic
    fn copy_without_neg_and_subtract<Scalar: UnsignedInteger>(
        dst: &mut [Scalar],
        src: &[Scalar],
        src_orig: &[Scalar],
    ) {
        for ((dst, src), src_orig) in dst.iter_mut().zip(src).zip(src_orig) {
            *dst = src.wrapping_sub(*src_orig);
        }
    }

    assert!(
        output.polynomial_size() == input.polynomial_size(),
        "Output polynomial size {:?} is not the same as input polynomial size {:?}.",
        output.polynomial_size(),
        input.polynomial_size(),
    );

    let polynomial_size = output.polynomial_size().0;
    let remaining_degree = monomial_degree.0 % polynomial_size;

    let full_cycles_count = monomial_degree.0 / polynomial_size;
    if full_cycles_count.is_multiple_of(2) {
        copy_with_neg_and_subtract(
            &mut output[..remaining_degree],
            &input[polynomial_size - remaining_degree..],
            &input[..remaining_degree],
        );
        copy_without_neg_and_subtract(
            &mut output[remaining_degree..],
            &input[..polynomial_size - remaining_degree],
            &input[remaining_degree..],
        );
    } else {
        copy_without_neg_and_subtract(
            &mut output[..remaining_degree],
            &input[polynomial_size - remaining_degree..],
            &input[..remaining_degree],
        );
        copy_with_neg_and_subtract(
            &mut output[remaining_degree..],
            &input[..polynomial_size - remaining_degree],
            &input[remaining_degree..],
        );
    }
}

/// Subtract the sum of the element-wise product between two lists of polynomials, to the output
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
/// # Panics
///
/// This function will panic in any of these situations:
/// - the lists are not of the same size
/// - the polynomial sizes are not the same
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let poly_list = PolynomialList::from_container(vec![100_u8, 20, 3, 4, 5, 6], PolynomialSize(3));
/// let bin_poly_list = PolynomialList::from_container(vec![0, 1, 1, 1, 0, 0], PolynomialSize(3));
/// let mut output = Polynomial::new(250_u8, PolynomialSize(3));
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
    assert_eq!(
        poly_list_1.polynomial_count(),
        poly_list_2.polynomial_count()
    );
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        polynomial_wrapping_sub_mul_assign(output, &poly_1, &poly_2);
    }
}

pub fn polynomial_wrapping_sub_multisum_assign_custom_mod<
    Scalar,
    OutputCont,
    InputCont1,
    InputCont2,
>(
    output: &mut Polynomial<OutputCont>,
    poly_list_1: &PolynomialList<InputCont1>,
    poly_list_2: &PolynomialList<InputCont2>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    assert_eq!(
        poly_list_1.polynomial_count(),
        poly_list_2.polynomial_count()
    );
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        polynomial_wrapping_sub_mul_assign_custom_mod(output, &poly_1, &poly_2, custom_modulus);
    }
}

fn polynomial_wrapping_sub_mul_schoolbook_assign<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    fn implementation<Scalar: UnsignedInteger>(
        mut output: Polynomial<&mut [Scalar]>,
        lhs: Polynomial<&[Scalar]>,
        rhs: Polynomial<&[Scalar]>,
    ) {
        let polynomial_size = output.polynomial_size();
        let degree = output.degree();

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
    implementation(output.as_mut_view(), lhs.as_view(), rhs.as_view());
}

fn polynomial_wrapping_sub_mul_schoolbook_assign_custom_mod<
    Scalar,
    OutputCont,
    InputCont1,
    InputCont2,
>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    fn implementation<Scalar: UnsignedInteger>(
        mut output: Polynomial<&mut [Scalar]>,
        lhs: Polynomial<&[Scalar]>,
        rhs: Polynomial<&[Scalar]>,
        custom_modulus: Scalar,
    ) {
        let polynomial_size = output.polynomial_size();
        let degree = output.degree();
        for (lhs_degree, &lhs_coeff) in lhs.iter().enumerate() {
            for (rhs_degree, &rhs_coeff) in rhs.iter().enumerate() {
                let target_degree = lhs_degree + rhs_degree;
                if target_degree <= degree {
                    let output_coefficient = &mut output.as_mut()[target_degree];

                    *output_coefficient = (*output_coefficient).wrapping_sub_custom_mod(
                        lhs_coeff.wrapping_mul_custom_mod(rhs_coeff, custom_modulus),
                        custom_modulus,
                    );
                } else {
                    let target_degree = target_degree % polynomial_size.0;
                    let output_coefficient = &mut output.as_mut()[target_degree];

                    *output_coefficient = (*output_coefficient).wrapping_add_custom_mod(
                        lhs_coeff.wrapping_mul_custom_mod(rhs_coeff, custom_modulus),
                        custom_modulus,
                    );
                }
            }
        }
    }
    implementation(
        output.as_mut_view(),
        lhs.as_view(),
        rhs.as_view(),
        custom_modulus,
    );
}

/// Subtract the result of the product between two polynomials, reduced modulo $(X^{N}+1)$, to the
/// output polynomial.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `output`, `lhs` and `rhs` do not have the same polynomial size.
///
/// # Example
///
/// ```rust
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

    let polynomial_size = output.polynomial_size();

    if polynomial_size.0.is_power_of_two() && polynomial_size.0 > KARATUSBA_STOP {
        let mut tmp = Polynomial::new(Scalar::ZERO, polynomial_size);

        polynomial_karatsuba_wrapping_mul(&mut tmp, lhs, rhs);
        polynomial_wrapping_sub_assign(output, &tmp);
    } else {
        polynomial_wrapping_sub_mul_schoolbook_assign(output, lhs, rhs);
    }
}

pub fn polynomial_wrapping_sub_mul_assign_custom_mod<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
    custom_modulus: Scalar,
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

    let polynomial_size = output.polynomial_size();

    if polynomial_size.0.is_power_of_two() && polynomial_size.0 > KARATUSBA_STOP {
        let mut tmp = Polynomial::new(Scalar::ZERO, polynomial_size);

        polynomial_karatsuba_wrapping_mul_custom_mod(&mut tmp, lhs, rhs, custom_modulus);
        polynomial_wrapping_sub_assign_custom_mod(output, &tmp, custom_modulus);
    } else {
        polynomial_wrapping_sub_mul_schoolbook_assign_custom_mod(output, lhs, rhs, custom_modulus)
    }
}

pub fn polynomial_list_wrapping_sub_mul_assign<Scalar, InputCont, OutputCont, PolyCont>(
    output_poly_list: &mut PolynomialList<OutputCont>,
    input_poly_list: &PolynomialList<InputCont>,
    scalar_poly: &Polynomial<PolyCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    PolyCont: Container<Element = Scalar>,
{
    assert_eq!(
        output_poly_list.polynomial_size(),
        input_poly_list.polynomial_size()
    );
    assert_eq!(
        output_poly_list.polynomial_count(),
        input_poly_list.polynomial_count()
    );
    for (mut output_poly, input_poly) in output_poly_list.iter_mut().zip_eq(input_poly_list.iter())
    {
        polynomial_wrapping_sub_mul_assign(&mut output_poly, &input_poly, scalar_poly)
    }
}

pub fn polynomial_list_wrapping_sub_mul_assign_custom_mod<Scalar, InputCont, OutputCont, PolyCont>(
    output_poly_list: &mut PolynomialList<OutputCont>,
    input_poly_list: &PolynomialList<InputCont>,
    scalar_poly: &Polynomial<PolyCont>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    PolyCont: Container<Element = Scalar>,
{
    assert_eq!(
        output_poly_list.polynomial_size(),
        input_poly_list.polynomial_size()
    );
    assert_eq!(
        output_poly_list.polynomial_count(),
        input_poly_list.polynomial_count()
    );
    for (mut output_poly, input_poly) in output_poly_list.iter_mut().zip_eq(input_poly_list.iter())
    {
        polynomial_wrapping_sub_mul_assign_custom_mod(
            &mut output_poly,
            &input_poly,
            scalar_poly,
            custom_modulus,
        )
    }
}

/// Fill the output polynomial, with the result of the product of two polynomials, reduced modulo
/// $(X^{N} + 1)$ with the schoolbook algorithm Complexity: $O(N^{2})$
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let lhs = Polynomial::from_container(vec![4_u8, 5, 0]);
/// let rhs = Polynomial::from_container(vec![7_u8, 9, 0]);
/// let mut output = Polynomial::new(2u8, PolynomialSize(3));
/// polynomial_wrapping_mul(&mut output, &lhs, &rhs);
/// assert_eq!(output.as_ref(), &[28, 71, 45]);
/// ```
pub fn polynomial_wrapping_mul<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<LhsCont>,
    rhs: &Polynomial<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    output.as_mut().fill(Scalar::ZERO);
    polynomial_wrapping_add_mul_assign(output, lhs, rhs);
}

/// Fill the output polynomial, with the result of the product of two polynomials, reduced modulo
/// $(X^{N} + 1)$ with the Karatsuba algorithm Complexity: $O(N^{1.58})$
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Panics
///
/// This function will panic if `output`, `lhs` and `rhs` do not have the same polynomial size.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::parameters::*;
/// use tfhe::core_crypto::entities::*;
/// let lhs = Polynomial::from_container(vec![1_u32; 128]);
/// let rhs = Polynomial::from_container(vec![2_u32; 128]);
/// let mut res_kara = Polynomial::new(0u32, PolynomialSize(128));
/// let mut res_mul = Polynomial::new(0u32, PolynomialSize(128));
/// polynomial_karatsuba_wrapping_mul(&mut res_kara, &lhs, &rhs);
/// polynomial_wrapping_mul(&mut res_mul, &lhs, &rhs);
/// assert_eq!(res_kara, res_mul);
/// ```
pub fn polynomial_karatsuba_wrapping_mul<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut Polynomial<OutputCont>,
    p: &Polynomial<LhsCont>,
    q: &Polynomial<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    // check same dimensions
    assert!(
        output.polynomial_size() == p.polynomial_size(),
        "Output polynomial size {:?} is not the same as input lhs polynomial {:?}.",
        output.polynomial_size(),
        p.polynomial_size(),
    );
    assert!(
        output.polynomial_size() == q.polynomial_size(),
        "Output polynomial size {:?} is not the same as input rhs polynomial {:?}.",
        output.polynomial_size(),
        q.polynomial_size(),
    );

    let poly_size = output.polynomial_size().0;

    // check dimensions are a power of 2
    assert!(poly_size.is_power_of_two());

    // allocate slices for the rec
    let mut a0 = vec![Scalar::ZERO; poly_size];
    let mut a1 = vec![Scalar::ZERO; poly_size];
    let mut a2 = vec![Scalar::ZERO; poly_size];
    let mut input_a2_p = vec![Scalar::ZERO; poly_size / 2];
    let mut input_a2_q = vec![Scalar::ZERO; poly_size / 2];

    // prepare for splitting
    let bottom = 0..(poly_size / 2);
    let top = (poly_size / 2)..poly_size;

    // induction
    induction_karatsuba(&mut a0, &p[bottom.clone()], &q[bottom.clone()]);
    induction_karatsuba(&mut a1, &p[top.clone()], &q[top.clone()]);
    slice_wrapping_add(&mut input_a2_p, &p[bottom.clone()], &p[top.clone()]);
    slice_wrapping_add(&mut input_a2_q, &q[bottom.clone()], &q[top.clone()]);
    induction_karatsuba(&mut a2, &input_a2_p, &input_a2_q);

    // rebuild the result
    let output: &mut [Scalar] = output.as_mut();
    slice_wrapping_sub(output, &a0, &a1);
    slice_wrapping_sub_assign(&mut output[bottom.clone()], &a2[top.clone()]);
    slice_wrapping_add_assign(&mut output[bottom.clone()], &a0[top.clone()]);
    slice_wrapping_add_assign(&mut output[bottom.clone()], &a1[top.clone()]);
    slice_wrapping_add_assign(&mut output[top.clone()], &a2[bottom.clone()]);
    slice_wrapping_sub_assign(&mut output[top.clone()], &a0[bottom.clone()]);
    slice_wrapping_sub_assign(&mut output[top], &a1[bottom]);
}

const KARATUSBA_STOP: usize = 64;
/// Compute the induction for the karatsuba algorithm.
fn induction_karatsuba<Scalar>(res: &mut [Scalar], p: &[Scalar], q: &[Scalar])
where
    Scalar: UnsignedInteger,
{
    // stop the induction when polynomials have KARATUSBA_STOP elements
    if p.len() <= KARATUSBA_STOP {
        // schoolbook algorithm
        for (lhs_degree, &lhs_elt) in p.iter().enumerate() {
            let res = &mut res[lhs_degree..];
            for (&rhs_elt, res) in q.iter().zip(res) {
                *res = (*res).wrapping_add(lhs_elt.wrapping_mul(rhs_elt));
            }
        }
    } else {
        let poly_size = res.len();

        // allocate slices for the rec
        let mut a0 = vec![Scalar::ZERO; poly_size / 2];
        let mut a1 = vec![Scalar::ZERO; poly_size / 2];
        let mut a2 = vec![Scalar::ZERO; poly_size / 2];
        let mut input_a2_p = vec![Scalar::ZERO; poly_size / 4];
        let mut input_a2_q = vec![Scalar::ZERO; poly_size / 4];

        // prepare for splitting
        let bottom = 0..(poly_size / 4);
        let top = (poly_size / 4)..(poly_size / 2);

        // rec
        induction_karatsuba(&mut a0, &p[bottom.clone()], &q[bottom.clone()]);
        induction_karatsuba(&mut a1, &p[top.clone()], &q[top.clone()]);
        slice_wrapping_add(&mut input_a2_p, &p[bottom.clone()], &p[top.clone()]);
        slice_wrapping_add(&mut input_a2_q, &q[bottom], &q[top]);
        induction_karatsuba(&mut a2, &input_a2_p, &input_a2_q);

        // rebuild the result
        slice_wrapping_sub(&mut res[(poly_size / 4)..(3 * poly_size / 4)], &a2, &a0);
        slice_wrapping_sub_assign(&mut res[(poly_size / 4)..(3 * poly_size / 4)], &a1);
        slice_wrapping_add_assign(&mut res[0..(poly_size / 2)], &a0);
        slice_wrapping_add_assign(&mut res[(poly_size / 2)..poly_size], &a1);
    }
}

pub fn polynomial_karatsuba_wrapping_mul_custom_mod<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut Polynomial<OutputCont>,
    p: &Polynomial<LhsCont>,
    q: &Polynomial<RhsCont>,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    // check same dimensions
    assert!(
        output.polynomial_size() == p.polynomial_size(),
        "Output polynomial size {:?} is not the same as input lhs polynomial {:?}.",
        output.polynomial_size(),
        p.polynomial_size(),
    );
    assert!(
        output.polynomial_size() == q.polynomial_size(),
        "Output polynomial size {:?} is not the same as input rhs polynomial {:?}.",
        output.polynomial_size(),
        q.polynomial_size(),
    );

    let poly_size = output.polynomial_size().0;

    // check dimensions are a power of 2
    assert!(poly_size.is_power_of_two());

    // allocate slices for the rec
    let mut a0 = vec![Scalar::ZERO; poly_size];
    let mut a1 = vec![Scalar::ZERO; poly_size];
    let mut a2 = vec![Scalar::ZERO; poly_size];
    let mut input_a2_p = vec![Scalar::ZERO; poly_size / 2];
    let mut input_a2_q = vec![Scalar::ZERO; poly_size / 2];

    // prepare for splitting
    let bottom = 0..(poly_size / 2);
    let top = (poly_size / 2)..poly_size;

    // induction
    induction_karatsuba_custom_mod(
        &mut a0,
        &p[bottom.clone()],
        &q[bottom.clone()],
        custom_modulus,
    );
    induction_karatsuba_custom_mod(&mut a1, &p[top.clone()], &q[top.clone()], custom_modulus);
    slice_wrapping_add_custom_mod(
        &mut input_a2_p,
        &p[bottom.clone()],
        &p[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_custom_mod(
        &mut input_a2_q,
        &q[bottom.clone()],
        &q[top.clone()],
        custom_modulus,
    );
    induction_karatsuba_custom_mod(&mut a2, &input_a2_p, &input_a2_q, custom_modulus);

    // rebuild the result
    let output: &mut [Scalar] = output.as_mut();
    slice_wrapping_sub_custom_mod(output, &a0, &a1, custom_modulus);
    slice_wrapping_sub_assign_custom_mod(
        &mut output[bottom.clone()],
        &a2[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_assign_custom_mod(
        &mut output[bottom.clone()],
        &a0[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_assign_custom_mod(
        &mut output[bottom.clone()],
        &a1[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_assign_custom_mod(
        &mut output[top.clone()],
        &a2[bottom.clone()],
        custom_modulus,
    );
    slice_wrapping_sub_assign_custom_mod(
        &mut output[top.clone()],
        &a0[bottom.clone()],
        custom_modulus,
    );
    slice_wrapping_sub_assign_custom_mod(&mut output[top], &a1[bottom], custom_modulus);
}

fn induction_karatsuba_custom_mod<Scalar>(
    res: &mut [Scalar],
    p: &[Scalar],
    q: &[Scalar],
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
{
    // stop the induction when polynomials have KARATUSBA_STOP elements
    if p.len() <= KARATUSBA_STOP {
        // schoolbook algorithm
        for (lhs_degree, &lhs_elt) in p.iter().enumerate() {
            let res = &mut res[lhs_degree..];
            for (&rhs_elt, res) in q.iter().zip(res) {
                *res = (*res).wrapping_add_custom_mod(
                    lhs_elt.wrapping_mul_custom_mod(rhs_elt, custom_modulus),
                    custom_modulus,
                )
            }
        }
    } else {
        let poly_size = res.len();

        // allocate slices for the rec
        let mut a0 = vec![Scalar::ZERO; poly_size / 2];
        let mut a1 = vec![Scalar::ZERO; poly_size / 2];
        let mut a2 = vec![Scalar::ZERO; poly_size / 2];
        let mut input_a2_p = vec![Scalar::ZERO; poly_size / 4];
        let mut input_a2_q = vec![Scalar::ZERO; poly_size / 4];

        // prepare for splitting
        let bottom = 0..(poly_size / 4);
        let top = (poly_size / 4)..(poly_size / 2);

        // rec
        induction_karatsuba_custom_mod(
            &mut a0,
            &p[bottom.clone()],
            &q[bottom.clone()],
            custom_modulus,
        );
        induction_karatsuba_custom_mod(&mut a1, &p[top.clone()], &q[top.clone()], custom_modulus);
        slice_wrapping_add_custom_mod(
            &mut input_a2_p,
            &p[bottom.clone()],
            &p[top.clone()],
            custom_modulus,
        );
        slice_wrapping_add_custom_mod(&mut input_a2_q, &q[bottom], &q[top], custom_modulus);
        induction_karatsuba_custom_mod(&mut a2, &input_a2_p, &input_a2_q, custom_modulus);

        // rebuild the result
        slice_wrapping_sub_custom_mod(
            &mut res[(poly_size / 4)..(3 * poly_size / 4)],
            &a2,
            &a0,
            custom_modulus,
        );
        slice_wrapping_sub_assign_custom_mod(
            &mut res[(poly_size / 4)..(3 * poly_size / 4)],
            &a1,
            custom_modulus,
        );
        slice_wrapping_add_assign_custom_mod(&mut res[0..(poly_size / 2)], &a0, custom_modulus);
        slice_wrapping_add_assign_custom_mod(
            &mut res[(poly_size / 2)..poly_size],
            &a1,
            custom_modulus,
        );
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
        let mut rng = rand::rng();
        let mut generator = new_random_generator();

        // settings
        let polynomial_size = random_polynomial_size(2048);

        // generate a random Torus polynomial
        let mut poly = Polynomial::new(T::ZERO, polynomial_size);
        generator.fill_slice_with_random_uniform(poly.as_mut());

        let polynomial_size = polynomial_size.0;

        // copy this polynomial
        let ground_truth = poly.clone();

        // generate a random r
        let mut r: usize = rng.gen();
        r %= polynomial_size;

        // multiply by X^r and then divides by X^r
        polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(r));
        polynomial_wrapping_monic_monomial_div_assign(&mut poly, MonomialDegree(r));

        // test
        assert_eq!(&poly, &ground_truth);

        // generate a random r_big
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

    /// test if we have the same result when using schoolbook or karatsuba
    /// for random polynomial multiplication
    fn test_multiply_karatsuba<T: UnsignedTorus>() {
        // 50 times the test
        for _ in 0..50 {
            // random source
            let mut rng = rand::rng();

            // random settings settings
            let polynomial_log = (rng.gen::<usize>() % 7) + 6;
            let polynomial_size = PolynomialSize(1 << polynomial_log);
            let mut generator = new_random_generator();

            // generate two random Torus polynomials
            let mut poly_1 = Polynomial::new(T::ZERO, polynomial_size);
            generator.fill_slice_with_random_uniform::<T>(poly_1.as_mut());
            let poly_1 = poly_1;

            let mut poly_2 = Polynomial::new(T::ZERO, polynomial_size);
            generator.fill_slice_with_random_uniform::<T>(poly_2.as_mut());
            let poly_2 = poly_2;

            // copy this polynomial
            let mut sb_mul = Polynomial::new(T::ZERO, polynomial_size);
            let mut ka_mul = Polynomial::new(T::ZERO, polynomial_size);

            // compute the schoolbook
            polynomial_wrapping_add_mul_schoolbook_assign(&mut sb_mul, &poly_1, &poly_2);

            // compute the karatsuba
            polynomial_karatsuba_wrapping_mul(&mut ka_mul, &poly_1, &poly_2);

            // test
            assert_eq!(&sb_mul, &ka_mul);
        }
    }

    /// test if we have the same result when using schoolbook or ntt/karatsuba
    /// for random polynomial multiplication
    fn test_add_mul<T: UnsignedTorus>() {
        for polynomial_log in 4..=12 {
            for _ in 0..10 {
                let polynomial_size = PolynomialSize(1 << polynomial_log);
                let mut generator = new_random_generator();

                // generate two random Torus polynomials
                let mut poly_1 = Polynomial::new(T::ZERO, polynomial_size);
                generator.fill_slice_with_random_uniform::<T>(poly_1.as_mut());
                let poly_1 = poly_1;

                let mut poly_2 = Polynomial::new(T::ZERO, polynomial_size);
                generator.fill_slice_with_random_uniform::<T>(poly_2.as_mut());
                let poly_2 = poly_2;

                // copy this polynomial
                let mut sb_mul = Polynomial::new(T::ZERO, polynomial_size);
                let mut ka_mul = Polynomial::new(T::ZERO, polynomial_size);

                // compute the schoolbook
                polynomial_wrapping_add_mul_schoolbook_assign(&mut sb_mul, &poly_1, &poly_2);

                // compute the ntt/karatsuba
                polynomial_wrapping_add_mul_assign(&mut ka_mul, &poly_1, &poly_2);

                // test
                assert_eq!(&sb_mul, &ka_mul);
            }
        }
    }

    /// test if we have the same result when using schoolbook or ntt/karatsuba
    /// for random polynomial multiplication
    fn test_sub_mul<T: UnsignedTorus>() {
        for polynomial_log in 4..=12 {
            for _ in 0..10 {
                let polynomial_size = PolynomialSize(1 << polynomial_log);
                let mut generator = new_random_generator();

                // generate two random Torus polynomials
                let mut poly_1 = Polynomial::new(T::ZERO, polynomial_size);
                generator.fill_slice_with_random_uniform::<T>(poly_1.as_mut());
                let poly_1 = poly_1;

                let mut poly_2 = Polynomial::new(T::ZERO, polynomial_size);
                generator.fill_slice_with_random_uniform::<T>(poly_2.as_mut());
                let poly_2 = poly_2;

                // copy this polynomial
                let mut sb_mul = Polynomial::new(T::ZERO, polynomial_size);
                let mut ka_mul = Polynomial::new(T::ZERO, polynomial_size);

                // compute the schoolbook
                polynomial_wrapping_sub_mul_schoolbook_assign(&mut sb_mul, &poly_1, &poly_2);

                // compute the ntt/karatsuba
                polynomial_wrapping_sub_mul_assign(&mut ka_mul, &poly_1, &poly_2);

                // test
                assert_eq!(&sb_mul, &ka_mul);
            }
        }
    }

    #[test]
    pub fn test_multiply_divide_unit_monomial_u32() {
        test_multiply_divide_unit_monomial::<u32>();
    }

    #[test]
    pub fn test_multiply_divide_unit_monomial_u64() {
        test_multiply_divide_unit_monomial::<u64>();
    }

    #[test]
    pub fn test_multiply_karatsuba_u32() {
        test_multiply_karatsuba::<u32>();
    }

    #[test]
    pub fn test_multiply_karatsuba_u64() {
        test_multiply_karatsuba::<u64>();
    }

    #[test]
    pub fn test_add_mul_u32() {
        test_add_mul::<u32>();
    }

    #[test]
    pub fn test_add_mul_u64() {
        test_add_mul::<u64>();
    }

    #[test]
    pub fn test_sub_mul_u32() {
        test_sub_mul::<u32>();
    }

    #[test]
    pub fn test_sub_mul_u64() {
        test_sub_mul::<u64>();
    }
}
