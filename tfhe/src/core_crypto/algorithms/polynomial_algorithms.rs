#![allow(deprecated)] // For MonomialDegree for now
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::polynomial::MonomialDegree;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn update_polynomial_with_wrapping_add<Scalar, OutputCont, InputCont>(
    lhs: &mut PolynomialBase<OutputCont>,
    rhs: &PolynomialBase<InputCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(lhs.polynomial_size() == rhs.polynomial_size());
    update_with_wrapping_add(lhs.as_mut(), rhs.as_ref())
}

pub fn update_polynomial_with_wrapping_add_multisum<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut PolynomialBase<OutputCont>,
    poly_list_1: &PolynomialListBase<InputCont1>,
    poly_list_2: &PolynomialListBase<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        update_polynomial_with_wrapping_add_mul(output, &poly_1, &poly_2);
    }
}

pub fn update_polynomial_with_wrapping_add_mul<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut PolynomialBase<OutputCont>,
    lhs: &PolynomialBase<InputCont1>,
    rhs: &PolynomialBase<InputCont2>,
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

pub fn update_polynomial_with_wrapping_unit_monomial_div<Scalar, OutputCont>(
    output: &mut PolynomialBase<OutputCont>,
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

pub fn update_polynomial_with_wrapping_monic_monomial_mul<Scalar, OutputCont>(
    output: &mut PolynomialBase<OutputCont>,
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

pub fn update_polynomial_with_wrapping_sub_multisum<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut PolynomialBase<OutputCont>,
    poly_list_1: &PolynomialListBase<InputCont1>,
    poly_list_2: &PolynomialListBase<InputCont2>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont1: Container<Element = Scalar>,
    InputCont2: Container<Element = Scalar>,
{
    for (poly_1, poly_2) in poly_list_1.iter().zip(poly_list_2.iter()) {
        update_polynomial_with_wrapping_sub_mul(output, &poly_1, &poly_2);
    }
}

pub fn update_polynomial_with_wrapping_sub_mul<Scalar, OutputCont, InputCont1, InputCont2>(
    output: &mut PolynomialBase<OutputCont>,
    lhs: &PolynomialBase<InputCont1>,
    rhs: &PolynomialBase<InputCont2>,
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
