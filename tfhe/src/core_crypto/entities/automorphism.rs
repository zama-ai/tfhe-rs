use super::{GlweCiphertext, Polynomial};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::{
    CastFrom, Container, ContainerMut, ContiguousEntityContainer, ContiguousEntityContainerMut,
    PolynomialSize, UnsignedInteger,
};

pub struct Automorphism {
    power: usize,
    polynomial_size: PolynomialSize,
}

impl Automorphism {
    pub fn new(power: usize, polynomial_size: PolynomialSize) -> Self {
        Self {
            power,
            polynomial_size,
        }
    }

    /// Applies the automorphism to the input polynomial and store the result to the output
    ///
    /// ```rust
    /// use tfhe::core_crypto::entities::automorphism::Automorphism;
    /// use tfhe::core_crypto::prelude::{
    ///     CastFrom, Container, ContainerMut, Polynomial, PolynomialSize, UnsignedInteger,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(8);
    ///
    /// let in_polynomial = Polynomial::from_container(vec![0_u64, 1, 2, 3, 4, 5, 6, 7]);
    /// let mut out_polynomial = Polynomial::from_container(vec![0_u64; 8]);
    ///
    /// let automorphism = Automorphism::new(3, polynomial_size);
    ///
    /// automorphism.apply_to_polynomial(&in_polynomial, &mut out_polynomial);
    ///
    /// let expected_result = [
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    /// ];
    /// assert_eq!(out_polynomial.as_ref(), expected_result.as_slice());
    /// ```
    pub fn apply_to_polynomial<Scalar, InCont, OutCont>(
        &self,
        input: &Polynomial<InCont>,
        output: &mut Polynomial<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        let log_poly_size_minus_1 = self.polynomial_size.log2().0 - 1;

        let modular_mask = self.polynomial_size.0 - 1;

        let modular_sign_change_mask = self.polynomial_size.0;

        let output = output.as_mut();

        for (i, a) in input.as_ref().iter().enumerate() {
            let power = i * self.power;

            // = 0 if power does not change sign
            // = 2 if power does change sign
            let should_be_negated = (power & modular_sign_change_mask) >> log_poly_size_minus_1;

            // = 1 if power does not change sign
            // = -1 if power does change sign
            let sign = 1.wrapping_sub(should_be_negated);

            dbg!(sign);

            output[power & modular_mask] = Scalar::cast_from(sign).wrapping_mul(*a);
        }
    }

    /// Applies the automorphism to the input polynomial and store the result to the output
    ///
    /// ```rust
    /// use tfhe::core_crypto::entities::automorphism::Automorphism;
    /// use tfhe::core_crypto::prelude::{
    ///     CastFrom, CiphertextModulus, Container, ContainerMut, GlweCiphertext, GlweSize, Polynomial,
    ///     PolynomialSize, UnsignedInteger,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(8);
    /// let glwe_size = GlweSize(2);
    /// let ciphertetx_modulus = CiphertextModulus::new_native();
    ///
    /// let in_glwe = GlweCiphertext::from_container(
    ///     vec![0_u64, 1, 2, 3, 4, 5, 6, 7, 0_u64, 1, 2, 3, 4, 5, 6, 7],
    ///     polynomial_size,
    ///     ciphertetx_modulus,
    /// );
    /// let mut out_glwe =
    ///     GlweCiphertext::from_container(vec![0_u64; 16], polynomial_size, ciphertetx_modulus);
    ///
    /// let automorphism = Automorphism::new(3, polynomial_size);
    ///
    /// automorphism.apply_to_glwe_ciphertext(&in_glwe, &mut out_glwe);
    ///
    /// let expected_result = [
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    /// ];
    /// assert_eq!(out_glwe.as_ref(), expected_result.as_slice());
    /// ```
    pub fn apply_to_glwe_ciphertext<Scalar, InCont, OutCont>(
        &self,
        input: &GlweCiphertext<InCont>,
        output: &mut GlweCiphertext<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        for (i, mut j) in izip!(input.iter(), output.iter_mut()) {
            self.apply_to_polynomial(&i, &mut j);
        }
    }
}
