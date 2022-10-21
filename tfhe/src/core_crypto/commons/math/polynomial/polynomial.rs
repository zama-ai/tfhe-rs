use crate::core_crypto::commons::math::tensor::Container;
use std::fmt::Debug;
use std::iter::Iterator;

use crate::core_crypto::commons::math::tensor::{
    ck_dim_eq, tensor_traits, AsMutSlice, AsMutTensor, AsRefTensor, Tensor,
};

use super::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::prelude::{MonomialDegree, PolynomialSize};

// stop the induction when polynomials have KARATUSBA_STOP elements
const KARATUSBA_STOP: usize = 32;

/// A dense polynomial.
///
/// This type represent a dense polynomial in $\mathbb{Z}\_{2^q}\[X\] / <X^N + 1>$, composed of $N$
/// integer coefficients encoded on $q$ bits.
///
///  # Example:
///
/// ```
/// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
/// use tfhe::core_crypto::prelude::PolynomialSize;
/// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
/// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
/// ```
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Polynomial<Cont> {
    pub(crate) tensor: Tensor<Cont>,
}

tensor_traits!(Polynomial);

impl<Scalar> Polynomial<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a new polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn allocate(value: Scalar, coef_count: PolynomialSize) -> Polynomial<Vec<Scalar>> {
        Polynomial::from_container(vec![value; coef_count.0])
    }
}

impl<Cont> Polynomial<Cont> {
    /// Creates a polynomial from a container of values.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let vec = vec![0 as u32; 100];
    /// let poly = Polynomial::from_container(vec.as_slice());
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn from_container(cont: Cont) -> Self {
        Polynomial {
            tensor: Tensor::from_container(cont),
        }
    }

    pub(crate) fn from_tensor(tensor: Tensor<Cont>) -> Self {
        Polynomial { tensor }
    }

    pub fn as_view(&self) -> Polynomial<&'_ [Cont::Element]>
    where
        Cont: Container,
    {
        Polynomial {
            tensor: Tensor::from_container(self.tensor.as_container().as_ref()),
        }
    }

    pub fn as_mut_view(&mut self) -> Polynomial<&'_ mut [Cont::Element]>
    where
        Cont: Container,
        Cont: AsMut<[Cont::Element]>,
    {
        Polynomial {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut()),
        }
    }

    /// Returns the number of coefficients in the polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize
    where
        Self: AsRefTensor,
    {
        PolynomialSize(self.as_tensor().len())
    }

    /// Builds an iterator over `Monomial<&Coef>` elements.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for monomial in poly.monomial_iter() {
    ///     assert!(monomial.degree().0 <= 99)
    /// }
    /// assert_eq!(poly.monomial_iter().count(), 100);
    /// ```
    pub fn monomial_iter(&self) -> impl Iterator<Item = Monomial<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(1)
            .enumerate()
            .map(|(i, coef)| Monomial::from_container(coef.into_container(), MonomialDegree(i)))
    }

    /// Builds an iterator over `&Coef` elements, in order of increasing degree.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for coef in poly.coefficient_iter() {
    ///     assert_eq!(*coef, 0);
    /// }
    /// assert_eq!(poly.coefficient_iter().count(), 100);
    /// ```
    pub fn coefficient_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = &<Self as AsRefTensor>::Element>
    where
        Self: AsRefTensor,
    {
        self.as_tensor().iter()
    }

    /// Returns the monomial of a given degree.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let poly = Polynomial::from_container(vec![16_u32, 8, 19, 12, 3]);
    /// let mono = poly.get_monomial(MonomialDegree(0));
    /// assert_eq!(*mono.get_coefficient(), 16_u32);
    /// let mono = poly.get_monomial(MonomialDegree(2));
    /// assert_eq!(*mono.get_coefficient(), 19_u32);
    /// ```
    pub fn get_monomial(
        &self,
        degree: MonomialDegree,
    ) -> Monomial<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        Monomial::from_container(
            self.as_tensor()
                .get_sub(degree.0..=degree.0)
                .into_container(),
            degree,
        )
    }

    /// Builds an iterator over `Monomial<&mut Coef>` elements.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let mut poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for mut monomial in poly.monomial_iter_mut() {
    ///     monomial.set_coefficient(monomial.degree().0 as u32);
    /// }
    /// for (i, monomial) in poly.monomial_iter().enumerate() {
    ///     assert_eq!(*monomial.get_coefficient(), i as u32);
    /// }
    /// assert_eq!(poly.monomial_iter_mut().count(), 100);
    /// ```
    pub fn monomial_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = Monomial<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        self.as_mut_tensor()
            .subtensor_iter_mut(1)
            .enumerate()
            .map(|(i, coef)| Monomial::from_container(coef.into_container(), MonomialDegree(i)))
    }

    /// Builds an iterator over `&mut Coef` elements, in order of increasing
    /// degree.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let mut poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for mut coef in poly.coefficient_iter_mut() {
    ///     *coef = 1;
    /// }
    /// for coef in poly.coefficient_iter() {
    ///     assert_eq!(*coef, 1);
    /// }
    /// assert_eq!(poly.coefficient_iter_mut().count(), 100);
    /// ```
    pub fn coefficient_iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = &mut <Self as AsMutTensor>::Element>
    where
        Self: AsMutTensor,
    {
        self.as_mut_tensor().iter_mut()
    }

    /// Returns the mutable monomial of a given degree.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let mut poly = Polynomial::from_container(vec![16_u32, 8, 19, 12, 3]);
    /// let mut mono = poly.get_mut_monomial(MonomialDegree(0));
    /// mono.set_coefficient(18);
    /// let mono = poly.get_monomial(MonomialDegree(0));
    /// assert_eq!(*mono.get_coefficient(), 18);
    /// ```
    pub fn get_mut_monomial(
        &mut self,
        degree: MonomialDegree,
    ) -> Monomial<&mut [<Self as AsMutTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        Monomial::from_container(
            self.as_mut_tensor()
                .get_sub_mut(degree.0..=degree.0)
                .into_container(),
            degree,
        )
    }

    /// Fills the current polynomial, with the result of the (slow) product of
    /// two polynomials, reduced modulo $(X^N + 1)$.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let lhs = Polynomial::from_container(vec![4_u8, 5, 0]);
    /// let rhs = Polynomial::from_container(vec![7_u8, 9, 0]);
    /// let mut res = Polynomial::allocate(0 as u8, PolynomialSize(3));
    /// res.fill_with_wrapping_mul(&lhs, &rhs);
    /// assert_eq!(
    ///     *res.get_monomial(MonomialDegree(0)).get_coefficient(),
    ///     28 as u8
    /// );
    /// assert_eq!(
    ///     *res.get_monomial(MonomialDegree(1)).get_coefficient(),
    ///     71 as u8
    /// );
    /// assert_eq!(
    ///     *res.get_monomial(MonomialDegree(2)).get_coefficient(),
    ///     45 as u8
    /// );
    /// ```
    pub fn fill_with_wrapping_mul<Coef, LhsCont, RhsCont>(
        &mut self,
        lhs: &Polynomial<LhsCont>,
        rhs: &Polynomial<RhsCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<LhsCont>: AsRefTensor<Element = Coef>,
        Polynomial<RhsCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(self.polynomial_size() => lhs.polynomial_size(), rhs.polynomial_size());
        self.coefficient_iter_mut().for_each(|a| *a = Coef::ZERO);
        let degree = lhs.polynomial_size().0 - 1;
        for lhsi in lhs.monomial_iter() {
            for rhsi in rhs.monomial_iter() {
                let target_degree = lhsi.degree().0 + rhsi.degree().0;
                if target_degree <= degree {
                    let element = self.as_mut_tensor().get_element_mut(target_degree);
                    let new = lhsi.get_coefficient().wrapping_mul(*rhsi.get_coefficient());
                    *element = element.wrapping_add(new);
                } else {
                    let element = self
                        .as_mut_tensor()
                        .get_element_mut(target_degree % (degree + 1));
                    let new = lhsi.get_coefficient().wrapping_mul(*rhsi.get_coefficient());
                    *element = element.wrapping_sub(new);
                }
            }
        }
    }

    /// Fills the current polynomial, with the result of the product of two
    /// polynomials, reduced modulo $(X^N + 1)$ with the Karatsuba algorithm
    /// Complexity: N^{1.58}
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let lhs = Polynomial::from_container(vec![1_u32; 128]);
    /// let rhs = Polynomial::from_container(vec![2_u32; 128]);
    /// let mut res_kara = Polynomial::allocate(0 as u32, PolynomialSize(128));
    /// let mut res_mul = Polynomial::allocate(0 as u32, PolynomialSize(128));
    /// res_kara.fill_with_karatsuba_mul(&lhs, &rhs);
    /// res_mul.fill_with_wrapping_mul(&lhs, &rhs);
    /// assert_eq!(res_kara, res_mul);
    /// ```
    pub fn fill_with_karatsuba_mul<Coef, LhsCont, RhsCont>(
        &mut self,
        p: &Polynomial<LhsCont>,
        q: &Polynomial<RhsCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<LhsCont>: AsRefTensor<Element = Coef>,
        Polynomial<RhsCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        // check same dimensions
        ck_dim_eq!(self.polynomial_size() => p.polynomial_size(), q.polynomial_size());

        // check dimensions are a power of 2
        debug_assert!(
            f64::abs(
                f64::floor(f64::log2(p.polynomial_size().0 as f64))
                    - f64::log2(p.polynomial_size().0 as f64)
            ) < f64::EPSILON
        );

        let poly_size = self.polynomial_size().0;

        // allocate slices for the rec
        let mut a0 = Tensor::allocate(Coef::ZERO, poly_size);
        let mut a1 = Tensor::allocate(Coef::ZERO, poly_size);
        let mut a2 = Tensor::allocate(Coef::ZERO, poly_size);
        let mut input_a2_p = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut input_a2_q = Tensor::allocate(Coef::ZERO, poly_size / 2);

        // prepare for splitting
        let bottom = 0..(poly_size / 2);
        let top = (poly_size / 2)..poly_size;

        // induction
        induction_karatsuba(
            &mut a0.get_sub_mut(..),
            &p.as_tensor().get_sub(bottom.clone()),
            &q.as_tensor().get_sub(bottom.clone()),
        );
        induction_karatsuba(
            &mut a1.get_sub_mut(..),
            &p.as_tensor().get_sub(top.clone()),
            &q.as_tensor().get_sub(top.clone()),
        );
        input_a2_p.fill_with_wrapping_add(
            &p.as_tensor().get_sub(bottom.clone()),
            &p.as_tensor().get_sub(top.clone()),
        );
        input_a2_q.fill_with_wrapping_add(
            &q.as_tensor().get_sub(bottom.clone()),
            &q.as_tensor().get_sub(top.clone()),
        );
        induction_karatsuba(
            &mut a2.get_sub_mut(..),
            &input_a2_p.get_sub(..),
            &input_a2_q.get_sub(..),
        );

        // rebuild the result
        self.as_mut_tensor().fill_with_wrapping_sub(&a0, &a1);
        self.as_mut_tensor()
            .get_sub_mut(bottom.clone())
            .update_with_wrapping_sub(&a2.get_sub(top.clone()));
        self.as_mut_tensor()
            .get_sub_mut(bottom.clone())
            .update_with_wrapping_add(&a0.get_sub(top.clone()));
        self.as_mut_tensor()
            .get_sub_mut(bottom.clone())
            .update_with_wrapping_add(&a1.get_sub(top.clone()));
        self.as_mut_tensor()
            .get_sub_mut(top.clone())
            .update_with_wrapping_add(&a2.get_sub(bottom.clone()));
        self.as_mut_tensor()
            .get_sub_mut(top.clone())
            .update_with_wrapping_sub(&a0.get_sub(bottom.clone()));
        self.as_mut_tensor()
            .get_sub_mut(top)
            .update_with_wrapping_sub(&a1.get_sub(bottom));
    }

    /// Adds the sum of the element-wise product between two lists of integer polynomial to the
    /// current polynomial.
    ///
    /// I.e., if the current polynomial is $C(X)$, for a collection of polynomials $(P\_i(X)))\_i$
    /// and another collection of polynomials $(B\_i(X))\_i$ we perform the operation:
    /// $$
    /// C(X) := C(X) + \sum\_i P\_i(X) \times B\_i(X) mod (X^N + 1)
    /// $$
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial, PolynomialList,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let poly_list = PolynomialList::from_container(vec![100_u8, 20, 3, 4, 5, 6], PolynomialSize(3));
    /// let bin_poly_list = PolynomialList::from_container(vec![0, 1, 1, 1, 0, 0], PolynomialSize(3));
    /// let mut output = Polynomial::allocate(250, PolynomialSize(3));
    /// output.update_with_wrapping_add_multisum(&poly_list, &bin_poly_list);
    /// assert_eq!(
    ///     *output.get_monomial(MonomialDegree(0)).get_coefficient(),
    ///     231
    /// );
    /// assert_eq!(
    ///     *output.get_monomial(MonomialDegree(1)).get_coefficient(),
    ///     96
    /// );
    /// assert_eq!(
    ///     *output.get_monomial(MonomialDegree(2)).get_coefficient(),
    ///     120
    /// );
    /// ```
    pub fn update_with_wrapping_add_multisum<Coef, Cont1, Cont2>(
        &mut self,
        coef_list: &PolynomialList<Cont1>,
        bin_list: &PolynomialList<Cont2>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<Cont1>: AsRefTensor<Element = Coef>,
        PolynomialList<Cont2>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for (poly, bin_poly) in coef_list.polynomial_iter().zip(bin_list.polynomial_iter()) {
            self.update_with_wrapping_add_mul(&poly, &bin_poly);
        }
    }

    /// Subtracts the sum of the element-wise product between two lists of integer polynomials,
    /// to the current polynomial.
    ///
    /// I.e., if the current polynomial is $C(X)$, for two lists of polynomials $(P\_i(X)))\_i$ and
    /// $(B\_i(X))\_i$ we perform the operation:
    /// $$
    /// C(X) := C(X) + \sum\_i P\_i(X) \times B\_i(X) mod (X^N + 1)
    /// $$
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial, PolynomialList,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let poly_list =
    ///     PolynomialList::from_container(vec![100 as u8, 20, 3, 4, 5, 6], PolynomialSize(3));
    /// let bin_poly_list = PolynomialList::from_container(vec![0, 1, 1, 1, 0, 0], PolynomialSize(3));
    /// let mut output = Polynomial::allocate(250 as u8, PolynomialSize(3));
    /// output.update_with_wrapping_sub_multisum(&poly_list, &bin_poly_list);
    /// assert_eq!(
    ///     *output.get_monomial(MonomialDegree(0)).get_coefficient(),
    ///     13
    /// );
    /// assert_eq!(
    ///     *output.get_monomial(MonomialDegree(1)).get_coefficient(),
    ///     148
    /// );
    /// assert_eq!(
    ///     *output.get_monomial(MonomialDegree(2)).get_coefficient(),
    ///     124
    /// );
    /// ```
    pub fn update_with_wrapping_sub_multisum<Coef, InCont, BinCont>(
        &mut self,
        coef_list: &PolynomialList<InCont>,
        bin_list: &PolynomialList<BinCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<InCont>: AsRefTensor<Element = Coef>,
        PolynomialList<BinCont>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for (poly, bin_poly) in coef_list.polynomial_iter().zip(bin_list.polynomial_iter()) {
            self.update_with_wrapping_sub_mul(&poly, &bin_poly);
        }
    }

    /// Adds the result of the product between two integer polynomials, reduced modulo $(X^N+1)$,
    /// to the current polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let poly_1 = Polynomial::from_container(vec![1_u8, 2, 3]);
    /// let poly_2 = Polynomial::from_container(vec![0, 1, 1]);
    /// let mut res = Polynomial::from_container(vec![1, 0, 253]);
    /// res.update_with_wrapping_add_mul(&poly_1, &poly_2);
    /// assert_eq!(*res.get_monomial(MonomialDegree(0)).get_coefficient(), 252);
    /// assert_eq!(*res.get_monomial(MonomialDegree(1)).get_coefficient(), 254);
    /// assert_eq!(*res.get_monomial(MonomialDegree(2)).get_coefficient(), 0);
    /// ```
    pub fn update_with_wrapping_add_mul<Coef, Cont1, Cont2>(
        &mut self,
        polynomial: &Polynomial<Cont1>,
        bin_polynomial: &Polynomial<Cont2>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<Cont1>: AsRefTensor<Element = Coef>,
        Polynomial<Cont2>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            polynomial.polynomial_size(),
            bin_polynomial.polynomial_size()
        );
        let degree = polynomial.polynomial_size().0 - 1;
        for lhsi in polynomial.monomial_iter() {
            for rhsi in bin_polynomial.monomial_iter() {
                let target_degree = lhsi.degree().0 + rhsi.degree().0;
                if target_degree <= degree {
                    let update = self
                        .as_tensor()
                        .get_element(target_degree)
                        .wrapping_add(*lhsi.get_coefficient() * *rhsi.get_coefficient());
                    *self.as_mut_tensor().get_element_mut(target_degree) = update;
                } else {
                    let update = self
                        .as_tensor()
                        .get_element(target_degree % (degree + 1))
                        .wrapping_sub(*lhsi.get_coefficient() * *rhsi.get_coefficient());
                    *self
                        .as_mut_tensor()
                        .get_element_mut(target_degree % (degree + 1)) = update;
                }
            }
        }
    }

    /// Subtracts the result of the product between two integer polynomials, reduced
    /// modulo $(X^N+1)$, to the current polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let poly = Polynomial::from_container(vec![1_u8, 2, 3]);
    /// let bin_poly = Polynomial::from_container(vec![0, 1, 1]);
    /// let mut res = Polynomial::from_container(vec![255, 255, 1]);
    /// res.update_with_wrapping_sub_mul(&poly, &bin_poly);
    /// assert_eq!(*res.get_monomial(MonomialDegree(0)).get_coefficient(), 4);
    /// assert_eq!(*res.get_monomial(MonomialDegree(1)).get_coefficient(), 1);
    /// assert_eq!(*res.get_monomial(MonomialDegree(2)).get_coefficient(), 254);
    /// ```
    pub fn update_with_wrapping_sub_mul<Coef, PolyCont, BinCont>(
        &mut self,
        polynomial: &Polynomial<PolyCont>,
        bin_polynomial: &Polynomial<BinCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<PolyCont>: AsRefTensor<Element = Coef>,
        Polynomial<BinCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            polynomial.polynomial_size(),
            bin_polynomial.polynomial_size()
        );
        let degree = polynomial.polynomial_size().0 - 1;
        for lhsi in polynomial.monomial_iter() {
            for rhsi in bin_polynomial.monomial_iter() {
                let target_degree = lhsi.degree().0 + rhsi.degree().0;
                if target_degree <= degree {
                    let update = self
                        .as_tensor()
                        .get_element(target_degree)
                        .wrapping_sub(*lhsi.get_coefficient() * *rhsi.get_coefficient());
                    *self.as_mut_tensor().get_element_mut(target_degree) = update;
                } else {
                    let update = self
                        .as_tensor()
                        .get_element(target_degree % (degree + 1))
                        .wrapping_add(*lhsi.get_coefficient() * *rhsi.get_coefficient());
                    *self
                        .as_mut_tensor()
                        .as_mut_slice()
                        .get_mut(target_degree % (degree + 1))
                        .unwrap() = update;
                }
            }
        }
    }

    /// Adds a integer polynomial to another one.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let mut first = Polynomial::from_container(vec![1u8, 2, 3]);
    /// let second = Polynomial::from_container(vec![255u8, 255, 255]);
    /// first.update_with_wrapping_add(&second);
    /// assert_eq!(*first.get_monomial(MonomialDegree(0)).get_coefficient(), 0);
    /// assert_eq!(*first.get_monomial(MonomialDegree(1)).get_coefficient(), 1);
    /// assert_eq!(*first.get_monomial(MonomialDegree(2)).get_coefficient(), 2);
    /// ```
    pub fn update_with_wrapping_add<Coef, OtherCont>(&mut self, other: &Polynomial<OtherCont>)
    where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<OtherCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            other.polynomial_size()
        );
        self.as_mut_tensor()
            .update_with_wrapping_add(other.as_tensor());
    }

    /// Subtracts an integer polynomial to another one.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let mut first = Polynomial::from_container(vec![1u8, 2, 3]);
    /// let second = Polynomial::from_container(vec![4u8, 5, 6]);
    /// first.update_with_wrapping_sub(&second);
    /// assert_eq!(
    ///     *first.get_monomial(MonomialDegree(0)).get_coefficient(),
    ///     253
    /// );
    /// assert_eq!(
    ///     *first.get_monomial(MonomialDegree(1)).get_coefficient(),
    ///     253
    /// );
    /// assert_eq!(
    ///     *first.get_monomial(MonomialDegree(2)).get_coefficient(),
    ///     253
    /// );
    /// ```
    pub fn update_with_wrapping_sub<Coef, OtherCont>(&mut self, other: &Polynomial<OtherCont>)
    where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<OtherCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            other.polynomial_size()
        );
        self.as_mut_tensor()
            .update_with_wrapping_sub(other.as_tensor());
    }

    /// Multiplies (mod $(X^N+1)$), the current polynomial with a monomial of a given degree, and
    /// a coefficient of one.
    ///
    /// # Examples
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let mut poly = Polynomial::from_container(vec![1u8, 2, 3]);
    /// poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(2));
    /// assert_eq!(*poly.get_monomial(MonomialDegree(0)).get_coefficient(), 254);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(1)).get_coefficient(), 253);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(2)).get_coefficient(), 1);
    /// ```
    pub fn update_with_wrapping_monic_monomial_mul<Coef>(&mut self, monomial_degree: MonomialDegree)
    where
        Self: AsMutTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        let full_cycles_count = monomial_degree.0 / self.as_tensor().len();
        if full_cycles_count % 2 != 0 {
            self.as_mut_tensor()
                .as_mut_slice()
                .iter_mut()
                .for_each(|a| *a = a.wrapping_neg());
        }
        let remaining_degree = monomial_degree.0 % self.as_tensor().len();
        self.as_mut_tensor()
            .as_mut_slice()
            .rotate_right(remaining_degree);
        self.as_mut_tensor()
            .as_mut_slice()
            .iter_mut()
            .take(remaining_degree)
            .for_each(|a| *a = a.wrapping_neg());
    }

    /// Divides (mod $(X^N+1)$), the current polynomial with a monomial of a given degree, and a
    /// coefficient of one.
    ///
    /// # Examples
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial,
    /// };
    /// let mut poly = Polynomial::from_container(vec![1u8, 2, 3]);
    /// poly.update_with_wrapping_unit_monomial_div(MonomialDegree(2));
    /// assert_eq!(*poly.get_monomial(MonomialDegree(0)).get_coefficient(), 3);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(1)).get_coefficient(), 255);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(2)).get_coefficient(), 254);
    /// ```
    pub fn update_with_wrapping_unit_monomial_div<Coef>(&mut self, monomial_degree: MonomialDegree)
    where
        Self: AsMutTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        let full_cycles_count = monomial_degree.0 / self.as_tensor().len();
        if full_cycles_count % 2 != 0 {
            self.as_mut_tensor()
                .as_mut_slice()
                .iter_mut()
                .for_each(|a| *a = a.wrapping_neg());
        }
        let remaining_degree = monomial_degree.0 % self.as_tensor().len();
        self.as_mut_tensor()
            .as_mut_slice()
            .rotate_left(remaining_degree);
        self.as_mut_tensor()
            .as_mut_slice()
            .iter_mut()
            .rev()
            .take(remaining_degree)
            .for_each(|a| *a = a.wrapping_neg());
    }

    /// Adds multiple integer polynomials to the current one.
    ///
    /// # Examples
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial, PolynomialList,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let mut poly = Polynomial::from_container(vec![1u8, 2, 3]);
    /// let poly_list = PolynomialList::from_container(vec![4u8, 5, 6, 7, 8, 9], PolynomialSize(3));
    /// poly.update_with_wrapping_add_several(&poly_list);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(0)).get_coefficient(), 12);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(1)).get_coefficient(), 15);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(2)).get_coefficient(), 18);
    /// ```
    pub fn update_with_wrapping_add_several<Coef, InCont>(
        &mut self,
        coef_list: &PolynomialList<InCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<InCont>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for poly in coef_list.polynomial_iter() {
            self.update_with_wrapping_add(&poly);
        }
    }

    /// Subtracts multiple integer polynomials to the current one.
    ///
    /// # Examples
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{
    ///     MonomialDegree, Polynomial, PolynomialList,
    /// };
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let mut poly = Polynomial::from_container(vec![1u32, 2, 3]);
    /// let poly_list = PolynomialList::from_container(vec![4u32, 5, 6, 7, 8, 9], PolynomialSize(3));
    /// poly.update_with_wrapping_sub_several(&poly_list);
    /// assert_eq!(
    ///     *poly.get_monomial(MonomialDegree(0)).get_coefficient(),
    ///     4294967286
    /// );
    /// assert_eq!(
    ///     *poly.get_monomial(MonomialDegree(1)).get_coefficient(),
    ///     4294967285
    /// );
    /// assert_eq!(
    ///     *poly.get_monomial(MonomialDegree(2)).get_coefficient(),
    ///     4294967284
    /// );
    /// ```
    pub fn update_with_wrapping_sub_several<Coef, InCont>(
        &mut self,
        coef_list: &PolynomialList<InCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<InCont>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for poly in coef_list.polynomial_iter() {
            self.update_with_wrapping_sub(&poly);
        }
    }
}

/// function used to compute the induction for the karatsuba algorithm
fn induction_karatsuba<Coef>(
    res: &mut Tensor<&mut [Coef]>,
    p: &Tensor<&[Coef]>,
    q: &Tensor<&[Coef]>,
) where
    Coef: UnsignedInteger,
{
    if p.len() == KARATUSBA_STOP {
        // schoolbook algorithm
        for i in 0..p.len() {
            for j in 0..q.len() {
                *res.get_element_mut(i + j) = res
                    .get_element(i + j)
                    .wrapping_add(p.get_element(i).wrapping_mul(*q.get_element(j)))
            }
        }
    } else {
        let poly_size = res.len();

        // allocate slices for the rec
        let mut a0 = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut a1 = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut a2 = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut input_a2_p = Tensor::allocate(Coef::ZERO, poly_size / 4);
        let mut input_a2_q = Tensor::allocate(Coef::ZERO, poly_size / 4);

        // prepare for splitting
        let bottom = 0..(poly_size / 4);
        let top = (poly_size / 4)..(poly_size / 2);

        // rec
        induction_karatsuba(
            &mut a0.get_sub_mut(..),
            &p.get_sub(bottom.clone()),
            &q.get_sub(bottom.clone()),
        );
        induction_karatsuba(
            &mut a1.get_sub_mut(..),
            &p.get_sub(top.clone()),
            &q.get_sub(top.clone()),
        );
        input_a2_p
            .as_mut_tensor()
            .fill_with_wrapping_add(&p.get_sub(bottom.clone()), &p.get_sub(top.clone()));
        input_a2_q
            .as_mut_tensor()
            .fill_with_wrapping_add(&q.get_sub(bottom), &q.get_sub(top));
        induction_karatsuba(
            &mut a2.get_sub_mut(..),
            &input_a2_p.get_sub(..),
            &input_a2_q.get_sub(..),
        );

        // rebuild the result
        res.get_sub_mut((poly_size / 4)..(3 * poly_size / 4))
            .as_mut_tensor()
            .fill_with_wrapping_sub(&a2, &a0);
        res.get_sub_mut((poly_size / 4)..(3 * poly_size / 4))
            .update_with_wrapping_sub(&a1);
        res.get_sub_mut(0..(poly_size / 2))
            .update_with_wrapping_add(&a0);
        res.get_sub_mut((poly_size / 2)..poly_size)
            .update_with_wrapping_add(&a1);
    }
}
