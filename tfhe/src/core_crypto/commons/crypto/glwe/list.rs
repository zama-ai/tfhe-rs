use super::GlweCiphertext;
use crate::core_crypto::commons::crypto::encoding::PlaintextList;
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::{
    CiphertextCount, GlweDimension, GlweSize, PlaintextCount, PolynomialSize,
};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A list of ciphertexts encoded with the GLWE scheme.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweList<Cont> {
    pub(crate) tensor: Tensor<Cont>,
    pub(crate) rlwe_size: GlweSize,
    pub(crate) poly_size: PolynomialSize,
}

tensor_traits!(GlweList);

impl<Scalar> GlweList<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates storage for an owned [`GlweList`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweList;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, GlweSize, PolynomialSize};
    /// let list = GlweList::allocate(
    ///     0 as u8,
    ///     PolynomialSize(10),
    ///     GlweDimension(20),
    ///     CiphertextCount(30),
    /// );
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(30));
    /// assert_eq!(list.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(list.glwe_size(), GlweSize(21));
    /// assert_eq!(list.glwe_dimension(), GlweDimension(20));
    /// ```
    pub fn allocate(
        value: Scalar,
        poly_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        ciphertext_number: CiphertextCount,
    ) -> Self {
        GlweList {
            tensor: Tensor::from_container(vec![
                value;
                poly_size.0
                    * (glwe_dimension.0 + 1)
                    * ciphertext_number.0
            ]),
            rlwe_size: GlweSize(glwe_dimension.0 + 1),
            poly_size,
        }
    }
}

impl<Cont> GlweList<Cont> {
    /// Creates a list from a container of values.
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweList;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, GlweSize, PolynomialSize};
    /// let list = GlweList::from_container(
    ///     vec![0 as u8; 10 * 21 * 30],
    ///     GlweDimension(20),
    ///     PolynomialSize(10),
    /// );
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(30));
    /// assert_eq!(list.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(list.glwe_size(), GlweSize(21));
    /// assert_eq!(list.glwe_dimension(), GlweDimension(20));
    /// ```
    pub fn from_container(
        cont: Cont,
        rlwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => rlwe_dimension.0 + 1, poly_size.0);
        GlweList {
            tensor,
            rlwe_size: GlweSize(rlwe_dimension.0 + 1),
            poly_size,
        }
    }

    /// Returns the number of ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweList;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, PolynomialSize};
    /// let list = GlweList::allocate(
    ///     0 as u8,
    ///     PolynomialSize(10),
    ///     GlweDimension(20),
    ///     CiphertextCount(30),
    /// );
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(30));
    /// ```
    pub fn ciphertext_count(&self) -> CiphertextCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.rlwe_size.0, self.poly_size.0);
        CiphertextCount(self.as_tensor().len() / (self.rlwe_size.0 * self.polynomial_size().0))
    }

    /// Returns the size of the glwe ciphertexts contained in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweList;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, GlweSize, PolynomialSize};
    /// let list = GlweList::allocate(
    ///     0 as u8,
    ///     PolynomialSize(10),
    ///     GlweDimension(20),
    ///     CiphertextCount(30),
    /// );
    /// assert_eq!(list.glwe_size(), GlweSize(21));
    /// ```
    pub fn glwe_size(&self) -> GlweSize
    where
        Self: AsRefTensor,
    {
        self.rlwe_size
    }

    /// Returns the number of coefficients of the polynomials used for the list ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweList;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, PolynomialSize};
    /// let list = GlweList::allocate(
    ///     0 as u8,
    ///     PolynomialSize(10),
    ///     GlweDimension(20),
    ///     CiphertextCount(30),
    /// );
    /// assert_eq!(list.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns the number of masks of the ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweList;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, PolynomialSize};
    /// let list = GlweList::allocate(
    ///     0 as u8,
    ///     PolynomialSize(10),
    ///     GlweDimension(20),
    ///     CiphertextCount(30),
    /// );
    /// assert_eq!(list.glwe_dimension(), GlweDimension(20));
    /// ```
    pub fn glwe_dimension(&self) -> GlweDimension
    where
        Self: AsRefTensor,
    {
        GlweDimension(self.rlwe_size.0 - 1)
    }

    /// Returns an iterator over ciphertexts borrowed from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweBody, GlweList};
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, PolynomialSize};
    /// let list = GlweList::allocate(
    ///     0 as u8,
    ///     PolynomialSize(10),
    ///     GlweDimension(20),
    ///     CiphertextCount(30),
    /// );
    /// for ciphertext in list.ciphertext_iter() {
    ///     let (body, masks) = ciphertext.get_body_and_mask();
    ///     assert_eq!(body.as_polynomial().polynomial_size(), PolynomialSize(10));
    /// }
    /// assert_eq!(list.ciphertext_iter().count(), 30);
    /// ```
    pub fn ciphertext_iter(
        &self,
    ) -> impl Iterator<Item = GlweCiphertext<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.rlwe_size.0, self.poly_size.0);
        let poly_size = self.poly_size;
        let size = self.rlwe_size.0 * self.polynomial_size().0;
        self.as_tensor()
            .subtensor_iter(size)
            .map(move |sub| GlweCiphertext::from_container(sub.into_container(), poly_size))
    }

    /// Returns an iterator over ciphertexts borrowed from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweBody, GlweList};
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, GlweDimension, PolynomialSize};
    /// let mut list = GlweList::allocate(
    ///     0 as u8,
    ///     PolynomialSize(10),
    ///     GlweDimension(20),
    ///     CiphertextCount(30),
    /// );
    /// for mut ciphertext in list.ciphertext_iter_mut() {
    ///     let mut body = ciphertext.get_mut_body();
    ///     body.as_mut_tensor().fill_with_element(9);
    /// }
    /// for ciphertext in list.ciphertext_iter() {
    ///     let body = ciphertext.get_body();
    ///     assert!(body.as_tensor().iter().all(|a| *a == 9));
    /// }
    /// assert_eq!(list.ciphertext_iter_mut().count(), 30);
    /// ```
    pub fn ciphertext_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = GlweCiphertext<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.rlwe_size.0, self.poly_size.0);
        let poly_size = self.poly_size;
        let chunks_size = self.rlwe_size.0 * self.polynomial_size().0;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |sub| GlweCiphertext::from_container(sub.into_container(), poly_size))
    }

    pub fn fill_with_trivial_encryption<PlaintextContainer, Scalar>(
        &mut self,
        plaintexts: &PlaintextList<PlaintextContainer>,
    ) where
        PlaintextList<PlaintextContainer>: AsRefTensor<Element = Scalar>,
        for<'a> PlaintextList<&'a [Scalar]>: AsRefTensor<Element = Scalar>,
        Self: AsMutTensor<Element = Scalar>,
        Scalar: Numeric,
    {
        debug_assert_eq!(
            plaintexts.count().0,
            self.poly_size.0 * self.ciphertext_count().0
        );
        let plaintext_count = PlaintextCount(self.poly_size.0);
        for (mut ciphertext, plaintext) in self
            .ciphertext_iter_mut()
            .zip(plaintexts.sublist_iter(plaintext_count))
        {
            ciphertext.fill_with_trivial_encryption(&plaintext);
        }
    }
}
