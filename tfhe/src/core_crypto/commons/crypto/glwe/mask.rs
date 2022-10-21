use crate::core_crypto::commons::math::polynomial::{Polynomial, PolynomialList};
use crate::core_crypto::commons::math::tensor::{
    tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::prelude::PolynomialSize;

/// The mask of a GLWE ciphertext
pub struct GlweMask<Cont> {
    pub(crate) tensor: Tensor<Cont>,
    pub(crate) poly_size: PolynomialSize,
}

tensor_traits!(GlweMask);

impl<Cont> GlweMask<Cont> {
    /// Returns an iterator over borrowed mask elements contained in the mask.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let rlwe_ciphertext = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// for mask in rlwe_ciphertext.get_mask().mask_element_iter() {
    ///     assert_eq!(mask.as_polynomial().polynomial_size(), PolynomialSize(10));
    /// }
    /// assert_eq!(rlwe_ciphertext.get_mask().mask_element_iter().count(), 99);
    /// ```
    pub fn mask_element_iter(
        &self,
    ) -> impl Iterator<Item = GlweMaskElement<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(self.poly_size.0)
            .map(|sub| GlweMaskElement::from_container(sub.into_container()))
    }

    /// Returns an iterator over mutably borrowed mask elements contained in the mask.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut rlwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// for mut mask in rlwe.get_mut_mask().mask_element_iter_mut() {
    ///     mask.as_mut_tensor().fill_with_element(9);
    /// }
    /// assert!(rlwe.get_mask().as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(rlwe.get_mask().mask_element_iter().count(), 99);
    /// ```
    pub fn mask_element_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = GlweMaskElement<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.poly_size.0;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(|sub| GlweMaskElement::from_container(sub.into_container()))
    }

    /// Returns a borrowed polynomial list from the current mask.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialCount, PolynomialSize};
    /// let rlwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let masks = rlwe.get_mask();
    /// let list = masks.as_polynomial_list();
    /// assert_eq!(list.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(list.polynomial_count(), PolynomialCount(99));
    /// ```
    pub fn as_polynomial_list(&self) -> PolynomialList<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        PolynomialList::from_container(self.as_tensor().as_slice(), self.poly_size)
    }

    /// Returns a mutably borrowed polynomial list from the current mask list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialCount, PolynomialSize};
    /// let mut rlwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let mut masks = rlwe.get_mut_mask();
    /// let mut tensor = masks.as_mut_polynomial_list();
    /// assert_eq!(tensor.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(tensor.polynomial_count(), PolynomialCount(99));
    /// ```
    pub fn as_mut_polynomial_list(
        &mut self,
    ) -> PolynomialList<&mut [<Self as AsRefTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        let poly_size = self.poly_size;
        PolynomialList::from_container(self.as_mut_tensor().as_mut_slice(), poly_size)
    }
}

/// A mask of an GLWE ciphertext.
pub struct GlweMaskElement<Cont> {
    tensor: Tensor<Cont>,
}

tensor_traits!(GlweMaskElement);

impl<Container> GlweMaskElement<Container> {
    /// Creates a mask element from a container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweMaskElement;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let mask = GlweMaskElement::from_container(vec![0 as u8; 10]);
    /// assert_eq!(mask.as_polynomial().polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn from_container(cont: Container) -> GlweMaskElement<Container> {
        GlweMaskElement {
            tensor: Tensor::from_container(cont),
        }
    }

    /// Returns a borrowed polynomial from the current mask element.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweMaskElement;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let mask = GlweMaskElement::from_container(vec![0 as u8; 10]);
    /// assert_eq!(mask.as_polynomial().polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn as_polynomial(&self) -> Polynomial<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        Polynomial::from_container(self.as_tensor().as_slice())
    }

    /// Returns a mutably borrowed polynomial from the current mask element.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweMaskElement;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// let mut mask = GlweMaskElement::from_container(vec![0 as u8; 10]);
    /// mask.as_mut_polynomial()
    ///     .as_mut_tensor()
    ///     .fill_with_element(9);
    /// assert!(mask.as_tensor().iter().all(|a| *a == 9));
    /// ```
    pub fn as_mut_polynomial(&mut self) -> Polynomial<&mut [<Self as AsRefTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        Polynomial::from_container(self.as_mut_tensor().as_mut_slice())
    }
}
