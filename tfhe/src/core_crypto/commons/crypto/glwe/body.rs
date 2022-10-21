use crate::core_crypto::commons::math::polynomial::Polynomial;
use crate::core_crypto::commons::math::tensor::{
    tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};

/// The body of a GLWE ciphertext.
pub struct GlweBody<Cont> {
    pub(crate) tensor: Tensor<Cont>,
}

tensor_traits!(GlweBody);

impl<Cont> GlweBody<Cont> {
    /// Consumes the current ciphertext body, and return a polynomial over the original container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let body = glwe.get_body();
    /// let poly = body.into_polynomial();
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn into_polynomial(self) -> Polynomial<Cont>
    where
        Self: IntoTensor<Container = Cont>,
    {
        Polynomial::from_container(self.into_tensor().into_container())
    }

    /// Returns a borrowed polynomial from the current body.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let body = glwe.get_body();
    /// let poly = body.as_polynomial();
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn as_polynomial(&self) -> Polynomial<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        Polynomial::from_container(self.as_tensor().as_slice())
    }

    /// Returns a mutably borrowed polynomial from the current body.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let mut body = glwe.get_mut_body();
    /// let mut poly = body.as_mut_polynomial();
    /// poly.as_mut_tensor().fill_with_element(9);
    /// assert!(body.as_tensor().iter().all(|a| *a == 9));
    /// ```
    pub fn as_mut_polynomial(&mut self) -> Polynomial<&mut [<Self as AsMutTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        Polynomial::from_container(self.as_mut_tensor().as_mut_slice())
    }
}
