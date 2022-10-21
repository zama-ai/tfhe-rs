use crate::core_crypto::commons::math::tensor::{
    tensor_traits, AsMutElement, AsMutTensor, AsRefElement, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::prelude::MonomialDegree;

/// A monomial term.
///
/// This type represents a free monomial term of a given degree.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::commons::math::polynomial::Monomial;
/// use tfhe::core_crypto::prelude::MonomialDegree;
/// let mono = Monomial::allocate(1u8, MonomialDegree(5));
/// assert_eq!(*mono.get_coefficient(), 1u8);
/// assert_eq!(mono.degree(), MonomialDegree(5));
/// ```
#[derive(PartialEq, Eq)]
pub struct Monomial<Cont> {
    tensor: Tensor<Cont>,
    degree: MonomialDegree,
}

tensor_traits!(Monomial);

impl<Cont> AsRefElement for Monomial<Cont>
where
    Monomial<Cont>: AsRefTensor,
{
    type Element = <Monomial<Cont> as AsRefTensor>::Element;
    fn as_element(&self) -> &Self::Element {
        self.as_tensor().first()
    }
}

impl<Cont> AsMutElement for Monomial<Cont>
where
    Monomial<Cont>: AsMutTensor,
{
    type Element = <Monomial<Cont> as AsRefTensor>::Element;
    fn as_mut_element(&mut self) -> &mut <Self as AsMutElement>::Element {
        self.as_mut_tensor().first_mut()
    }
}

impl<Coef> Monomial<Vec<Coef>> {
    /// Allocates a new monomial.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{Monomial, MonomialDegree};
    /// let mono = Monomial::allocate(1u8, MonomialDegree(5));
    /// assert_eq!(*mono.get_coefficient(), 1u8);
    /// assert_eq!(mono.degree(), MonomialDegree(5));
    /// ```
    pub fn allocate(value: Coef, degree: MonomialDegree) -> Monomial<Vec<Coef>> {
        Monomial {
            tensor: Tensor::from_container(vec![value]),
            degree,
        }
    }
}

impl<Cont> Monomial<Cont> {
    /// Creates a new monomial from a value container and a degree.
    ///
    /// # Examples
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{Monomial, MonomialDegree};
    /// let vector = vec![1u8];
    /// let mono = Monomial::from_container(vector.as_slice(), MonomialDegree(5));
    /// assert_eq!(*mono.get_coefficient(), 1u8);
    /// assert_eq!(mono.degree(), MonomialDegree(5));
    /// ```
    pub fn from_container(cont: Cont, degree: MonomialDegree) -> Monomial<Cont>
    where
        Cont: AsRefSlice,
    {
        debug_assert!(
            cont.as_slice().len() == 1,
            "Tried to create a monomial with a container of size different than one"
        );
        Monomial {
            tensor: Tensor::from_container(cont),
            degree,
        }
    }

    /// Returns a reference to the monomial coefficient.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{Monomial, MonomialDegree};
    /// let mono = Monomial::allocate(1u8, MonomialDegree(5));
    /// assert_eq!(*mono.get_coefficient(), 1u8);
    /// ```
    pub fn get_coefficient(&self) -> &<Self as AsRefElement>::Element
    where
        Self: AsRefElement,
    {
        self.as_element()
    }

    /// Sets the monomial coefficient.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{Monomial, MonomialDegree};
    /// let mut mono = Monomial::allocate(1u8, MonomialDegree(5));
    /// mono.set_coefficient(5u8);
    /// assert_eq!(*mono.get_coefficient(), 5u8);
    /// ```
    pub fn set_coefficient<Coef>(&mut self, coefficient: Coef)
    where
        Self: AsMutElement<Element = Coef>,
    {
        *(self.as_mut_element()) = coefficient;
    }

    /// Returns a mutable reference to the coefficient.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{Monomial, MonomialDegree};
    /// let mut mono = Monomial::allocate(1u8, MonomialDegree(5));
    /// *mono.get_mut_coefficient() += 1u8;
    /// assert_eq!(*mono.get_coefficient(), 2u8);
    /// ```
    pub fn get_mut_coefficient(&mut self) -> &mut <Self as AsMutElement>::Element
    where
        Self: AsMutElement,
    {
        self.as_mut_element()
    }

    /// Returns the degree of the monomial.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::polynomial::{Monomial, MonomialDegree};
    /// let mono = Monomial::allocate(1u8, MonomialDegree(5));
    /// assert_eq!(mono.degree(), MonomialDegree(5));
    /// ```
    pub fn degree(&self) -> MonomialDegree {
        self.degree
    }
}
