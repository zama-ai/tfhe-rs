use crate::core_crypto::commons::math::polynomial::Polynomial;
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::PlaintextCount;
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// An plaintext (encoded) value.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Plaintext<T: Numeric>(pub T);

/// A list of plaintexts
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextList<Cont> {
    pub(crate) tensor: Tensor<Cont>,
}

tensor_traits!(PlaintextList);

impl<Scalar> PlaintextList<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a new list of plaintexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::PlaintextCount;
    /// let plain_list = PlaintextList::allocate(1 as u8, PlaintextCount(100));
    /// assert_eq!(plain_list.count(), PlaintextCount(100));
    /// ```
    pub fn allocate(value: Scalar, count: PlaintextCount) -> PlaintextList<Vec<Scalar>> {
        PlaintextList::from_container(vec![value; count.0])
    }
}

impl<Cont> PlaintextList<Cont> {
    /// Creates a plaintext list from a container of values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::PlaintextCount;
    /// let plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// assert_eq!(plain_list.count(), PlaintextCount(100));
    /// ```
    pub fn from_container(cont: Cont) -> PlaintextList<Cont> {
        PlaintextList {
            tensor: Tensor::from_container(cont),
        }
    }

    pub fn from_tensor(tensor: Tensor<Cont>) -> PlaintextList<Cont> {
        PlaintextList { tensor }
    }

    /// Returns the number of elements in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::PlaintextCount;
    /// let plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// assert_eq!(plain_list.count(), PlaintextCount(100));
    /// ```
    pub fn count(&self) -> PlaintextCount
    where
        Self: AsRefTensor,
    {
        PlaintextCount(self.as_tensor().len())
    }

    /// Creates an iterator over borrowed plaintexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// let plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// plain_list.plaintext_iter().for_each(|a| assert_eq!(a.0, 1));
    /// assert_eq!(plain_list.plaintext_iter().count(), 100);
    /// ```
    pub fn plaintext_iter(&self) -> impl Iterator<Item = &Plaintext<<Self as AsRefTensor>::Element>>
    where
        Self: AsRefTensor,
        <Self as AsRefTensor>::Element: Numeric,
    {
        self.as_tensor().iter().map(|refe| unsafe {
            &*{
                refe as *const <Self as AsRefTensor>::Element
                    as *const Plaintext<<Self as AsRefTensor>::Element>
            }
        })
    }

    #[cfg(feature = "__commons_parallel")]
    pub fn par_plaintext_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = &Plaintext<<Self as AsRefTensor>::Element>>
    where
        Self: AsRefTensor,
        <Self as AsRefTensor>::Element: Numeric + Sync,
    {
        self.as_tensor().par_iter().map(|refe| unsafe {
            &*{
                refe as *const <Self as AsRefTensor>::Element
                    as *const Plaintext<<Self as AsRefTensor>::Element>
            }
        })
    }

    /// Creates an iterator over mutably borrowed plaintexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// let mut plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// plain_list
    ///     .plaintext_iter_mut()
    ///     .for_each(|a| *a = Plaintext(2));
    /// plain_list.plaintext_iter().for_each(|a| assert_eq!(a.0, 2));
    /// assert_eq!(plain_list.plaintext_iter_mut().count(), 100);
    /// ```
    pub fn plaintext_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut Plaintext<<Self as AsMutTensor>::Element>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Numeric,
    {
        self.as_mut_tensor().iter_mut().map(|refe| unsafe {
            &mut *{
                refe as *mut <Self as AsMutTensor>::Element
                    as *mut Plaintext<<Self as AsMutTensor>::Element>
            }
        })
    }

    #[cfg(feature = "__commons_parallel")]
    pub fn par_plaintext_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = &mut Plaintext<<Self as AsMutTensor>::Element>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Numeric + Send + Sync,
    {
        self.as_mut_tensor().par_iter_mut().map(|refe| unsafe {
            &mut *{
                refe as *mut <Self as AsMutTensor>::Element
                    as *mut Plaintext<<Self as AsMutTensor>::Element>
            }
        })
    }

    /// Creates an iterator over borrowed sub-lists.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::PlaintextCount;
    /// let mut plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// plain_list
    ///     .sublist_iter(PlaintextCount(10))
    ///     .for_each(|a| assert_eq!(a.count(), PlaintextCount(10)));
    /// assert_eq!(plain_list.sublist_iter(PlaintextCount(10)).count(), 10);
    /// ```
    pub fn sublist_iter(
        &self,
        count: PlaintextCount,
    ) -> impl DoubleEndedIterator<Item = PlaintextList<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(count.0)
            .map(|sub| PlaintextList::from_container(sub.into_container()))
    }

    /// Creates an iterator over mutably borrowed sub-lists.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::PlaintextCount;
    /// let mut plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// plain_list
    ///     .sublist_iter_mut(PlaintextCount(10))
    ///     .for_each(|mut a| a.plaintext_iter_mut().for_each(|b| *b = Plaintext(2)));
    /// plain_list
    ///     .plaintext_iter()
    ///     .for_each(|a| assert_eq!(*a, Plaintext(2)));
    /// assert_eq!(plain_list.sublist_iter_mut(PlaintextCount(10)).count(), 10);
    /// ```
    pub fn sublist_iter_mut(
        &mut self,
        count: PlaintextCount,
    ) -> impl Iterator<Item = PlaintextList<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.count().0 => count.0);
        self.as_mut_tensor()
            .subtensor_iter_mut(count.0)
            .map(|sub| PlaintextList::from_container(sub.into_container()))
    }

    /// Return a borrowed polynomial whose coefficients are the plaintexts of this list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// let plain_poly = plain_list.as_polynomial();
    /// assert_eq!(plain_poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn as_polynomial(&self) -> Polynomial<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        Polynomial::from_container(self.as_tensor().as_slice())
    }

    /// Return a mutably borrowed polynomial whose coefficients are the plaintexts of this list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let mut plain_list = PlaintextList::from_container(vec![1 as u8; 100]);
    /// let mut plain_poly = plain_list.as_mut_polynomial();
    /// assert_eq!(plain_poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn as_mut_polynomial(&mut self) -> Polynomial<&mut [<Self as AsRefTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        Polynomial::from_container(self.as_mut_tensor().as_mut_slice())
    }
}
