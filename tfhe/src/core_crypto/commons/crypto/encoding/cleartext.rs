use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutTensor, AsRefTensor, Tensor,
};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::CleartextCount;
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A clear, non-encoded, value.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cleartext<T: Numeric>(pub T);

/// A list of clear, non-encoded, values.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextList<Cont> {
    tensor: Tensor<Cont>,
}

tensor_traits!(CleartextList);

impl<Scalar> CleartextList<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a new list of cleartexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::prelude::CleartextCount;
    /// let clear_list = CleartextList::allocate(1 as u8, CleartextCount(100));
    /// assert_eq!(clear_list.count(), CleartextCount(100));
    /// ```
    pub fn allocate(value: Scalar, count: CleartextCount) -> CleartextList<Vec<Scalar>> {
        CleartextList::from_container(vec![value; count.0])
    }
}

impl<Cont> CleartextList<Cont> {
    /// Creates a cleartext list from a container of values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::CleartextList;
    /// use tfhe::core_crypto::prelude::CleartextCount;
    /// let clear_list = CleartextList::from_container(vec![1 as u8; 100]);
    /// assert_eq!(clear_list.count(), CleartextCount(100));
    /// ```
    pub fn from_container(cont: Cont) -> CleartextList<Cont> {
        CleartextList {
            tensor: Tensor::from_container(cont),
        }
    }

    /// Returns the number of elements in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::CleartextList;
    /// use tfhe::core_crypto::prelude::CleartextCount;
    /// let clear_list = CleartextList::from_container(vec![1 as u8; 100]);
    /// assert_eq!(clear_list.count(), CleartextCount(100));
    /// ```
    pub fn count(&self) -> CleartextCount
    where
        Self: AsRefTensor,
    {
        CleartextCount(self.as_tensor().len())
    }

    /// Creates an iterator over borrowed cleartexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::CleartextList;
    /// let clear_list = CleartextList::from_container(vec![1 as u8; 100]);
    /// clear_list.cleartext_iter().for_each(|a| assert_eq!(a.0, 1));
    /// assert_eq!(clear_list.cleartext_iter().count(), 100);
    /// ```
    pub fn cleartext_iter(&self) -> impl Iterator<Item = &Cleartext<<Self as AsRefTensor>::Element>>
    where
        Self: AsRefTensor,
        <Self as AsRefTensor>::Element: Numeric,
    {
        self.as_tensor().iter().map(|refe| unsafe {
            &*{
                refe as *const <Self as AsRefTensor>::Element
                    as *const Cleartext<<Self as AsRefTensor>::Element>
            }
        })
    }

    /// Creates an iterator over mutably borrowed cleartexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::{Cleartext, CleartextList};
    /// let mut clear_list = CleartextList::from_container(vec![1 as u8; 100]);
    /// clear_list
    ///     .cleartext_iter_mut()
    ///     .for_each(|a| *a = Cleartext(2));
    /// clear_list.cleartext_iter().for_each(|a| assert_eq!(a.0, 2));
    /// assert_eq!(clear_list.cleartext_iter_mut().count(), 100);
    /// ```
    pub fn cleartext_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut Cleartext<<Self as AsMutTensor>::Element>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Numeric,
    {
        self.as_mut_tensor().iter_mut().map(|refe| unsafe {
            &mut *{
                refe as *mut <Self as AsMutTensor>::Element
                    as *mut Cleartext<<Self as AsMutTensor>::Element>
            }
        })
    }

    /// Creates an iterator over borrowed sub-lists.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::encoding::CleartextList;
    /// use tfhe::core_crypto::prelude::CleartextCount;
    /// let clear_list = CleartextList::from_container(vec![1 as u8; 100]);
    /// clear_list
    ///     .sublist_iter(CleartextCount(10))
    ///     .for_each(|a| assert_eq!(a.count(), CleartextCount(10)));
    /// assert_eq!(clear_list.sublist_iter(CleartextCount(10)).count(), 10);
    /// ```
    pub fn sublist_iter(
        &self,
        sub_len: CleartextCount,
    ) -> impl Iterator<Item = CleartextList<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => sub_len.0);
        self.as_tensor()
            .subtensor_iter(sub_len.0)
            .map(|sub| CleartextList::from_container(sub.into_container()))
    }

    /// Creates an iterator over mutably borrowed sub-lists.
    ///
    /// #Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::encoding::{Cleartext, CleartextList};
    /// use tfhe::core_crypto::prelude::CleartextCount;
    /// let mut clear_list = CleartextList::from_container(vec![1 as u8; 100]);
    /// clear_list
    ///     .sublist_iter_mut(CleartextCount(10))
    ///     .for_each(|mut a| a.cleartext_iter_mut().for_each(|b| *b = Cleartext(3)));
    /// clear_list
    ///     .cleartext_iter()
    ///     .for_each(|a| assert_eq!(*a, Cleartext(3)));
    /// assert_eq!(clear_list.sublist_iter_mut(CleartextCount(10)).count(), 10);
    /// ```
    pub fn sublist_iter_mut(
        &mut self,
        sub_len: CleartextCount,
    ) -> impl Iterator<Item = CleartextList<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => sub_len.0);
        self.as_mut_tensor()
            .subtensor_iter_mut(sub_len.0)
            .map(|sub| CleartextList::from_container(sub.into_container()))
    }
}
