use std::iter::FromIterator;
use std::ops::{
    BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Shl, ShlAssign, Shr, ShrAssign,
};
use std::slice::SliceIndex;

#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::numeric::{CastFrom, UnsignedInteger};

use crate::core_crypto::commons::utils::zip;

use super::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor};

/// A generic type to perform operations on collections of scalar values.
///
/// See the [module-level](`super`) documentation for more explanations on the logic of this type.
///
/// # Naming convention
///
/// The methods that may mutate the values of a `Tensor`, follow a convention:
///
/// + Methods prefixed with `update_with` use the current values of `self` when performing the
/// operation.
/// + Methods prefixed with `fill_with` discard the current vales of `self`, and overwrite it with
/// the result of an operation on other values.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Tensor<Container: ?Sized>(Container);

impl<Element> Tensor<Vec<Element>> {
    /// Allocates a new `Tensor<Vec<T>>` whose values are all `value`.
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// assert_eq!(tensor.len(), 1000);
    /// assert_eq!(*tensor.get_element(0), 9);
    /// assert_eq!(*tensor.get_element(1), 9);
    /// ```
    pub fn allocate(value: Element, size: usize) -> Self
    where
        Element: Copy,
    {
        Tensor(vec![value; size])
    }
}

macro_rules! fill_with {
    ($Trait:ident, $name: ident, $($func:tt)*) => {
            pub fn $name<Lhs, Rhs>(
                &mut self,
                lhs: &Tensor<Lhs>,
                rhs: &Tensor<Rhs>,
            ) where
                Tensor<Lhs>: AsRefSlice,
                Tensor<Rhs>: AsRefSlice,
                Self: AsMutSlice,
                <Tensor<Lhs> as AsRefSlice>::Element: $Trait<<Tensor<Rhs> as AsRefSlice>::Element,
                Output=<Self as AsMutSlice>::Element>,
                <Tensor<Lhs> as AsRefSlice>::Element: Copy,
                <Tensor<Rhs> as AsRefSlice>::Element: Copy
            {
                ck_dim_eq!(self.len() => lhs.len());
                ck_dim_eq!(self.len() => rhs.len());
                Tensor::fill_with_two(self, lhs, rhs, $($func)*);
            }
    };
}

macro_rules! fill_with_wrapping {
    ($name: ident, $($func:tt)*) => {
            pub fn $name<Lhs, Rhs, Element>(
                &mut self,
                lhs: &Tensor<Lhs>,
                rhs: &Tensor<Rhs>,
            ) where
                Tensor<Lhs>: AsRefSlice<Element=Element>,
                Tensor<Rhs>: AsRefSlice<Element=Element>,
                Self: AsMutSlice<Element=Element>,
                Element: UnsignedInteger
            {
                ck_dim_eq!(self.len() => lhs.len());
                ck_dim_eq!(self.len() => rhs.len());
                Tensor::fill_with_two(self, lhs, rhs, $($func)*);
            }
    };
}

macro_rules! update_with {
    ($Trait:ident, $name: ident, $($func:tt)*) => {
            pub fn $name<Other>(
                &mut self,
                other: &Tensor<Other>,
            ) where
                Self: AsMutSlice,
                Tensor<Other>: AsRefSlice,
                <Self as AsMutSlice>::Element: $Trait<<Tensor<Other> as AsRefSlice>::Element>,
                <Tensor<Other> as AsRefSlice>::Element: Copy
            {
                ck_dim_eq!(self.len() => other.len());
                self.update_with_one(other, $($func)*);
            }
    };
}

macro_rules! update_with_wrapping {
    ($name: ident, $($func:tt)*) => {
            pub fn $name<Other, Element>(
                &mut self,
                other: &Tensor<Other>,
            ) where
                Self: AsMutSlice<Element=Element>,
                Tensor<Other>: AsRefSlice<Element=Element>,
                Element: UnsignedInteger
            {
                ck_dim_eq!(self.len() => other.len());
                self.update_with_one(other, $($func)*);
            }
    };
}

macro_rules! update_with_scalar {
    ($Trait:ident, $name: ident, $($func:tt)*) => {
            pub fn $name<Element>(
                &mut self,
                element: &Element,
            ) where
                Self: AsMutSlice,
                <Self as AsMutSlice>::Element: $Trait<Element>,
                Element: Copy
            {
                self.update_with_element(element, $($func)*);
            }
    };
}

macro_rules! update_with_wrapping_scalar {
    ($name: ident, $($func:tt)*) => {
            pub fn $name<Element>(
                &mut self,
                element: &Element,
            ) where
                Self: AsMutSlice<Element=Element>,
                Element: UnsignedInteger
            {
                self.update_with_element(element, $($func)*);
            }
    };
}

impl<Container> Tensor<Container> {
    /// Creates a new tensor from a container.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let vec = vec![9 as u8; 1000];
    /// let view = vec.as_slice();
    /// let tensor = Tensor::from_container(view);
    /// assert_eq!(tensor.len(), 1000);
    /// assert_eq!(*tensor.get_element(0), 9);
    /// assert_eq!(*tensor.get_element(1), 9);
    /// ```
    pub fn from_container(cont: Container) -> Self {
        Tensor(cont)
    }

    /// Consumes a tensor and returns its container.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// let vec = tensor.into_container();
    /// assert_eq!(vec.len(), 1000);
    /// assert_eq!(vec[0], 9);
    /// assert_eq!(vec[1], 9);
    /// ```
    pub fn into_container(self) -> Container {
        self.0
    }

    /// Returns a reference to the tensor container.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// let vecref: &Vec<_> = tensor.as_container();
    /// ```
    pub fn as_container(&self) -> &Container {
        &self.0
    }

    /// Returns a mutable reference to the tensor container.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// let vecmut: &mut Vec<_> = tensor.as_mut_container();
    /// ```
    pub fn as_mut_container(&mut self) -> &mut Container {
        &mut self.0
    }

    /// Returns the length of the tensor.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// assert_eq!(tensor.len(), 1000);
    /// ```
    pub fn len(&self) -> usize
    where
        Self: AsRefSlice,
    {
        self.as_slice().len()
    }

    /// Returns whether the tensor is empty.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// assert_eq!(tensor.is_empty(), false);
    /// ```
    pub fn is_empty(&self) -> bool
    where
        Self: AsRefSlice,
    {
        self.as_slice().len() == 0
    }

    /// Returns an iterator over `&Scalar` elements.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// for scalar in tensor.iter() {
    ///     assert_eq!(*scalar, 9);
    /// }
    /// ```
    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = &<Self as AsRefSlice>::Element> + ExactSizeIterator
    where
        Self: AsRefSlice,
    {
        self.as_slice().iter()
    }

    /// Returns a parallel iterator over `&Scalar` elements.
    ///
    /// # Notes:
    /// This iterator is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Example
    /// ```
    /// use rayon::iter::ParallelIterator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// tensor.par_iter().for_each(|scalar| {
    ///     assert_eq!(*scalar, 9);
    /// });
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_iter(&self) -> impl IndexedParallelIterator<Item = &<Self as AsRefSlice>::Element>
    where
        Self: AsRefSlice,
        <Self as AsRefSlice>::Element: Sync,
    {
        self.as_slice().as_parallel_slice().par_iter()
    }

    /// Returns an iterator over `&mut T` elements.
    ///
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// for mut scalar in tensor.iter_mut() {
    ///     *scalar = 8;
    /// }
    /// for scalar in tensor.iter() {
    ///     assert_eq!(*scalar, 8);
    /// }
    /// ```
    pub fn iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = &mut <Self as AsMutSlice>::Element> + ExactSizeIterator
    where
        Self: AsMutSlice,
    {
        self.as_mut_slice().iter_mut()
    }

    /// Returns a parallel iterator over `&mut T` elements.
    ///
    /// # Notes:
    /// This iterator is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// tensor.iter_mut().for_each(|mut scalar| {
    ///     *scalar = 8;
    /// });
    /// for scalar in tensor.iter() {
    ///     assert_eq!(*scalar, 8);
    /// }
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = &mut <Self as AsMutSlice>::Element>
    where
        Self: AsMutSlice,
        <Self as AsMutSlice>::Element: Sync + Send,
    {
        self.as_mut_slice().as_parallel_slice_mut().par_iter_mut()
    }

    /// Returns an iterator over sub tensors `Tensor<&[Scalar]>`.
    ///
    /// # Note:
    /// The length of the sub-tensors must divide the size of the tensor.
    ///
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// for sub in tensor.subtensor_iter(10) {
    ///     assert_eq!(sub.len(), 10);
    /// }
    /// ```
    pub fn subtensor_iter(
        &self,
        size: usize,
    ) -> impl DoubleEndedIterator<Item = Tensor<&[<Self as AsRefSlice>::Element]>> + ExactSizeIterator
    where
        Self: AsRefSlice,
    {
        debug_assert!(self.as_slice().len() % size == 0, "Uneven chunks size");
        self.as_slice().chunks(size).map(Tensor::from_container)
    }

    /// Returns a parallel iterator over sub tensors `Tensor<&[Scalar]>`.
    ///
    /// # Note:
    /// The length of the sub-tensors must divide the size of the tensor.
    /// This iterator is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Example:
    /// ```
    /// use rayon::iter::ParallelIterator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// tensor.par_subtensor_iter(10).for_each(|sub| {
    ///     assert_eq!(sub.len(), 10);
    /// });
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_subtensor_iter(
        &self,
        size: usize,
    ) -> impl IndexedParallelIterator<Item = Tensor<&[<Self as AsRefSlice>::Element]>>
    where
        Self: AsRefSlice,
        <Self as AsRefSlice>::Element: Sync,
    {
        debug_assert!(self.as_slice().len() % size == 0, "Uneven chunks size");
        self.as_slice().par_chunks(size).map(Tensor::from_container)
    }

    /// Returns an iterator over mutable sub tensors `Tensor<&mut [Scalar]>`.
    ///
    /// # Note:
    /// The length of the sub-tensors must divide the size of the tensor.
    ///
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// for mut sub in tensor.subtensor_iter_mut(10) {
    ///     assert_eq!(sub.len(), 10);
    ///     *sub.get_element_mut(0) = 1;
    /// }
    /// for sub in tensor.subtensor_iter(20) {
    ///     assert_eq!(*sub.get_element(0), 1);
    ///     assert_eq!(*sub.get_element(10), 1);
    /// }
    /// ```
    pub fn subtensor_iter_mut(
        &mut self,
        size: usize,
    ) -> impl DoubleEndedIterator<Item = Tensor<&mut [<Self as AsMutSlice>::Element]>> + ExactSizeIterator
    where
        Self: AsMutSlice,
    {
        debug_assert!(self.as_slice().len() % size == 0, "Uneven chunks size");
        self.as_mut_slice()
            .chunks_mut(size)
            .map(Tensor::from_container)
    }

    /// Returns a parallel iterator over mutable sub tensors `Tensor<&mut [Scalar]>`.
    ///
    /// # Note:
    ///
    /// The length of the sub-tensors must divide the size of the tensor.
    /// This iterator is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Example:
    /// ```
    /// use rayon::iter::ParallelIterator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// tensor.par_subtensor_iter_mut(10).for_each(|mut sub| {
    ///     assert_eq!(sub.len(), 10);
    ///     *sub.get_element_mut(0) = 1;
    /// });
    /// for sub in tensor.subtensor_iter(20) {
    ///     assert_eq!(*sub.get_element(0), 1);
    ///     assert_eq!(*sub.get_element(10), 1);
    /// }
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_subtensor_iter_mut(
        &mut self,
        size: usize,
    ) -> impl IndexedParallelIterator<Item = Tensor<&mut [<Self as AsMutSlice>::Element]>>
    where
        Self: AsMutSlice,
        <Self as AsMutSlice>::Element: Sync + Send,
    {
        debug_assert!(self.as_slice().len() % size == 0, "Uneven chunks size");
        self.as_mut_slice()
            .par_chunks_mut(size)
            .map(Tensor::from_container)
    }

    /// Returns a reference to the first element.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// assert_eq!(*tensor.first(), 9);
    /// ```
    pub fn first<Element>(&self) -> &Element
    where
        Self: AsRefSlice<Element = Element>,
    {
        self.as_slice().first().unwrap()
    }

    /// Returns a reference to the last element.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// assert_eq!(*tensor.last(), 9);
    /// ```
    pub fn last<Element>(&self) -> &Element
    where
        Self: AsRefSlice<Element = Element>,
    {
        self.as_slice().last().unwrap()
    }

    /// Returns a mutable reference to the first element.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// *tensor.first_mut() = 8;
    /// assert_eq!(*tensor.get_element(0), 8);
    /// assert_eq!(*tensor.get_element(1), 9);
    /// ```
    pub fn first_mut<Element>(&mut self) -> &mut Element
    where
        Self: AsMutSlice<Element = Element>,
    {
        self.as_mut_slice().first_mut().unwrap()
    }

    /// Returns a mutable reference to the last element.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// *tensor.last_mut() = 8;
    /// assert_eq!(*tensor.get_element(999), 8);
    /// assert_eq!(*tensor.get_element(1), 9);
    /// ```
    pub fn last_mut<Element>(&mut self) -> &mut Element
    where
        Self: AsMutSlice<Element = Element>,
    {
        self.as_mut_slice().last_mut().unwrap()
    }

    /// Returns a reference to the first element, and a ref tensor for the rest of the values.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// let (first, end) = tensor.split_first();
    /// assert_eq!(*first, 9);
    /// assert_eq!(end.len(), 999);
    /// ```
    pub fn split_first<Element>(&self) -> (&Element, Tensor<&[Element]>)
    where
        Self: AsRefSlice<Element = Element>,
    {
        self.as_slice()
            .split_first()
            .map(|(f, r)| (f, Tensor(r)))
            .unwrap()
    }

    /// Returns a reference to the last element, and a ref tensor to the rest of the values.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// let (last, beginning) = tensor.split_last();
    /// assert_eq!(*last, 9);
    /// assert_eq!(beginning.len(), 999);
    /// ```
    pub fn split_last<Element>(&self) -> (&Element, Tensor<&[Element]>)
    where
        Self: AsRefSlice<Element = Element>,
    {
        self.as_slice()
            .split_last()
            .map(|(f, r)| (f, Tensor(r)))
            .unwrap()
    }

    /// Returns a mutable reference to the first element, and a mut tensor for the rest of the
    /// values.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// let (mut first, mut end) = tensor.split_first_mut();
    /// *first = 8;
    /// *end.get_element_mut(0) = 7;
    /// assert_eq!(*tensor.get_element(0), 8);
    /// assert_eq!(*tensor.get_element(1), 7);
    /// assert_eq!(*tensor.get_element(2), 9);
    /// ```
    pub fn split_first_mut<Element>(&mut self) -> (&mut Element, Tensor<&mut [Element]>)
    where
        Self: AsMutSlice<Element = Element>,
    {
        self.as_mut_slice()
            .split_first_mut()
            .map(|(f, r)| (f, Tensor(r)))
            .unwrap()
    }

    /// Returns a mutable reference to the last element, and a mut tensor for the rest of the
    /// values.
    ///
    /// # Note:
    ///
    /// Panics if the tensor is empty.
    ///
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// let (mut last, mut beginning) = tensor.split_last_mut();
    /// *last = 8;
    /// *beginning.get_element_mut(0) = 7;
    /// assert_eq!(*tensor.get_element(0), 7);
    /// assert_eq!(*tensor.get_element(999), 8);
    /// assert_eq!(*tensor.get_element(2), 9);
    /// ```
    pub fn split_last_mut<Element>(&mut self) -> (&mut Element, Tensor<&mut [Element]>)
    where
        Self: AsMutSlice<Element = Element>,
    {
        self.as_mut_slice()
            .split_last_mut()
            .map(|(f, r)| (f, Tensor(r)))
            .unwrap()
    }

    /// Returns a sub tensor from a range of indices.
    ///
    /// # Note:
    ///
    /// Panics if the indices are out of range.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// let sub = tensor.get_sub(0..3);
    /// assert_eq!(sub.len(), 3);
    /// ```
    pub fn get_sub<Index>(&self, index: Index) -> Tensor<&[<Self as AsRefSlice>::Element]>
    where
        Self: AsRefSlice,
        Index:
            SliceIndex<[<Self as AsRefSlice>::Element], Output = [<Self as AsRefSlice>::Element]>,
    {
        Tensor(&self.as_slice()[index])
    }

    /// Returns a mutable sub tensor from a range of indices.
    ///
    /// # Note:
    ///
    /// Panics if the indices are out of range.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// let mut sub = tensor.get_sub_mut(0..3);
    /// sub.fill_with_element(0);
    /// assert_eq!(*tensor.get_element(0), 0);
    /// assert_eq!(*tensor.get_element(3), 9);
    /// ```
    pub fn get_sub_mut<Index>(
        &mut self,
        index: Index,
    ) -> Tensor<&mut [<Self as AsMutSlice>::Element]>
    where
        Self: AsMutSlice,
        Index:
            SliceIndex<[<Self as AsMutSlice>::Element], Output = [<Self as AsMutSlice>::Element]>,
    {
        Tensor(&mut self.as_mut_slice()[index])
    }

    /// Returns a reference to an element from an index.
    ///
    /// # Note:
    ///
    /// Panics if the index is out of range.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let tensor = Tensor::allocate(9 as u8, 1000);
    /// assert_eq!(*tensor.get_element(0), 9);
    /// ```
    pub fn get_element(&self, index: usize) -> &<Self as AsRefSlice>::Element
    where
        Self: AsRefSlice,
    {
        &self.as_slice()[index]
    }

    /// Returns a mutable reference to an element from an index.
    ///
    /// # Note:
    ///
    /// Panics if the index is out of range.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// *tensor.get_element_mut(0) = 8;
    /// assert_eq!(*tensor.get_element(0), 8);
    /// assert_eq!(*tensor.get_element(1), 9);
    /// ```
    pub fn get_element_mut(&mut self, index: usize) -> &mut <Self as AsMutSlice>::Element
    where
        Self: AsMutSlice,
    {
        &mut self.as_mut_slice()[index]
    }

    /// Sets the value of an element at a given index.
    ///
    /// # Note:
    ///
    /// Panics if the index is out of range.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// *tensor.get_element_mut(0) = 8;
    /// assert_eq!(*tensor.get_element(0), 8);
    /// assert_eq!(*tensor.get_element(1), 9);
    /// ```
    pub fn set_element(&mut self, index: usize, val: <Self as AsMutSlice>::Element)
    where
        Self: AsMutSlice,
    {
        self.as_mut_slice()[index] = val;
    }

    /// Fills a tensor with the values of another tensor, using memcpy.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor1 = Tensor::allocate(9 as u8, 1000);
    /// let tensor2 = Tensor::allocate(10 as u8, 1000);
    /// tensor1.fill_with_copy(&tensor2);
    /// assert_eq!(*tensor2.get_element(0), 10);
    /// ```
    pub fn fill_with_copy<InputCont, Element>(&mut self, other: &Tensor<InputCont>)
    where
        Self: AsMutSlice<Element = Element>,
        Tensor<InputCont>: AsRefSlice<Element = Element>,
        Element: Copy,
    {
        ck_dim_eq!(self.len() => other.len());
        self.as_mut_slice().copy_from_slice(other.as_slice());
    }

    /// Fills two tensors with the result of the operation on a single one.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor1 = Tensor::allocate(9 as u8, 1000);
    /// let mut tensor2 = Tensor::allocate(9 as u8, 1000);
    /// let tensor3 = Tensor::allocate(10 as u8, 1000);
    /// Tensor::fill_two_with_one(&mut tensor1, &mut tensor2, &tensor3, |a| (*a, *a));
    /// assert_eq!(*tensor1.get_element(0), 10);
    /// assert_eq!(*tensor2.get_element(0), 10);
    /// ```
    pub fn fill_two_with_one<Cont1, Cont2>(
        first: &mut Self,
        second: &mut Tensor<Cont1>,
        one: &Tensor<Cont2>,
        ope: impl Fn(
            &<Tensor<Cont2> as AsRefSlice>::Element,
        ) -> (
            <Self as AsRefSlice>::Element,
            <Tensor<Cont1> as AsRefSlice>::Element,
        ),
    ) where
        Self: AsMutSlice,
        Tensor<Cont1>: AsMutSlice,
        Tensor<Cont2>: AsRefSlice,
    {
        ck_dim_eq!(first.len() => one.len());
        ck_dim_eq!(second.len() => one.len());
        for (first_i, (second_i, one_i)) in zip!(first.iter_mut(), second.iter_mut(), one.iter()) {
            let (f, s) = ope(one_i);
            *first_i = f;
            *second_i = s;
        }
    }

    /// Fills a mutable tensor with the result of an element-wise operation on two other tensors of
    /// the same size
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u8, 1000);
    /// let t2 = Tensor::allocate(1 as u8, 1000);
    /// let t3 = Tensor::allocate(2 as u8, 1000);
    /// t1.fill_with_two(&t2, &t3, |t2, t3| t3 + t2);
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 3);
    /// }
    /// ```
    pub fn fill_with_two<Cont1, Cont2>(
        &mut self,
        lhs: &Tensor<Cont1>,
        rhs: &Tensor<Cont2>,
        ope: impl Fn(
            &<Tensor<Cont1> as AsRefSlice>::Element,
            &<Tensor<Cont2> as AsRefSlice>::Element,
        ) -> <Self as AsMutSlice>::Element,
    ) where
        Tensor<Cont1>: AsRefSlice,
        Tensor<Cont2>: AsRefSlice,
        Self: AsMutSlice,
    {
        ck_dim_eq!(self.len() => lhs.len());
        ck_dim_eq!(self.len() => rhs.len());
        for (output_i, (lhs_i, rhs_i)) in zip!(
            self.iter_mut(),
            lhs.as_slice().iter(),
            rhs.as_slice().iter()
        ) {
            *output_i = ope(lhs_i, rhs_i);
        }
    }

    /// Fills a mutable tensor with the result of an element-wise operation on one other tensor of
    /// the same size
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u8, 1000);
    /// let t2 = Tensor::allocate(2 as u8, 1000);
    /// t1.fill_with_one(&t2, |t2| t2.pow(2));
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 4);
    /// }
    /// ```
    pub fn fill_with_one<Cont>(
        &mut self,
        other: &Tensor<Cont>,
        ope: impl Fn(&<Tensor<Cont> as AsRefSlice>::Element) -> <Self as AsMutSlice>::Element,
    ) where
        Tensor<Cont>: AsRefSlice,
        Self: AsMutSlice,
    {
        ck_dim_eq!(self.len() => other.len());
        for (output_i, other_i) in zip!(self.iter_mut(), other.as_slice().iter()) {
            *output_i = ope(other_i);
        }
    }

    /// Fills a mutable tensor with an element.
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// tensor.fill_with_element(8);
    /// for scalar in tensor.iter() {
    ///     assert_eq!(*scalar, 8);
    /// }
    /// ```
    pub fn fill_with_element(&mut self, element: <Self as AsMutSlice>::Element)
    where
        Self: AsMutSlice,
        <Self as AsMutSlice>::Element: Copy,
    {
        for output_i in self.iter_mut() {
            *output_i = element;
        }
    }

    /// Fills a mutable tensor by repeatedly calling a closure.
    ///
    /// ```
    /// use std::cell::RefCell;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u16, 1000);
    /// let mut boxed = RefCell::from(0);
    /// tensor.fill_with(|| {
    ///     *boxed.borrow_mut() += 1;
    ///     *boxed.borrow()
    /// });
    /// assert_eq!(*tensor.get_element(0), 1);
    /// assert_eq!(*tensor.get_element(1), 2);
    /// assert_eq!(*tensor.get_element(2), 3);
    /// ```
    pub fn fill_with(&mut self, ope: impl Fn() -> <Self as AsMutSlice>::Element)
    where
        Self: AsMutSlice,
    {
        for output_i in self.iter_mut() {
            *output_i = ope();
        }
    }

    /// Fills a mutable tensor by casting elements of another one.
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u16, 1000);
    /// let mut t2 = Tensor::allocate(8. as f32, 1000);
    /// t1.fill_with_cast(&t2);
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 8);
    /// }
    /// ```
    pub fn fill_with_cast<Cont>(&mut self, other: &Tensor<Cont>)
    where
        Self: AsMutSlice,
        Tensor<Cont>: AsRefSlice,
        <Self as AsMutSlice>::Element: CastFrom<<Tensor<Cont> as AsRefSlice>::Element>,
        <Tensor<Cont> as AsRefSlice>::Element: Copy,
    {
        ck_dim_eq!(self.len() => other.len());
        self.fill_with_one(other, |a| <Self as AsMutSlice>::Element::cast_from(*a));
    }

    fill_with!(BitAnd, fill_with_bit_and, |l, r| *l & *r);
    fill_with!(BitOr, fill_with_bit_or, |l, r| *l | *r);
    fill_with!(BitXor, fill_with_bit_xor, |l, r| *l ^ *r);
    fill_with!(Shl, fill_with_bit_shl, |l, r| *l << *r);
    fill_with!(Shr, fill_with_bit_shr, |l, r| *l >> *r);

    fill_with_wrapping!(fill_with_wrapping_add, |l, r| l.wrapping_add(*r));
    fill_with_wrapping!(fill_with_wrapping_sub, |l, r| l.wrapping_sub(*r));
    fill_with_wrapping!(fill_with_wrapping_mul, |l, r| l.wrapping_mul(*r));
    fill_with_wrapping!(fill_with_wrapping_div, |l, r| l.wrapping_div(*r));

    /// Updates two tensors with the result of the operation with a single one.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor1 = Tensor::allocate(9 as u8, 1000);
    /// let mut tensor2 = Tensor::allocate(9 as u8, 1000);
    /// let tensor3 = Tensor::allocate(10 as u8, 1000);
    /// Tensor::update_two_with_one(&mut tensor1, &mut tensor2, &tensor3, |a, b, c| {
    ///     *a += *c;
    ///     *b += *c + 1;
    /// });
    /// assert_eq!(*tensor1.get_element(0), 19);
    /// assert_eq!(*tensor2.get_element(0), 20);
    /// ```
    pub fn update_two_with_one<Cont1, Cont2>(
        first: &mut Self,
        second: &mut Tensor<Cont1>,
        one: &Tensor<Cont2>,
        ope: impl Fn(
            &mut <Self as AsRefSlice>::Element,
            &mut <Tensor<Cont1> as AsRefSlice>::Element,
            &<Tensor<Cont2> as AsRefSlice>::Element,
        ),
    ) where
        Self: AsMutSlice,
        Tensor<Cont1>: AsMutSlice,
        Tensor<Cont2>: AsRefSlice,
    {
        ck_dim_eq!(first.len() => one.len());
        ck_dim_eq!(second.len() => one.len());
        for (first_i, (second_i, one_i)) in zip!(first.iter_mut(), second.iter_mut(), one.iter()) {
            ope(first_i, second_i, one_i);
        }
    }

    /// Updates a mutable tensor with the result of an element-wise operation with two other
    /// tensors of the same size.
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u8, 1000);
    /// let t2 = Tensor::allocate(1 as u8, 1000);
    /// let t3 = Tensor::allocate(2 as u8, 1000);
    /// t1.update_with_two(&t2, &t3, |t1, t2, t3| *t1 += t3 + t2);
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 12);
    /// }
    /// ```
    pub fn update_with_two<Cont1, Cont2>(
        &mut self,
        first: &Tensor<Cont1>,
        second: &Tensor<Cont2>,
        ope: impl Fn(
            &mut <Self as AsMutSlice>::Element,
            &<Tensor<Cont1> as AsRefSlice>::Element,
            &<Tensor<Cont2> as AsRefSlice>::Element,
        ),
    ) where
        Self: AsMutSlice,
        Tensor<Cont1>: AsRefSlice,
        Tensor<Cont2>: AsRefSlice,
    {
        ck_dim_eq!(self.len() => first.len());
        ck_dim_eq!(self.len() => second.len());
        for (self_i, (first_i, second_i)) in zip!(
            self.iter_mut(),
            first.as_slice().iter(),
            second.as_slice().iter()
        ) {
            ope(self_i, first_i, second_i);
        }
    }

    /// Updates a mutable tensor with the result of an element-wise operation with one other tensor
    /// of the same size
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u8, 1000);
    /// let t2 = Tensor::allocate(2 as u8, 1000);
    /// t1.update_with_one(&t2, |t1, t2| *t1 += t2.pow(2));
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 13);
    /// }
    /// ```
    pub fn update_with_one<Cont>(
        &mut self,
        other: &Tensor<Cont>,
        ope: impl Fn(&mut <Self as AsMutSlice>::Element, &<Tensor<Cont> as AsRefSlice>::Element),
    ) where
        Self: AsMutSlice,
        Tensor<Cont>: AsRefSlice,
    {
        ck_dim_eq!(self.len() => other.len());
        for (self_i, other_i) in zip!(self.iter_mut(), other.as_slice().iter()) {
            ope(self_i, other_i);
        }
    }

    /// Updates a mutable tensor with an element.
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// tensor.update_with_element(8, |t, s| *t += s);
    /// for scalar in tensor.iter() {
    ///     assert_eq!(*scalar, 17);
    /// }
    /// ```
    pub fn update_with_element<Element>(
        &mut self,
        scalar: Element,
        ope: impl Fn(&mut <Self as AsMutSlice>::Element, Element),
    ) where
        Self: AsMutSlice,
        Element: Copy,
    {
        for self_i in self.iter_mut() {
            ope(self_i, scalar);
        }
    }

    /// Updates a mutable tensor by repeatedly calling a closure.
    ///
    /// ```
    /// use std::cell::RefCell;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u16, 1000);
    /// let mut boxed = RefCell::from(0);
    /// tensor.update_with(|t| {
    ///     *boxed.borrow_mut() += 1;
    ///     *t += *boxed.borrow()
    /// });
    /// assert_eq!(*tensor.get_element(0), 10);
    /// assert_eq!(*tensor.get_element(1), 11);
    /// assert_eq!(*tensor.get_element(2), 12);
    /// ```
    pub fn update_with(&mut self, ope: impl Fn(&mut <Self as AsMutSlice>::Element))
    where
        Self: AsMutSlice,
    {
        for self_i in self.iter_mut() {
            ope(self_i);
        }
    }

    update_with!(BitAndAssign, update_with_and, |s, a| *s &= *a);
    update_with!(BitOrAssign, update_with_or, |s, a| *s |= *a);
    update_with!(BitXorAssign, update_with_xor, |s, a| *s ^= *a);
    update_with!(ShlAssign, update_with_shl, |s, a| *s <<= *a);
    update_with!(ShrAssign, update_with_shr, |s, a| *s >>= *a);

    update_with_wrapping!(update_with_wrapping_add, |s, a| *s = s.wrapping_add(*a));
    update_with_wrapping!(update_with_wrapping_sub, |s, a| *s = s.wrapping_sub(*a));
    update_with_wrapping!(update_with_wrapping_mul, |s, a| *s = s.wrapping_mul(*a));
    update_with_wrapping!(update_with_wrapping_div, |s, a| *s = s.wrapping_div(*a));

    update_with_scalar!(BitAndAssign, update_with_scalar_and, |s, a| *s &= *a);
    update_with_scalar!(BitOrAssign, update_with_scalar_or, |s, a| *s |= *a);
    update_with_scalar!(BitXorAssign, update_with_scalar_xor, |s, a| *s ^= *a);
    update_with_scalar!(ShlAssign, update_with_scalar_shl, |s, a| *s <<= *a);
    update_with_scalar!(ShrAssign, update_with_scalar_shr, |s, a| *s >>= *a);

    update_with_wrapping_scalar!(update_with_wrapping_scalar_add, |s, a| *s =
        s.wrapping_add(*a));
    update_with_wrapping_scalar!(update_with_wrapping_scalar_sub, |s, a| *s =
        s.wrapping_sub(*a));
    update_with_wrapping_scalar!(update_with_wrapping_scalar_mul, |s, a| *s =
        s.wrapping_mul(*a));
    update_with_wrapping_scalar!(update_with_wrapping_scalar_div, |s, a| *s =
        s.wrapping_div(*a));

    /// Sets each value of `self` to its own wrapping opposite.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::allocate(9 as u8, 1000);
    /// tensor.update_with_wrapping_neg();
    /// for scalar in tensor.iter() {
    ///     assert_eq!(*scalar, 247);
    /// }
    /// ```
    pub fn update_with_wrapping_neg(&mut self)
    where
        Self: AsMutSlice,
        <Self as AsMutSlice>::Element: UnsignedInteger,
    {
        self.update_with(|a| *a = a.wrapping_neg());
    }

    /// Fills a mutable tensor with the result of the wrapping multiplication of elements of
    /// another tensor by an element.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u8, 1000);
    /// let t2 = Tensor::allocate(3 as u8, 1000);
    /// t1.fill_with_wrapping_element_mul(&t2, 250);
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 238);
    /// }
    /// ```
    pub fn fill_with_wrapping_element_mul<Cont, Element>(
        &mut self,
        tensor: &Tensor<Cont>,
        element: Element,
    ) where
        Self: AsMutSlice<Element = Element>,
        Tensor<Cont>: AsRefSlice<Element = Element>,
        Element: UnsignedInteger,
    {
        ck_dim_eq!(self.len() => tensor.len());
        self.fill_with_one(tensor, |t| t.wrapping_mul(element));
    }

    /// Updates the values of a mutable tensor by wrap-subtracting the wrapping product of the
    /// elements of another tensor and an element.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u8, 1000);
    /// let t2 = Tensor::allocate(2 as u8, 1000);
    /// t1.update_with_wrapping_sub_element_mul(&t2, 250);
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 21);
    /// }
    /// ```
    pub fn update_with_wrapping_sub_element_mul<Cont, Element>(
        &mut self,
        tensor: &Tensor<Cont>,
        scalar: Element,
    ) where
        Self: AsMutSlice<Element = Element>,
        Tensor<Cont>: AsRefSlice<Element = Element>,
        Element: UnsignedInteger,
    {
        ck_dim_eq!(self.len() => tensor.len());
        self.update_with_one(tensor, |s, t| *s = s.wrapping_sub(t.wrapping_mul(scalar)));
    }

    /// Updates the values of a mutable tensor by wrap-adding the wrapping product of the elements
    /// of another tensor and an element.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut t1 = Tensor::allocate(9 as u8, 1000);
    /// let t2 = Tensor::allocate(2 as u8, 1000);
    /// t1.update_with_wrapping_add_element_mul(&t2, 250);
    /// for scalar in t1.iter() {
    ///     assert_eq!(*scalar, 253);
    /// }
    /// ```
    pub fn update_with_wrapping_add_element_mul<Cont, Element>(
        &mut self,
        tensor: &Tensor<Cont>,
        element: Element,
    ) where
        Self: AsMutSlice<Element = Element>,
        Tensor<Cont>: AsRefSlice<Element = Element>,
        Element: UnsignedInteger,
    {
        ck_dim_eq!(self.len() => tensor.len());
        self.update_with_one(tensor, |s, t| *s = s.wrapping_add(t.wrapping_mul(element)));
    }

    /// Computes a value by folding a tensor with another.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let t1 = Tensor::allocate(10 as u16, 10);
    /// let t2 = Tensor::allocate(2 as u16, 10);
    /// let val = t1.fold_with_one(&t2, 0, |mut a, t1, t2| {
    ///     a += t1 + t2;
    ///     a
    /// });
    /// assert_eq!(val, 120);
    /// ```
    pub fn fold_with_one<Cont, Output>(
        &self,
        other: &Tensor<Cont>,
        acc: Output,
        ope: impl Fn(
            Output,
            &<Self as AsRefSlice>::Element,
            &<Tensor<Cont> as AsRefSlice>::Element,
        ) -> Output,
    ) -> Output
    where
        Self: AsRefSlice,
        Tensor<Cont>: AsRefSlice,
    {
        ck_dim_eq!(self.len() => other.len());
        self.iter()
            .zip(other.as_slice().iter())
            .fold(acc, |acc, (s_i, o_i)| ope(acc, s_i, o_i))
    }

    /// Reverses the elements of the tensor inplace.
    ///
    /// # Example
    ///  
    /// ```rust
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::from_container(vec![1u8, 2, 3, 4]);
    /// tensor.reverse();
    /// assert_eq!(*tensor.get_element(0), 4);
    /// ```
    pub fn reverse(&mut self)
    where
        Self: AsMutSlice,
    {
        self.as_mut_slice().reverse()
    }

    /// Rotates the elements of the tensor to the right, inplace.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::from_container(vec![1u8, 2, 3, 4]);
    /// tensor.rotate_right(2);
    /// assert_eq!(*tensor.get_element(0), 3);
    /// ```
    pub fn rotate_right(&mut self, n: usize)
    where
        Self: AsMutSlice,
    {
        self.as_mut_slice().rotate_right(n)
    }

    /// Rotates the elements of the tensor to the left, inplace.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut tensor = Tensor::from_container(vec![1u8, 2, 3, 4]);
    /// tensor.rotate_left(2);
    /// assert_eq!(*tensor.get_element(0), 3);
    /// ```
    pub fn rotate_left(&mut self, n: usize)
    where
        Self: AsMutSlice,
    {
        self.as_mut_slice().rotate_left(n)
    }
}

impl<Element> FromIterator<Element> for Tensor<Vec<Element>> {
    fn from_iter<I: IntoIterator<Item = Element>>(iter: I) -> Self {
        let mut v = Vec::new();
        for i in iter {
            v.push(i);
        }
        Tensor(v)
    }
}

impl<Cont> AsRefSlice for Tensor<Cont>
where
    Cont: AsRefSlice,
{
    type Element = Cont::Element;
    fn as_slice(&self) -> &[Self::Element] {
        self.0.as_slice()
    }
}

impl<Cont> AsMutSlice for Tensor<Cont>
where
    Cont: AsMutSlice,
{
    type Element = <Cont as AsMutSlice>::Element;
    fn as_mut_slice(&mut self) -> &mut [<Self as AsMutSlice>::Element] {
        self.0.as_mut_slice()
    }
}

impl<Cont> AsRefTensor for Tensor<Cont>
where
    Cont: AsRefSlice,
{
    type Element = Cont::Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Cont> {
        self
    }
}

impl<Cont> AsMutTensor for Tensor<Cont>
where
    Cont: AsMutSlice,
{
    type Element = <Cont as AsMutSlice>::Element;
    type Container = Cont;
    fn as_mut_tensor(&mut self) -> &mut Tensor<Cont> {
        self
    }
}
