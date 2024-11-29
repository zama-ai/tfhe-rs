pub(crate) mod booleans;
pub(crate) mod integers;

use crate::array::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use crate::array::traits::{
    ArithmeticArrayBackend, ArrayBackend, BackendDataContainer, BackendDataContainerMut,
    TensorSlice,
};
pub use booleans::{
    CpuFheBoolArray, CpuFheBoolArrayBackend, CpuFheBoolSlice, CpuFheBoolSliceMut, FheBoolId,
};
pub use integers::{
    CpuFheIntArray, CpuFheIntSlice, CpuFheIntSliceMut, CpuFheUintArray, CpuFheUintSlice,
    CpuFheUintSliceMut, CpuIntegerArrayBackend,
};
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Div, Mul, RangeBounds, Rem, Sub};

pub struct ClearArrayBackend<T>(PhantomData<T>);

#[derive(Clone)]
pub struct ClearContainer<C>(C);

impl<C> From<C> for ClearContainer<C> {
    fn from(value: C) -> Self {
        Self(value)
    }
}

impl<C> ClearContainer<C> {
    pub fn into_inner(self) -> C {
        self.0
    }
}

impl<C, T> AsRef<[T]> for ClearContainer<C>
where
    C: AsRef<[T]>,
{
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T> ArrayBackend for ClearArrayBackend<T>
where
    T: Copy,
{
    type Slice<'a>
        = ClearContainer<&'a [T]>
    where
        Self: 'a;
    type SliceMut<'a>
        = ClearContainer<&'a mut [T]>
    where
        Self: 'a;
    type Owned = ClearContainer<Vec<T>>;
}

impl<T> BackendDataContainer for ClearContainer<&'_ [T]>
where
    T: Copy,
{
    type Backend = ClearArrayBackend<T>;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        create_sub_slice_with_bound(self.0, range).into()
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self.0.to_vec().into()
    }
}

impl<T> BackendDataContainer for ClearContainer<&mut [T]>
where
    T: Copy,
{
    type Backend = ClearArrayBackend<T>;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        create_sub_slice_with_bound(self.0, range).into()
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self.0.to_vec().into()
    }
}

impl<T> BackendDataContainerMut for ClearContainer<&mut [T]>
where
    T: Copy,
{
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        create_sub_mut_slice_with_bound(self.0, range).into()
    }
}

impl<T> BackendDataContainer for ClearContainer<Vec<T>>
where
    T: Copy,
{
    type Backend = ClearArrayBackend<T>;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        create_sub_slice_with_bound(self.0.as_slice(), range).into()
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self.0.into()
    }
}

impl<T> BackendDataContainerMut for ClearContainer<Vec<T>>
where
    T: Copy,
{
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        create_sub_mut_slice_with_bound(&mut self.0, range).into()
    }
}

#[inline]
fn map_binary_element_wise_op<T, Op>(
    lhs: TensorSlice<'_, ClearContainer<&'_ [T]>>,
    rhs: TensorSlice<'_, ClearContainer<&'_ [T]>>,
    op: Op,
) -> Vec<T>
where
    T: Copy,
    Op: Fn(T, T) -> T,
{
    lhs.map(ClearContainer::into_inner)
        .iter()
        .copied()
        .zip(rhs.map(ClearContainer::into_inner).iter().copied())
        .map(|(l, r)| op(l, r))
        .collect()
}

impl<T> ArithmeticArrayBackend for ClearArrayBackend<T>
where
    T: Copy
        + Add<T, Output = T>
        + AddAssign<T>
        + Sub<T, Output = T>
        + Mul<T, Output = T>
        + Div<T, Output = T>
        + Rem<T, Output = T>,
{
    fn add_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        map_binary_element_wise_op(lhs, rhs, Add::add).into()
    }

    fn sub_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        map_binary_element_wise_op(lhs, rhs, Sub::sub).into()
    }

    fn mul_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        map_binary_element_wise_op(lhs, rhs, Mul::mul).into()
    }

    fn div_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        map_binary_element_wise_op(lhs, rhs, Div::div).into()
    }

    fn rem_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        map_binary_element_wise_op(lhs, rhs, Rem::rem).into()
    }
}
