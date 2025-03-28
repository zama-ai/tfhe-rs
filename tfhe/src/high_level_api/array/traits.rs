use crate::array::stride::{DynDimensions, ParStridedIter, ParStridedIterMut, StridedIter};
use std::ops::RangeBounds;

pub struct TensorSlice<'a, Slc> {
    pub slice: Slc,
    pub dims: &'a DynDimensions,
}

impl<'a, Slc> TensorSlice<'a, Slc> {
    pub fn new(slice: Slc, dims: &'a DynDimensions) -> Self {
        Self { slice, dims }
    }

    pub fn map<F, T>(self, transform: F) -> TensorSlice<'a, T>
    where
        F: FnOnce(Slc) -> T,
    {
        let Self { slice, dims } = self;
        TensorSlice::new(transform(slice), dims)
    }
}

impl<'a, T> TensorSlice<'a, &'a [T]> {
    pub fn iter(self) -> StridedIter<'a, T> {
        StridedIter::new(self.slice, self.dims.clone())
    }

    pub fn par_iter(self) -> ParStridedIter<'a, T> {
        ParStridedIter::new(self.slice, self.dims.clone())
    }
}

impl<'a, T> TensorSlice<'a, &'a mut [T]> {
    pub fn par_iter_mut(self) -> ParStridedIterMut<'a, T> {
        ParStridedIterMut::new(self.slice, self.dims.clone())
    }
}

/// Trait to abstract backends of arrays
///
/// The backend manages where and how the array data is stored
///
/// This is more or less a way to work around some rust limitations
/// when mixing HTRBs and GATs, as it allows to 'hide' the GAT in
/// some traits bounds. But it leads to the code's organization being a bit weirder
/// than it could be (one backend per type if container, and not per actual backend [cpu/gpu])
///
/// https://blog.rust-lang.org/2022/10/28/gats-stabilization.html#implied-static-requirement-from-higher-ranked-trait-bounds
pub trait ArrayBackend {
    type Slice<'a>: BackendDataContainer<Backend = Self>
    where
        Self: 'a;
    type SliceMut<'a>: BackendDataContainerMut<Backend = Self>
    where
        Self: 'a;
    type Owned: BackendDataContainerMut<Backend = Self>;
}

/// Trait for backends that can do arithmetic operations
pub trait ArithmeticArrayBackend: ArrayBackend {
    fn add_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;

    fn sub_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;

    fn mul_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;

    fn div_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;

    fn rem_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;
}

/// Trait for backends that can do arithmetic operations with clear
pub trait ClearArithmeticArrayBackend<Clear>: ArrayBackend {
    fn add_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;

    fn sub_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;

    fn mul_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;

    fn div_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;

    fn rem_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;
}

/// Trait for backends that can do bitwise operations
pub trait BitwiseArrayBackend: ArrayBackend {
    fn bitand<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;

    fn bitor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;

    fn bitxor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned;

    fn bitnot(lhs: TensorSlice<Self::Slice<'_>>) -> Self::Owned;
}

/// Trait for backends that can do bitwise operations
pub trait ClearBitwiseArrayBackend<Clear>: ArrayBackend {
    fn bitand_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;

    fn bitor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;

    fn bitxor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned;
}

/// Internal trait to abstract how container store data for the
/// associated backend
///
/// This is to be implemented for all containers where we can make
/// non-mutable access to data (i.e. owned arrays, slices, slices mut)
pub trait BackendDataContainer {
    type Backend: ArrayBackend;

    fn len(&self) -> usize;

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_>;

    fn as_slice(&self) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        self.as_sub_slice(..)
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned;
}

/// Internal trait to abstract how container store data for the
/// associated backend
///
/// This is to be implemented for all containers where we can make
/// mutable access to data (i.e. owned arrays, slices mut)
pub trait BackendDataContainerMut: BackendDataContainer {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_>;

    fn as_slice_mut(&mut self) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        self.as_sub_slice_mut(..)
    }
}

pub trait HasClear {
    type Clear;
}

pub trait Slicing {
    type Slice<'a>
    where
        Self: 'a;

    fn slice(&self, ranges: &[impl RangeBounds<usize> + Clone]) -> Self::Slice<'_>;

    fn as_slice(&self) -> Self::Slice<'_>;
}

pub trait SlicingMut {
    type SliceMut<'a>
    where
        Self: 'a;

    fn slice_mut(&mut self, range: &[impl RangeBounds<usize> + Clone]) -> Self::SliceMut<'_>;

    fn as_slice_mut(&mut self) -> Self::SliceMut<'_>;
}

/// Super trait in order to ease a bit writing some trait bounds
/// in generic code that works on Array
///
/// This trait is for "Owned" array types
pub trait IOwnedArray: Clone + Slicing + SlicingMut {}

// Trait to overload `dot_product` free functions
pub trait FheSliceDotProduct<Lhs, Rhs> {
    fn dot_product(lhs: &[Lhs], rhs: &[Rhs]) -> Self;
}
