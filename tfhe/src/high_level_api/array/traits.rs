use std::ops::RangeBounds;

/// Trait to abstract backends of arrays
///
/// The backend manages where and how the array data is stored
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
    fn add_slices<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned;

    fn add_assign_slices<'a>(lhs: Self::SliceMut<'a>, rhs: Self::Slice<'a>);
}

/// Trait for backends that can do bitwise operations
pub trait BitwiseArrayBackend: ArrayBackend {
    fn bitand<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned;

    fn bitor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned;

    fn bitxor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned;

    fn bitnot(lhs: Self::Slice<'_>) -> Self::Owned;
}

/// Trait for backends that can do bitwise operations
pub trait ClearBitwiseArrayBackend<Clear>: ArrayBackend {
    fn bitand_slice(lhs: Self::Slice<'_>, rhs: &[Clear]) -> Self::Owned;
}

pub trait Slicing {
    type Slice<'a>
    where
        Self: 'a;

    fn slice(&self, range: impl RangeBounds<usize>) -> Self::Slice<'_>;

    fn as_slice(&self) -> Self::Slice<'_> {
        self.slice(..)
    }
}

pub trait SlicingMut {
    type SliceMut<'a>
    where
        Self: 'a;

    fn slice_mut(&mut self, range: impl RangeBounds<usize>) -> Self::SliceMut<'_>;

    fn as_slice_mut(&mut self) -> Self::SliceMut<'_> {
        self.slice_mut(..)
    }
}

/// Super trait in order to ease a bit writing some trait bounds
/// in generic code that works on Array
///
/// This trait is for "Owned" array types
pub trait IOwnedArray: Clone + Slicing + SlicingMut {}

/// Internal trait to abstract how container store data for the
/// associated backend
///
/// This is to be implemented for all containers where we can make
/// non-mutable access to data (i.e. owned arrays, slices, slices mut)
pub trait BackendDataContainer {
    type Backend: ArrayBackend;

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
