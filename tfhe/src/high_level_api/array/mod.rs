mod clear_ops;
mod cpu_boolean_backend;
mod cpu_integer_backend;
mod dyn_boolean_backend;
mod dyn_integer_backend;
mod helpers;
mod ops;
#[cfg(test)]
mod tests;
pub(in crate::high_level_api) mod traits;

use crate::high_level_api::array::traits::{HasClear, SlicingMut};
use crate::FheId;
pub use cpu_boolean_backend::FheBoolId;
use std::ops::RangeBounds;
use traits::{ArrayBackend, BackendDataContainer, BackendDataContainerMut, IOwnedArray, Slicing};

pub use cpu_boolean_backend::{CpuFheBoolArray, CpuFheBoolSlice, CpuFheBoolSliceMut};
pub use cpu_integer_backend::{
    CpuFheIntArray, CpuFheIntSlice, CpuFheIntSliceMut, CpuFheUintArray, CpuFheUintSlice,
    CpuFheUintSliceMut,
};
pub use dyn_boolean_backend::{FheBoolArray, FheBoolSlice, FheBoolSliceMut};
pub use dyn_integer_backend::{
    FheIntArray, FheIntSlice, FheIntSliceMut, FheUintArray, FheUintSlice, FheUintSliceMut,
};

/// The base struct for Fhe array types.
///
/// You  will generally interact with concrete instantiation of this struct.
///
/// The final concrete type depends on;
/// - The backend (cpu, gpu, dynamic[i.e. hardware is determined at runtime)
/// - The Fhe data type (boolean, unsigned integer, signed integer)
/// - The "ownership status": Does the array owns its memory, is it a reference (slice) to the data
///   of some other array.
///
/// Type aliases are available to select which kind you want to use e.g:
/// - [crate::CpuFheBoolArray]: An array of boolean values, always stored on the CPU
/// - [crate::CpuFheUint64Array]: An array of 64 bits unsigned integers, always stored on the CPU
/// - [crate::FheUint64Array]: An array of 64 bits unsigned integers, where the storage can be
///   changed at runtime (depending on the features enabled at compiletime and available hardware)
#[derive(Copy, Clone)]
pub struct FheArrayBase<C, Id>
where
    Id: FheId,
{
    elems: C,
    _id: Id,
}

impl<C, Id> FheArrayBase<C, Id>
where
    Id: FheId,
{
    pub(crate) fn new(data: impl Into<C>) -> Self {
        let elems = data.into();
        Self {
            elems,
            _id: Id::default(),
        }
    }

    /// Returns a non-mutable slice that spans the given range of the array
    pub fn slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> FheArrayBase<<C::Backend as ArrayBackend>::Slice<'_>, Id>
    where
        C: BackendDataContainer,
    {
        let sub_elems = self.elems.as_sub_slice(range);
        FheArrayBase::new(sub_elems)
    }

    /// Returns a non-mutable slice that spans the whole array
    pub fn as_slice(&self) -> FheArrayBase<<C::Backend as ArrayBackend>::Slice<'_>, Id>
    where
        C: BackendDataContainer,
    {
        self.slice(..)
    }

    /// Returns a mutable slice that spans the given range of the array
    pub fn slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> FheArrayBase<<C::Backend as ArrayBackend>::SliceMut<'_>, Id>
    where
        C: BackendDataContainerMut,
    {
        let sub_elems = self.elems.as_sub_slice_mut(range);
        FheArrayBase::new(sub_elems)
    }

    /// Returns a mutable slice that spans the whole array
    pub fn as_slice_mut(&mut self) -> FheArrayBase<<C::Backend as ArrayBackend>::SliceMut<'_>, Id>
    where
        C: BackendDataContainerMut,
    {
        self.slice_mut(..)
    }

    /// Consumes the array and returns its inner container
    pub fn into_container(self) -> C {
        self.elems
    }

    /// Consumes the array and returns and owned version of it.
    ///
    /// This will trigger a clone of all the elements if the internal container does
    /// not own its data.
    pub fn into_owned(self) -> FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>
    where
        C: BackendDataContainer,
    {
        FheArrayBase::new(self.elems.into_owned())
    }
}

impl<C, Id> Slicing for FheArrayBase<C, Id>
where
    Id: FheId,
    C: BackendDataContainer,
{
    type Slice<'a> = FheArrayBase<<C::Backend as ArrayBackend>::Slice<'a>, Id> where Self: 'a;

    fn slice(&self, range: impl RangeBounds<usize>) -> Self::Slice<'_> {
        self.slice(range)
    }
}

impl<C, Id> SlicingMut for FheArrayBase<C, Id>
where
    Id: FheId,
    C: BackendDataContainerMut,
{
    type SliceMut<'a> = FheArrayBase<<C::Backend as ArrayBackend>::SliceMut<'a>, Id> where Self: 'a;

    fn slice_mut(&mut self, range: impl RangeBounds<usize>) -> Self::SliceMut<'_> {
        self.slice_mut(range)
    }
}

impl<C, Id> IOwnedArray for FheArrayBase<C, Id>
where
    Id: FheId,
    C: BackendDataContainerMut + Clone,
{
}

// Aliases that expects a backend
pub type FheBackendArray<Backend, Id> = FheArrayBase<<Backend as ArrayBackend>::Owned, Id>;
pub type FheBackendArraySlice<'a, Backend, Id> =
    FheArrayBase<<Backend as ArrayBackend>::Slice<'a>, Id>;
pub type FheBackendArraySliceMut<'a, Backend, Id> =
    FheArrayBase<<Backend as ArrayBackend>::SliceMut<'a>, Id>;

impl<C, Id> HasClear for FheArrayBase<C, Id>
where
    Id: FheId + HasClear,
{
    type Clear = <Id as HasClear>::Clear;
}

impl HasClear for FheBoolId {
    type Clear = bool;
}

impl HasClear for crate::FheUint32Id {
    type Clear = u32;
}

impl HasClear for crate::FheInt32Id {
    type Clear = i32;
}

macro_rules! declare_concrete_array_types {
    (
        unsigned: $($num_bits:literal),*
    ) => {
        ::paste::paste!{
            $(
                // Instanciate Array Types for dyn backend
                pub type [<FheUint $num_bits Array>] = FheUintArray<crate::[<FheUint $num_bits Id>]>;
                pub type [<FheUint $num_bits Slice>]<'a> = FheUintSlice<'a, crate::[<FheUint $num_bits Id>]>;
                pub type [<FheUint $num_bits SliceMut>]<'a> = FheUintSliceMut<'a, crate::[<FheUint $num_bits Id>]>;

                // Instanciate Array Types for Cpu backend
                pub type [<CpuFheUint $num_bits Array>] = CpuFheUintArray<crate::[<FheUint $num_bits Id>]>;
                pub type [<CpuFheUint $num_bits Slice>]<'a> = CpuFheUintSlice<'a, crate::[<FheUint $num_bits Id>]>;
                pub type [<CpuFheUint $num_bits SliceMut>]<'a> = CpuFheUintSliceMut<'a, crate::[<FheUint $num_bits Id>]>;

            )*

        }
    };
    (
        signed: $($num_bits:literal),*
    ) => {
        ::paste::paste!{
            $(
                // Instanciate Array Types for dyn backend
                pub type [<FheInt $num_bits Array>] = FheIntArray<crate::[<FheInt $num_bits Id>]>;
                pub type [<FheInt $num_bits Slice>]<'a> = FheIntSlice<'a, crate::[<FheInt $num_bits Id>]>;
                pub type [<FheInt $num_bits SliceMut>]<'a> = FheIntSliceMut<'a, crate::[<FheInt $num_bits Id>]>;

                // Instanciate Array Types for Cpu backend
                pub type [<CpuFheInt $num_bits Array>] = CpuFheIntArray<crate::[<FheInt $num_bits Id>]>;
                pub type [<CpuFheInt $num_bits Slice>]<'a> = CpuFheIntSlice<'a, crate::[<FheInt $num_bits Id>]>;
                pub type [<CpuFheInt $num_bits SliceMut>]<'a> = CpuFheIntSliceMut<'a, crate::[<FheInt $num_bits Id>]>;

            )*

        }
    };
}

declare_concrete_array_types!(
    unsigned: 2, 4, 8, 16, 32, 64, 128, 256
);
declare_concrete_array_types!(
    signed: 2, 4, 8, 16, 32, 64, 128, 256
);

use crate::high_level_api::global_state::with_cpu_internal_keys;
use crate::high_level_api::integers::FheUintId;
use crate::{FheBool, FheUint};

pub fn fhe_uint_array_eq<Id: FheUintId>(lhs: &[FheUint<Id>], rhs: &[FheUint<Id>]) -> FheBool {
    with_cpu_internal_keys(|cpu_keys| {
        let tmp_lhs = lhs
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();
        let tmp_rhs = rhs
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();

        let result = cpu_keys
            .pbs_key()
            .all_eq_slices_parallelized(&tmp_lhs, &tmp_rhs);
        FheBool::new(result)
    })
}

pub fn fhe_uint_array_contains_sub_slice<Id: FheUintId>(
    lhs: &[FheUint<Id>],
    pattern: &[FheUint<Id>],
) -> FheBool {
    with_cpu_internal_keys(|cpu_keys| {
        let tmp_lhs = lhs
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();
        let tmp_pattern = pattern
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();

        let result = cpu_keys
            .pbs_key()
            .contains_sub_slice_parallelized(&tmp_lhs, &tmp_pattern);
        FheBool::new(result)
    })
}
