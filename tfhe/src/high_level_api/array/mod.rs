mod clear_ops;
mod cpu;
mod dynamic;
#[cfg(feature = "gpu")]
mod gpu;
mod helpers;
mod ops;
pub mod stride;
#[cfg(test)]
mod tests;
pub(in crate::high_level_api) mod traits;

use crate::array::traits::TensorSlice;
use crate::high_level_api::array::traits::HasClear;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams;
use crate::high_level_api::integers::FheUintId;
use crate::high_level_api::keys::InternalServerKey;
use crate::{FheBool, FheId, FheUint};
use std::ops::RangeBounds;
use traits::{ArrayBackend, BackendDataContainer, BackendDataContainerMut};
pub use traits::{IOwnedArray, Slicing, SlicingMut};

use crate::array::stride::DynDimensions;
pub use cpu::{
    CpuFheBoolArray, CpuFheBoolSlice, CpuFheBoolSliceMut, CpuFheIntArray, CpuFheIntSlice,
    CpuFheIntSliceMut, CpuFheUintArray, CpuFheUintSlice, CpuFheUintSliceMut, FheBoolId,
};
pub use dynamic::{
    FheBoolArray, FheBoolSlice, FheBoolSliceMut, FheIntArray, FheIntSlice, FheIntSliceMut,
    FheUintArray, FheUintSlice, FheUintSliceMut,
};
#[cfg(feature = "gpu")]
pub use gpu::{
    GpuFheBoolArray, GpuFheBoolSlice, GpuFheBoolSliceMut, GpuFheIntArray, GpuFheIntSlice,
    GpuFheIntSliceMut, GpuFheUintArray, GpuFheUintSlice, GpuFheUintSliceMut,
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
#[derive(Clone)]
pub struct FheArrayBase<C, Id> {
    elems: C,
    dims: DynDimensions,
    _id: Id,
}

impl<C, Id> FheArrayBase<C, Id> {
    pub fn num_dim(&self) -> usize {
        self.dims.num_dim()
    }

    pub fn shape(&self) -> &[usize] {
        self.dims.shape.as_slice()
    }

    /// Consumes the array and returns its inner container
    pub fn into_container(self) -> C {
        self.elems
    }

    pub fn container(&self) -> &C {
        &self.elems
    }

    pub fn container_mut(&mut self) -> &mut C {
        &mut self.elems
    }

    fn has_same_shape<C2, Id2>(&self, other: &FheArrayBase<C2, Id2>) -> bool {
        self.shape() == other.shape()
    }
}

impl<C, Id> FheArrayBase<C, Id>
where
    Id: Default,
{
    /// Creates an array from the given container and shape information
    pub fn new(data: impl Into<C>, shape: impl Into<DynDimensions>) -> Self {
        let elems = data.into();
        Self {
            elems,
            dims: shape.into(),
            _id: Id::default(),
        }
    }

    pub(in crate::high_level_api) fn as_tensor_slice(
        &self,
    ) -> TensorSlice<'_, <C::Backend as ArrayBackend>::Slice<'_>>
    where
        C: BackendDataContainer,
    {
        TensorSlice::new(self.elems.as_slice(), &self.dims)
    }

    pub fn get_slice<R>(
        &self,
        ranges: &[R],
    ) -> Option<FheArrayBase<<C::Backend as ArrayBackend>::Slice<'_>, Id>>
    where
        C: BackendDataContainer,
        R: Clone + RangeBounds<usize>,
    {
        let (new_dim, flat_range) = self.dims.get_slice_info(ranges)?;
        let sub_elems = self.elems.as_sub_slice(flat_range);
        Some(FheArrayBase::new(sub_elems, new_dim))
    }

    /// Returns a non-mutable slice that spans the given range of the array
    pub fn slice<R>(
        &self,
        ranges: &[R],
    ) -> FheArrayBase<<C::Backend as ArrayBackend>::Slice<'_>, Id>
    where
        C: BackendDataContainer,
        R: Clone + RangeBounds<usize>,
    {
        self.get_slice(ranges).unwrap()
    }

    /// Returns a non-mutable slice that spans the whole array
    pub fn as_slice(&self) -> FheArrayBase<<C::Backend as ArrayBackend>::Slice<'_>, Id>
    where
        C: BackendDataContainer,
    {
        FheArrayBase::new(self.elems.as_slice(), self.dims.clone())
    }

    /// Returns a mutable slice that spans the given range of the array
    pub fn get_slice_mut<R>(
        &mut self,
        ranges: &[R],
    ) -> Option<FheArrayBase<<C::Backend as ArrayBackend>::SliceMut<'_>, Id>>
    where
        C: BackendDataContainerMut,
        R: Clone + RangeBounds<usize>,
    {
        let (new_dim, flat_range) = self.dims.get_slice_info(ranges)?;
        let sub_elems = self.elems.as_sub_slice_mut(flat_range);
        Some(FheArrayBase::new(sub_elems, new_dim))
    }

    /// Returns a mutable slice that spans the given range of the array
    pub fn slice_mut<R>(
        &mut self,
        ranges: &[R],
    ) -> FheArrayBase<<C::Backend as ArrayBackend>::SliceMut<'_>, Id>
    where
        C: BackendDataContainerMut,
        R: Clone + RangeBounds<usize>,
    {
        self.get_slice_mut(ranges).unwrap()
    }

    /// Returns a mutable slice that spans the whole array
    pub fn as_slice_mut(&mut self) -> FheArrayBase<<C::Backend as ArrayBackend>::SliceMut<'_>, Id>
    where
        C: BackendDataContainerMut,
    {
        FheArrayBase::new(self.elems.as_slice_mut(), self.dims.clone())
    }

    pub fn reshape(&mut self, new_shape: Vec<usize>) -> crate::Result<()>
    where
        C: BackendDataContainerMut,
    {
        if new_shape.iter().copied().product::<usize>() != self.elems.len() {
            return Err(crate::Error::new(format!(
                "cannot reshape array of size {} into shape {:?}",
                self.elems.len(),
                new_shape.as_slice()
            )));
        }

        self.dims = DynDimensions::from(new_shape);
        Ok(())
    }

    /// Consumes the array and returns and owned version of it.
    ///
    /// This will trigger a clone of all the elements if the internal container does
    /// not own its data.
    pub fn into_owned(self) -> FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>
    where
        C: BackendDataContainer,
    {
        FheArrayBase::new(self.elems.into_owned(), self.dims)
    }
}

impl<C, Id> Slicing for FheArrayBase<C, Id>
where
    Id: Default,
    C: BackendDataContainer,
{
    type Slice<'a>
        = FheArrayBase<<C::Backend as ArrayBackend>::Slice<'a>, Id>
    where
        Self: 'a;

    fn slice(&self, ranges: &[impl RangeBounds<usize> + Clone]) -> Self::Slice<'_> {
        self.get_slice(ranges).unwrap()
    }

    fn as_slice(&self) -> Self::Slice<'_> {
        self.as_slice()
    }
}

impl<C, Id> SlicingMut for FheArrayBase<C, Id>
where
    Id: Default,
    C: BackendDataContainerMut,
{
    type SliceMut<'a>
        = FheArrayBase<<C::Backend as ArrayBackend>::SliceMut<'a>, Id>
    where
        Self: 'a;

    fn slice_mut(&mut self, range: &[impl RangeBounds<usize> + Clone]) -> Self::SliceMut<'_> {
        self.get_slice_mut(range).unwrap()
    }

    fn as_slice_mut(&mut self) -> Self::SliceMut<'_> {
        self.as_slice_mut()
    }
}

impl<C, Id> IOwnedArray for FheArrayBase<C, Id>
where
    Id: Default + Clone,
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

#[derive(Default, Copy, Clone)]
pub struct ClearId;

pub type ClearArrayBase<C> = FheArrayBase<cpu::ClearContainer<C>, ClearId>;
pub type ClearArray<T> = ClearArrayBase<Vec<T>>;
pub type ClearSlice<'a, T> = ClearArrayBase<&'a [T]>;
pub type ClearSliceMut<'a, T> = ClearArrayBase<&'a mut [T]>;

macro_rules! declare_concrete_array_types {
    (
        unsigned: $($num_bits:literal),*
    ) => {
        ::paste::paste!{
            $(
                // Instantiate Array Types for dyn backend
                pub type [<FheUint $num_bits Array>] = FheUintArray<crate::[<FheUint $num_bits Id>]>;
                pub type [<FheUint $num_bits Slice>]<'a> = FheUintSlice<'a, crate::[<FheUint $num_bits Id>]>;
                pub type [<FheUint $num_bits SliceMut>]<'a> = FheUintSliceMut<'a, crate::[<FheUint $num_bits Id>]>;

                // Instantiate Array Types for Cpu backend
                pub type [<CpuFheUint $num_bits Array>] = CpuFheUintArray<crate::[<FheUint $num_bits Id>]>;
                pub type [<CpuFheUint $num_bits Slice>]<'a> = CpuFheUintSlice<'a, crate::[<FheUint $num_bits Id>]>;
                pub type [<CpuFheUint $num_bits SliceMut>]<'a> = CpuFheUintSliceMut<'a, crate::[<FheUint $num_bits Id>]>;

                // Instantiate Array Types for Gpu backend
                #[cfg(feature="gpu")]
                pub type [<GpuFheUint $num_bits Array>] = GpuFheUintArray<crate::[<FheUint $num_bits Id>]>;
                #[cfg(feature="gpu")]
                pub type [<GpuFheUint $num_bits Slice>]<'a> = GpuFheUintSlice<'a, crate::[<FheUint $num_bits Id>]>;
                #[cfg(feature="gpu")]
                pub type [<GpuFheUint $num_bits SliceMut>]<'a> = GpuFheUintSliceMut<'a, crate::[<FheUint $num_bits Id>]>;

            )*

        }
    };
    (
        signed: $($num_bits:literal),*
    ) => {
        ::paste::paste!{
            $(
                // Instantiate Array Types for dyn backend
                pub type [<FheInt $num_bits Array>] = FheIntArray<crate::[<FheInt $num_bits Id>]>;
                pub type [<FheInt $num_bits Slice>]<'a> = FheIntSlice<'a, crate::[<FheInt $num_bits Id>]>;
                pub type [<FheInt $num_bits SliceMut>]<'a> = FheIntSliceMut<'a, crate::[<FheInt $num_bits Id>]>;

                // Instantiate Array Types for Cpu backend
                pub type [<CpuFheInt $num_bits Array>] = CpuFheIntArray<crate::[<FheInt $num_bits Id>]>;
                pub type [<CpuFheInt $num_bits Slice>]<'a> = CpuFheIntSlice<'a, crate::[<FheInt $num_bits Id>]>;
                pub type [<CpuFheInt $num_bits SliceMut>]<'a> = CpuFheIntSliceMut<'a, crate::[<FheInt $num_bits Id>]>;

                // Instantiate Array Types for Gpu backend
                #[cfg(feature="gpu")]
                pub type [<GpuFheInt $num_bits Array>] = GpuFheIntArray<crate::[<FheInt $num_bits Id>]>;
                #[cfg(feature="gpu")]
                pub type [<GpuFheInt $num_bits Slice>]<'a> = GpuFheIntSlice<'a, crate::[<FheInt $num_bits Id>]>;
                #[cfg(feature="gpu")]
                pub type [<GpuFheInt $num_bits SliceMut>]<'a> = GpuFheIntSliceMut<'a, crate::[<FheInt $num_bits Id>]>;

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

pub fn fhe_uint_array_eq<Id: FheUintId>(lhs: &[FheUint<Id>], rhs: &[FheUint<Id>]) -> FheBool {
    global_state::with_internal_keys(|sks| match sks {
        InternalServerKey::Cpu(cpu_key) => {
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();
            let tmp_rhs = rhs
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();

            let result = cpu_key
                .pbs_key()
                .all_eq_slices_parallelized(&tmp_lhs, &tmp_rhs);
            FheBool::new(result, cpu_key.tag.clone())
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(gpu_key) => with_thread_local_cuda_streams(|streams| {
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();
            let tmp_rhs = rhs
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();

            let result = gpu_key.key.key.all_eq_slices(&tmp_lhs, &tmp_rhs, streams);
            FheBool::new(result, gpu_key.tag.clone())
        }),
    })
}

pub fn fhe_uint_array_contains_sub_slice<Id: FheUintId>(
    lhs: &[FheUint<Id>],
    pattern: &[FheUint<Id>],
) -> FheBool {
    global_state::with_internal_keys(|sks| match sks {
        InternalServerKey::Cpu(cpu_key) => {
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();
            let tmp_pattern = pattern
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();

            let result = cpu_key
                .pbs_key()
                .contains_sub_slice_parallelized(&tmp_lhs, &tmp_pattern);
            FheBool::new(result, cpu_key.tag.clone())
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(gpu_key) => with_thread_local_cuda_streams(|streams| {
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();
            let tmp_pattern = pattern
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();

            let result = gpu_key
                .key
                .key
                .contains_sub_slice(&tmp_lhs, &tmp_pattern, streams);
            FheBool::new(result, gpu_key.tag.clone())
        }),
    })
}
