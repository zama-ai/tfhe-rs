//! This module contains the implementation of the FheBool array backend
//! where the location of the values and computations can be changed/selected at runtime
use super::super::cpu::{CpuFheBoolArrayBackend, FheBoolId};
use super::super::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use super::super::traits::{
    ArrayBackend, BackendDataContainer, BackendDataContainerMut, BitwiseArrayBackend,
    ClearBitwiseArrayBackend,
};
use super::super::{FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut};

use crate::array::traits::TensorSlice;
use crate::integer::BooleanBlock;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::{ClientKey, Device};
use std::borrow::{Borrow, Cow};
use std::ops::RangeBounds;

pub type FheBoolArray = FheBackendArray<DynFheBoolArrayBackend, FheBoolId>;
pub type FheBoolSlice<'a> = FheBackendArraySlice<'a, DynFheBoolArrayBackend, FheBoolId>;
pub type FheBoolSliceMut<'a> = FheBackendArraySliceMut<'a, DynFheBoolArrayBackend, FheBoolId>;

pub struct DynFheBoolArrayBackend;

impl ArrayBackend for DynFheBoolArrayBackend {
    type Slice<'a>
        = InnerBoolSlice<'a>
    where
        Self: 'a;
    type SliceMut<'a>
        = InnerBoolSliceMut<'a>
    where
        Self: 'a;
    type Owned = InnerBoolArray;
}

impl BitwiseArrayBackend for DynFheBoolArrayBackend {
    fn bitand<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuFheBoolArrayBackend::bitand)
    }

    fn bitor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuFheBoolArrayBackend::bitor)
    }

    fn bitxor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuFheBoolArrayBackend::bitxor)
    }

    fn bitnot(lhs: TensorSlice<'_, Self::Slice<'_>>) -> Self::Owned {
        dispatch_unary_op(&lhs, CpuFheBoolArrayBackend::bitnot)
    }
}

impl ClearBitwiseArrayBackend<bool> for DynFheBoolArrayBackend {
    fn bitand_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        dispatch_binary_scalar_op(&lhs, &rhs, CpuFheBoolArrayBackend::bitand_slice)
    }

    fn bitor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        dispatch_binary_scalar_op(&lhs, &rhs, CpuFheBoolArrayBackend::bitor_slice)
    }

    fn bitxor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        dispatch_binary_scalar_op(&lhs, &rhs, CpuFheBoolArrayBackend::bitxor_slice)
    }
}

#[inline]
fn dispatch_binary_op<CpuFn>(
    lhs: &TensorSlice<'_, InnerBoolSlice<'_>>,
    rhs: &TensorSlice<'_, InnerBoolSlice<'_>>,
    cpu_fn: CpuFn,
) -> InnerBoolArray
where
    CpuFn: for<'a> Fn(
        TensorSlice<'_, &'a [BooleanBlock]>,
        TensorSlice<'_, &'a [BooleanBlock]>,
    ) -> Vec<BooleanBlock>,
{
    match crate::high_level_api::global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();
            let rhs_cpu_cow = rhs.slice.on_cpu();

            let lhs_cpu_slice: &[BooleanBlock] = lhs_cpu_cow.borrow();
            let rhs_cpu_slice: &[BooleanBlock] = rhs_cpu_cow.borrow();

            let result = cpu_fn(
                TensorSlice::new(lhs_cpu_slice, lhs.dims),
                TensorSlice::new(rhs_cpu_slice, rhs.dims),
            );
            InnerBoolArray::Cpu(result)
        }
        #[cfg(feature = "gpu")]
        Some(Device::CudaGpu) => {
            panic!("Not supported by Cuda devices")
        }
        #[cfg(feature = "hpu")]
        Some(Device::Hpu) => {
            panic!("Not supported by Hpu devices")
        }
        None => {
            panic!("{}", crate::high_level_api::errors::UninitializedServerKey);
        }
    }
}

#[inline]
fn dispatch_unary_op<CpuFn>(
    lhs: &TensorSlice<'_, InnerBoolSlice<'_>>,
    cpu_fn: CpuFn,
) -> InnerBoolArray
where
    CpuFn: for<'a> Fn(TensorSlice<'_, &'a [BooleanBlock]>) -> Vec<BooleanBlock>,
{
    match crate::high_level_api::global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();

            let lhs_cpu_slice: &[BooleanBlock] = lhs_cpu_cow.borrow();

            let result = cpu_fn(TensorSlice::new(lhs_cpu_slice, lhs.dims));
            InnerBoolArray::Cpu(result)
        }
        #[cfg(feature = "gpu")]
        Some(Device::CudaGpu) => {
            panic!("Not supported by Cuda devices")
        }
        #[cfg(feature = "hpu")]
        Some(Device::Hpu) => {
            panic!("Not supported by Hpu devices")
        }
        None => {
            panic!("{}", crate::high_level_api::errors::UninitializedServerKey);
        }
    }
}

#[inline]
fn dispatch_binary_scalar_op<CpuFn>(
    lhs: &TensorSlice<'_, InnerBoolSlice<'_>>,
    rhs: &TensorSlice<'_, &'_ [bool]>,
    cpu_fn: CpuFn,
) -> InnerBoolArray
where
    CpuFn: for<'a> Fn(
        TensorSlice<'_, &'a [BooleanBlock]>,
        TensorSlice<'_, &'a [bool]>,
    ) -> Vec<BooleanBlock>,
{
    match crate::high_level_api::global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();

            let lhs_cpu_slice: &[BooleanBlock] = lhs_cpu_cow.borrow();

            let result = cpu_fn(
                TensorSlice::new(lhs_cpu_slice, lhs.dims),
                TensorSlice::new(rhs.slice, rhs.dims),
            );
            InnerBoolArray::Cpu(result)
        }
        #[cfg(feature = "gpu")]
        Some(Device::CudaGpu) => {
            panic!("Not supported by Cuda devices")
        }
        #[cfg(feature = "hpu")]
        Some(Device::Hpu) => {
            panic!("Not supported by Hpu devices")
        }
        None => {
            panic!("{}", crate::high_level_api::errors::UninitializedServerKey);
        }
    }
}

#[derive(Clone)]
pub enum InnerBoolArray {
    Cpu(Vec<BooleanBlock>),
}

impl BackendDataContainer for InnerBoolArray {
    type Backend = DynFheBoolArrayBackend;

    fn len(&self) -> usize {
        match self {
            Self::Cpu(cpu_array) => cpu_array.len(),
        }
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        match self {
            Self::Cpu(cpu_vec) => {
                InnerBoolSlice::Cpu(create_sub_slice_with_bound(cpu_vec.as_slice(), range))
            }
        }
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self
    }
}

impl BackendDataContainerMut for InnerBoolArray {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        match self {
            Self::Cpu(cpu_vec) => InnerBoolSliceMut::Cpu(create_sub_mut_slice_with_bound(
                cpu_vec.as_mut_slice(),
                range,
            )),
        }
    }
}

#[derive(Copy, Clone)]
pub enum InnerBoolSlice<'a> {
    Cpu(&'a [BooleanBlock]),
}

impl InnerBoolSlice<'_> {
    fn on_cpu(&self) -> Cow<'_, [BooleanBlock]> {
        match self {
            InnerBoolSlice::Cpu(cpu_slice) => Cow::Borrowed(cpu_slice),
        }
    }
}

impl BackendDataContainer for InnerBoolSlice<'_> {
    type Backend = DynFheBoolArrayBackend;

    fn len(&self) -> usize {
        match self {
            InnerBoolSlice::Cpu(cpu_slice) => cpu_slice.len(),
        }
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        match self {
            InnerBoolSlice::Cpu(cpu_slice) => {
                InnerBoolSlice::Cpu(create_sub_slice_with_bound(*cpu_slice, range))
            }
        }
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        match self {
            InnerBoolSlice::Cpu(cpu_slice) => InnerBoolArray::Cpu(cpu_slice.to_vec()),
        }
    }
}

pub enum InnerBoolSliceMut<'a> {
    Cpu(&'a mut [BooleanBlock]),
}

impl BackendDataContainer for InnerBoolSliceMut<'_> {
    type Backend = DynFheBoolArrayBackend;

    fn len(&self) -> usize {
        match self {
            InnerBoolSliceMut::Cpu(cpu_slice) => cpu_slice.len(),
        }
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                InnerBoolSlice::Cpu(create_sub_slice_with_bound(*cpu_slice, range))
            }
        }
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        match self {
            Self::Cpu(cpu_slice) => InnerBoolArray::Cpu(cpu_slice.to_vec()),
        }
    }
}

impl BackendDataContainerMut for InnerBoolSliceMut<'_> {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        match self {
            InnerBoolSliceMut::Cpu(cpu_slice) => {
                InnerBoolSliceMut::Cpu(create_sub_mut_slice_with_bound(*cpu_slice, range))
            }
        }
    }
}

impl<'a> FheTryEncrypt<&'a [bool], ClientKey> for FheBoolArray {
    type Error = crate::Error;

    fn try_encrypt(value: &'a [bool], key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_array = crate::CpuFheBoolArray::try_encrypt(value, key)?;
        let inner = InnerBoolArray::Cpu(cpu_array.into_container());
        // TODO move to default device
        Ok(Self::new(inner, vec![value.len()]))
    }
}

impl FheDecrypt<Vec<bool>> for FheBoolArray {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        let slice = self.elems.as_slice();
        let cpu_cow = slice.on_cpu();
        let cpu_slice = cpu_cow.as_ref();

        crate::CpuFheBoolSlice::<'_>::new(cpu_slice, self.dims.clone()).decrypt(key)
    }
}
