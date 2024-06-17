//! This module contains the implementation of the FheBool array backend
//! where the location of the values and computations can be changed/selected at runtime
use super::cpu_boolean_backend::{CpuFheBoolArrayBackend, FheBoolId};
use super::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use super::traits::{
    ArrayBackend, BackendDataContainer, BackendDataContainerMut, BitwiseArrayBackend,
    ClearBitwiseArrayBackend,
};
use super::{FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut};

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
    type Slice<'a> = InnerBoolSlice<'a> where Self: 'a;
    type SliceMut<'a> = InnerBoolSliceMut<'a> where Self: 'a;
    type Owned = InnerBoolArray;
}

impl BitwiseArrayBackend for DynFheBoolArrayBackend {
    fn bitand<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
        dispatch_binary_op(
            &lhs,
            &rhs,
            super::cpu_boolean_backend::CpuFheBoolArrayBackend::bitand,
        )
    }

    fn bitor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
        dispatch_binary_op(
            &lhs,
            &rhs,
            super::cpu_boolean_backend::CpuFheBoolArrayBackend::bitor,
        )
    }

    fn bitxor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
        dispatch_binary_op(
            &lhs,
            &rhs,
            super::cpu_boolean_backend::CpuFheBoolArrayBackend::bitxor,
        )
    }

    fn bitnot(lhs: Self::Slice<'_>) -> Self::Owned {
        dispatch_unary_op(
            &lhs,
            super::cpu_boolean_backend::CpuFheBoolArrayBackend::bitnot,
        )
    }
}

impl ClearBitwiseArrayBackend<bool> for DynFheBoolArrayBackend {
    fn bitand_slice(lhs: Self::Slice<'_>, rhs: &[bool]) -> Self::Owned {
        match crate::high_level_api::global_state::device_of_internal_keys() {
            Some(Device::Cpu) => {
                let lhs_cpu_cow = lhs.on_cpu();

                let lhs_cpu_slice: &[BooleanBlock] = lhs_cpu_cow.borrow();

                let result = CpuFheBoolArrayBackend::bitand_slice(lhs_cpu_slice, rhs);
                InnerBoolArray::Cpu(result)
            }
            #[cfg(feature = "gpu")]
            Some(Device::CudaGpu) => {
                panic!("Not supported by Cuda devices")
            }
            None => {
                panic!("{}", crate::high_level_api::errors::UninitializedServerKey);
            }
        }
    }
}

#[inline]
fn dispatch_binary_op<CpuFn>(
    lhs: &InnerBoolSlice<'_>,
    rhs: &InnerBoolSlice<'_>,
    cpu_fn: CpuFn,
) -> InnerBoolArray
where
    CpuFn: for<'a> Fn(&'a [BooleanBlock], &'a [BooleanBlock]) -> Vec<BooleanBlock>,
{
    match crate::high_level_api::global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.on_cpu();
            let rhs_cpu_cow = rhs.on_cpu();

            let lhs_cpu_slice: &[BooleanBlock] = lhs_cpu_cow.borrow();
            let rhs_cpu_slice: &[BooleanBlock] = rhs_cpu_cow.borrow();

            let result = cpu_fn(lhs_cpu_slice, rhs_cpu_slice);
            InnerBoolArray::Cpu(result)
        }
        #[cfg(feature = "gpu")]
        Some(Device::CudaGpu) => {
            panic!("Not supported by Cuda devices")
        }
        None => {
            panic!("{}", crate::high_level_api::errors::UninitializedServerKey);
        }
    }
}

#[inline]
fn dispatch_unary_op<CpuFn>(lhs: &InnerBoolSlice<'_>, cpu_fn: CpuFn) -> InnerBoolArray
where
    CpuFn: for<'a> Fn(&'a [BooleanBlock]) -> Vec<BooleanBlock>,
{
    match crate::high_level_api::global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.on_cpu();

            let lhs_cpu_slice: &[BooleanBlock] = lhs_cpu_cow.borrow();

            let result = cpu_fn(lhs_cpu_slice);
            InnerBoolArray::Cpu(result)
        }
        #[cfg(feature = "gpu")]
        Some(Device::CudaGpu) => {
            panic!("Not supported by Cuda devices")
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

impl<'a> InnerBoolSlice<'a> {
    fn on_cpu(&self) -> Cow<'_, [BooleanBlock]> {
        match self {
            InnerBoolSlice::Cpu(cpu_slice) => Cow::Borrowed(cpu_slice),
        }
    }
}

impl<'a> BackendDataContainer for InnerBoolSlice<'a> {
    type Backend = DynFheBoolArrayBackend;

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

impl<'a> BackendDataContainer for InnerBoolSliceMut<'a> {
    type Backend = DynFheBoolArrayBackend;

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

impl<'a> BackendDataContainerMut for InnerBoolSliceMut<'a> {
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
        Ok(Self::new(inner))
    }
}

impl FheDecrypt<Vec<bool>> for FheBoolArray {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        let slice = self.elems.as_slice();
        let cpu_cow = slice.on_cpu();
        let cpu_slice = cpu_cow.as_ref();

        crate::CpuFheBoolSlice::<'_>::new(cpu_slice).decrypt(key)
    }
}
