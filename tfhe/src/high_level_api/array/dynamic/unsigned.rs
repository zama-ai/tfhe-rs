use crate::array::helpers::{
    create_sub_mut_slice_with_bound, create_sub_slice_with_bound, range_bounds_to_exclusive_range,
};
use crate::array::traits::{
    ArithmeticArrayBackend, ArrayBackend, BackendDataContainer, BackendDataContainerMut,
    BitwiseArrayBackend, TensorSlice,
};
use crate::core_crypto::prelude::UnsignedNumeric;
use crate::high_level_api::array::cpu::CpuIntegerArrayBackend;
use crate::high_level_api::array::traits::ClearBitwiseArrayBackend;
use crate::high_level_api::array::{
    FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut,
};
use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheUintId;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::RadixCiphertext;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::{ClientKey, Device, Error};
use std::borrow::{Borrow, Cow};
use std::ops::RangeBounds;

#[derive(Clone)]
pub enum InnerUintArray {
    Cpu(Vec<RadixCiphertext>),
}

impl From<Vec<RadixCiphertext>> for InnerUintArray {
    fn from(value: Vec<RadixCiphertext>) -> Self {
        Self::Cpu(value)
    }
}

#[derive(Copy, Clone)]
pub enum InnerUintSlice<'a> {
    Cpu(&'a [RadixCiphertext]),
}

impl InnerUintSlice<'_> {
    pub(crate) fn on_cpu(&self) -> Cow<'_, [RadixCiphertext]> {
        match self {
            InnerUintSlice::Cpu(cpu_slice) => Cow::Borrowed(cpu_slice),
        }
    }
}

impl<'a> From<InnerUintSlice<'a>> for InnerUintArray {
    fn from(value: InnerUintSlice<'a>) -> Self {
        match value {
            InnerUintSlice::Cpu(cpu_slice) => Self::Cpu(cpu_slice.to_vec()),
        }
    }
}

pub enum InnerUintSliceMut<'a> {
    Cpu(&'a mut [RadixCiphertext]),
}

impl<'a> From<InnerUintSliceMut<'a>> for InnerUintArray {
    fn from(value: InnerUintSliceMut<'a>) -> Self {
        match value {
            InnerUintSliceMut::Cpu(cpu_slice) => Self::Cpu(cpu_slice.to_vec()),
        }
    }
}

impl BackendDataContainer for InnerUintArray {
    type Backend = DynUintBackend;

    fn len(&self) -> usize {
        match self {
            Self::Cpu(cpu_array) => cpu_array.len(),
        }
    }

    fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerUintSlice<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let sliced = create_sub_slice_with_bound(cpu_slice, range);
                InnerUintSlice::Cpu(sliced)
            }
        }
    }

    fn into_owned(self) -> Self {
        self
    }
}

impl BackendDataContainerMut for InnerUintArray {
    fn as_sub_slice_mut(&mut self, range: impl RangeBounds<usize>) -> InnerUintSliceMut<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let sliced = create_sub_mut_slice_with_bound(cpu_slice, range);
                InnerUintSliceMut::Cpu(sliced)
            }
        }
    }
}

impl BackendDataContainer for InnerUintSlice<'_> {
    type Backend = DynUintBackend;

    fn len(&self) -> usize {
        match self {
            InnerUintSlice::Cpu(cpu_slice) => cpu_slice.len(),
        }
    }

    fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerUintSlice<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let range = range_bounds_to_exclusive_range(range, cpu_slice.len());
                InnerUintSlice::Cpu(&cpu_slice[range])
            }
        }
    }

    fn into_owned(self) -> InnerUintArray {
        match self {
            Self::Cpu(cpu_slice) => InnerUintArray::Cpu(cpu_slice.to_owned()),
        }
    }
}

impl BackendDataContainer for InnerUintSliceMut<'_> {
    type Backend = DynUintBackend;

    fn len(&self) -> usize {
        match self {
            InnerUintSliceMut::Cpu(cpu_slice) => cpu_slice.len(),
        }
    }

    fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerUintSlice<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let range = range_bounds_to_exclusive_range(range, cpu_slice.len());
                InnerUintSlice::Cpu(&cpu_slice[range])
            }
        }
    }

    fn into_owned(self) -> InnerUintArray {
        match self {
            Self::Cpu(cpu_slice) => InnerUintArray::Cpu(cpu_slice.to_owned()),
        }
    }
}

impl BackendDataContainerMut for InnerUintSliceMut<'_> {
    fn as_sub_slice_mut(&mut self, range: impl RangeBounds<usize>) -> InnerUintSliceMut<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let range = range_bounds_to_exclusive_range(range, cpu_slice.len());
                InnerUintSliceMut::Cpu(&mut cpu_slice[range])
            }
        }
    }
}

// Base alias for array of unsigned integers on the dynamic backend
pub type FheUintArray<Id> = FheBackendArray<DynUintBackend, Id>;
pub type FheUintSlice<'a, Id> = FheBackendArraySlice<'a, DynUintBackend, Id>;
pub type FheUintSliceMut<'a, Id> = FheBackendArraySliceMut<'a, DynUintBackend, Id>;

pub struct DynUintBackend;

impl ArrayBackend for DynUintBackend {
    type Slice<'a> = InnerUintSlice<'a>;
    type SliceMut<'a> = InnerUintSliceMut<'a>;
    type Owned = InnerUintArray;
}

#[inline]
fn dispatch_binary_op<CpuFn>(
    lhs: &TensorSlice<'_, InnerUintSlice<'_>>,
    rhs: &TensorSlice<'_, InnerUintSlice<'_>>,
    cpu_fn: CpuFn,
) -> InnerUintArray
where
    CpuFn: for<'a> Fn(
        TensorSlice<'_, &'a [RadixCiphertext]>,
        TensorSlice<'_, &'a [RadixCiphertext]>,
    ) -> Vec<RadixCiphertext>,
{
    match global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();
            let rhs_cpu_cow = rhs.slice.on_cpu();

            let lhs_cpu_slice: &[RadixCiphertext] = lhs_cpu_cow.borrow();
            let rhs_cpu_slice: &[RadixCiphertext] = rhs_cpu_cow.borrow();

            let result = cpu_fn(
                TensorSlice::new(lhs_cpu_slice, lhs.dims),
                TensorSlice::new(rhs_cpu_slice, rhs.dims),
            );
            InnerUintArray::Cpu(result)
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
    lhs: &TensorSlice<'_, InnerUintSlice<'_>>,
    cpu_fn: CpuFn,
) -> InnerUintArray
where
    CpuFn: for<'a> Fn(TensorSlice<'_, &'a [RadixCiphertext]>) -> Vec<RadixCiphertext>,
{
    match global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();

            let lhs_cpu_slice: &[RadixCiphertext] = lhs_cpu_cow.borrow();

            let result = cpu_fn(TensorSlice::new(lhs_cpu_slice, lhs.dims));
            InnerUintArray::Cpu(result)
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

impl ArithmeticArrayBackend for DynUintBackend {
    fn add_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, Self::Slice<'_>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::add_slices)
    }

    fn sub_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::sub_slices)
    }

    fn mul_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::mul_slices)
    }

    fn div_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::div_slices)
    }

    fn rem_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::rem_slices)
    }
}

impl BitwiseArrayBackend for DynUintBackend {
    fn bitand<'a>(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, Self::Slice<'_>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::bitand)
    }

    fn bitor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, Self::Slice<'_>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::bitor)
    }

    fn bitxor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, Self::Slice<'_>>,
    ) -> Self::Owned {
        dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::bitxor)
    }

    fn bitnot(lhs: TensorSlice<'_, Self::Slice<'_>>) -> Self::Owned {
        dispatch_unary_op(&lhs, CpuIntegerArrayBackend::bitnot)
    }
}

impl<Clear> ClearBitwiseArrayBackend<Clear> for DynUintBackend
where
    Clear: DecomposableInto<u8>,
{
    fn bitand_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        dispatch_binary_scalar_op(&lhs, &rhs, CpuIntegerArrayBackend::bitand_slice)
    }

    fn bitor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        dispatch_binary_scalar_op(&lhs, &rhs, CpuIntegerArrayBackend::bitor_slice)
    }

    fn bitxor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        dispatch_binary_scalar_op(&lhs, &rhs, CpuIntegerArrayBackend::bitxor_slice)
    }
}

#[inline]
fn dispatch_binary_scalar_op<CpuFn, Clear>(
    lhs: &TensorSlice<'_, InnerUintSlice<'_>>,
    rhs: &TensorSlice<'_, &'_ [Clear]>,
    cpu_fn: CpuFn,
) -> InnerUintArray
where
    CpuFn: for<'a> Fn(
        TensorSlice<'_, &'a [RadixCiphertext]>,
        TensorSlice<'_, &'a [Clear]>,
    ) -> Vec<RadixCiphertext>,
{
    match global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();

            let lhs_cpu_slice: &[RadixCiphertext] = lhs_cpu_cow.borrow();

            let result = cpu_fn(
                TensorSlice::new(lhs_cpu_slice, lhs.dims),
                TensorSlice::new(rhs.slice, rhs.dims),
            );
            InnerUintArray::Cpu(result)
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

impl<'a, Clear, Id> FheTryEncrypt<&'a [Clear], ClientKey> for FheUintArray<Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = Error;

    fn try_encrypt(clears: &'a [Clear], key: &ClientKey) -> Result<Self, Self::Error> {
        Self::try_encrypt((clears, vec![clears.len()]), key)
    }
}

impl<'a, Clear, Id> FheTryEncrypt<(&'a [Clear], Vec<usize>), ClientKey> for FheUintArray<Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = Error;

    fn try_encrypt(
        (clears, shape): (&'a [Clear], Vec<usize>),
        key: &ClientKey,
    ) -> Result<Self, Self::Error> {
        if clears.len() != shape.iter().copied().product::<usize>() {
            return Err(Error::new(
                "Shape does not matches the number of elements given".to_string(),
            ));
        }
        let cpu_data = crate::CpuFheUintArray::<Id>::try_encrypt((clears, shape.clone()), key)?;
        let data = Self::new(InnerUintArray::Cpu(cpu_data.into_container()), shape);
        Ok(data)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for FheUintArray<Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for FheUintSliceMut<'_, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for FheUintSlice<'_, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        let cpu_cow = self.elems.on_cpu();
        let cpu_slice = cpu_cow.as_ref();

        crate::CpuFheUintSlice::<'_, Id>::new(cpu_slice, self.dims.clone()).decrypt(key)
    }
}
