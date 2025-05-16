use crate::array::cpu::CpuIntegerArrayBackend;
use crate::array::helpers::{create_sub_mut_slice_with_bound, range_bounds_to_exclusive_range};
use crate::array::traits::{
    ArithmeticArrayBackend, ArrayBackend, BackendDataContainer, BackendDataContainerMut,
    BitwiseArrayBackend, TensorSlice,
};
use crate::core_crypto::prelude::SignedNumeric;
use crate::high_level_api::array::traits::ClearBitwiseArrayBackend;
use crate::high_level_api::array::{
    FheArrayBase, FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut,
};
use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntId;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableSignedInteger};
use crate::integer::SignedRadixCiphertext;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::{ClientKey, Device, Error};
use std::borrow::{Borrow, Cow};
use std::ops::RangeBounds;

#[derive(Clone)]
pub enum InnerIntArray {
    Cpu(Vec<SignedRadixCiphertext>),
}

impl From<Vec<SignedRadixCiphertext>> for InnerIntArray {
    fn from(value: Vec<SignedRadixCiphertext>) -> Self {
        Self::Cpu(value)
    }
}

impl BackendDataContainer for InnerIntArray {
    type Backend = DynIntBackend;

    fn len(&self) -> usize {
        match self {
            Self::Cpu(cpu_array) => cpu_array.len(),
        }
    }

    fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerIntSlice<'_> {
        match self {
            Self::Cpu(cpu_vec) => {
                let range = range_bounds_to_exclusive_range(range, cpu_vec.len());
                InnerIntSlice::Cpu(&cpu_vec[range])
            }
        }
    }

    fn into_owned(self) -> Self {
        match self {
            Self::Cpu(cpu_vec) => Self::Cpu(cpu_vec),
        }
    }
}

impl BackendDataContainerMut for InnerIntArray {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        match self {
            Self::Cpu(cpu_vec) => InnerIntSliceMut::Cpu(create_sub_mut_slice_with_bound(
                cpu_vec.as_mut_slice(),
                range,
            )),
        }
    }
}

#[derive(Copy, Clone)]
pub enum InnerIntSlice<'a> {
    Cpu(&'a [SignedRadixCiphertext]),
}

impl InnerIntSlice<'_> {
    pub(crate) fn on_cpu(&self) -> Cow<'_, [SignedRadixCiphertext]> {
        match self {
            Self::Cpu(cpu_slice) => Cow::Borrowed(cpu_slice),
        }
    }
}

impl BackendDataContainer for InnerIntSlice<'_> {
    type Backend = DynIntBackend;

    fn len(&self) -> usize {
        match self {
            InnerIntSlice::Cpu(cpu_cpu) => cpu_cpu.len(),
        }
    }

    fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerIntSlice<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let range = range_bounds_to_exclusive_range(range, cpu_slice.len());
                InnerIntSlice::Cpu(&cpu_slice[range])
            }
        }
    }

    fn into_owned(self) -> InnerIntArray {
        match self {
            InnerIntSlice::Cpu(cpu_slice) => InnerIntArray::Cpu(cpu_slice.to_vec()),
        }
    }
}

pub enum InnerIntSliceMut<'a> {
    Cpu(&'a mut [SignedRadixCiphertext]),
}

impl BackendDataContainer for InnerIntSliceMut<'_> {
    type Backend = DynIntBackend;

    fn len(&self) -> usize {
        match self {
            InnerIntSliceMut::Cpu(cpu_slice) => cpu_slice.len(),
        }
    }

    fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerIntSlice<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let range = range_bounds_to_exclusive_range(range, cpu_slice.len());
                InnerIntSlice::Cpu(&cpu_slice[range])
            }
        }
    }

    fn into_owned(self) -> InnerIntArray {
        match self {
            Self::Cpu(cpu_slice) => InnerIntArray::Cpu(cpu_slice.to_owned()),
        }
    }
}

impl BackendDataContainerMut for InnerIntSliceMut<'_> {
    fn as_sub_slice_mut(&mut self, range: impl RangeBounds<usize>) -> InnerIntSliceMut<'_> {
        match self {
            Self::Cpu(cpu_slice) => {
                let range = range_bounds_to_exclusive_range(range, cpu_slice.len());
                InnerIntSliceMut::Cpu(&mut cpu_slice[range])
            }
        }
    }
}

// Base alias for array of signed integers on the dynamic backend
pub type FheIntArray<Id> = FheBackendArray<DynIntBackend, Id>;
pub type FheIntSlice<'a, Id> = FheBackendArraySlice<'a, DynIntBackend, Id>;
pub type FheIntSliceMut<'a, Id> = FheBackendArraySliceMut<'a, DynIntBackend, Id>;

pub struct DynIntBackend;

impl ArrayBackend for DynIntBackend {
    type Slice<'a>
        = InnerIntSlice<'a>
    where
        Self: 'a;
    type SliceMut<'a>
        = InnerIntSliceMut<'a>
    where
        Self: 'a;
    type Owned = InnerIntArray;
}

#[inline]
fn dispatch_binary_op<CpuFn>(
    lhs: &TensorSlice<'_, InnerIntSlice<'_>>,
    rhs: &TensorSlice<'_, InnerIntSlice<'_>>,
    cpu_fn: CpuFn,
) -> InnerIntArray
where
    CpuFn: for<'a> Fn(
        TensorSlice<'a, &'a [SignedRadixCiphertext]>,
        TensorSlice<'a, &'a [SignedRadixCiphertext]>,
    ) -> Vec<SignedRadixCiphertext>,
{
    match global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();
            let rhs_cpu_cow = rhs.slice.on_cpu();

            let lhs_cpu_slice: &[SignedRadixCiphertext] = lhs_cpu_cow.borrow();
            let rhs_cpu_slice: &[SignedRadixCiphertext] = rhs_cpu_cow.borrow();

            let result = cpu_fn(
                TensorSlice::new(lhs_cpu_slice, lhs.dims),
                TensorSlice::new(rhs_cpu_slice, rhs.dims),
            );
            InnerIntArray::Cpu(result)
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
    lhs: &TensorSlice<'_, InnerIntSlice<'_>>,
    cpu_fn: CpuFn,
) -> InnerIntArray
where
    CpuFn: for<'a> Fn(TensorSlice<'_, &'a [SignedRadixCiphertext]>) -> Vec<SignedRadixCiphertext>,
{
    match global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();

            let lhs_cpu_slice: &[SignedRadixCiphertext] = lhs_cpu_cow.borrow();

            let result = cpu_fn(TensorSlice::new(lhs_cpu_slice, lhs.dims));
            InnerIntArray::Cpu(result)
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

impl ArithmeticArrayBackend for DynIntBackend {
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

impl BitwiseArrayBackend for DynIntBackend {
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

impl<Clear> ClearBitwiseArrayBackend<Clear> for DynIntBackend
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
    lhs: &TensorSlice<'_, InnerIntSlice<'_>>,
    rhs: &TensorSlice<'_, &'_ [Clear]>,
    cpu_fn: CpuFn,
) -> InnerIntArray
where
    CpuFn: for<'a> Fn(
        TensorSlice<'_, &'a [SignedRadixCiphertext]>,
        TensorSlice<'_, &'a [Clear]>,
    ) -> Vec<SignedRadixCiphertext>,
{
    match global_state::device_of_internal_keys() {
        Some(Device::Cpu) => {
            let lhs_cpu_cow = lhs.slice.on_cpu();

            let lhs_cpu_slice: &[SignedRadixCiphertext] = lhs_cpu_cow.borrow();

            let result = cpu_fn(
                TensorSlice::new(lhs_cpu_slice, lhs.dims),
                TensorSlice::new(rhs.slice, rhs.dims),
            );
            InnerIntArray::Cpu(result)
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

impl<'a, Clear, Id> FheTryEncrypt<&'a [Clear], ClientKey> for FheArrayBase<InnerIntArray, Id>
where
    Id: FheIntId,
    Clear: DecomposableInto<u64> + SignedNumeric,
{
    type Error = Error;

    fn try_encrypt(clears: &'a [Clear], key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_array = crate::CpuFheIntArray::<Id>::try_encrypt(clears, key)?;
        let inner = InnerIntArray::Cpu(cpu_array.into_container());
        // TODO move to default device
        Ok(Self::new(inner, vec![clears.len()]))
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for FheArrayBase<InnerIntArray, Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        let slice = self.elems.as_slice();
        let cpu_cow = slice.on_cpu();
        let cpu_slice = cpu_cow.as_ref();

        crate::CpuFheIntSlice::<'_, Id>::new(cpu_slice, self.dims.clone()).decrypt(key)
    }
}
