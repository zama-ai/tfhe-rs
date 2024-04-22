//! This module contains the implementations of the FheUint array and FheInt array backend
//! where the location of the values and computations can be changed/selected at runtime
use super::helpers::{
    create_sub_mut_slice_with_bound, create_sub_slice_with_bound, range_bounds_to_exclusive_range,
};
use crate::high_level_api::array::{ArrayBackend, BackendDataContainer, BackendDataContainerMut};
pub use signed::{FheIntArray, FheIntSlice, FheIntSliceMut};
pub use unsigned::{FheUintArray, FheUintSlice, FheUintSliceMut};

#[cfg(test)]
pub use signed::DynIntBackend;
#[cfg(test)]
pub use unsigned::DynUintBackend;

mod unsigned {
    use super::super::traits::{ArithmeticArrayBackend, BitwiseArrayBackend};
    use super::{
        create_sub_mut_slice_with_bound, create_sub_slice_with_bound,
        range_bounds_to_exclusive_range, ArrayBackend, BackendDataContainer,
        BackendDataContainerMut,
    };

    use crate::core_crypto::prelude::UnsignedNumeric;
    use crate::high_level_api::array::cpu_integer_backend::{
        CpuIntegerArrayBackend, CpuUintArrayBackend,
    };
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

    impl<'a> InnerUintSlice<'a> {
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

    impl<'a> InnerUintSliceMut<'a> {
        pub(crate) fn as_cpu_mut(&mut self) -> &'_ mut [RadixCiphertext] {
            match self {
                Self::Cpu(cpu_slice) => cpu_slice,
            }
        }
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

    impl<'a> BackendDataContainer for InnerUintSlice<'a> {
        type Backend = DynUintBackend;

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

    impl<'a> BackendDataContainer for InnerUintSliceMut<'a> {
        type Backend = DynUintBackend;

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

    impl<'a> BackendDataContainerMut for InnerUintSliceMut<'a> {
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
        lhs: &InnerUintSlice<'_>,
        rhs: &InnerUintSlice<'_>,
        cpu_fn: CpuFn,
    ) -> InnerUintArray
    where
        CpuFn: for<'a> Fn(&'a [RadixCiphertext], &'a [RadixCiphertext]) -> Vec<RadixCiphertext>,
    {
        match global_state::device_of_internal_keys() {
            Some(Device::Cpu) => {
                let lhs_cpu_cow = lhs.on_cpu();
                let rhs_cpu_cow = rhs.on_cpu();

                let lhs_cpu_slice: &[RadixCiphertext] = lhs_cpu_cow.borrow();
                let rhs_cpu_slice: &[RadixCiphertext] = rhs_cpu_cow.borrow();

                let result = cpu_fn(lhs_cpu_slice, rhs_cpu_slice);
                InnerUintArray::Cpu(result)
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
    fn dispatch_unary_op<CpuFn>(lhs: &InnerUintSlice<'_>, cpu_fn: CpuFn) -> InnerUintArray
    where
        CpuFn: for<'a> Fn(&'a [RadixCiphertext]) -> Vec<RadixCiphertext>,
    {
        match global_state::device_of_internal_keys() {
            Some(Device::Cpu) => {
                let lhs_cpu_cow = lhs.on_cpu();

                let lhs_cpu_slice: &[RadixCiphertext] = lhs_cpu_cow.borrow();

                let result = cpu_fn(lhs_cpu_slice);
                InnerUintArray::Cpu(result)
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

    impl ArithmeticArrayBackend for DynUintBackend {
        fn add_slices(lhs: Self::Slice<'_>, rhs: Self::Slice<'_>) -> Self::Owned {
            dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::add_slices)
        }

        fn add_assign_slices<'a>(mut lhs: Self::SliceMut<'a>, rhs: Self::Slice<'a>) {
            global_state::with_internal_keys(|key| match key {
                crate::high_level_api::keys::InternalServerKey::Cpu(_) => {
                    let lhs_cpu_slice = lhs.as_cpu_mut();
                    let rhs_cpu_cow = rhs.on_cpu();

                    let rhs_cpu_slice: &[RadixCiphertext] = rhs_cpu_cow.borrow();

                    CpuIntegerArrayBackend::<RadixCiphertext>::add_assign_slices(
                        lhs_cpu_slice,
                        rhs_cpu_slice,
                    );
                }
                #[cfg(feature = "gpu")]
                crate::high_level_api::keys::InternalServerKey::Cuda(_) => {
                    panic!("Not supported by Cuda devices")
                }
            })
        }
    }

    impl BitwiseArrayBackend for DynUintBackend {
        fn bitand<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
            dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::bitand)
        }

        fn bitor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
            dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::bitor)
        }

        fn bitxor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
            dispatch_binary_op(&lhs, &rhs, CpuIntegerArrayBackend::bitxor)
        }

        fn bitnot(lhs: Self::Slice<'_>) -> Self::Owned {
            dispatch_unary_op(&lhs, CpuIntegerArrayBackend::bitnot)
        }
    }

    impl<Clear> ClearBitwiseArrayBackend<Clear> for DynUintBackend
    where
        Clear: DecomposableInto<u8>,
    {
        fn bitand_slice(lhs: Self::Slice<'_>, rhs: &[Clear]) -> Self::Owned {
            match global_state::device_of_internal_keys() {
                Some(Device::Cpu) => {
                    let lhs_cpu_cow = lhs.on_cpu();

                    let lhs_cpu_slice: &[RadixCiphertext] = lhs_cpu_cow.borrow();

                    let result = CpuUintArrayBackend::bitand_slice(lhs_cpu_slice, rhs);
                    InnerUintArray::Cpu(result)
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

    impl<'a, Clear, Id> FheTryEncrypt<&'a [Clear], ClientKey> for FheUintArray<Id>
    where
        Id: FheUintId,
        Clear: DecomposableInto<u64> + UnsignedNumeric,
    {
        type Error = Error;

        fn try_encrypt(clears: &'a [Clear], key: &ClientKey) -> Result<Self, Self::Error> {
            let cpu_data = crate::CpuFheUintArray::<Id>::try_encrypt(clears, key)?;
            let data = Self::new(InnerUintArray::Cpu(cpu_data.into_container()));
            Ok(data)
        }
    }

    impl<Clear, Id> FheDecrypt<Vec<Clear>> for FheUintArray<Id>
    where
        Id: FheUintId,
        Clear: RecomposableFrom<u64> + UnsignedNumeric,
    {
        fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
            let slice = self.elems.as_slice();
            let cpu_cow = slice.on_cpu();
            let cpu_slice = cpu_cow.as_ref();

            crate::CpuFheUintSlice::<'_, Id>::new(cpu_slice).decrypt(key)
        }
    }
}

mod signed {
    use super::super::helpers::{create_sub_mut_slice_with_bound, range_bounds_to_exclusive_range};
    use super::super::traits::{ArithmeticArrayBackend, BitwiseArrayBackend};
    use super::{ArrayBackend, BackendDataContainer, BackendDataContainerMut};

    use crate::core_crypto::prelude::SignedNumeric;
    use crate::high_level_api::array::cpu_integer_backend::CpuIntArrayBackend;
    use crate::high_level_api::array::traits::ClearBitwiseArrayBackend;
    use crate::high_level_api::array::{
        FheArrayBase, FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut,
    };
    use crate::high_level_api::global_state;
    use crate::high_level_api::integers::FheIntId;
    use crate::integer::block_decomposition::DecomposableInto;
    use crate::integer::client_key::RecomposableSignedInteger;
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

        fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerIntSlice<'_> {
            match self {
                Self::Cpu(cpu_vec) => {
                    let range = super::range_bounds_to_exclusive_range(range, cpu_vec.len());
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

    impl<'a> InnerIntSlice<'a> {
        pub(crate) fn on_cpu(&self) -> Cow<'_, [SignedRadixCiphertext]> {
            match self {
                Self::Cpu(cpu_slice) => Cow::Borrowed(cpu_slice),
            }
        }
    }

    impl<'a> BackendDataContainer for InnerIntSlice<'a> {
        type Backend = DynIntBackend;

        fn as_sub_slice(&self, range: impl RangeBounds<usize>) -> InnerIntSlice<'_> {
            match self {
                Self::Cpu(cpu_slice) => {
                    let range = super::range_bounds_to_exclusive_range(range, cpu_slice.len());
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

    impl<'a> BackendDataContainer for InnerIntSliceMut<'a> {
        type Backend = DynIntBackend;

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

    impl<'a> BackendDataContainerMut for InnerIntSliceMut<'a> {
        fn as_sub_slice_mut(&mut self, range: impl RangeBounds<usize>) -> InnerIntSliceMut<'_> {
            match self {
                Self::Cpu(cpu_slice) => {
                    let range = range_bounds_to_exclusive_range(range, cpu_slice.len());
                    InnerIntSliceMut::Cpu(&mut cpu_slice[range])
                }
            }
        }
    }

    impl<'a> InnerIntSliceMut<'a> {
        pub(crate) fn as_cpu_mut(&mut self) -> &'_ mut [SignedRadixCiphertext] {
            match self {
                Self::Cpu(cpu_slice) => cpu_slice,
            }
        }
    }

    // Base alias for array of signed integers on the dynamic backend
    pub type FheIntArray<Id> = FheBackendArray<DynIntBackend, Id>;
    pub type FheIntSlice<'a, Id> = FheBackendArraySlice<'a, DynIntBackend, Id>;
    pub type FheIntSliceMut<'a, Id> = FheBackendArraySliceMut<'a, DynIntBackend, Id>;

    pub struct DynIntBackend;

    impl ArrayBackend for DynIntBackend {
        type Slice<'a> = InnerIntSlice<'a> where Self: 'a;
        type SliceMut<'a> = InnerIntSliceMut<'a> where Self: 'a;
        type Owned = InnerIntArray;
    }

    #[inline]
    fn dispatch_binary_op<CpuFn>(
        lhs: &InnerIntSlice<'_>,
        rhs: &InnerIntSlice<'_>,
        cpu_fn: CpuFn,
    ) -> InnerIntArray
    where
        CpuFn: for<'a> Fn(
            &'a [SignedRadixCiphertext],
            &'a [SignedRadixCiphertext],
        ) -> Vec<SignedRadixCiphertext>,
    {
        match crate::high_level_api::global_state::device_of_internal_keys() {
            Some(Device::Cpu) => {
                let lhs_cpu_cow = lhs.on_cpu();
                let rhs_cpu_cow = rhs.on_cpu();

                let lhs_cpu_slice: &[SignedRadixCiphertext] = lhs_cpu_cow.borrow();
                let rhs_cpu_slice: &[SignedRadixCiphertext] = rhs_cpu_cow.borrow();

                let result = cpu_fn(lhs_cpu_slice, rhs_cpu_slice);
                InnerIntArray::Cpu(result)
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
    fn dispatch_unary_op<CpuFn>(lhs: &InnerIntSlice<'_>, cpu_fn: CpuFn) -> InnerIntArray
    where
        CpuFn: for<'a> Fn(&'a [SignedRadixCiphertext]) -> Vec<SignedRadixCiphertext>,
    {
        match crate::high_level_api::global_state::device_of_internal_keys() {
            Some(Device::Cpu) => {
                let lhs_cpu_cow = lhs.on_cpu();

                let lhs_cpu_slice: &[SignedRadixCiphertext] = lhs_cpu_cow.borrow();

                let result = cpu_fn(lhs_cpu_slice);
                InnerIntArray::Cpu(result)
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

    impl ArithmeticArrayBackend for DynIntBackend {
        fn add_slices(lhs: Self::Slice<'_>, rhs: Self::Slice<'_>) -> Self::Owned {
            dispatch_binary_op(
                &lhs,
                &rhs,
                super::super::cpu_integer_backend::CpuIntegerArrayBackend::add_slices,
            )
        }

        fn add_assign_slices<'a>(mut lhs: Self::SliceMut<'a>, rhs: Self::Slice<'a>) {
            crate::high_level_api::global_state::with_internal_keys(|key| match key {
                crate::high_level_api::keys::InternalServerKey::Cpu(_) => {
                    let lhs_cpu_slice = lhs.as_cpu_mut();
                    let rhs_cpu_cow = rhs.on_cpu();

                    let rhs_cpu_slice: &[SignedRadixCiphertext] = rhs_cpu_cow.borrow();

                    super::super::cpu_integer_backend::CpuIntegerArrayBackend::add_assign_slices(
                        lhs_cpu_slice,
                        rhs_cpu_slice,
                    );
                }
                #[cfg(feature = "gpu")]
                crate::high_level_api::keys::InternalServerKey::Cuda(_) => {
                    panic!("Not supported by Cuda devices")
                }
            })
        }
    }

    impl BitwiseArrayBackend for DynIntBackend {
        fn bitand<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
            dispatch_binary_op(
                &lhs,
                &rhs,
                super::super::cpu_integer_backend::CpuIntegerArrayBackend::bitand,
            )
        }

        fn bitor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
            dispatch_binary_op(
                &lhs,
                &rhs,
                super::super::cpu_integer_backend::CpuIntegerArrayBackend::bitor,
            )
        }

        fn bitxor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
            dispatch_binary_op(
                &lhs,
                &rhs,
                super::super::cpu_integer_backend::CpuIntegerArrayBackend::bitxor,
            )
        }

        fn bitnot(lhs: Self::Slice<'_>) -> Self::Owned {
            dispatch_unary_op(
                &lhs,
                super::super::cpu_integer_backend::CpuIntegerArrayBackend::bitnot,
            )
        }
    }

    impl<Clear> ClearBitwiseArrayBackend<Clear> for DynIntBackend
    where
        Clear: DecomposableInto<u8>,
    {
        fn bitand_slice(lhs: Self::Slice<'_>, rhs: &[Clear]) -> Self::Owned {
            match global_state::device_of_internal_keys() {
                Some(Device::Cpu) => {
                    let lhs_cpu_cow = lhs.on_cpu();

                    let lhs_cpu_slice: &[SignedRadixCiphertext] = lhs_cpu_cow.borrow();

                    let result = CpuIntArrayBackend::bitand_slice(lhs_cpu_slice, rhs);
                    InnerIntArray::Cpu(result)
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
            Ok(Self::new(inner))
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

            crate::CpuFheIntSlice::<'_, Id>::new(cpu_slice).decrypt(key)
        }
    }
}
