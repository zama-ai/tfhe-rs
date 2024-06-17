//! This module contains the implementations of the FheUint array and FheInt array backend
//! where the values and computations are always done on CPU
use super::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use super::traits::{ArithmeticArrayBackend, BitwiseArrayBackend, ClearBitwiseArrayBackend};
use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::high_level_api::array::{
    ArrayBackend, FheArrayBase, FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut,
};

use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::{IntegerRadixCiphertext, RadixCiphertext, SignedRadixCiphertext};
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::{ClientKey, Error};
use rayon::prelude::*;
use std::marker::PhantomData;
use std::ops::RangeBounds;

pub struct CpuIntegerArrayBackend<T>(PhantomData<T>);

pub type CpuUintArrayBackend = CpuIntegerArrayBackend<RadixCiphertext>;
pub type CpuIntArrayBackend = CpuIntegerArrayBackend<SignedRadixCiphertext>;

// Base alias for array of unsigned integers on the CPU only backend
pub type CpuFheUintArray<Id> = FheBackendArray<CpuUintArrayBackend, Id>;
pub type CpuFheUintSlice<'a, Id> = FheBackendArraySlice<'a, CpuUintArrayBackend, Id>;
pub type CpuFheUintSliceMut<'a, Id> = FheBackendArraySliceMut<'a, CpuUintArrayBackend, Id>;

// Base alias for array of signed integers on the CPU only backend
pub type CpuFheIntArray<Id> = FheBackendArray<CpuIntArrayBackend, Id>;
pub type CpuFheIntSlice<'a, Id> = FheBackendArraySlice<'a, CpuIntArrayBackend, Id>;
pub type CpuFheIntSliceMut<'a, Id> = FheBackendArraySliceMut<'a, CpuIntArrayBackend, Id>;

impl<T> ArrayBackend for CpuIntegerArrayBackend<T>
where
    T: IntegerRadixCiphertext,
{
    type Slice<'a> = &'a [T]  where Self: 'a;
    type SliceMut<'a> = &'a mut [T]  where Self: 'a;
    type Owned = Vec<T>;
}

impl<T> ArithmeticArrayBackend for CpuIntegerArrayBackend<T>
where
    T: IntegerRadixCiphertext,
{
    fn add_slices<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| cpu_key.pbs_key().add_parallelized(lhs, rhs))
                .collect::<Vec<_>>()
        })
    }

    fn add_assign_slices<'a>(lhs: Self::SliceMut<'a>, rhs: Self::Slice<'a>) {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter_mut()
                .zip(rhs.par_iter())
                .for_each(|(lhs, rhs)| cpu_key.pbs_key().add_assign_parallelized(lhs, rhs));
        })
    }
}

impl<T> BitwiseArrayBackend for CpuIntegerArrayBackend<T>
where
    T: IntegerRadixCiphertext,
{
    fn bitand<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| cpu_key.pbs_key().bitand_parallelized(lhs, rhs))
                .collect::<Vec<_>>()
        })
    }

    fn bitor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| cpu_key.pbs_key().bitor_parallelized(lhs, rhs))
                .collect::<Vec<_>>()
        })
    }

    fn bitxor<'a>(lhs: Self::Slice<'a>, rhs: Self::Slice<'a>) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| cpu_key.pbs_key().bitxor_parallelized(lhs, rhs))
                .collect::<Vec<_>>()
        })
    }

    fn bitnot(lhs: Self::Slice<'_>) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .map(|lhs| cpu_key.pbs_key().bitnot(lhs))
                .collect::<Vec<_>>()
        })
    }
}

impl<Clear, T> ClearBitwiseArrayBackend<Clear> for CpuIntegerArrayBackend<T>
where
    T: IntegerRadixCiphertext,
    Clear: DecomposableInto<u8>,
{
    fn bitand_slice(lhs: Self::Slice<'_>, rhs: &[Clear]) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter().copied())
                .map(|(lhs, rhs)| cpu_key.pbs_key().scalar_bitand_parallelized(lhs, rhs))
                .collect::<Vec<_>>()
        })
    }
}

impl<T> super::BackendDataContainer for Vec<T>
where
    T: IntegerRadixCiphertext,
{
    type Backend = CpuIntegerArrayBackend<T>;

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        create_sub_slice_with_bound(Self::as_slice(self), range)
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self
    }
}

impl<T> super::BackendDataContainerMut for Vec<T>
where
    T: IntegerRadixCiphertext,
{
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        create_sub_mut_slice_with_bound(self.as_mut_slice(), range)
    }
}

impl<'a, T> super::BackendDataContainer for &'a [T]
where
    T: IntegerRadixCiphertext,
{
    type Backend = CpuIntegerArrayBackend<T>;

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        create_sub_slice_with_bound(*self, range)
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self.to_vec()
    }
}

impl<'a, T> super::BackendDataContainer for &'a mut [T]
where
    T: IntegerRadixCiphertext,
{
    type Backend = CpuIntegerArrayBackend<T>;

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        create_sub_slice_with_bound(*self, range)
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self.to_vec()
    }
}

impl<'a, T> super::BackendDataContainerMut for &'a mut [T]
where
    T: IntegerRadixCiphertext,
{
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        create_sub_mut_slice_with_bound(*self, range)
    }
}

impl<'a, Clear, Id> FheTryEncrypt<&'a [Clear], ClientKey> for FheArrayBase<Vec<RadixCiphertext>, Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = Error;

    fn try_encrypt(clears: &'a [Clear], key: &ClientKey) -> Result<Self, Self::Error> {
        let num_blocks = Id::num_blocks(key.message_modulus());
        Ok(Self::new(
            clears
                .iter()
                .copied()
                .map(|clear| key.key.key.encrypt_radix(clear, num_blocks))
                .collect::<Vec<_>>(),
        ))
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheUintArray<Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<'a, Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheUintSliceMut<'a, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<'a, Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheUintSlice<'a, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.elems
            .iter()
            .map(|ct| key.key.key.decrypt_radix(ct))
            .collect()
    }
}

impl<'a, Clear, Id> FheTryEncrypt<&'a [Clear], ClientKey> for CpuFheIntArray<Id>
where
    Id: FheIntId,
    Clear: DecomposableInto<u64> + SignedNumeric,
{
    type Error = Error;

    fn try_encrypt(clears: &'a [Clear], key: &ClientKey) -> Result<Self, Self::Error> {
        let num_blocks = Id::num_blocks(key.message_modulus());
        Ok(Self::new(
            clears
                .iter()
                .copied()
                .map(|clear| key.key.key.encrypt_signed_radix(clear, num_blocks))
                .collect::<Vec<_>>(),
        ))
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheIntArray<Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<'a, Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheIntSliceMut<'a, Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<'a, Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheIntSlice<'a, Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.elems
            .iter()
            .map(|ct| key.key.key.decrypt_signed_radix(ct))
            .collect()
    }
}
