//! This module contains the implementations of the FheUint array and FheInt array backend
//! where the values and computations are always done on CPU
use super::super::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use super::super::traits::{ArithmeticArrayBackend, BitwiseArrayBackend, ClearBitwiseArrayBackend};
use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::high_level_api::array::{
    ArrayBackend, FheArrayBase, FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut,
};

use crate::array::traits::{
    BackendDataContainer, BackendDataContainerMut, ClearArithmeticArrayBackend, TensorSlice,
};
use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::integer::block_decomposition::{
    DecomposableInto, RecomposableFrom, RecomposableSignedInteger,
};
use crate::integer::server_key::radix_parallel::scalar_div_mod::SignedReciprocable;
use crate::integer::server_key::{Reciprocable, ScalarMultiplier};
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
    type Slice<'a>
        = &'a [T]
    where
        Self: 'a;
    type SliceMut<'a>
        = &'a mut [T]
    where
        Self: 'a;
    type Owned = Vec<T>;
}

#[inline]
#[track_caller]
fn par_map_sks_op_on_pair_of_elements<'a, T, F>(
    lhs: TensorSlice<'a, &'a [T]>,
    rhs: TensorSlice<'a, &'a [T]>,
    op: F,
) -> Vec<T>
where
    T: IntegerRadixCiphertext,
    F: Send + Sync + Fn(&crate::integer::ServerKey, &T, &T) -> T,
{
    global_state::with_cpu_internal_keys(|cpu_key| {
        lhs.par_iter()
            .zip(rhs.par_iter())
            .map(|(lhs, rhs)| op(cpu_key.pbs_key(), lhs, rhs))
            .collect::<Vec<_>>()
    })
}

impl<T> ArithmeticArrayBackend for CpuIntegerArrayBackend<T>
where
    T: IntegerRadixCiphertext,
{
    fn add_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::add_parallelized)
    }

    fn sub_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::sub_parallelized)
    }

    fn mul_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::mul_parallelized)
    }

    fn div_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::div_parallelized)
    }

    fn rem_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::rem_parallelized)
    }
}

#[inline]
#[track_caller]
fn par_map_sks_scalar_op_on_pair_of_elements<'a, T, Clear, F>(
    lhs: TensorSlice<'a, &'a [T]>,
    rhs: TensorSlice<'a, &'a [Clear]>,
    op: F,
) -> Vec<T>
where
    T: IntegerRadixCiphertext,
    Clear: Copy + Send + Sync,
    F: Send + Sync + Fn(&crate::integer::ServerKey, &T, Clear) -> T,
{
    global_state::with_cpu_internal_keys(|cpu_key| {
        lhs.par_iter()
            .zip(rhs.par_iter())
            .map(|(lhs, rhs)| op(cpu_key.pbs_key(), lhs, *rhs))
            .collect::<Vec<_>>()
    })
}

impl<Clear> ClearArithmeticArrayBackend<Clear> for CpuIntegerArrayBackend<RadixCiphertext>
where
    Clear: DecomposableInto<u8>
        + std::ops::Not<Output = Clear>
        + std::ops::Add<Clear, Output = Clear>
        + ScalarMultiplier
        + Reciprocable,
{
    fn add_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_add_parallelized,
        )
    }

    fn sub_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_sub_parallelized,
        )
    }

    fn mul_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_mul_parallelized,
        )
    }

    fn div_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_div_parallelized,
        )
    }

    fn rem_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_rem_parallelized,
        )
    }
}

impl<Clear> ClearArithmeticArrayBackend<Clear> for CpuIntegerArrayBackend<SignedRadixCiphertext>
where
    Clear: DecomposableInto<u8>
        + std::ops::Not<Output = Clear>
        + std::ops::Add<Clear, Output = Clear>
        + ScalarMultiplier
        + SignedReciprocable,
{
    fn add_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_add_parallelized,
        )
    }

    fn sub_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_sub_parallelized,
        )
    }

    fn mul_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_mul_parallelized,
        )
    }

    fn div_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::signed_scalar_div_parallelized,
        )
    }

    fn rem_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::signed_scalar_rem_parallelized,
        )
    }
}

impl<T> BitwiseArrayBackend for CpuIntegerArrayBackend<T>
where
    T: IntegerRadixCiphertext,
{
    fn bitand<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::bitand_parallelized)
    }

    fn bitor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::bitor_parallelized)
    }

    fn bitxor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::ServerKey::bitxor_parallelized)
    }

    fn bitnot(lhs: TensorSlice<'_, Self::Slice<'_>>) -> Self::Owned {
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
    fn bitand_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_bitand_parallelized,
        )
    }

    fn bitor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_bitor_parallelized,
        )
    }

    fn bitxor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::ServerKey::scalar_bitxor_parallelized,
        )
    }
}

impl<T> BackendDataContainer for Vec<T>
where
    T: IntegerRadixCiphertext,
{
    type Backend = CpuIntegerArrayBackend<T>;

    fn len(&self) -> usize {
        self.len()
    }

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

impl<T> BackendDataContainerMut for Vec<T>
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

impl<T> BackendDataContainer for &[T]
where
    T: IntegerRadixCiphertext,
{
    type Backend = CpuIntegerArrayBackend<T>;

    fn len(&self) -> usize {
        <[T]>::len(self)
    }

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

impl<T> BackendDataContainer for &mut [T]
where
    T: IntegerRadixCiphertext,
{
    type Backend = CpuIntegerArrayBackend<T>;

    fn len(&self) -> usize {
        <[T]>::len(self)
    }

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

impl<T> BackendDataContainerMut for &mut [T]
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
            vec![clears.len()],
        ))
    }
}

impl<'a, Clear, Id> FheTryEncrypt<(&'a [Clear], Vec<usize>), ClientKey>
    for FheArrayBase<Vec<RadixCiphertext>, Id>
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
            return Err(crate::Error::new(
                "Shape does not matches the number of elements given".to_string(),
            ));
        }
        let num_blocks = Id::num_blocks(key.message_modulus());
        let elems = clears
            .iter()
            .copied()
            .map(|clear| key.key.key.encrypt_radix(clear, num_blocks))
            .collect::<Vec<_>>();
        let data = Self::new(elems, shape);
        Ok(data)
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

impl<Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheUintSliceMut<'_, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheUintSlice<'_, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_tensor_slice()
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
            vec![clears.len()],
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

impl<Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheIntSliceMut<'_, Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for CpuFheIntSlice<'_, Id>
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
