//! This module contains the implementations of the FheUint array and FheInt array backend
//! where the values and computations are always done on GPU
use super::super::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use super::super::traits::{ArithmeticArrayBackend, BitwiseArrayBackend, ClearBitwiseArrayBackend};
use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::high_level_api::array::{
    ArrayBackend, FheArrayBase, FheBackendArray, FheBackendArraySlice, FheBackendArraySliceMut,
};

use crate::array::stride::{ParStridedIter, ParStridedIterMut, StridedIter};
use crate::array::traits::{
    BackendDataContainer, BackendDataContainerMut, ClearArithmeticArrayBackend, TensorSlice,
};
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::global_state;
use crate::high_level_api::global_state::with_cuda_internal_keys;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::integer::block_decomposition::{
    DecomposableInto, RecomposableFrom, RecomposableSignedInteger,
};
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::server_key::radix_parallel::scalar_div_mod::SignedReciprocable;
use crate::integer::server_key::{Reciprocable, ScalarMultiplier};
use crate::prelude::{CastInto, FheDecrypt, FheTryEncrypt};
use crate::{ClientKey, Error};
use rayon::prelude::*;
use std::marker::PhantomData;
use std::ops::RangeBounds;

pub struct GpuIntegerArrayBackend<T>(PhantomData<T>);

pub type GpuUintArrayBackend = GpuIntegerArrayBackend<CudaUnsignedRadixCiphertext>;
pub type GpuIntArrayBackend = GpuIntegerArrayBackend<CudaSignedRadixCiphertext>;

// Base alias for array of unsigned integers on the CPU only backend
pub type GpuFheUintArray<Id> = FheBackendArray<GpuUintArrayBackend, Id>;
pub type GpuFheUintSlice<'a, Id> = FheBackendArraySlice<'a, GpuUintArrayBackend, Id>;
pub type GpuFheUintSliceMut<'a, Id> = FheBackendArraySliceMut<'a, GpuUintArrayBackend, Id>;

// Base alias for array of signed integers on the CPU only backend
pub type GpuFheIntArray<Id> = FheBackendArray<GpuIntArrayBackend, Id>;
pub type GpuFheIntSlice<'a, Id> = FheBackendArraySlice<'a, GpuIntArrayBackend, Id>;
pub type GpuFheIntSliceMut<'a, Id> = FheBackendArraySliceMut<'a, GpuIntArrayBackend, Id>;

pub struct GpuSlice<'a, T>(&'a [T]);
pub struct GpuSliceMut<'a, T>(&'a mut [T]);
pub struct GpuOwned<T>(Vec<T>);

impl<T> Clone for GpuOwned<T>
where
    T: CudaIntegerRadixCiphertext,
{
    fn clone(&self) -> Self {
        with_cuda_internal_keys(|key| {
            let streams = &key.streams;
            Self(self.0.iter().map(|elem| elem.duplicate(streams)).collect())
        })
    }
}

impl<T> ArrayBackend for GpuIntegerArrayBackend<T>
where
    T: CudaIntegerRadixCiphertext,
{
    type Slice<'a>
        = GpuSlice<'a, T>
    where
        Self: 'a;
    type SliceMut<'a>
        = GpuSliceMut<'a, T>
    where
        Self: 'a;
    type Owned = GpuOwned<T>;
}

impl<'a, T> TensorSlice<'a, GpuSlice<'a, T>> {
    pub fn iter(self) -> StridedIter<'a, T> {
        StridedIter::new(self.slice.0, self.dims.clone())
    }

    pub fn par_iter(self) -> ParStridedIter<'a, T> {
        ParStridedIter::new(self.slice.0, self.dims.clone())
    }
}

impl<'a, T> TensorSlice<'a, GpuSliceMut<'a, T>> {
    pub fn par_iter_mut(self) -> ParStridedIterMut<'a, T> {
        ParStridedIterMut::new(self.slice.0, self.dims.clone())
    }
}

impl<T> From<Vec<T>> for GpuOwned<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

#[inline]
#[track_caller]
fn par_map_sks_op_on_pair_of_elements<'a, T, F>(
    lhs: TensorSlice<'a, GpuSlice<'a, T>>,
    rhs: TensorSlice<'a, GpuSlice<'a, T>>,
    op: F,
) -> GpuOwned<T>
where
    T: CudaIntegerRadixCiphertext + Send + Sync,
    F: Send + Sync + Fn(&crate::integer::gpu::CudaServerKey, &T, &T, &CudaStreams) -> T,
{
    GpuOwned(global_state::with_cuda_internal_keys(|cuda_key| {
        let streams = &cuda_key.streams;
        lhs.par_iter()
            .zip(rhs.par_iter())
            .map(|(lhs, rhs)| op(cuda_key.pbs_key(), lhs, rhs, streams))
            .collect::<Vec<_>>()
    }))
}

impl<T> ArithmeticArrayBackend for GpuIntegerArrayBackend<T>
where
    T: CudaIntegerRadixCiphertext + Send + Sync,
{
    fn add_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::add)
    }

    fn sub_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::sub)
    }

    fn mul_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::mul)
    }

    fn div_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::div)
    }

    fn rem_slices<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::rem)
    }
}

#[inline]
#[track_caller]
fn par_map_sks_scalar_op_on_pair_of_elements<'a, T, Clear, F>(
    lhs: TensorSlice<'a, GpuSlice<'a, T>>,
    rhs: TensorSlice<'a, &'a [Clear]>,
    op: F,
) -> GpuOwned<T>
where
    T: CudaIntegerRadixCiphertext + Send + Sync,
    Clear: Copy + Send + Sync,
    F: Send + Sync + Fn(&crate::integer::gpu::CudaServerKey, &T, Clear, &CudaStreams) -> T,
{
    GpuOwned(global_state::with_cuda_internal_keys(|cuda_key| {
        let streams = &cuda_key.streams;
        lhs.par_iter()
            .zip(rhs.par_iter())
            .map(|(lhs, rhs)| op(cuda_key.pbs_key(), lhs, *rhs, streams))
            .collect::<Vec<_>>()
    }))
}

impl<Clear> ClearArithmeticArrayBackend<Clear>
    for GpuIntegerArrayBackend<CudaUnsignedRadixCiphertext>
where
    Clear: DecomposableInto<u8>
        + std::ops::Not<Output = Clear>
        + std::ops::Add<Clear, Output = Clear>
        + ScalarMultiplier
        + Reciprocable
        + CastInto<u64>,
{
    fn add_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_add,
        )
    }

    fn sub_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_sub,
        )
    }

    fn mul_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_mul,
        )
    }

    fn div_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_div,
        )
    }

    fn rem_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_rem,
        )
    }
}

impl<Clear> ClearArithmeticArrayBackend<Clear> for GpuIntegerArrayBackend<CudaSignedRadixCiphertext>
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
            crate::integer::gpu::CudaServerKey::scalar_add,
        )
    }

    fn sub_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_sub,
        )
    }

    fn mul_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_mul,
        )
    }

    fn div_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::signed_scalar_div,
        )
    }

    fn rem_slices(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::signed_scalar_rem,
        )
    }
}

impl<T> BitwiseArrayBackend for GpuIntegerArrayBackend<T>
where
    T: CudaIntegerRadixCiphertext + Send + Sync,
{
    fn bitand<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::bitand)
    }

    fn bitor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::bitor)
    }

    fn bitxor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        par_map_sks_op_on_pair_of_elements(lhs, rhs, crate::integer::gpu::CudaServerKey::bitxor)
    }

    fn bitnot(lhs: TensorSlice<'_, Self::Slice<'_>>) -> Self::Owned {
        GpuOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .map(|lhs| cuda_key.pbs_key().bitnot(lhs, streams))
                .collect::<Vec<_>>()
        }))
    }
}

impl<Clear, T> ClearBitwiseArrayBackend<Clear> for GpuIntegerArrayBackend<T>
where
    T: CudaIntegerRadixCiphertext + Send + Sync,
    Clear: DecomposableInto<u8>,
{
    fn bitand_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_bitand,
        )
    }

    fn bitor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_bitor,
        )
    }

    fn bitxor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [Clear]>,
    ) -> Self::Owned {
        par_map_sks_scalar_op_on_pair_of_elements(
            lhs,
            rhs,
            crate::integer::gpu::CudaServerKey::scalar_bitxor,
        )
    }
}

impl<T> BackendDataContainer for GpuOwned<T>
where
    T: CudaIntegerRadixCiphertext,
{
    type Backend = GpuIntegerArrayBackend<T>;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        GpuSlice(create_sub_slice_with_bound(self.0.as_slice(), range))
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self
    }
}

impl<T> BackendDataContainerMut for GpuOwned<T>
where
    T: CudaIntegerRadixCiphertext,
{
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        GpuSliceMut(create_sub_mut_slice_with_bound(
            self.0.as_mut_slice(),
            range,
        ))
    }
}

impl<T> BackendDataContainer for GpuSlice<'_, T>
where
    T: CudaIntegerRadixCiphertext,
{
    type Backend = GpuIntegerArrayBackend<T>;

    fn len(&self) -> usize {
        <[T]>::len(self.0)
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        GpuSlice(create_sub_slice_with_bound(self.0, range))
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        with_cuda_internal_keys(|key| {
            let streams = &key.streams;
            GpuOwned(self.0.iter().map(|elem| elem.duplicate(streams)).collect())
        })
    }
}

impl<T> BackendDataContainer for GpuSliceMut<'_, T>
where
    T: CudaIntegerRadixCiphertext,
{
    type Backend = GpuIntegerArrayBackend<T>;

    fn len(&self) -> usize {
        <[T]>::len(self.0)
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        GpuSlice(create_sub_slice_with_bound(self.0, range))
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        with_cuda_internal_keys(|key| {
            let streams = &key.streams;
            GpuOwned(self.0.iter().map(|elem| elem.duplicate(streams)).collect())
        })
    }
}

impl<T> BackendDataContainerMut for GpuSliceMut<'_, T>
where
    T: CudaIntegerRadixCiphertext,
{
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        GpuSliceMut(create_sub_mut_slice_with_bound(self.0, range))
    }
}

impl<'a, Clear, Id> FheTryEncrypt<&'a [Clear], ClientKey>
    for FheArrayBase<GpuOwned<CudaUnsignedRadixCiphertext>, Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = Error;

    fn try_encrypt(clears: &'a [Clear], key: &ClientKey) -> Result<Self, Self::Error> {
        let num_blocks = Id::num_blocks(key.message_modulus());
        Ok(Self::new(
            with_cuda_internal_keys(|cuda_key| {
                let streams = &cuda_key.streams;
                clears
                    .iter()
                    .copied()
                    .map(|clear| {
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                            &key.key.key.encrypt_radix(clear, num_blocks),
                            streams,
                        )
                    })
                    .collect::<Vec<_>>()
            }),
            vec![clears.len()],
        ))
    }
}

impl<'a, Clear, Id> FheTryEncrypt<(&'a [Clear], Vec<usize>), ClientKey>
    for FheArrayBase<GpuOwned<CudaUnsignedRadixCiphertext>, Id>
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
        let elems = with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            clears
                .iter()
                .copied()
                .map(|clear| {
                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                        &key.key.key.encrypt_radix(clear, num_blocks),
                        streams,
                    )
                })
                .collect::<Vec<_>>()
        });
        let data = Self::new(elems, shape);
        Ok(data)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for GpuFheUintArray<Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for GpuFheUintSliceMut<'_, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for GpuFheUintSlice<'_, Id>
where
    Id: FheUintId,
    Clear: RecomposableFrom<u64> + UnsignedNumeric,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            self.as_tensor_slice()
                .iter()
                .map(|ct: &CudaUnsignedRadixCiphertext| {
                    key.key.key.decrypt_radix(&ct.to_radix_ciphertext(streams))
                })
                .collect()
        })
    }
}

impl<'a, Clear, Id> FheTryEncrypt<&'a [Clear], ClientKey> for GpuFheIntArray<Id>
where
    Id: FheIntId,
    Clear: DecomposableInto<u64> + SignedNumeric,
{
    type Error = Error;

    fn try_encrypt(clears: &'a [Clear], key: &ClientKey) -> Result<Self, Self::Error> {
        let num_blocks = Id::num_blocks(key.message_modulus());
        Ok(Self::new(
            with_cuda_internal_keys(|cuda_key| {
                let streams = &cuda_key.streams;
                clears
                    .iter()
                    .copied()
                    .map(|clear| {
                        CudaSignedRadixCiphertext::from_signed_radix_ciphertext(
                            &key.key.key.encrypt_signed_radix(clear, num_blocks),
                            streams,
                        )
                    })
                    .collect::<Vec<_>>()
            }),
            vec![clears.len()],
        ))
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for GpuFheIntArray<Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for GpuFheIntSliceMut<'_, Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        self.as_slice().decrypt(key)
    }
}

impl<Clear, Id> FheDecrypt<Vec<Clear>> for GpuFheIntSlice<'_, Id>
where
    Id: FheIntId,
    Clear: RecomposableSignedInteger,
{
    fn decrypt(&self, key: &ClientKey) -> Vec<Clear> {
        with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            self.elems
                .0
                .iter()
                .map(|ct| {
                    key.key
                        .key
                        .decrypt_signed_radix(&ct.to_signed_radix_ciphertext(streams))
                })
                .collect()
        })
    }
}
