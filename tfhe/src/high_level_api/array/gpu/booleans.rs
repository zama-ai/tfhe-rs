//! This module contains the implementation of the FheBool array backend
//! where the values and computations are always done on GPU

use super::super::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use super::super::traits::{BitwiseArrayBackend, ClearBitwiseArrayBackend};
use crate::array::stride::{ParStridedIter, ParStridedIterMut, StridedIter};
use crate::array::traits::TensorSlice;
use crate::high_level_api::array::{ArrayBackend, BackendDataContainer, BackendDataContainerMut};
use crate::high_level_api::global_state;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::{ClientKey, FheBoolId};
use rayon::prelude::*;
use std::ops::RangeBounds;

pub struct GpuFheBoolArrayBackend;

pub type GpuFheBoolArray = super::super::FheBackendArray<GpuFheBoolArrayBackend, FheBoolId>;
pub type GpuFheBoolSlice<'a> =
    super::super::FheBackendArraySlice<'a, GpuFheBoolArrayBackend, FheBoolId>;
pub type GpuFheBoolSliceMut<'a> =
    super::super::FheBackendArraySliceMut<'a, GpuFheBoolArrayBackend, FheBoolId>;

pub struct GpuBooleanSlice<'a>(pub(crate) &'a [CudaBooleanBlock]);
pub struct GpuBooleanSliceMut<'a>(pub(crate) &'a mut [CudaBooleanBlock]);
pub struct GpuBooleanOwned(pub(crate) Vec<CudaBooleanBlock>);
use crate::high_level_api::global_state::with_cuda_internal_keys;

impl Clone for GpuBooleanOwned {
    fn clone(&self) -> Self {
        // When cloning, we assume that the intention is to return a ciphertext that lies in the GPU
        // 0 defined in the set server key. Hence, we use the server key to get the streams instead
        // of those inside the ciphertext itself
        with_cuda_internal_keys(|key| {
            let streams = &key.streams;
            Self(self.0.iter().map(|elem| elem.duplicate(streams)).collect())
        })
    }
}

impl ArrayBackend for GpuFheBoolArrayBackend {
    type Slice<'a>
        = GpuBooleanSlice<'a>
    where
        Self: 'a;
    type SliceMut<'a>
        = GpuBooleanSliceMut<'a>
    where
        Self: 'a;
    type Owned = GpuBooleanOwned;
}

impl<'a> TensorSlice<'a, GpuBooleanSlice<'a>> {
    pub fn iter(self) -> StridedIter<'a, CudaBooleanBlock> {
        StridedIter::new(self.slice.0, self.dims.clone())
    }

    pub fn par_iter(self) -> ParStridedIter<'a, CudaBooleanBlock> {
        ParStridedIter::new(self.slice.0, self.dims.clone())
    }
}

impl<'a> TensorSlice<'a, GpuBooleanSliceMut<'a>> {
    pub fn par_iter_mut(self) -> ParStridedIterMut<'a, CudaBooleanBlock> {
        ParStridedIterMut::new(self.slice.0, self.dims.clone())
    }
}

impl From<Vec<CudaBooleanBlock>> for GpuBooleanOwned {
    fn from(value: Vec<CudaBooleanBlock>) -> Self {
        Self(value)
    }
}

impl BackendDataContainer for GpuBooleanSlice<'_> {
    type Backend = GpuFheBoolArrayBackend;

    fn len(&self) -> usize {
        <[CudaBooleanBlock]>::len(self.0)
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        GpuBooleanSlice(create_sub_slice_with_bound(self.0, range))
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        with_cuda_internal_keys(|key| {
            let streams = &key.streams;
            GpuBooleanOwned(self.0.iter().map(|elem| elem.duplicate(streams)).collect())
        })
    }
}

impl BackendDataContainer for GpuBooleanSliceMut<'_> {
    type Backend = GpuFheBoolArrayBackend;

    fn len(&self) -> usize {
        <[CudaBooleanBlock]>::len(self.0)
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        GpuBooleanSlice(create_sub_slice_with_bound(self.0, range))
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        with_cuda_internal_keys(|key| {
            let streams = &key.streams;
            GpuBooleanOwned(self.0.iter().map(|elem| elem.duplicate(streams)).collect())
        })
    }
}

impl BackendDataContainerMut for GpuBooleanSliceMut<'_> {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        GpuBooleanSliceMut(create_sub_mut_slice_with_bound(self.0, range))
    }
}

impl BackendDataContainer for GpuBooleanOwned {
    type Backend = GpuFheBoolArrayBackend;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        GpuBooleanSlice(create_sub_slice_with_bound(self.0.as_slice(), range))
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self
    }
}

impl BackendDataContainerMut for GpuBooleanOwned {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        GpuBooleanSliceMut(create_sub_mut_slice_with_bound(
            self.0.as_mut_slice(),
            range,
        ))
    }
}

impl BitwiseArrayBackend for GpuFheBoolArrayBackend {
    fn bitand<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        GpuBooleanOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| {
                    CudaBooleanBlock(cuda_key.pbs_key().bitand(&lhs.0, &rhs.0, streams))
                })
                .collect::<Vec<_>>()
        }))
    }

    fn bitor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        GpuBooleanOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| {
                    CudaBooleanBlock(cuda_key.pbs_key().bitor(&lhs.0, &rhs.0, streams))
                })
                .collect::<Vec<_>>()
        }))
    }

    fn bitxor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        GpuBooleanOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| {
                    CudaBooleanBlock(cuda_key.pbs_key().bitxor(&lhs.0, &rhs.0, streams))
                })
                .collect::<Vec<_>>()
        }))
    }

    fn bitnot(lhs: TensorSlice<'_, Self::Slice<'_>>) -> Self::Owned {
        GpuBooleanOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .map(|lhs| CudaBooleanBlock(cuda_key.pbs_key().bitnot(&lhs.0, streams)))
                .collect::<Vec<_>>()
        }))
    }
}

impl ClearBitwiseArrayBackend<bool> for GpuFheBoolArrayBackend {
    fn bitand_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        GpuBooleanOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .zip(rhs.par_iter().copied())
                .map(|(lhs, rhs)| {
                    CudaBooleanBlock(cuda_key.pbs_key().scalar_bitand(&lhs.0, rhs as u8, streams))
                })
                .collect::<Vec<_>>()
        }))
    }

    fn bitor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        GpuBooleanOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .zip(rhs.par_iter().copied())
                .map(|(lhs, rhs)| {
                    CudaBooleanBlock(cuda_key.pbs_key().scalar_bitor(&lhs.0, rhs as u8, streams))
                })
                .collect::<Vec<_>>()
        }))
    }

    fn bitxor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        GpuBooleanOwned(global_state::with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            lhs.par_iter()
                .zip(rhs.par_iter().copied())
                .map(|(lhs, rhs)| {
                    CudaBooleanBlock(cuda_key.pbs_key().scalar_bitxor(&lhs.0, rhs as u8, streams))
                })
                .collect::<Vec<_>>()
        }))
    }
}

impl FheTryEncrypt<&[bool], ClientKey> for GpuFheBoolArray {
    type Error = crate::Error;

    fn try_encrypt(values: &[bool], cks: &ClientKey) -> Result<Self, Self::Error> {
        let encrypted = with_cuda_internal_keys(|key| {
            let streams = &key.streams;
            values
                .iter()
                .copied()
                .map(|value| {
                    CudaBooleanBlock::from_boolean_block(&cks.key.key.encrypt_bool(value), streams)
                })
                .collect::<Vec<_>>()
        });
        Ok(Self::new(encrypted, vec![values.len()]))
    }
}

impl FheDecrypt<Vec<bool>> for GpuFheBoolSlice<'_> {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        with_cuda_internal_keys(|cuda_key| {
            let streams = &cuda_key.streams;
            self.elems
                .0
                .iter()
                .map(|encrypted_value| {
                    key.key
                        .key
                        .decrypt_bool(&encrypted_value.to_boolean_block(streams))
                })
                .collect()
        })
    }
}

impl FheDecrypt<Vec<bool>> for GpuFheBoolSliceMut<'_> {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        self.as_slice().decrypt(key)
    }
}

impl FheDecrypt<Vec<bool>> for GpuFheBoolArray {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        self.as_slice().decrypt(key)
    }
}
