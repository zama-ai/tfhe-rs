//! This module contains the implementation of the FheBool array backend
//! where the values and computations are always done on CPU
use super::super::helpers::{create_sub_mut_slice_with_bound, create_sub_slice_with_bound};
use super::super::traits::{BitwiseArrayBackend, ClearBitwiseArrayBackend};
use crate::array::traits::TensorSlice;
use crate::high_level_api::array::{ArrayBackend, BackendDataContainer, BackendDataContainerMut};
use crate::high_level_api::global_state;
use crate::integer::BooleanBlock;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::{ClientKey, FheId};
use rayon::prelude::*;
use std::ops::RangeBounds;

#[derive(Default, Copy, Clone)]
pub struct FheBoolId;

impl FheId for FheBoolId {}

pub struct CpuFheBoolArrayBackend;

pub type CpuFheBoolArray = super::super::FheBackendArray<CpuFheBoolArrayBackend, FheBoolId>;
pub type CpuFheBoolSlice<'a> =
    super::super::FheBackendArraySlice<'a, CpuFheBoolArrayBackend, FheBoolId>;
pub type CpuFheBoolSliceMut<'a> =
    super::super::FheBackendArraySliceMut<'a, CpuFheBoolArrayBackend, FheBoolId>;

impl ArrayBackend for CpuFheBoolArrayBackend {
    type Slice<'a>
        = &'a [BooleanBlock]
    where
        Self: 'a;
    type SliceMut<'a>
        = &'a mut [BooleanBlock]
    where
        Self: 'a;
    type Owned = Vec<BooleanBlock>;
}

impl BackendDataContainer for &[BooleanBlock] {
    type Backend = CpuFheBoolArrayBackend;

    fn len(&self) -> usize {
        <[BooleanBlock]>::len(self)
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

impl BackendDataContainer for &mut [BooleanBlock] {
    type Backend = CpuFheBoolArrayBackend;

    fn len(&self) -> usize {
        <[BooleanBlock]>::len(self)
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

impl BackendDataContainerMut for &mut [BooleanBlock] {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        create_sub_mut_slice_with_bound(*self, range)
    }
}

impl BackendDataContainer for Vec<BooleanBlock> {
    type Backend = CpuFheBoolArrayBackend;

    fn len(&self) -> usize {
        self.len()
    }

    fn as_sub_slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::Slice<'_> {
        create_sub_slice_with_bound(self, range)
    }

    fn into_owned(self) -> <Self::Backend as ArrayBackend>::Owned {
        self
    }
}

impl BackendDataContainerMut for Vec<BooleanBlock> {
    fn as_sub_slice_mut(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> <Self::Backend as ArrayBackend>::SliceMut<'_> {
        create_sub_mut_slice_with_bound(self.as_mut_slice(), range)
    }
}

impl BitwiseArrayBackend for CpuFheBoolArrayBackend {
    fn bitand<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| cpu_key.pbs_key().boolean_bitand(lhs, rhs))
                .collect()
        })
    }

    fn bitor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| cpu_key.pbs_key().boolean_bitor(lhs, rhs))
                .collect()
        })
    }

    fn bitxor<'a>(
        lhs: TensorSlice<'_, Self::Slice<'a>>,
        rhs: TensorSlice<'_, Self::Slice<'a>>,
    ) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter())
                .map(|(lhs, rhs)| cpu_key.pbs_key().boolean_bitxor(lhs, rhs))
                .collect()
        })
    }

    fn bitnot(lhs: TensorSlice<'_, Self::Slice<'_>>) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .map(|lhs| cpu_key.pbs_key().boolean_bitnot(lhs))
                .collect()
        })
    }
}

impl ClearBitwiseArrayBackend<bool> for CpuFheBoolArrayBackend {
    fn bitand_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter().copied())
                .map(|(lhs, rhs)| {
                    BooleanBlock::new_unchecked(
                        cpu_key.pbs_key().key.scalar_bitand(&lhs.0, rhs as u8),
                    )
                })
                .collect()
        })
    }

    fn bitor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter().copied())
                .map(|(lhs, rhs)| {
                    BooleanBlock::new_unchecked(
                        cpu_key.pbs_key().key.scalar_bitor(&lhs.0, rhs as u8),
                    )
                })
                .collect()
        })
    }

    fn bitxor_slice(
        lhs: TensorSlice<'_, Self::Slice<'_>>,
        rhs: TensorSlice<'_, &'_ [bool]>,
    ) -> Self::Owned {
        global_state::with_cpu_internal_keys(|cpu_key| {
            lhs.par_iter()
                .zip(rhs.par_iter().copied())
                .map(|(lhs, rhs)| {
                    BooleanBlock::new_unchecked(
                        cpu_key.pbs_key().key.scalar_bitxor(&lhs.0, rhs as u8),
                    )
                })
                .collect()
        })
    }
}

impl FheTryEncrypt<&[bool], ClientKey> for CpuFheBoolArray {
    type Error = crate::Error;

    fn try_encrypt(values: &[bool], cks: &ClientKey) -> Result<Self, Self::Error> {
        let encrypted = values
            .iter()
            .copied()
            .map(|value| cks.key.key.encrypt_bool(value))
            .collect::<Vec<_>>();
        Ok(Self::new(encrypted, vec![values.len()]))
    }
}

impl FheDecrypt<Vec<bool>> for CpuFheBoolSlice<'_> {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        self.elems
            .iter()
            .map(|encrypted_value| key.key.key.decrypt_bool(encrypted_value))
            .collect()
    }
}

impl FheDecrypt<Vec<bool>> for CpuFheBoolSliceMut<'_> {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        self.as_slice().decrypt(key)
    }
}

impl FheDecrypt<Vec<bool>> for CpuFheBoolArray {
    fn decrypt(&self, key: &ClientKey) -> Vec<bool> {
        self.as_slice().decrypt(key)
    }
}
