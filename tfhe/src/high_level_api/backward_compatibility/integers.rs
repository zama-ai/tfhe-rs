#![allow(deprecated)]

use tfhe_versionable::{Versionize, VersionsDispatch};

use crate::{
    high_level_api::integers::*, integer::ciphertext::DataKind, prelude::ParameterSetConformant,
    CompactCiphertextList, Error,
};
use serde::{Deserialize, Serialize};

// Manual impl
#[derive(Serialize, Deserialize)]
pub(crate) enum SignedRadixCiphertextVersionedOwned {
    V0(SignedRadixCiphertextVersionOwned),
}

#[derive(Serialize, Deserialize)]
pub(crate) enum UnsignedRadixCiphertextVersionedOwned {
    V0(UnsignedRadixCiphertextVersionOwned),
}

#[derive(VersionsDispatch)]
pub enum CompressedSignedRadixCiphertextVersions {
    V0(CompressedSignedRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub enum CompressedRadixCiphertextVersions {
    V0(CompressedRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub enum FheIntVersions<Id: FheIntId> {
    V0(FheInt<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompactFheIntVersions<Id: FheIntId> {
    V0(CompactFheInt<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheIntVersions<Id: FheIntId> {
    V0(CompressedFheInt<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompactFheIntListVersions<Id: FheIntId> {
    V0(CompactFheIntList<Id>),
}

#[derive(VersionsDispatch)]
pub enum FheUintVersions<Id: FheUintId> {
    V0(FheUint<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompactFheUintVersions<Id: FheUintId> {
    V0(CompactFheUint<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheUintVersions<Id: FheUintId> {
    V0(CompressedFheUint<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompactFheUintListVersions<Id: FheUintId> {
    V0(CompactFheUintList<Id>),
}

// Basic support for deprecated compact list, to be able to load them and convert them to something else

#[derive(Clone, Versionize)]
#[versionize(CompactFheIntVersions)]
#[deprecated(since = "0.7.0", note = "Use CompactCiphertextList instead")]
pub struct CompactFheInt<Id: FheIntId> {
    list: CompactCiphertextList,
    id: Id,
}

impl<Id> CompactFheInt<Id>
where
    Id: FheIntId,
{
    /// Expand to a [FheInt]
    pub fn expand(mut self) -> Result<FheInt<Id>, Error> {
        // This compact list might have been loaded from an homogenous compact list without type info
        self.list
            .0
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Signed(info.num_blocks()));
        let list = self.list.expand()?;

        let ct = list
            .get::<crate::integer::SignedRadixCiphertext>(0)
            .ok_or_else(|| Error::new("Failed to expand compact list".to_string()))??;
        Ok(FheInt::new(ct))
    }
}

#[derive(Clone, Versionize)]
#[versionize(CompactFheIntListVersions)]
#[deprecated(since = "0.7.0", note = "Use CompactCiphertextList instead")]
pub struct CompactFheIntList<Id: FheIntId> {
    list: CompactCiphertextList,
    id: Id,
}

impl<Id> CompactFheIntList<Id>
where
    Id: FheIntId,
{
    /// Expand to a Vec<[FheInt]>
    pub fn expand(mut self) -> Result<Vec<FheInt<Id>>, Error> {
        // This compact list might have been loaded from an homogenous compact list without type info
        self.list
            .0
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Signed(info.num_blocks()));

        let list = self.list.expand()?;

        let len = list.len();

        (0..len)
            .map(|idx| {
                let ct = list
                    .get::<crate::integer::SignedRadixCiphertext>(idx)
                    .ok_or_else(|| Error::new("Failed to expand compact list".to_string()))??;
                Ok(FheInt::new(ct))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

#[derive(Clone, Versionize)]
#[versionize(CompactFheUintVersions)]
#[deprecated(since = "0.7.0", note = "Use CompactCiphertextList instead")]
pub struct CompactFheUint<Id: FheUintId> {
    list: CompactCiphertextList,
    id: Id,
}

impl<Id> CompactFheUint<Id>
where
    Id: FheUintId,
{
    /// Expand to a [FheUint]
    pub fn expand(mut self) -> Result<FheUint<Id>, Error> {
        // This compact list might have been loaded from an homogenous compact list without type info
        self.list
            .0
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Unsigned(info.num_blocks()));

        let list = self.list.expand()?;

        let ct = list
            .get::<crate::integer::RadixCiphertext>(0)
            .ok_or_else(|| Error::new("Failed to expand compact list".to_string()))??;
        Ok(FheUint::new(ct))
    }
}

#[derive(Clone, Versionize)]
#[versionize(CompactFheUintListVersions)]
#[deprecated(since = "0.7.0", note = "Use CompactCiphertextList instead")]
pub struct CompactFheUintList<Id: FheUintId> {
    list: CompactCiphertextList,
    id: Id,
}

impl<Id> CompactFheUintList<Id>
where
    Id: FheUintId,
{
    /// Expand to a Vec<[FheUint]>
    pub fn expand(mut self) -> Result<Vec<FheUint<Id>>, Error> {
        // This compact list might have been loaded from an homogenous compact list without type info
        self.list
            .0
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Unsigned(info.num_blocks()));

        let list = self.list.expand()?;

        let len = list.len();

        (0..len)
            .map(|idx| {
                let ct = list
                    .get::<crate::integer::RadixCiphertext>(idx)
                    .ok_or_else(|| Error::new("Failed to expand compact list".to_string()))??;
                Ok(FheUint::new(ct))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

macro_rules! static_int_type {
    (num_bits: $num_bits:literal,) => {
        ::paste::paste! {
            pub type [<Compact FheInt $num_bits>] = CompactFheInt<[<FheInt $num_bits Id>]>;

            pub type [<Compact FheInt $num_bits List>] = CompactFheIntList<[<FheInt $num_bits Id>]>;

            pub type [<Compact FheUint $num_bits>] = CompactFheUint<[<FheUint $num_bits Id>]>;

            pub type [<Compact FheUint $num_bits List>] = CompactFheUintList<[<FheUint $num_bits Id>]>;
        }
    };
}

static_int_type! {
    num_bits: 2,
}

static_int_type! {
    num_bits: 4,
}

static_int_type! {
    num_bits: 6,
}

static_int_type! {
    num_bits: 8,
}

static_int_type! {
    num_bits: 10,
}

static_int_type! {
    num_bits: 12,
}

static_int_type! {
    num_bits: 14,
}

static_int_type! {
    num_bits: 16,
}

static_int_type! {
    num_bits: 32,
}

static_int_type! {
    num_bits: 64,
}

static_int_type! {
    num_bits: 128,
}

static_int_type! {
    num_bits: 160,
}

static_int_type! {
    num_bits: 256,
}
