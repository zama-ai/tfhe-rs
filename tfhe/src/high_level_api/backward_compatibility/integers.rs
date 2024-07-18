#![allow(deprecated)]

use std::convert::Infallible;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};

use crate::high_level_api::global_state::with_cpu_internal_keys;
use crate::high_level_api::integers::*;
use crate::integer::backward_compatibility::ciphertext::{
    CompressedModulusSwitchedRadixCiphertextTFHE06,
    CompressedModulusSwitchedSignedRadixCiphertextTFHE06,
};
use crate::integer::ciphertext::{
    BaseRadixCiphertext, BaseSignedRadixCiphertext, CompactCiphertextList,
    CompressedRadixCiphertext as IntegerCompressedRadixCiphertext,
    CompressedSignedRadixCiphertext as IntegerCompressedSignedRadixCiphertext, DataKind,
};
use crate::shortint::ciphertext::CompressedModulusSwitchedCiphertext;
use crate::shortint::{Ciphertext, ServerKey};
use crate::{CompactCiphertextList as HlCompactCiphertextList, Error};
use serde::{Deserialize, Serialize};

// Manual impl
#[derive(Serialize, Deserialize)]
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
pub(crate) enum SignedRadixCiphertextVersionedOwned {
    V0(SignedRadixCiphertextVersionOwned),
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
pub(crate) enum UnsignedRadixCiphertextVersionedOwned {
    V0(UnsignedRadixCiphertextVersionOwned),
}

// This method was used to decompress a ciphertext in tfhe-rs < 0.7
fn old_sk_decompress(
    sk: &ServerKey,
    compressed_ct: &CompressedModulusSwitchedCiphertext,
) -> Ciphertext {
    let acc = sk.generate_lookup_table(|a| a);

    let mut result = sk.decompress_and_apply_lookup_table(compressed_ct, &acc);

    result.degree = compressed_ct.degree;

    result
}

#[derive(Version)]
pub enum CompressedSignedRadixCiphertextV0 {
    Seeded(IntegerCompressedSignedRadixCiphertext),
    ModulusSwitched(CompressedModulusSwitchedSignedRadixCiphertextTFHE06),
}

impl Upgrade<CompressedSignedRadixCiphertext> for CompressedSignedRadixCiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedSignedRadixCiphertext, Self::Error> {
        match self {
            Self::Seeded(ct) => Ok(CompressedSignedRadixCiphertext::Seeded(ct)),

            // Upgrade by decompressing and recompressing with the new scheme
            Self::ModulusSwitched(ct) => {
                let upgraded = with_cpu_internal_keys(|sk| {
                    let blocks = ct
                        .blocks
                        .par_iter()
                        .map(|a| old_sk_decompress(&sk.key.key, a))
                        .collect();

                    let radix = BaseSignedRadixCiphertext { blocks };
                    sk.key
                        .switch_modulus_and_compress_signed_parallelized(&radix)
                });
                Ok(CompressedSignedRadixCiphertext::ModulusSwitched(upgraded))
            }
        }
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedSignedRadixCiphertextVersions {
    V0(CompressedSignedRadixCiphertextV0),
    V1(CompressedSignedRadixCiphertext),
}

#[derive(Version)]
pub enum CompressedRadixCiphertextV0 {
    Seeded(IntegerCompressedRadixCiphertext),
    ModulusSwitched(CompressedModulusSwitchedRadixCiphertextTFHE06),
}

impl Upgrade<CompressedRadixCiphertext> for CompressedRadixCiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedRadixCiphertext, Self::Error> {
        match self {
            Self::Seeded(ct) => Ok(CompressedRadixCiphertext::Seeded(ct)),

            // Upgrade by decompressing and recompressing with the new scheme
            Self::ModulusSwitched(ct) => {
                let upgraded = with_cpu_internal_keys(|sk| {
                    let blocks = ct
                        .blocks
                        .par_iter()
                        .map(|a| old_sk_decompress(&sk.key.key, a))
                        .collect();

                    let radix = BaseRadixCiphertext { blocks };
                    sk.key.switch_modulus_and_compress_parallelized(&radix)
                });
                Ok(CompressedRadixCiphertext::ModulusSwitched(upgraded))
            }
        }
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedRadixCiphertextVersions {
    V0(CompressedRadixCiphertextV0),
    V1(CompressedRadixCiphertext),
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

// Basic support for deprecated compact list, to be able to load them and convert them to something
// else

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
        // This compact list might have been loaded from an homogenous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Signed(info.num_blocks()));
        let hl_list = HlCompactCiphertextList(self.list);
        let list = hl_list.expand()?;

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
        // This compact list might have been loaded from an homogenous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Signed(info.num_blocks()));

        let hl_list = HlCompactCiphertextList(self.list);
        let list = hl_list.expand()?;

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
        // This compact list might have been loaded from an homogenous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Unsigned(info.num_blocks()));

        let hl_list = HlCompactCiphertextList(self.list);
        let list = hl_list.expand()?;

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
        // This compact list might have been loaded from an homogenous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Unsigned(info.num_blocks()));

        let hl_list = HlCompactCiphertextList(self.list);
        let list = hl_list.expand()?;

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
