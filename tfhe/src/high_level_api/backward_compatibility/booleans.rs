#![allow(deprecated)]

use serde::{Deserialize, Serialize};
use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};

use crate::high_level_api::booleans::{
    InnerBoolean, InnerBooleanVersionOwned, InnerCompressedFheBool,
};
use crate::integer::ciphertext::{CompactCiphertextList, DataKind};
use crate::prelude::CiphertextList;
use crate::{
    CompactCiphertextList as HlCompactCiphertextList, CompressedFheBool, Error, FheBool, Tag,
};
use std::convert::Infallible;

// Manual impl
#[derive(Serialize, Deserialize)]
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
pub(crate) enum InnerBooleanVersionedOwned {
    V0(InnerBooleanVersionOwned),
}

#[derive(Version)]
pub struct FheBoolV0 {
    pub(in crate::high_level_api) ciphertext: InnerBoolean,
}

impl Upgrade<FheBool> for FheBoolV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<FheBool, Self::Error> {
        Ok(FheBool {
            ciphertext: self.ciphertext,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum FheBoolVersions {
    V0(FheBoolV0),
    V1(FheBool),
}

#[derive(VersionsDispatch)]
pub enum CompactFheBoolVersions {
    V0(CompactFheBool),
}

#[derive(VersionsDispatch)]
pub enum InnerCompressedFheBoolVersions {
    V0(InnerCompressedFheBool),
}

// Before V1 where we added the Tag, the CompressedFheBool
// was simply the inner enum
type CompressedFheBoolV0 = InnerCompressedFheBool;

impl Upgrade<CompressedFheBool> for CompressedFheBoolV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedFheBool, Self::Error> {
        Ok(CompressedFheBool {
            inner: match self {
                Self::Seeded(s) => Self::Seeded(s),
                Self::ModulusSwitched(m) => Self::ModulusSwitched(m),
            },
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedFheBoolVersions {
    V0(CompressedFheBoolV0),
    V1(CompressedFheBool),
}

#[derive(VersionsDispatch)]
pub enum CompactFheBoolListVersions {
    V0(CompactFheBoolList),
}

// Basic support for deprecated compact list, to be able to load them and convert them to something
// else

#[derive(Versionize)]
#[versionize(CompactFheBoolVersions)]
#[deprecated(since = "0.7.0", note = "Use CompactCiphertextList instead")]
pub struct CompactFheBool {
    pub(in crate::high_level_api) list: CompactCiphertextList,
}

impl CompactFheBool {
    /// Expand to a [FheBool]
    ///
    /// See [CompactFheBool] example.
    pub fn expand(mut self) -> Result<FheBool, Error> {
        // This compact list might have been loaded from an homogeneous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Boolean);

        let hl_list = HlCompactCiphertextList {
            inner: self.list,
            tag: Tag::default(),
        };
        let list = hl_list.expand()?;

        let block = list
            .inner
            .get::<crate::integer::BooleanBlock>(0)
            .map(|b| b.ok_or_else(|| Error::new("Failed to expand compact list".to_string())))??;

        let mut ciphertext = FheBool::new(block, Tag::default());
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

#[derive(Versionize)]
#[versionize(CompactFheBoolListVersions)]
#[deprecated(since = "0.7.0", note = "Use CompactCiphertextList instead")]
pub struct CompactFheBoolList {
    list: CompactCiphertextList,
}

impl CompactFheBoolList {
    /// Expand to a Vec<[FheBool]>
    pub fn expand(mut self) -> Result<Vec<FheBool>, Error> {
        // This compact list might have been loaded from an homogeneous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Boolean);

        let hl_list = HlCompactCiphertextList {
            inner: self.list,
            tag: Tag::default(),
        };
        let list = hl_list.expand()?;
        let len = list.len();

        (0..len)
            .map(|idx| {
                let block = list
                    .inner
                    .get::<crate::integer::BooleanBlock>(idx)
                    .map(|list| {
                        list.ok_or_else(|| Error::new("Failed to expand compact list".to_string()))
                    })??;

                let mut ciphertext = FheBool::new(block, Tag::default());
                ciphertext.ciphertext.move_to_device_of_server_key_if_set();
                Ok(ciphertext)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}
