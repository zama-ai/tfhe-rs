#![allow(deprecated)]

use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};

use crate::high_level_api::booleans::InnerBooleanVersionOwned;
use crate::integer::ciphertext::{CompactCiphertextList, DataKind};
use crate::{CompactCiphertextList as HlCompactCiphertextList, CompressedFheBool, Error, FheBool};

// Manual impl
#[derive(Serialize, Deserialize)]
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
pub(crate) enum InnerBooleanVersionedOwned {
    V0(InnerBooleanVersionOwned),
}

#[derive(VersionsDispatch)]
pub enum FheBoolVersions {
    V0(FheBool),
}

#[derive(VersionsDispatch)]
pub enum CompactFheBoolVersions {
    V0(CompactFheBool),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheBoolVersions {
    V0(CompressedFheBool),
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
        // This compact list might have been loaded from an homogenous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Boolean);

        let hl_list = HlCompactCiphertextList(self.list);
        let list = hl_list.expand()?;

        let block = list
            .get::<crate::integer::BooleanBlock>(0)
            .ok_or_else(|| Error::new("Failed to expand compact list".to_string()))??;

        let mut ciphertext = FheBool::new(block);
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
        // This compact list might have been loaded from an homogenous compact list without type
        // info
        self.list
            .info
            .iter_mut()
            .for_each(|info| *info = DataKind::Boolean);

        let hl_list = HlCompactCiphertextList(self.list);
        let list = hl_list.expand()?;
        let len = list.len();

        (0..len)
            .map(|idx| {
                let block = list
                    .get::<crate::integer::BooleanBlock>(idx)
                    .ok_or_else(|| Error::new("Failed to expand compact list".to_string()))??;

                let mut ciphertext = FheBool::new(block);
                ciphertext.ciphertext.move_to_device_of_server_key_if_set();
                Ok(ciphertext)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}
