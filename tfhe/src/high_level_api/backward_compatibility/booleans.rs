use serde::{Deserialize, Serialize};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::high_level_api::booleans::{
    InnerBoolean, InnerBooleanVersionOwned, InnerCompressedFheBool,
};
use crate::{CompressedFheBool, FheBool, Tag};
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
