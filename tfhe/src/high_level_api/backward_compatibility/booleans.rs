use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::high_level_api::booleans::{
    InnerBoolean, InnerCompressedFheBool, InnerSquashedNoiseBoolean, SerializableInnerBoolean,
    SerializableInnerSquashedNoiseBoolean, SquashedNoiseFheBool,
};
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::SquashedNoiseCiphertextState;
use crate::{CompressedFheBool, FheBool, Tag};
use std::convert::Infallible;

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum SerializableInnerBooleanVersions {
    V0(SerializableInnerBoolean),
}

#[derive(Version)]
pub struct FheBoolV0 {
    pub(in crate::high_level_api) ciphertext: InnerBoolean,
}

impl Upgrade<FheBoolV1> for FheBoolV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<FheBoolV1, Self::Error> {
        Ok(FheBoolV1 {
            ciphertext: self.ciphertext,
            tag: Tag::default(),
        })
    }
}

#[derive(Version)]
pub struct FheBoolV1 {
    pub(in crate::high_level_api) ciphertext: InnerBoolean,
    pub(crate) tag: Tag,
}

impl Upgrade<FheBool> for FheBoolV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<FheBool, Self::Error> {
        let Self { ciphertext, tag } = self;

        Ok(FheBool::new(
            ciphertext,
            tag,
            ReRandomizationMetadata::default(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum FheBoolVersions {
    V0(FheBoolV0),
    V1(FheBoolV1),
    V2(FheBool),
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

// Squashed Noise
#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum SerializableInnerSquashedNoiseBooleanVersions {
    V0(SerializableInnerSquashedNoiseBoolean),
}

#[derive(Version)]
pub struct SquashedNoiseFheBoolV0 {
    pub(in crate::high_level_api) inner: InnerSquashedNoiseBoolean,
    pub(in crate::high_level_api) tag: Tag,
}

impl Upgrade<SquashedNoiseFheBool> for SquashedNoiseFheBoolV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SquashedNoiseFheBool, Self::Error> {
        Ok(SquashedNoiseFheBool::new(
            self.inner,
            SquashedNoiseCiphertextState::Normal,
            self.tag,
        ))
    }
}

// Squashed Noise
#[derive(VersionsDispatch)]
pub enum SquashedNoiseFheBoolVersions {
    V0(SquashedNoiseFheBoolV0),
    V1(SquashedNoiseFheBool),
}
