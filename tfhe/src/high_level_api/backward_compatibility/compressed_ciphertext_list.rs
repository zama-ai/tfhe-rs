use crate::high_level_api::compressed_ciphertext_list::InnerCompressedCiphertextList;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::SquashedNoiseCiphertextState;
use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::{CompressedCiphertextList, CompressedSquashedNoiseCiphertextList, Tag};

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum SquashedNoiseCiphertextStateVersions {
    V0(SquashedNoiseCiphertextState),
}

#[derive(Version)]
pub struct CompressedCiphertextListV0(crate::integer::ciphertext::CompressedCiphertextList);

impl Upgrade<CompressedCiphertextListV1> for CompressedCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextListV1, Self::Error> {
        Ok(CompressedCiphertextListV1 {
            inner: self.0,
            tag: Tag::default(),
        })
    }
}

#[derive(Version)]
pub struct CompressedCiphertextListV1 {
    inner: crate::integer::ciphertext::CompressedCiphertextList,
    tag: Tag,
}

impl Upgrade<CompressedCiphertextListV2> for CompressedCiphertextListV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextListV2, Self::Error> {
        Ok(CompressedCiphertextListV2 {
            inner: InnerCompressedCiphertextList::Cpu(self.inner),
            tag: self.tag,
        })
    }
}

#[derive(Version)]
pub struct CompressedCiphertextListV2 {
    pub(in crate::high_level_api) inner: InnerCompressedCiphertextList,
    pub(in crate::high_level_api) tag: Tag,
}

impl Upgrade<CompressedCiphertextList> for CompressedCiphertextListV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextList, Self::Error> {
        let Self { inner, tag } = self;

        // Empty metadata for older lists which did not store any
        let re_randomization_metadata =
            vec![ReRandomizationMetadata::default(); inner.info().len()];

        Ok(CompressedCiphertextList {
            inner,
            tag,
            re_randomization_metadata,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextListV0),
    V1(CompressedCiphertextListV1),
    V2(CompressedCiphertextListV2),
    V3(CompressedCiphertextList),
}

#[derive(VersionsDispatch)]
pub enum CompressedSquashedNoiseCiphertextListVersions {
    V0(CompressedSquashedNoiseCiphertextList),
}
