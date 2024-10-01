use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::{CompressedCiphertextList, Tag};

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

impl Upgrade<CompressedCiphertextList> for CompressedCiphertextListV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextList, Self::Error> {
        Ok(CompressedCiphertextList {
            inner: crate::high_level_api::compressed_ciphertext_list::InnerCompressedCiphertextList::Cpu(self.inner),
            tag: self.tag,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextListV0),
    V1(CompressedCiphertextListV1),
    V2(CompressedCiphertextList),
}
