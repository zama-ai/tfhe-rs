use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::{CompressedCiphertextList, Tag};

#[derive(Version)]
pub struct CompressedCiphertextListV0(crate::integer::ciphertext::CompressedCiphertextList);

impl Upgrade<CompressedCiphertextList> for CompressedCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextList, Self::Error> {
        Ok(CompressedCiphertextList {
            inner: self.0,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextListV0),
    V1(CompressedCiphertextList),
}
