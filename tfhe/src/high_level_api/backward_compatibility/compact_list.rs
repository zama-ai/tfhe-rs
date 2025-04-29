use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::{CompactCiphertextList, Tag};

#[cfg(feature = "zk-pok")]
use crate::ProvenCompactCiphertextList;

#[derive(Version)]
pub struct CompactCiphertextListV0(crate::integer::ciphertext::CompactCiphertextList);

impl Upgrade<CompactCiphertextList> for CompactCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactCiphertextList, Self::Error> {
        Ok(CompactCiphertextList {
            inner: crate::high_level_api::compact_list::InnerCompactCiphertextList::Cpu(self.0),
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextListV0),
    V1(CompactCiphertextList),
}

#[cfg(feature = "zk-pok")]
#[derive(VersionsDispatch)]
pub enum ProvenCompactCiphertextListVersions {
    V0(ProvenCompactCiphertextList),
}
