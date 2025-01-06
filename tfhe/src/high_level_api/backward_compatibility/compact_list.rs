use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::{CompactCiphertextList, SerializedKind, Tag};

#[derive(Version)]
pub struct CompactCiphertextListV0(crate::integer::ciphertext::CompactCiphertextList);

impl Upgrade<CompactCiphertextListV1> for CompactCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactCiphertextListV1, Self::Error> {
        Ok(CompactCiphertextListV1 {
            inner: self.0,
            tag: Tag::default(),
        })
    }
}

#[derive(Version)]
pub struct CompactCiphertextListV1 {
    pub(crate) inner: crate::integer::ciphertext::CompactCiphertextList,
    pub(crate) tag: Tag,
}

impl Upgrade<CompactCiphertextList> for CompactCiphertextListV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactCiphertextList, Self::Error> {
        let Self { inner, tag } = self;
        let crate::integer::ciphertext::CompactCiphertextList { ct_list, info } = inner;

        let info = info
            .iter()
            .map(|&kind| SerializedKind::from_data_kind(kind, ct_list.message_modulus))
            .collect();

        Ok(CompactCiphertextList { ct_list, info, tag })
    }
}

#[cfg(feature = "zk-pok")]
use crate::ProvenCompactCiphertextList;

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextListV0),
    V1(CompactCiphertextListV1),
    V2(CompactCiphertextList),
}

#[cfg(feature = "zk-pok")]
#[derive(Version)]
pub struct ProvenCompactCiphertextListV0 {
    pub(crate) inner: crate::integer::ciphertext::ProvenCompactCiphertextList,
    pub(crate) tag: Tag,
}

#[cfg(feature = "zk-pok")]
impl Upgrade<ProvenCompactCiphertextList> for ProvenCompactCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ProvenCompactCiphertextList, Self::Error> {
        let Self { inner, tag } = self;
        let crate::integer::ciphertext::ProvenCompactCiphertextList { ct_list, info } = inner;

        let info = info
            .iter()
            .map(|&kind| SerializedKind::from_data_kind(kind, ct_list.message_modulus()))
            .collect();

        Ok(ProvenCompactCiphertextList { ct_list, info, tag })
    }
}

#[cfg(feature = "zk-pok")]
#[derive(VersionsDispatch)]
pub enum ProvenCompactCiphertextListVersions {
    V0(ProvenCompactCiphertextListV0),
    V1(ProvenCompactCiphertextList),
}
