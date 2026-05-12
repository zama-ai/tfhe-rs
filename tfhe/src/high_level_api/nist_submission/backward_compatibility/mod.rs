#![allow(clippy::large_enum_variant)]
#![cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]

#[cfg(feature = "zk-pok")]
mod zk {
    use tfhe_versionable::VersionsDispatch;

    use super::super::compact_ciphertext_list::ProvenCompactCiphertextList;

    #[derive(VersionsDispatch)]
    pub enum ProvenCompactCiphertextListVersions {
        V0(ProvenCompactCiphertextList),
    }
}

#[cfg(feature = "zk-pok")]
pub use zk::ProvenCompactCiphertextListVersions;
