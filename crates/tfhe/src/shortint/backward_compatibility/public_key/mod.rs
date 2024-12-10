use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{
    Container, LweCompactPublicKeyOwned, SeededLweCompactPublicKeyOwned,
};
use crate::shortint::{
    CompactPrivateKey, CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey, PBSOrder,
    PublicKey, ShortintParameterSet,
};

#[derive(VersionsDispatch)]
pub enum PublicKeyVersions {
    V0(PublicKey),
}

#[derive(Version)]
pub struct CompactPublicKeyV0 {
    pub(crate) key: LweCompactPublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub pbs_order: PBSOrder,
}

impl Upgrade<CompactPublicKey> for CompactPublicKeyV0 {
    fn upgrade(self) -> Result<CompactPublicKey, Self::Error> {
        let parameters = self.parameters.try_into()?;
        Ok(CompactPublicKey {
            key: self.key,
            parameters,
        })
    }

    type Error = crate::Error;
}

#[derive(VersionsDispatch)]
pub enum CompactPublicKeyVersions {
    V0(CompactPublicKeyV0),
    V1(CompactPublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompactPrivateKeyVersions<KeyCont: Container<Element = u64>> {
    V0(CompactPrivateKey<KeyCont>),
}

#[derive(VersionsDispatch)]
pub enum CompressedPublicKeyVersions {
    V0(CompressedPublicKey),
}

#[derive(Version)]
pub struct CompressedCompactPublicKeyV0 {
    pub(crate) key: SeededLweCompactPublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub pbs_order: PBSOrder,
}

impl Upgrade<CompressedCompactPublicKey> for CompressedCompactPublicKeyV0 {
    fn upgrade(self) -> Result<CompressedCompactPublicKey, Self::Error> {
        let parameters = self.parameters.try_into()?;
        Ok(CompressedCompactPublicKey {
            key: self.key,
            parameters,
        })
    }

    type Error = crate::Error;
}

#[derive(VersionsDispatch)]
pub enum CompressedCompactPublicKeyVersions {
    V0(CompressedCompactPublicKeyV0),
    V1(CompressedCompactPublicKey),
}
