use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{
    Container, LweCompactPublicKeyOwned, LwePublicKeyOwned, SeededLweCompactPublicKeyOwned,
    SeededLwePublicKeyOwned,
};
use crate::shortint::{
    AtomicPatternKind, CompactPrivateKey, CompactPublicKey, CompressedCompactPublicKey,
    CompressedPublicKey, PBSOrder, PublicKey, ShortintParameterSet,
};

#[derive(Version)]
pub struct PublicKeyV0 {
    lwe_public_key: LwePublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    pbs_order: PBSOrder,
}

impl Upgrade<PublicKey> for PublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<PublicKey, Self::Error> {
        Ok(PublicKey::from_raw_parts(
            self.lwe_public_key,
            self.parameters,
            AtomicPatternKind::Standard(self.pbs_order),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum PublicKeyVersions {
    V0(PublicKeyV0),
    V1(PublicKey),
}

#[derive(Version)]
pub struct CompactPublicKeyV0 {
    key: LweCompactPublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    pbs_order: PBSOrder,
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

#[derive(Version)]
pub struct CompressedPublicKeyV0 {
    lwe_public_key: SeededLwePublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    pbs_order: PBSOrder,
}

impl Upgrade<CompressedPublicKey> for CompressedPublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedPublicKey, Self::Error> {
        Ok(CompressedPublicKey::from_raw_parts(
            self.lwe_public_key,
            self.parameters,
            AtomicPatternKind::Standard(self.pbs_order),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedPublicKeyVersions {
    V0(CompressedPublicKeyV0),
    V1(CompressedPublicKey),
}

#[derive(Version)]
pub struct CompressedCompactPublicKeyV0 {
    key: SeededLweCompactPublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    pbs_order: PBSOrder,
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
