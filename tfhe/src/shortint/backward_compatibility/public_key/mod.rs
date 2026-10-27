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

impl Upgrade<PublicKeyV1> for PublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<PublicKeyV1, Self::Error> {
        Ok(PublicKeyV1 {
            lwe_public_key: self.lwe_public_key,
            parameters: self.parameters,
            atomic_pattern: AtomicPatternKind::Standard(self.pbs_order),
        })
    }
}

#[derive(Version)]
pub struct PublicKeyV1 {
    lwe_public_key: LwePublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    atomic_pattern: AtomicPatternKind,
}

impl Upgrade<PublicKey> for PublicKeyV1 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<PublicKey, Self::Error> {
        let key = PublicKey::from_raw_parts(self.lwe_public_key, self.parameters.ap_parameters())?;

        if key.atomic_pattern() != self.atomic_pattern {
            return Err(crate::Error::new(format!(
                "Mismatch between the stored atomic pattern ({:?}) and the one expected from \
                the parameters ({:?})",
                self.atomic_pattern,
                key.atomic_pattern(),
            )));
        }

        Ok(key)
    }
}

#[derive(VersionsDispatch)]
pub enum PublicKeyVersions {
    V0(PublicKeyV0),
    V1(PublicKeyV1),
    V2(PublicKey),
}

#[derive(Version)]
pub struct CompactPublicKeyV0 {
    key: LweCompactPublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    pbs_order: PBSOrder,
}

impl Upgrade<CompactPublicKey> for CompactPublicKeyV0 {
    fn upgrade(self) -> Result<CompactPublicKey, Self::Error> {
        let parameters = self.parameters.ap_parameters().try_into()?;
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

impl Upgrade<CompressedPublicKeyV1> for CompressedPublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedPublicKeyV1, Self::Error> {
        Ok(CompressedPublicKeyV1 {
            lwe_public_key: self.lwe_public_key,
            parameters: self.parameters,
            atomic_pattern: AtomicPatternKind::Standard(self.pbs_order),
        })
    }
}

#[derive(Version)]
pub struct CompressedPublicKeyV1 {
    lwe_public_key: SeededLwePublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    atomic_pattern: AtomicPatternKind,
}

impl Upgrade<CompressedPublicKey> for CompressedPublicKeyV1 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<CompressedPublicKey, Self::Error> {
        let key = CompressedPublicKey::from_raw_parts(
            self.lwe_public_key,
            self.parameters.ap_parameters(),
        )?;

        if key.atomic_pattern() != self.atomic_pattern {
            return Err(crate::Error::new(format!(
                "Mismatch between the stored atomic pattern ({:?}) and the one expected from \
                the parameters ({:?})",
                self.atomic_pattern,
                key.atomic_pattern(),
            )));
        }

        Ok(key)
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedPublicKeyVersions {
    V0(CompressedPublicKeyV0),
    V1(CompressedPublicKeyV1),
    V2(CompressedPublicKey),
}

#[derive(Version)]
pub struct CompressedCompactPublicKeyV0 {
    key: SeededLweCompactPublicKeyOwned<u64>,
    parameters: ShortintParameterSet,
    pbs_order: PBSOrder,
}

impl Upgrade<CompressedCompactPublicKey> for CompressedCompactPublicKeyV0 {
    fn upgrade(self) -> Result<CompressedCompactPublicKey, Self::Error> {
        let parameters = self.parameters.ap_parameters().try_into()?;
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
