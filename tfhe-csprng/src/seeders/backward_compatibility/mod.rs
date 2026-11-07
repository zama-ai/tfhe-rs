use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::seeders::{AesVariant, Seed, SeedKind, XofSeed};

#[derive(VersionsDispatch)]
pub enum XofSeedVersions {
    V0(XofSeed),
}

#[derive(VersionsDispatch)]
pub enum SeedVersions {
    V0(Seed),
}

#[derive(VersionsDispatch)]
pub enum AesVariantVersions {
    V0(AesVariant),
}

#[derive(Version)]
pub enum SeedKindV0 {
    Ctr(Seed),
    Xof(XofSeed),
}

impl Upgrade<SeedKind> for SeedKindV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SeedKind, Self::Error> {
        Ok(match self {
            Self::Ctr(seed) => SeedKind::Ctr(seed),
            // Everything serialized with a SeedKindV0 was using aes128
            Self::Xof(seed) => SeedKind::xof_aes128(seed),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SeedKindVersions {
    V0(SeedKindV0),
    V1(SeedKind),
}
