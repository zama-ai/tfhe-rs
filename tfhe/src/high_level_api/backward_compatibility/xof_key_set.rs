use std::convert::Infallible;

use tfhe_csprng::seeders::XofSeed;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::high_level_api::xof_key_set::{CompressedXofKeySet, XofKeySet};
use crate::xof_key_set::XofSeedStart;
use crate::{CompressedCompactPublicKey, CompressedServerKey};

#[derive(Version)]
pub struct CompressedXofKeySetV0 {
    seed: XofSeed,
    compressed_public_key: CompressedCompactPublicKey,
    compressed_server_key: CompressedServerKey,
}

impl Upgrade<CompressedXofKeySet> for CompressedXofKeySetV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedXofKeySet, Self::Error> {
        let Self {
            seed,
            compressed_public_key,
            compressed_server_key,
        } = self;

        Ok(CompressedXofKeySet::from_raw_parts(
            // Start on second byte to keep backward compatibility with csprng bug
            XofSeedStart::SecondByte(seed),
            compressed_public_key,
            compressed_server_key,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedXofKeySetVersions {
    V0(CompressedXofKeySetV0),
    V1(CompressedXofKeySet),
}

#[derive(VersionsDispatch)]
pub enum XofKeySetVersions {
    V0(XofKeySet),
}

#[derive(VersionsDispatch)]
pub enum XofSeedStartVersions {
    V0(XofSeedStart),
}
