use tfhe_versionable::VersionsDispatch;

use crate::seeders::{Seed, XofSeed};

#[derive(VersionsDispatch)]
pub enum XofSeedVersions {
    V0(XofSeed),
}

#[derive(VersionsDispatch)]
pub enum SeedVersions {
    V0(Seed),
}
