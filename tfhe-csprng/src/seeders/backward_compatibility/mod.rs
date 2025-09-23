use tfhe_versionable::VersionsDispatch;

use crate::seeders::XofSeed;

#[derive(VersionsDispatch)]
pub enum XofSeedVersions {
    V0(XofSeed),
}
