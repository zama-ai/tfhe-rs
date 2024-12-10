use tfhe_versionable::VersionsDispatch;

use crate::Config;

#[derive(VersionsDispatch)]
pub enum ConfigVersions {
    V0(Config),
}
