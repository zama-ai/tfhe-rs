use crate::commons::dispersion::StandardDev;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum StandardDevVersions {
    V0(StandardDev),
}
