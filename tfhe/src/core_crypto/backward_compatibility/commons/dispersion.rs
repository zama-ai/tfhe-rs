use crate::core_crypto::commons::dispersion::{StandardDev, Variance};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum StandardDevVersions {
    V0(StandardDev),
}

#[derive(VersionsDispatch)]
pub enum VarianceVersions {
    V0(Variance),
}
