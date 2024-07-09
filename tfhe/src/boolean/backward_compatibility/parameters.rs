use tfhe_versionable::VersionsDispatch;

use crate::boolean::parameters::{BooleanKeySwitchingParameters, BooleanParameters};

#[derive(VersionsDispatch)]
pub enum BooleanParametersVersions {
    V0(BooleanParameters),
}

#[derive(VersionsDispatch)]
pub enum BooleanKeySwitchingParametersVersions {
    V0(BooleanKeySwitchingParameters),
}
