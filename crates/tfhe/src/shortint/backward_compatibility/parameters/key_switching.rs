use tfhe_versionable::VersionsDispatch;

use super::parameters::ShortintKeySwitchingParameters;

#[derive(VersionsDispatch)]
pub enum ShortintKeySwitchingParametersVersions {
    V0(ShortintKeySwitchingParameters),
}
