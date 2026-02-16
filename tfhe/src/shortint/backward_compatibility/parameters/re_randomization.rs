use crate::shortint::parameters::re_randomization::ReRandomizationParameters;

use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum ReRandomizationParametersVersions {
    V0(ReRandomizationParameters), // Since v1.6.0
}
