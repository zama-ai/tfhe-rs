use crate::shortint::parameters::re_randomization::ReRandomizationParameters;

use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum ReRandomizationParametersVersions {
    V0(ReRandomizationParameters),
}
