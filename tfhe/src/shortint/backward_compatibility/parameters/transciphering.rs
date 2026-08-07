use super::parameters::transciphering::TranscipheringParameters;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum TranscipheringParametersVersions {
    V0(TranscipheringParameters),
}
