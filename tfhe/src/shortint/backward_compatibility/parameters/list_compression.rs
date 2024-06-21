use tfhe_versionable::VersionsDispatch;

use super::parameters::list_compression::CompressionParameters;

#[derive(VersionsDispatch)]
pub enum CompressionParametersVersions {
    V0(CompressionParameters),
}
