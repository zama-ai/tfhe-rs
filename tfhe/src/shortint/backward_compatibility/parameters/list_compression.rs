use tfhe_versionable::VersionsDispatch;

use super::parameters::list_compression::{
    CompressionParameters, NoiseSquashingCompressionParameters,
};

#[derive(VersionsDispatch)]
pub enum CompressionParametersVersions {
    V0(CompressionParameters),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingCompressionParametersVersions {
    V0(NoiseSquashingCompressionParameters),
}
