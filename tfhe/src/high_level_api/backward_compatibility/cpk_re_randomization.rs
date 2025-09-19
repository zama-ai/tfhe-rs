use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum ReRandomizationMetadataVersions {
    V0(ReRandomizationMetadata),
}
