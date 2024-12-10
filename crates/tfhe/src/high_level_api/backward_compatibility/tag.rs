use crate::high_level_api::tag::Tag;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum TagVersions {
    V0(Tag),
}
