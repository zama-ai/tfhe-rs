use tfhe_versionable::VersionsDispatch;

use crate::shortint::{CarryModulus, MessageModulus};

#[derive(VersionsDispatch)]
pub enum MessageModulusVersions {
    V0(MessageModulus),
}

#[derive(VersionsDispatch)]
pub enum CarryModulusVersions {
    V0(CarryModulus),
}
