use crate::FheAsciiString;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum FheAsciiStringVersions {
    V0(FheAsciiString),
}
