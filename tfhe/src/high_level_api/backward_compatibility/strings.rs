use crate::high_level_api::strings::ascii::SerializableAsciiDevice;
use crate::FheAsciiString;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum FheAsciiStringVersions {
    V0(FheAsciiString),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum SerializableAsciiDeviceVersions {
    V0(SerializableAsciiDevice),
}
