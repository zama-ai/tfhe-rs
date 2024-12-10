use tfhe_versionable::VersionsDispatch;

use crate::boolean::key_switching_key::KeySwitchingKey;

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyVersions {
    V0(KeySwitchingKey),
}
