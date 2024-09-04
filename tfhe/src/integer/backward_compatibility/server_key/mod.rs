use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::integer::{CompressedServerKey, ServerKey};

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions {
    V0(ServerKey),
}

#[derive(Version)]
pub struct UnsupportedCompressedServerKeyV0;

impl Upgrade<CompressedServerKey> for UnsupportedCompressedServerKeyV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<CompressedServerKey, Self::Error> {
        Err(crate::Error::new(
            "Unable to load CompressedServerKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(UnsupportedCompressedServerKeyV0),
    V1(CompressedServerKey),
}
