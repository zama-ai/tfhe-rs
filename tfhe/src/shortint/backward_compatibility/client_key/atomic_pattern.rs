use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{GlweSecretKeyOwned, LweSecretKeyOwned};
use crate::shortint::client_key::atomic_pattern::{
    AtomicPatternClientKey, KS32AtomicPatternClientKey, StandardAtomicPatternClientKey,
};
use crate::shortint::{PBSParameters, WopbsParameters};
use crate::Error;

#[derive(VersionsDispatch)]
pub enum AtomicPatternClientKeyVersions {
    V0(AtomicPatternClientKey),
}

#[derive(Version)]
pub struct StandardAtomicPatternClientKeyV0 {
    glwe_secret_key: GlweSecretKeyOwned<u64>,
    lwe_secret_key: LweSecretKeyOwned<u64>,
    parameters: PBSParameters,
    wopbs_parameters: Option<WopbsParameters>,
}

impl Upgrade<StandardAtomicPatternClientKey> for StandardAtomicPatternClientKeyV0 {
    type Error = Error;

    fn upgrade(self) -> Result<StandardAtomicPatternClientKey, Self::Error> {
        let Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
            wopbs_parameters,
        } = self;

        if wopbs_parameters.is_some() {
            return Err(Error::new(
                "StandardAtomicPatternClientKey had WopbsParameters which are now deprecated"
                    .to_string(),
            ));
        }

        Ok(StandardAtomicPatternClientKey {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum StandardAtomicPatternClientKeyVersions {
    V0(StandardAtomicPatternClientKeyV0),
    V1(StandardAtomicPatternClientKey),
}

#[derive(VersionsDispatch)]
pub enum KS32AtomicPatternClientKeyVersions {
    V0(KS32AtomicPatternClientKey),
}
