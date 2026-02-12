use crate::core_crypto::prelude::{GlweSecretKeyOwned, LweSecretKeyOwned};
use crate::shortint::backward_compatibility::parameters::WopbsParameters;
use crate::shortint::client_key::atomic_pattern::{
    AtomicPatternClientKey, KS32AtomicPatternClientKey, StandardAtomicPatternClientKey,
};
use crate::shortint::PBSParameters;
use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum AtomicPatternClientKeyVersions {
    V0(AtomicPatternClientKey),
}

#[derive(Version)]
pub struct StandardAtomicPatternClientKeyV0 {
    glwe_secret_key: GlweSecretKeyOwned<u64>,
    /// Key used as the output of the keyswitch operation
    lwe_secret_key: LweSecretKeyOwned<u64>,
    parameters: PBSParameters,
    wopbs_parameters: Option<WopbsParameters>,
}

impl Upgrade<StandardAtomicPatternClientKey> for StandardAtomicPatternClientKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<StandardAtomicPatternClientKey, Self::Error> {
        let Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
            wopbs_parameters: _,
        } = self;

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
