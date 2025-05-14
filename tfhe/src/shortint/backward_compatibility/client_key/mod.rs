pub mod atomic_pattern;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{GlweSecretKeyOwned, LweSecretKeyOwned};
use crate::shortint::client_key::atomic_pattern::{
    AtomicPatternClientKey, StandardAtomicPatternClientKey,
};
use crate::shortint::client_key::{GenericClientKey, StandardClientKey};
use crate::shortint::{ClientKey, ShortintParameterSet};
use crate::Error;

#[derive(Version)]
pub struct ClientKeyV0 {
    glwe_secret_key: GlweSecretKeyOwned<u64>,
    lwe_secret_key: LweSecretKeyOwned<u64>,
    parameters: ShortintParameterSet,
}

impl Upgrade<ClientKey> for ClientKeyV0 {
    type Error = Error;

    fn upgrade(self) -> Result<ClientKey, Self::Error> {
        let ap_params = self.parameters.pbs_parameters().ok_or_else(|| {
            Error::new(
                "ClientKey from TFHE-rs 1.2 and before needs PBS parameters to be upgraded to the latest version"
                    .to_string(),
            )
        })?;

        let std_ap = StandardAtomicPatternClientKey::from_raw_parts(
            self.glwe_secret_key,
            self.lwe_secret_key,
            ap_params,
            self.parameters.wopbs_parameters(),
        );

        let atomic_pattern = AtomicPatternClientKey::Standard(std_ap);
        Ok(ClientKey { atomic_pattern })
    }
}

impl Upgrade<StandardClientKey> for ClientKeyV0 {
    type Error = Error;

    fn upgrade(self) -> Result<StandardClientKey, Self::Error> {
        let ap_params = self.parameters.pbs_parameters().ok_or_else(|| {
            Error::new(
                "ClientKey from TFHE-rs 1.2 and before needs PBS parameters to be upgraded to the latest version"
                    .to_string(),
            )
        })?;

        let atomic_pattern = StandardAtomicPatternClientKey::from_raw_parts(
            self.glwe_secret_key,
            self.lwe_secret_key,
            ap_params,
            self.parameters.wopbs_parameters(),
        );

        Ok(StandardClientKey { atomic_pattern })
    }
}

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions<AP> {
    V0(ClientKeyV0),
    V1(GenericClientKey<AP>),
}
