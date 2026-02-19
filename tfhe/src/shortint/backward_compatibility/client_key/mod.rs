pub mod atomic_pattern;

use std::any::{Any, TypeId};

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{GlweSecretKeyOwned, LweSecretKeyOwned};
use crate::shortint::client_key::atomic_pattern::{
    AtomicPatternClientKey, StandardAtomicPatternClientKey,
};
use crate::shortint::client_key::GenericClientKey;
use crate::shortint::ShortintParameterSet;
use crate::Error;

#[derive(Version)]
pub struct GenericClientKeyV0 {
    glwe_secret_key: GlweSecretKeyOwned<u64>,
    lwe_secret_key: LweSecretKeyOwned<u64>,
    parameters: ShortintParameterSet,
}

impl<AP: 'static> Upgrade<GenericClientKey<AP>> for GenericClientKeyV0 {
    type Error = Error;

    fn upgrade(self) -> Result<GenericClientKey<AP>, Self::Error> {
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

        if TypeId::of::<AP>() == TypeId::of::<AtomicPatternClientKey>() {
            let atomic_pattern = AtomicPatternClientKey::Standard(std_ap);
            let ck: Box<dyn Any + 'static> = Box::new(GenericClientKey { atomic_pattern });
            Ok(*ck.downcast::<GenericClientKey<AP>>().unwrap()) // We know from the TypeId that
                                                                // AP is of the right type so we
                                                                // can unwrap
        } else if TypeId::of::<AP>() == TypeId::of::<StandardAtomicPatternClientKey>() {
            let ck: Box<dyn Any + 'static> = Box::new(GenericClientKey {
                atomic_pattern: std_ap,
            });
            Ok(*ck.downcast::<GenericClientKey<AP>>().unwrap()) // We know from the TypeId that
                                                                // AP is of the right type so we
                                                                // can unwrap
        } else {
            Err(Error::new(
                "ClientKey from TFHE-rs 1.2 and before can only be deserialized to the standard \
Atomic Pattern"
                    .to_string(),
            ))
        }
    }
}

#[derive(VersionsDispatch)]
pub enum GenericClientKeyVersions<AP> {
    V0(GenericClientKeyV0),
    V1(GenericClientKey<AP>),
}
