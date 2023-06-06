use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

#[cfg(feature = "internal-keycache")]
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::ClientKey;

use super::parameters::ShortIntegerParameter;
use concrete_csprng::seeders::Seed;

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;

/// The key associated to a short integer type
///
/// Can encrypt and decrypt it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntClientKey<P: ShortIntegerParameter> {
    pub(super) key: ClientKey,
    _marker: PhantomData<P>,
}

impl<P> GenericShortIntClientKey<P>
where
    P: ShortIntegerParameter,
{
    pub(crate) fn with_seed(parameters: P, seed: Seed) -> Self {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
        let key = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder)
            .new_client_key(parameters.into().into())
            .unwrap();

        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl<P> From<P> for GenericShortIntClientKey<P>
where
    P: ShortIntegerParameter,
{
    fn from(parameters: P) -> Self {
        #[cfg(feature = "internal-keycache")]
        let key = KEY_CACHE
            .get_from_param(parameters.into())
            .client_key()
            .clone();
        #[cfg(not(feature = "internal-keycache"))]
        let key = {
            let parameters: crate::shortint::ClassicPBSParameters = parameters.into();
            ClientKey::new(parameters)
        };

        Self {
            key,
            _marker: Default::default(),
        }
    }
}
