use std::marker::PhantomData;

use crate::boolean::client_key::ClientKey;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;

use concrete_csprng::seeders::Seed;
use serde::{Deserialize, Serialize};

use super::parameters::BooleanParameterSet;
use super::types::static_::StaticBoolParameters;
use super::FheBoolParameters;

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericBoolClientKey<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::high_level_api::booleans) key: ClientKey,
    _marker: std::marker::PhantomData<P>,
}

impl GenericBoolClientKey<StaticBoolParameters> {
    pub(crate) fn with_seed(parameters: FheBoolParameters, seed: Seed) -> Self {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
        let key = crate::boolean::engine::BooleanEngine::new_from_seeder(&mut seeder)
            .create_client_key(parameters.into());

        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl From<FheBoolParameters> for GenericBoolClientKey<StaticBoolParameters> {
    fn from(parameters: FheBoolParameters) -> Self {
        Self {
            key: ClientKey::new(&parameters.into()),
            _marker: Default::default(),
        }
    }
}
