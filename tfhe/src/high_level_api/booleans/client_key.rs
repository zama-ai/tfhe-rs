use crate::boolean::client_key::ClientKey;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;

use concrete_csprng::seeders::Seed;
use serde::{Deserialize, Serialize};

use super::FheBoolParameters;

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FheBoolClientKey {
    pub(in crate::high_level_api::booleans) key: ClientKey,
}

impl FheBoolClientKey {
    pub(crate) fn with_seed(parameters: FheBoolParameters, seed: Seed) -> Self {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
        let key = crate::boolean::engine::BooleanEngine::new_from_seeder(&mut seeder)
            .create_client_key(parameters.into());

        Self { key }
    }
}

impl From<FheBoolParameters> for FheBoolClientKey {
    fn from(parameters: FheBoolParameters) -> Self {
        Self {
            key: ClientKey::new(&parameters.into()),
        }
    }
}
