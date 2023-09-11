use super::client_key::FheBoolClientKey;
use super::server_key::FheBoolServerKey;
use crate::boolean::prelude::{BooleanKeySwitchingParameters, KeySwitchingKey};

#[derive(Clone, Debug, ::serde::Deserialize, ::serde::Serialize)]
pub(crate) struct FheBoolKeySwitchingParameters {
    pub(crate) params: BooleanKeySwitchingParameters,
}

impl From<BooleanKeySwitchingParameters> for FheBoolKeySwitchingParameters {
    fn from(params: BooleanKeySwitchingParameters) -> Self {
        Self { params }
    }
}

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheBoolKeySwitchingKey {
    pub(in crate::high_level_api::booleans) key: KeySwitchingKey,
}

impl FheBoolKeySwitchingKey {
    pub(crate) fn new(
        key_pair_1: (&FheBoolClientKey, &FheBoolServerKey),
        key_pair_2: (&FheBoolClientKey, &FheBoolServerKey),
        parameters: FheBoolKeySwitchingParameters,
    ) -> Self {
        Self {
            key: KeySwitchingKey::new(&key_pair_1.0.key, &key_pair_2.0.key, parameters.params),
        }
    }

    pub(crate) fn for_same_parameters(
        key_pair_1: (&FheBoolClientKey, &FheBoolServerKey),
        key_pair_2: (&FheBoolClientKey, &FheBoolServerKey),
    ) -> Option<Self> {
        if key_pair_1.0.key.parameters != key_pair_2.0.key.parameters {
            return None;
        }
        let ksk_params = BooleanKeySwitchingParameters::new(
            key_pair_2.0.key.parameters.ks_base_log,
            key_pair_2.0.key.parameters.ks_level,
        );
        Some(Self {
            key: KeySwitchingKey::new(&key_pair_1.0.key, &key_pair_2.0.key, ksk_params),
        })
    }
}
