use super::client_key::FheBoolClientKey;
use super::server_key::FheBoolServerKey;
use crate::boolean::casting_key::CastingKey;

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheBoolCastingKey {
    pub(in crate::high_level_api::booleans) key: CastingKey,
}

impl FheBoolCastingKey {
    pub(crate) fn new(
        key_pair_1: (&FheBoolClientKey, &FheBoolServerKey),
        key_pair_2: (&FheBoolClientKey, &FheBoolServerKey),
    ) -> Self {
        Self {
            key: CastingKey::new(&key_pair_1.0.key, &key_pair_2.0.key),
        }
    }
}
