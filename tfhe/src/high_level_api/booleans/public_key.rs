use serde::{Deserialize, Serialize};

use super::client_key::FheBoolClientKey;

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FheBoolPublicKey {
    pub(in crate::high_level_api::booleans) key: crate::boolean::public_key::PublicKey,
}

impl FheBoolPublicKey {
    pub fn new(client_key: &FheBoolClientKey) -> Self {
        let key = crate::boolean::public_key::PublicKey::new(&client_key.key);
        Self { key }
    }
}

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FheBoolCompressedPublicKey {
    pub(in crate::high_level_api::booleans) key: crate::boolean::public_key::CompressedPublicKey,
}

impl FheBoolCompressedPublicKey {
    pub fn new(client_key: &FheBoolClientKey) -> Self {
        let key = crate::boolean::public_key::CompressedPublicKey::new(&client_key.key);
        Self { key }
    }

    pub fn decompress(self) -> FheBoolPublicKey {
        FheBoolPublicKey {
            key: crate::boolean::public_key::PublicKey::from(self.key),
        }
    }
}
