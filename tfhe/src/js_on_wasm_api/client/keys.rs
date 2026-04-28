use super::TfheClientKey;
use crate::high_level_api as hlapi;
#[cfg(feature = "shortint-client-js-wasm-api")]
use crate::js_on_wasm_api::generic_safe_deserialize_conformant;
use crate::js_on_wasm_api::{catch_panic, generic_safe_deserialize, generic_safe_serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TfheCompactPublicKey(pub(crate) hlapi::CompactPublicKey);

#[wasm_bindgen]
impl TfheCompactPublicKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<Self, JsError> {
        catch_panic(|| Self(hlapi::CompactPublicKey::new(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        generic_safe_serialize(&self.0, serialized_size_limit)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        generic_safe_deserialize(buffer, serialized_size_limit).map(Self)
    }

    #[cfg(feature = "shortint-client-js-wasm-api")]
    #[wasm_bindgen]
    pub fn safe_deserialize_conformant(
        buffer: &[u8],
        serialized_size_limit: u64,
        conformance_params: &crate::js_on_wasm_api::shortint::ShortintCompactPublicKeyEncryptionParameters,
    ) -> Result<Self, JsError> {
        generic_safe_deserialize_conformant(
            buffer,
            serialized_size_limit,
            &conformance_params.compact_pke_params,
        )
        .map(Self)
    }
}
