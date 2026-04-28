use super::TfheClientKey;
use crate::high_level_api as hlapi;
use crate::js_on_wasm_api::{catch_panic, catch_panic_result, into_js_error};
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
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }

    #[cfg(feature = "shortint-client-js-wasm-api")]
    #[wasm_bindgen]
    pub fn safe_deserialize_conformant(
        buffer: &[u8],
        serialized_size_limit: u64,
        conformance_params: &crate::js_on_wasm_api::shortint::ShortintCompactPublicKeyEncryptionParameters,
    ) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .deserialize_from(buffer, &conformance_params.compact_pke_params)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}
