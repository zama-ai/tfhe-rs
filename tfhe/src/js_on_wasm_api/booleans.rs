use bincode;
use wasm_bindgen::prelude::*;

use super::seeder;

use std::panic::set_hook;

#[wasm_bindgen]
pub struct BooleanCiphertext(pub(crate) crate::boolean::ciphertext::Ciphertext);

#[wasm_bindgen]
pub struct BooleanClientKey(pub(crate) crate::boolean::client_key::ClientKey);

#[wasm_bindgen]
pub struct BooleanEngine(pub(crate) crate::boolean::engine::CpuBooleanEngine);

#[wasm_bindgen]
pub struct BooleanParameters(pub(crate) crate::boolean::parameters::BooleanParameters);


#[wasm_bindgen]
pub struct BooleanSerializer;

#[wasm_bindgen]
impl BooleanSerializer {
    #[wasm_bindgen]
    pub fn serialize_boolean_ciphertext(
        ciphertext: &BooleanCiphertext,
    ) -> Result<Vec<u8>, JsError> {
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_boolean_ciphertext(buffer: &[u8]) -> Result<BooleanCiphertext, JsError> {
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(BooleanCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_boolean_client_key(
        client_key: &BooleanClientKey,
    ) -> Result<Vec<u8>, JsError> {
        bincode::serialize(&client_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_boolean_client_key(buffer: &[u8]) -> Result<BooleanClientKey, JsError> {
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{:?}", e).as_str()))
            .map(BooleanClientKey)
    }
}
