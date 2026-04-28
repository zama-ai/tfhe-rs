use crate::high_level_api as hlapi;
use crate::js_on_wasm_api::{catch_panic, catch_panic_result, into_js_error};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TfheConfig(pub(crate) hlapi::Config);

#[wasm_bindgen]
impl TfheConfig {
    #[wasm_bindgen]
    pub fn default() -> Self {
        Self(hlapi::ConfigBuilder::default().build())
    }
}

#[wasm_bindgen]
pub struct TfheClientKey(pub(crate) hlapi::ClientKey);

#[wasm_bindgen]
impl TfheClientKey {
    #[wasm_bindgen]
    pub fn generate(config: &TfheConfig) -> Result<Self, JsError> {
        catch_panic(|| Self(hlapi::ClientKey::generate(config.0)))
    }

    #[wasm_bindgen]
    pub fn generate_with_seed(config: &TfheConfig, seed: JsValue) -> Result<Self, JsError> {
        catch_panic_result(|| {
            let seed =
                u128::try_from(seed).map_err(|_| JsError::new("Value does not fit in a u128"))?;
            let key = hlapi::ClientKey::generate_with_seed(config.0, crate::Seed(seed));
            Ok(Self(key))
        })
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
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
