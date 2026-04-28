use crate::high_level_api as hlapi;
use crate::js_on_wasm_api::{
    catch_panic, catch_panic_result, generic_safe_deserialize, generic_safe_serialize,
};
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
        generic_safe_serialize(&self.0, serialized_size_limit)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        generic_safe_deserialize(buffer, serialized_size_limit).map(Self)
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
