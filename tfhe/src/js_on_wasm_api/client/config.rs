use crate::high_level_api as hlapi;
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
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
