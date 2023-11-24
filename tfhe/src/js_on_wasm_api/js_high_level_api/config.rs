use wasm_bindgen::prelude::*;

use crate::high_level_api as hlapi;

#[wasm_bindgen]
pub struct TfheConfig(pub(crate) hlapi::Config);

#[wasm_bindgen]
pub struct TfheConfigBuilder(pub(crate) hlapi::ConfigBuilder);

#[wasm_bindgen]
impl TfheConfigBuilder {
    #[wasm_bindgen]
    pub fn default() -> Self {
        Self(hlapi::ConfigBuilder::default())
    }

    #[wasm_bindgen]
    pub fn default_with_small_encryption() -> Self {
        Self(hlapi::ConfigBuilder::default_with_small_encryption())
    }

    #[wasm_bindgen]
    pub fn default_with_big_encryption() -> Self {
        Self(hlapi::ConfigBuilder::default_with_big_encryption())
    }

    #[wasm_bindgen]
    pub fn use_custom_parameters(
        self,
        block_parameters: &crate::js_on_wasm_api::shortint::ShortintParameters,
    ) -> Self {
        Self(self.0.use_custom_parameters(block_parameters.0, None))
    }

    #[wasm_bindgen]
    pub fn build(self) -> TfheConfig {
        TfheConfig(self.0.build())
    }
}
