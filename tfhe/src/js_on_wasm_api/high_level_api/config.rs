use wasm_bindgen::prelude::*;

use crate::high_level_api as hlapi;

#[wasm_bindgen]
pub struct TfheConfig(pub(crate) hlapi::Config);

#[wasm_bindgen]
pub struct TfheConfigBuilder(pub(crate) hlapi::ConfigBuilder);

#[wasm_bindgen]
impl TfheConfigBuilder {
    #[wasm_bindgen]
    pub fn all_disabled() -> Self {
        Self(hlapi::ConfigBuilder::all_disabled())
    }

    #[wasm_bindgen]
    pub fn enable_default_integers(self) -> Self {
        Self(self.0.enable_default_integers())
    }

    #[wasm_bindgen]
    pub fn enable_default_integers_small(self) -> Self {
        Self(self.0.enable_default_integers_small())
    }

    #[wasm_bindgen]
    pub fn enable_custom_integers(
        self,
        block_parameters: crate::js_on_wasm_api::shortint::ShortintParameters,
    ) -> Self {
        Self(self.0.enable_custom_integers(block_parameters.0, None))
    }

    #[wasm_bindgen]
    pub fn build(self) -> TfheConfig {
        TfheConfig(self.0.build())
    }
}
