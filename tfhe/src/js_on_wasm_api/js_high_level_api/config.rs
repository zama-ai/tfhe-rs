use crate::high_level_api::ConfigBuilder;
use crate::js_on_wasm_api::js_high_level_api::client::TfheConfig;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TfheConfigBuilder(pub(crate) ConfigBuilder);

#[wasm_bindgen]
impl TfheConfigBuilder {
    #[wasm_bindgen]
    pub fn default() -> Self {
        Self(ConfigBuilder::default())
    }

    #[wasm_bindgen]
    pub fn with_custom_parameters(
        block_parameters: &crate::js_on_wasm_api::shortint::ShortintParameters,
    ) -> Self {
        Self(ConfigBuilder::with_custom_parameters(block_parameters.0))
    }

    #[wasm_bindgen]
    pub fn use_custom_parameters(
        self,
        block_parameters: &crate::js_on_wasm_api::shortint::ShortintParameters,
    ) -> Self {
        Self(self.0.use_custom_parameters(block_parameters.0))
    }

    #[wasm_bindgen]
    pub fn use_dedicated_compact_public_key_parameters(
        self,
        compact_public_key_parameters: &crate::js_on_wasm_api::shortint::ShortintCompactPublicKeyEncryptionParameters,
    ) -> Self {
        Self(self.0.use_dedicated_compact_public_key_parameters((
            compact_public_key_parameters.compact_pke_params,
            compact_public_key_parameters.casting_parameters,
        )))
    }

    #[wasm_bindgen]
    pub fn build(self) -> TfheConfig {
        TfheConfig(self.0.build())
    }
}
