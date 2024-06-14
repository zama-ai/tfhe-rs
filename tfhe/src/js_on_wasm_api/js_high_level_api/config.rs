use crate::high_level_api as hlapi;
use wasm_bindgen::prelude::*;

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
        compact_public_key_parameters: Option<
            crate::js_on_wasm_api::shortint::ShortintCompactPublicKeyEncryptionParameters,
        >,
    ) -> Self {
        let compact_pke_params =
            compact_public_key_parameters.map(|p| (p.compact_pke_params, p.casting_parameters));
        Self(
            self.0
                .use_custom_parameters(block_parameters.0, None, compact_pke_params),
        )
    }

    #[wasm_bindgen]
    pub fn build(self) -> TfheConfig {
        TfheConfig(self.0.build())
    }
}
