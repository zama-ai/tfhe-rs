use wasm_bindgen::prelude::*;

use crate::js_on_wasm_api::js_high_level_api::config::TfheConfig;
use crate::js_on_wasm_api::js_high_level_api::{catch_panic_result, into_js_error};
use crate::js_on_wasm_api::shortint::ShortintParameters;

#[derive(Copy, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub enum ZkComputeLoad {
    Proof,
    Verify,
}

impl Into<crate::zk::ZkComputeLoad> for ZkComputeLoad {
    fn into(self) -> crate::zk::ZkComputeLoad {
        match self {
            Self::Proof => crate::zk::ZkComputeLoad::Proof,
            Self::Verify => crate::zk::ZkComputeLoad::Verify,
        }
    }
}

#[wasm_bindgen]
pub struct CompactPkeCrs(pub(crate) crate::core_crypto::entities::CompactPkeCrs);

#[wasm_bindgen]
pub struct CompactPkePublicParams(pub(crate) crate::zk::CompactPkePublicParams);

#[wasm_bindgen]
impl CompactPkePublicParams {
    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<CompactPkePublicParams, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(CompactPkePublicParams)
                .map_err(into_js_error)
        })
    }
}

#[wasm_bindgen]
impl CompactPkeCrs {
    #[wasm_bindgen]
    pub fn from_parameters(
        parameters: ShortintParameters,
        max_num_message: usize,
    ) -> Result<CompactPkeCrs, JsError> {
        catch_panic_result(|| {
            crate::core_crypto::entities::CompactPkeCrs::from_shortint_params(
                parameters.0,
                max_num_message,
            )
            .map(CompactPkeCrs)
            .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn from_config(config: &TfheConfig, max_num_bits: usize) -> Result<CompactPkeCrs, JsError> {
        catch_panic_result(|| {
            crate::core_crypto::entities::CompactPkeCrs::from_config(config.0, max_num_bits)
                .map(CompactPkeCrs)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn public_params(&self) -> CompactPkePublicParams {
        CompactPkePublicParams(self.0.public_params().clone())
    }
}
