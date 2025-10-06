use wasm_bindgen::prelude::*;

use crate::js_on_wasm_api::js_high_level_api::config::TfheConfig;
use crate::js_on_wasm_api::js_high_level_api::{catch_panic_result, into_js_error};

use crate::zk::Compressible;

#[derive(Copy, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub enum ZkComputeLoad {
    Proof,
    Verify,
}

impl From<ZkComputeLoad> for crate::zk::ZkComputeLoad {
    fn from(value: ZkComputeLoad) -> Self {
        match value {
            ZkComputeLoad::Proof => Self::Proof,
            ZkComputeLoad::Verify => Self::Verify,
        }
    }
}

#[wasm_bindgen]
pub struct CompactPkeCrs(pub(crate) crate::core_crypto::entities::CompactPkeCrs);

// "wasm bindgen is fragile and prefers the actual type vs. Self"
#[allow(clippy::use_self)]
#[wasm_bindgen]
impl CompactPkeCrs {
    #[wasm_bindgen]
    pub fn serialize(&self, compress: bool) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| {
            let data = if compress {
                bincode::serialize(&self.0.compress())
            } else {
                bincode::serialize(&self.0)
            };
            data.map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<CompactPkeCrs, JsError> {
        // If buffer is compressed it is automatically detected and uncompressed.
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(CompactPkeCrs)
                .map_err(into_js_error)
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
    pub fn safe_deserialize(
        buffer: &[u8],
        serialized_size_limit: u64,
    ) -> Result<CompactPkeCrs, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
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
    pub fn deserialize_from_public_params(buffer: &[u8]) -> Result<CompactPkeCrs, JsError> {
        // If buffer is compressed it is automatically detected and uncompressed.
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(crate::zk::ZkCompactPkeV1PublicParams::into)
                .map(CompactPkeCrs)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_deserialize_from_public_params(
        buffer: &[u8],
        serialized_size_limit: u64,
    ) -> Result<CompactPkeCrs, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(crate::zk::ZkCompactPkeV1PublicParams::into)
                .map(CompactPkeCrs)
                .map_err(into_js_error)
        })
    }
}
