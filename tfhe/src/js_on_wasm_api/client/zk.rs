use super::TfheConfig;
use crate::js_on_wasm_api::{catch_panic_result, into_js_error};
use wasm_bindgen::prelude::*;

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

#[wasm_bindgen]
impl CompactPkeCrs {
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

    #[wasm_bindgen]
    pub fn from_config(config: &TfheConfig, max_num_bits: usize) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::core_crypto::entities::CompactPkeCrs::from_config(config.0, max_num_bits)
                .map(CompactPkeCrs)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_deserialize_from_public_params(
        buffer: &[u8],
        serialized_size_limit: u64,
    ) -> Result<Self, JsError> {
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
