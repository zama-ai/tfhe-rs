use crate::high_level_api as hlapi;
use crate::js_on_wasm_api::js_high_level_api::config::TfheConfig;
use crate::js_on_wasm_api::js_high_level_api::{catch_panic, catch_panic_result, into_js_error};
use crate::js_on_wasm_api::shortint::ShortintCompactPublicKeyEncryptionParameters;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Initialize a cross-origin worker pool for parallel computation.
///
/// This is an alternative to `initThreadPool` for environments where
/// cross-origin isolation headers (COOP/COEP) cannot be set.
/// It registers the coordinator Service Worker and starts the worker pool.
/// If `num_workers` is `None`, the number of workers is determined automatically.
#[cfg(feature = "zk-pok")]
#[wasm_bindgen]
pub async fn init_cross_origin_worker_pool(
    wasm_url: &str,
    bindgen_url: &str,
    coordinator_url: &str,
    num_workers: Option<u32>,
) -> Result<(), JsValue> {
    wasm_par_mq::register_coordinator(coordinator_url)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    wasm_par_mq::init_pool_sync(num_workers, wasm_url, bindgen_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Register the coordinator Service Worker for cross-origin parallelism.
///
/// This must be called from the main thread before using
/// [`init_cross_origin_worker_pool_from_worker`].
#[cfg(feature = "zk-pok")]
#[wasm_bindgen]
pub async fn register_cross_origin_coordinator(coordinator_url: &str) -> Result<(), JsValue> {
    wasm_par_mq::register_coordinator(coordinator_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Initialize a cross-origin worker pool from within a Web Worker context
/// (e.g., a Comlink worker).
///
/// The coordinator Service Worker must already be registered from the main
/// thread via [`register_cross_origin_coordinator`] before calling this.
/// If `num_workers` is `None`, the number of workers is determined automatically.
#[cfg(feature = "zk-pok")]
#[wasm_bindgen]
pub async fn init_cross_origin_worker_pool_from_worker(
    wasm_url: &str,
    bindgen_url: &str,
    num_workers: Option<u32>,
) -> Result<(), JsValue> {
    wasm_par_mq::init_pool_sync_from_worker(num_workers, wasm_url, bindgen_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub struct TfheClientKey(pub(crate) hlapi::ClientKey);

#[wasm_bindgen]
impl TfheClientKey {
    #[wasm_bindgen]
    pub fn generate(config: &TfheConfig) -> Result<TfheClientKey, JsError> {
        catch_panic(|| Self(hlapi::ClientKey::generate(config.0)))
    }

    #[wasm_bindgen]
    pub fn generate_with_seed(
        config: &TfheConfig,
        seed: JsValue,
    ) -> Result<TfheClientKey, JsError> {
        catch_panic_result(|| {
            let seed =
                u128::try_from(seed).map_err(|_| JsError::new("Value does not fit in a u128"))?;
            let key = hlapi::ClientKey::generate_with_seed(config.0, crate::Seed(seed));
            Ok(Self(key))
        })
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheClientKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
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
    ) -> Result<TfheClientKey, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

// Wasm cannot generate a normal server key, only a compressed one
#[wasm_bindgen]
pub struct TfheCompressedServerKey(pub(crate) hlapi::CompressedServerKey);

#[wasm_bindgen]
impl TfheCompressedServerKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfheCompressedServerKey, JsError> {
        catch_panic(|| Self(hlapi::CompressedServerKey::new(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheCompressedServerKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
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
    ) -> Result<TfheCompressedServerKey, JsError> {
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
pub struct TfheServerKey(pub(crate) hlapi::ServerKey);

#[wasm_bindgen]
impl TfheServerKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfheServerKey, JsError> {
        catch_panic_result(|| Ok(Self(hlapi::ServerKey::new(&client_key.0))))
    }
}

#[wasm_bindgen]
pub fn set_server_key(server_key: &TfheServerKey) -> Result<(), JsError> {
    catch_panic_result(|| {
        crate::set_server_key(server_key.0.clone());
        Ok(())
    })
}

#[wasm_bindgen]
pub struct TfhePublicKey(pub(crate) hlapi::PublicKey);

#[wasm_bindgen]
impl TfhePublicKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfhePublicKey, JsError> {
        catch_panic_result(|| {
            let uses_big_params = client_key.0.key.block_parameters().encryption_key_choice()
                == crate::shortint::parameters::EncryptionKeyChoice::Big;
            if uses_big_params {
                return Err(JsError::new(
                    "PublicKey using big parameters not compatible wasm",
                ));
            }
            Ok(Self(hlapi::PublicKey::new(&client_key.0)))
        })
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfhePublicKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
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
    ) -> Result<TfhePublicKey, JsError> {
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
pub struct TfheCompressedPublicKey(pub(crate) hlapi::CompressedPublicKey);

#[wasm_bindgen]
impl TfheCompressedPublicKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfheCompressedPublicKey, JsError> {
        catch_panic(|| Self(hlapi::CompressedPublicKey::new(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn decompress(&self) -> Result<TfhePublicKey, JsError> {
        catch_panic(|| TfhePublicKey(self.0.decompress()))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheCompressedPublicKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
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
    ) -> Result<TfheCompressedPublicKey, JsError> {
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
pub struct TfheCompactPublicKey(pub(crate) hlapi::CompactPublicKey);

#[wasm_bindgen]
impl TfheCompactPublicKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfheCompactPublicKey, JsError> {
        catch_panic(|| Self(hlapi::CompactPublicKey::new(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheCompactPublicKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
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
    ) -> Result<TfheCompactPublicKey, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_deserialize_conformant(
        buffer: &[u8],
        serialized_size_limit: u64,
        conformance_params: &ShortintCompactPublicKeyEncryptionParameters,
    ) -> Result<TfheCompactPublicKey, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .deserialize_from(buffer, &conformance_params.compact_pke_params)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

#[wasm_bindgen]
pub struct TfheCompressedCompactPublicKey(pub(crate) hlapi::CompressedCompactPublicKey);

#[wasm_bindgen]
impl TfheCompressedCompactPublicKey {
    #[wasm_bindgen]
    pub fn new(client_key: &TfheClientKey) -> Result<TfheCompressedCompactPublicKey, JsError> {
        catch_panic(|| Self(hlapi::CompressedCompactPublicKey::new(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<TfheCompressedCompactPublicKey, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn decompress(&self) -> Result<TfheCompactPublicKey, JsError> {
        catch_panic(|| TfheCompactPublicKey(self.0.decompress()))
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
    ) -> Result<TfheCompressedCompactPublicKey, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_deserialize_conformant(
        buffer: &[u8],
        serialized_size_limit: u64,
        conformance_params: &ShortintCompactPublicKeyEncryptionParameters,
    ) -> Result<TfheCompressedCompactPublicKey, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .deserialize_from(buffer, &conformance_params.compact_pke_params)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}
